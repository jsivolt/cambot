"""Minimal async Chrome DevTools Protocol client (flattened sessions)."""
from __future__ import annotations

import asyncio
import json
import urllib.request
from collections import Counter
from typing import Any, Awaitable, Callable

import websockets

Handler = Callable[[dict, "str | None"], "Awaitable[None] | None"]


def http_json(port: int, path: str, timeout: float = 3.0) -> Any:
    # Loopback only: never talk to a non-local debugging endpoint.
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=timeout) as r:
        return json.loads(r.read().decode())


class CDPError(RuntimeError):
    pass


class CDPClient:
    def __init__(self, ws) -> None:
        self._ws = ws
        self._id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._handlers: dict[str, list[Handler]] = {}
        self._tasks: set[asyncio.Task] = set()
        self._reader: asyncio.Task | None = None
        self.event_counts: Counter = Counter()

    @classmethod
    async def connect(cls, ws_url: str) -> "CDPClient":
        ws = await websockets.connect(ws_url, max_size=None, ping_interval=None)
        c = cls(ws)
        c._reader = asyncio.create_task(c._read_loop())
        return c

    def on(self, method: str, handler: Handler) -> None:
        self._handlers.setdefault(method, []).append(handler)

    def spawn(self, coro: Awaitable[Any]) -> None:
        t = asyncio.ensure_future(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def send(self, method: str, params: dict | None = None, session_id: str | None = None,
                   timeout: float = 15.0) -> dict:
        self._id += 1
        mid = self._id
        msg: dict[str, Any] = {"id": mid, "method": method, "params": params or {}}
        if session_id:
            msg["sessionId"] = session_id
        fut = asyncio.get_running_loop().create_future()
        self._pending[mid] = fut
        await self._ws.send(json.dumps(msg))
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(mid, None)

    async def _read_loop(self) -> None:
        try:
            async for raw in self._ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.get(msg["id"])
                    if fut and not fut.done():
                        if "error" in msg:
                            fut.set_exception(CDPError(f"{msg['error'].get('message')} ({msg['error'].get('code')})"))
                        else:
                            fut.set_result(msg.get("result", {}))
                    continue
                self.event_counts[msg.get("method", "?")] += 1
                for h in self._handlers.get(msg.get("method", ""), []):
                    try:
                        r = h(msg.get("params", {}), msg.get("sessionId"))
                        if asyncio.iscoroutine(r):
                            self.spawn(r)
                    except Exception as e:  # keep the reader alive on handler bugs
                        print(f"[cdp] handler error for {msg.get('method')}: {e!r}")
        except websockets.ConnectionClosed:
            pass
        except Exception as e:
            print(f"[cdp] reader crashed: {e!r}")
        finally:
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(CDPError("connection closed"))

    async def close(self) -> None:
        for t in list(self._tasks):
            t.cancel()
        await self._ws.close()
        if self._reader:
            self._reader.cancel()
