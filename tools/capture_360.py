#!/usr/bin/env python3
"""Capture network/WebSocket/WebRTC activity of a Chrome tab through CDP (loopback only).

Only observes the tab you are logged in on with your own account. It never types credentials,
never stores cookie values, and redacts tokens/signatures in everything written to events.jsonl.
Full playable URLs are written only with --save-urls, to a 0600 file under the git-ignored captures/.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import re

from cdp import CDPClient, CDPError, http_json  # noqa: E402
from common import (  # noqa: E402
    MEDIA_EXT_RE, MEDIA_MIME_RE, harvest_urls, json_fingerprints, parse_json_maybe, redact_headers,
    redact_json, redact_url, sniff, tags_for, url_params, fp, mask,
)
from live_probe import (  # noqa: E402
    LIFECYCLE_MARKS, default_headers, event_summary, format_report, lifecycle, lifecycle_summary, normalize_url,
    probe_url, url_key,
)

DEFAULT_URL = "https://my.jia.360.cn/web/myList?from=mpc_ipcam_web&cate=all"
HOOK_SRC = (Path(__file__).with_name("hook.js")).read_text()
NOISE_TYPES = {"Image", "Font", "Stylesheet", "Script", "Ping", "Other", "Document", "Manifest", "TextTrack"}
LOGGED_BODY_MIME = re.compile(r"(json|text/|xml|mpegurl|javascript\+json)", re.I)
OPAQUE_RUN = re.compile(r"[A-Za-z0-9_\-+/=.%~]{20,}")
LIVE_PATH_RE = re.compile(r"\.(flv|m3u8)$", re.I)


def scrub_text(s: str, limit: int = 200) -> str:
    s = OPAQUE_RUN.sub(lambda m: mask(m.group(0)), s)
    return s if len(s) <= limit else s[:limit] + "..."


def launch_chrome(port: int, profile: Path, url: str, headless: bool, extra: list[str]) -> subprocess.Popen:
    exe = next((p for p in (shutil.which(n) for n in ("google-chrome", "chromium", "chromium-browser")) if p), None)
    if not exe:
        sys.exit("No Chrome/Chromium found in PATH")
    if not headless and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        sys.exit("No DISPLAY/WAYLAND_DISPLAY: a headed Chrome cannot be shown here. Run this on the Linux desktop "
                 "session (or pass --headless if the profile is already logged in).")
    cmd = [exe, f"--user-data-dir={profile}", f"--remote-debugging-port={port}",
           "--remote-debugging-address=127.0.0.1", "--no-first-run", "--no-default-browser-check", url]
    if headless:
        cmd.insert(1, "--headless=new")
    cmd[1:1] = extra
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


async def wait_endpoint(port: int, timeout: float = 25.0) -> dict:
    end = time.monotonic() + timeout
    while True:
        try:
            return http_json(port, "/json/version")
        except Exception:
            if time.monotonic() > end:
                raise
            await asyncio.sleep(0.5)


def bash_quote(s: str) -> str:
    return "$'" + s.replace("\\", "\\\\").replace("'", "\\'").replace("\r", "\\r").replace("\n", "\\n") + "'"


class Capture:
    def __init__(self, cdp: CDPClient, args: argparse.Namespace, outdir: Path) -> None:
        self.cdp, self.args, self.outdir = cdp, args, outdir
        self.t0 = time.monotonic()
        self.fh = open(outdir / "events.jsonl", "a", buffering=1)
        self.events: list[dict] = []
        self.recs: dict[str, dict] = {}
        self.cur: dict[tuple, str] = {}
        self.extra: dict[tuple, dict] = {}
        self.ws: dict[str, dict] = {}
        self.body_urls: list[dict] = []
        self.seq = 0
        self.sessions: dict[str, asyncio.Future] = {}
        self.live_seen: set[str] = set()
        self.finished = asyncio.Event()
        self.lifecycle_started = False

    # ---- output ---------------------------------------------------------
    def emit(self, kind: str, **f: Any) -> dict:
        ev = {"t": round(time.monotonic() - self.t0, 3), "wall": round(time.time(), 3), "kind": kind, **f}
        self.events.append(ev)
        self.fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
        return ev

    def say(self, msg: str) -> None:
        print(f"[{time.monotonic() - self.t0:7.2f}s] {msg}", flush=True)

    # ---- session setup --------------------------------------------------
    async def setup(self, sid: str, info: dict) -> None:
        # Both our own attach and Target.attachedToTarget land here; the second caller waits for the first.
        if sid in self.sessions:
            await self.sessions[sid]
            return
        done = self.sessions[sid] = asyncio.get_running_loop().create_future()
        ttype = info.get("type", "")

        async def attempt(method: str, params: dict | None = None) -> None:
            try:
                await self.cdp.send(method, params, sid)
            except (CDPError, asyncio.TimeoutError) as e:
                if self.args.verbose:
                    self.say(f"setup {ttype}: {method} failed: {e}")

        await attempt("Network.enable", {"maxPostDataSize": 65536})
        await attempt("Runtime.enable")
        if ttype in ("page", "iframe"):
            await attempt("Page.enable")
            await attempt("Page.addScriptToEvaluateOnNewDocument", {"source": HOOK_SRC, "runImmediately": True})
        await attempt("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True})
        done.set_result(True)
        if self.args.verbose:
            self.say(f"session ready: {ttype} {redact_url(info.get('url', ''))}")

    def register(self) -> None:
        c = self.cdp
        c.on("Target.attachedToTarget", lambda p, s: self.setup(p["sessionId"], p["targetInfo"]))
        c.on("Network.requestWillBeSent", self.on_request)
        c.on("Network.requestWillBeSentExtraInfo", self.on_request_extra)
        c.on("Network.responseReceived", self.on_response)
        c.on("Network.dataReceived", self.on_data)
        c.on("Network.loadingFinished", self.on_finished)
        c.on("Network.loadingFailed", self.on_failed)
        c.on("Network.webSocketCreated", self.on_ws_created)
        c.on("Network.webSocketWillSendHandshakeRequest", self.on_ws_hs_req)
        c.on("Network.webSocketHandshakeResponseReceived", self.on_ws_hs_resp)
        c.on("Network.webSocketFrameSent", lambda p, s: self.on_ws_frame(p, "sent"))
        c.on("Network.webSocketFrameReceived", lambda p, s: self.on_ws_frame(p, "recv"))
        c.on("Network.webSocketClosed", self.on_ws_closed)
        c.on("Network.webSocketFrameError", lambda p, s: self.emit("ws.error", id=self.ws_id(p), error=p.get("errorMessage")))
        c.on("Runtime.consoleAPICalled", self.on_console)
        c.on("Page.frameNavigated", self.on_navigated)

    # ---- HTTP -----------------------------------------------------------
    def on_navigated(self, p: dict, sid: str | None) -> None:
        fr = p.get("frame", {})
        if not fr.get("parentId"):
            self.say(f"NAV   {redact_url(fr.get('url', ''))}")
            self.emit("navigate", url=redact_url(fr.get("url", "")))

    def on_request(self, p: dict, sid: str | None) -> None:
        req, key = p["request"], (sid, p["requestId"])
        url = req["url"]
        if url.startswith(("data:", "blob:", "chrome-extension:")):
            return
        if p.get("redirectResponse") and key in self.cur:
            old = self.cur[key]
            self.apply_response(old, p["redirectResponse"], p.get("type", "Other"), redirect=True)
        self.seq += 1
        rid = f"r{self.seq}"
        self.cur[key] = rid
        sp = urlsplit(url)
        tags = tags_for(sp.path + "?" + sp.query)
        hdrs = {k.lower(): v for k, v in req.get("headers", {}).items()}
        rec = {"url": url, "method": req["method"], "rtype": p.get("type", "Other"), "tags": tags, "sid": sid,
               "raw": p["requestId"], "bytes": 0, "chunks": 0, "first": None, "status": None, "mime": "",
               "hdr": {h: hdrs[h] for h in ("referer", "origin", "user-agent") if h in hdrs}, "cookie": False,
               "sent": time.time()}
        self.recs[rid] = rec
        post, post_fps = None, {}
        text = req.get("postData")
        if text:
            js = parse_json_maybe(text)
            if js is not None:
                post, post_fps = redact_json(js), json_fingerprints(js)
            elif "=" in text and len(text) < 8192:
                items = parse_qsl(text, keep_blank_values=True)
                post = {k: v if len(v) < 20 else mask(v) for k, v in items}
                post_fps = {k: fp(v) for k, v in items if len(v) >= 6}
            else:
                post = f"<{len(text)} bytes>" + scrub_text(text, 80)
            tags = sorted(set(tags) | set(tags_for(text[:2000])))
            rec["tags"] = tags
        init = p.get("initiator", {})
        frames = (init.get("stack") or {}).get("callFrames") or []
        where = init.get("type", "")
        if frames:
            f0 = frames[0]
            where += f" {f0.get('functionName') or '<anon>'}@{os.path.basename(urlsplit(f0.get('url', '')).path)}:{f0.get('lineNumber')}"
        self.emit("request", id=rid, method=req["method"], url=redact_url(url), host=sp.netloc, rtype=rec["rtype"],
                  tags=tags, params=url_params(url), url_fp=fp(url), path_fp=fp(sp.path), post=post, post_fps=post_fps,
                  req_headers=redact_headers(req.get("headers", {})), initiator=where)
        if key in self.extra:
            self.apply_extra(rid, self.extra.pop(key))

    def apply_extra(self, rid: str, headers: dict) -> None:
        rec = self.recs[rid]
        low = {k.lower(): v for k, v in headers.items()}
        rec["cookie"] = "cookie" in low
        for h in ("referer", "origin", "user-agent"):
            if h in low:
                rec["hdr"][h] = low[h]
        self.emit("request.extra", id=rid, req_headers=redact_headers(headers), cookie_sent=rec["cookie"])

    def on_request_extra(self, p: dict, sid: str | None) -> None:
        key = (sid, p["requestId"])
        if key in self.cur:
            self.apply_extra(self.cur[key], p.get("headers", {}))
        else:
            self.extra[key] = p.get("headers", {})

    def want_stream(self, rec: dict) -> bool:
        path = urlsplit(rec["url"]).path.lower()
        if path.endswith((".m3u8", ".mpd")):
            return False
        return rec["rtype"] == "Media" or bool(MEDIA_MIME_RE.search(rec["mime"])) or \
            rec["mime"] == "application/octet-stream" or bool(MEDIA_EXT_RE.search(rec["url"]))

    def apply_response(self, rid: str, r: dict, rtype: str, redirect: bool = False) -> None:
        rec = self.recs[rid]
        rec.update(status=r.get("status"), mime=r.get("mimeType", ""), rtype=rec["rtype"] or rtype)
        self.emit("response", id=rid, status=r.get("status"), mime=rec["mime"], protocol=r.get("protocol"),
                  redirect=redirect, resp_headers=redact_headers(r.get("headers", {})))
        self.print_line(rid)

    def print_line(self, rid: str) -> None:
        rec = self.recs[rid]
        if rec["rtype"] in NOISE_TYPES and not rec["tags"]:
            return
        self.say(f"{rec['rtype']:<7} {rec['method']:<4} {rec['status']} {','.join(rec['tags']) or '-':<22} {redact_url(rec['url'])[:150]}")

    def on_response(self, p: dict, sid: str | None) -> None:
        rid = self.cur.get((sid, p["requestId"]))
        if not rid:
            return
        self.apply_response(rid, p["response"], p.get("type", "Other"))
        rec = self.recs[rid]
        if self.want_stream(rec) and rec["status"] in (200, 206):
            self.cdp.spawn(self.start_stream(rid))
        if getattr(self.args, "probe_live", False) and rec["status"] in (200, 206) \
                and LIVE_PATH_RE.search(urlsplit(rec["url"]).path):
            key = url_key(rec["url"])
            if key not in self.live_seen:
                self.live_seen.add(key)
                self.cdp.spawn(self.run_live_probe(rid))

    # ---- live probe (second HTTP client on the same stream URL) ---------
    async def run_live_probe(self, rid: str) -> None:
        rec = self.recs[rid]
        url, headers = rec["url"], default_headers(normalize_url(rec["url"]), rec["hdr"])
        secs = self.args.probe_seconds
        self.say(f"LIVE   probing {redact_url(url)[:120]} in background ({secs:g}s)")
        res = await asyncio.to_thread(probe_url, url, headers, secs)
        browser_playing = bool(rec["bytes"]) and not rec.get("done")
        if res["result"] == "LIVE STREAM OK" and browser_playing:
            verdict = "PASS"
        elif browser_playing:
            verdict = "FAIL"
        else:
            verdict = f"INCONCLUSIVE (browser request not streaming: bytes={rec['bytes']} done={bool(rec.get('done'))})"
        self.emit("live.probe", id=rid, second_client=verdict, browser_bytes=rec["bytes"], **event_summary(res))
        for line in format_report(res).splitlines():
            self.say(line)
        self.say(f"SECOND_CLIENT_STREAM = {verdict}")
        if getattr(self.args, "lifecycle", False) and res["result"] == "LIVE STREAM OK" and res["kind"] == "FLV" \
                and not self.lifecycle_started:
            self.lifecycle_started = True
            await self.run_lifecycle(rid, headers)
        elif getattr(self.args, "lifecycle", False) and not self.lifecycle_started and res["kind"] == "FLV":
            self.finished.set()

    async def run_lifecycle(self, rid: str, headers: dict[str, str]) -> None:
        rec = self.recs[rid]
        try:
            if self.args.stop_after:
                self.say(f"LIFECYCLE closing the player tab in {self.args.stop_after:g}s")
                await asyncio.sleep(self.args.stop_after)
                await self.cdp.send("Page.navigate", {"url": "about:blank"}, rec["sid"])
            else:
                self.say("LIFECYCLE waiting until you stop the playback in the page ...")
            while not rec.get("done"):
                await asyncio.sleep(0.25)
            t_stop = time.monotonic()
            self.say("LIFECYCLE player stopped; probing the SAME url without calling playV2")
            rows = await asyncio.to_thread(
                lifecycle, rec["url"], headers, t_stop, LIFECYCLE_MARKS, 3.0,
                lambda s: print(f"[lifecycle] {s}", flush=True))
            self.emit("live.lifecycle", id=rid, rows=[{"t": m, "media": r["media"], "result": r["result"],
                                                         "status": r["status"], "bytes": r["bytes"]} for m, r in rows])
            for line in lifecycle_summary(rows).splitlines():
                self.say(line)
        finally:
            self.finished.set()

    async def start_stream(self, rid: str) -> None:
        rec = self.recs[rid]
        try:
            res = await self.cdp.send("Network.streamResourceContent", {"requestId": rec["raw"]}, rec["sid"])
            if res.get("bufferedData"):
                self.note_bytes(rid, base64.b64decode(res["bufferedData"]))
        except (CDPError, asyncio.TimeoutError):
            pass

    def note_bytes(self, rid: str, data: bytes) -> None:
        rec = self.recs[rid]
        if rec["first"] is None and data:
            rec["first"] = data[:256]
            self.emit("stream.head", id=rid, magic=sniff(data[:256]), head=data[:24].hex(), len=len(data))
            self.say(f"STREAM {redact_url(rec['url'])[:100]} first bytes -> {sniff(data[:256])}")

    def on_data(self, p: dict, sid: str | None) -> None:
        rid = self.cur.get((sid, p["requestId"]))
        if not rid:
            return
        rec = self.recs[rid]
        rec["bytes"] += p.get("dataLength", 0)
        rec["chunks"] += 1
        if p.get("data"):
            self.note_bytes(rid, base64.b64decode(p["data"]))

    def body_wanted(self, rec: dict) -> bool:
        if rec["rtype"] not in ("XHR", "Fetch", "Other", "Media") or rec["status"] not in (200, 206):
            return False
        path = urlsplit(rec["url"]).path.lower()
        return path.endswith(".m3u8") or bool(LOGGED_BODY_MIME.search(rec["mime"])) and rec["rtype"] in ("XHR", "Fetch")

    def on_finished(self, p: dict, sid: str | None) -> None:
        rid = self.cur.get((sid, p["requestId"]))
        if not rid:
            return
        rec = self.recs[rid]
        rec["done"] = True
        self.emit("finish", id=rid, bytes=rec["bytes"] or int(p.get("encodedDataLength", 0)), chunks=rec["chunks"])
        if self.body_wanted(rec):
            self.cdp.spawn(self.fetch_body(rid))

    def on_failed(self, p: dict, sid: str | None) -> None:
        rid = self.cur.get((sid, p["requestId"]))
        if rid:
            self.recs[rid]["done"] = True
            self.emit("finish", id=rid, bytes=self.recs[rid]["bytes"], error=p.get("errorText"), canceled=p.get("canceled"))
    async def fetch_body(self, rid: str) -> None:
        rec = self.recs[rid]
        try:
            res = await self.cdp.send("Network.getResponseBody", {"requestId": rec["raw"]}, rec["sid"])
        except (CDPError, asyncio.TimeoutError):
            return
        raw = base64.b64decode(res["body"]) if res.get("base64Encoded") else res["body"].encode()
        magic = sniff(raw[:256])
        ev: dict[str, Any] = {"id": rid, "size": len(raw), "magic": magic}
        if len(raw) <= self.args.max_body and (magic.startswith(("text", "HLS"))):
            text = raw.decode("utf-8", "replace")
            js = parse_json_maybe(text)
            if js is not None:
                ev["json"] = redact_json(js)
                ev["fps"] = json_fingerprints(js)
                found = harvest_urls(js)
                ev["urls"] = [{"path": pth, "url": redact_url(u)} for pth, u in found]
                for pth, u in found:
                    self.body_urls.append({"url": u, "source": f"{rid}:{pth}", "headers": rec["hdr"]})
            elif text.lstrip().startswith("#EXTM3U"):
                ev["playlist"] = [redact_url(l) if not l.startswith("#") else scrub_text(l, 160)
                                  for l in text.splitlines()[:60]]
            else:
                ev["text"] = scrub_text(text, 300)
        self.emit("body", **ev)
        if ev.get("urls"):
            for u in ev["urls"]:
                self.say(f"URL    in response {rid} at {u['path']}: {u['url'][:140]}")

    # ---- WebSocket ------------------------------------------------------
    def ws_id(self, p: dict) -> str:
        return f"ws:{p['requestId']}"

    def on_ws_created(self, p: dict, sid: str | None) -> None:
        wid = self.ws_id(p)
        self.ws[wid] = {"url": p["url"], "frames": {"sent": 0, "recv": 0}, "bytes": {"sent": 0, "recv": 0},
                        "magics": {}, "opcodes": {}, "hdr": {}}
        self.emit("ws.created", id=wid, url=redact_url(p["url"]), tags=tags_for(p["url"]), params=url_params(p["url"]),
                  url_fp=fp(p["url"]), initiator=(p.get("initiator") or {}).get("type"))
        self.say(f"WS     open {redact_url(p['url'])[:140]}")

    def on_ws_hs_req(self, p: dict, sid: str | None) -> None:
        wid = self.ws_id(p)
        h = p.get("request", {}).get("headers", {})
        if wid in self.ws:
            low = {k.lower(): v for k, v in h.items()}
            self.ws[wid]["hdr"] = {k: low[k] for k in ("origin", "user-agent") if k in low}
            self.ws[wid]["cookie"] = "cookie" in low
        self.emit("ws.handshake.request", id=wid, req_headers=redact_headers(h))

    def on_ws_hs_resp(self, p: dict, sid: str | None) -> None:
        r = p.get("response", {})
        self.emit("ws.handshake.response", id=self.ws_id(p), status=r.get("status"), resp_headers=redact_headers(r.get("headers", {})))

    def on_ws_frame(self, p: dict, direction: str) -> None:
        wid = self.ws_id(p)
        w = self.ws.get(wid)
        if w is None:
            return
        fr = p["response"]
        opcode = fr.get("opcode")
        payload = fr.get("payloadData", "")
        if opcode == 2:
            raw = base64.b64decode(payload)
            magic = sniff(raw[:256], len(raw))
        else:
            raw = payload.encode("utf-8", "replace")
            magic = "text" if opcode == 1 else f"opcode {opcode}"
        w["frames"][direction] += 1
        w["bytes"][direction] += len(raw)
        w["opcodes"][str(opcode)] = w["opcodes"].get(str(opcode), 0) + 1
        new_magic = (direction, magic) not in w["magics"]
        w["magics"][(direction, magic)] = w["magics"].get((direction, magic), 0) + 1
        n = w["frames"][direction]
        if n <= 15 or new_magic:
            ev: dict[str, Any] = {"id": wid, "dir": direction, "n": n, "opcode": opcode, "len": len(raw), "magic": magic}
            if opcode == 2:
                ev["head"] = raw[:24].hex()
            else:
                js = parse_json_maybe(payload)
                ev["json"] = redact_json(js) if js is not None else None
                if js is None:
                    ev["text"] = scrub_text(payload, 160)
                ev["tags"] = tags_for(payload[:2000])
                ev["fps"] = json_fingerprints(js) if js is not None else {}
            self.emit("ws.frame", **ev)
            if n <= 3 or new_magic:
                self.say(f"WSFRM  {direction} #{n} opcode={opcode} len={len(raw)} -> {magic}")

    def on_ws_closed(self, p: dict, sid: str | None) -> None:
        wid = self.ws_id(p)
        self.emit("ws.closed", id=wid)
        self.say(f"WS     closed {redact_url(self.ws.get(wid, {}).get('url', ''))[:100]}")

    # ---- page hook ------------------------------------------------------
    def on_console(self, p: dict, sid: str | None) -> None:
        args = p.get("args") or []
        if not args or args[0].get("type") != "string":
            return
        v = args[0].get("value", "")
        if not v.startswith("__CAM360__"):
            return
        obj = parse_json_maybe(v[len("__CAM360__"):])
        if not obj:
            return
        self.emit("hook", name=obj.get("name"), data=obj.get("data"), page=obj.get("page"))
        if obj["name"].startswith(("rtc.", "mse.", "media.", "webcodecs", "wasm")) and not obj["name"].endswith("count"):
            self.say(f"HOOK   {obj['name']} {json.dumps(obj.get('data'))[:160]}")

    # ---- finish ---------------------------------------------------------
    def finalize(self) -> None:
        for rid, rec in self.recs.items():
            if not rec.get("done") and rec["bytes"]:
                self.emit("finish", id=rid, bytes=rec["bytes"], chunks=rec["chunks"], partial=True)
        for wid, w in self.ws.items():
            self.emit("ws.summary", id=wid, frames=w["frames"], bytes=w["bytes"], opcodes=w["opcodes"],
                      magics=[{"dir": d, "magic": m, "count": c} for (d, m), c in w["magics"].items()])
        self.fh.close()

    def write_candidates(self) -> list[dict]:
        cands: list[dict] = []
        seen: set[str] = set()
        for rid, rec in self.recs.items():
            if rec["rtype"] == "Media" or MEDIA_EXT_RE.search(rec["url"]) or MEDIA_MIME_RE.search(rec["mime"]):
                if rec["url"] not in seen:
                    seen.add(rec["url"])
                    cands.append({"url": rec["url"], "source": f"request {rid}", "headers": rec["hdr"],
                                  "cookie_sent": rec["cookie"], "mime": rec["mime"]})
        for wid, w in self.ws.items():
            cands.append({"url": w["url"], "source": wid, "headers": w["hdr"], "cookie_sent": w.get("cookie", False)})
        for b in self.body_urls:
            if b["url"] not in seen:
                seen.add(b["url"])
                cands.append({**b, "cookie_sent": None})
        return cands

    def save_urls(self) -> None:
        cands = self.write_candidates()
        p = self.outdir / "urls.local.json"
        p.write_text(json.dumps(cands, indent=1))
        p.chmod(0o600)
        lines = ["#!/usr/bin/env bash", "# Contains temporary credentials. Never commit; delete after use.", ""]
        for i, c in enumerate(cands):
            u = c["url"]
            h = c.get("headers", {})
            lines.append(f"# [{i}] {c['source']}  {redact_url(u)}")
            if u.startswith(("http://", "https://")):
                hdr = "".join(f"{k.title()}: {h[k]}\r\n" for k in ("referer", "origin") if k in h)
                ua = f" -user_agent {shlex.quote(h['user-agent'])}" if "user-agent" in h else ""
                lines.append(f"ffprobe -hide_banner{ua} -headers {bash_quote(hdr)} {shlex.quote(u)}")
            elif u.startswith(("rtsp", "rtmp")):
                lines.append(f"ffprobe -hide_banner {shlex.quote(u)}")
            else:
                lines.append("# ws/wss: ffmpeg cannot read it; use: python tools/probe_stream.py --from-file urls.local.json --index %d" % i)
            lines.append("")
        sh = self.outdir / "probe.local.sh"
        sh.write_text("\n".join(lines))
        sh.chmod(0o700)
        self.say(f"saved {len(cands)} candidate URL(s) -> {p} and {sh} (0600/0700, git-ignored)")


async def run(args: argparse.Namespace) -> int:
    os.umask(0o077)
    profile = Path(os.path.expanduser(args.profile))
    try:
        ver = await wait_endpoint(args.port, 1.5)
    except Exception:
        if not args.launch:
            print(f"No Chrome on 127.0.0.1:{args.port}. Start it (see README) or pass --launch.")
            return 2
        launch_chrome(args.port, profile, "about:blank", args.headless, args.chrome_arg)
        ver = await wait_endpoint(args.port)
    print(f"Connected to {ver.get('Browser')}")
    outdir = Path(args.out) / time.strftime("%Y%m%d-%H%M%S")
    outdir.mkdir(parents=True, exist_ok=True)
    outdir.chmod(0o700)

    cdp = await CDPClient.connect(ver["webSocketDebuggerUrl"])
    cap = Capture(cdp, args, outdir)
    cap.register()
    targets = (await cdp.send("Target.getTargets"))["targetInfos"]
    page = next((t for t in targets if t["type"] == "page" and args.match in t["url"]), None)
    navigate = page is None
    if page is None:
        page = next((t for t in targets if t["type"] == "page" and t["url"] in ("about:blank", "chrome://newtab/")), None)
    if page is None:
        tid = (await cdp.send("Target.createTarget", {"url": "about:blank"}))["targetId"]
        page = {"targetId": tid, "type": "page", "url": "about:blank"}
    sid = (await cdp.send("Target.attachToTarget", {"targetId": page["targetId"], "flatten": True}))["sessionId"]
    await cap.setup(sid, page)
    if navigate:
        await cdp.send("Page.navigate", {"url": args.url}, sid, timeout=90)
    elif not args.no_reload:
        # Reloading while a navigation is still in flight can stall for a long time.
        for _ in range(60):
            try:
                r = await cdp.send("Runtime.evaluate", {"expression": "document.readyState"}, sid, timeout=5)
                if r.get("result", {}).get("value") == "complete":
                    break
            except (CDPError, asyncio.TimeoutError):
                pass
            await asyncio.sleep(0.5)
        await cdp.send("Page.reload", {"ignoreCache": True}, sid, timeout=90)
    print(f"Capturing into {outdir}\nLog in manually if prompted, open the camera list, click ONE of your cameras to start live view.\n"
          "Press Ctrl-C when playback has run for ~20-30s.\n")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(s, stop.set)
    waiters = [asyncio.ensure_future(stop.wait()), asyncio.ensure_future(cap.finished.wait())]
    await asyncio.wait(waiters, timeout=args.duration or None, return_when=asyncio.FIRST_COMPLETED)
    for w in waiters:
        w.cancel()
    await asyncio.sleep(0.5)
    cap.finalize()
    if args.verbose:
        print("CDP event counts:", dict(cdp.event_counts.most_common(15)))
    if args.save_urls or getattr(args, "probe_live", False):
        cap.save_urls()
    await cdp.close()

    from analyze_har import analyze, render
    report = render(analyze(cap.events))
    (outdir / "report.txt").write_text(report)
    print("\n" + report)
    print(f"\nArtifacts: {outdir}/events.jsonl, report.txt" + (", urls.local.json, probe.local.sh" if args.save_urls else ""))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=9222)
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("--match", default="360.cn", help="substring identifying the tab to attach to")
    ap.add_argument("--profile", default="~/.360cam-debug")
    ap.add_argument("--launch", action="store_true", help="start Chrome with the dedicated profile if none is listening")
    ap.add_argument("--headless", action="store_true", help="only with --launch (profile must already be logged in)")
    ap.add_argument("--chrome-arg", action="append", default=[], help="extra Chrome flag with --launch (repeatable)")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "captures"))
    ap.add_argument("--duration", type=float, default=0, help="stop after N seconds (0 = until Ctrl-C)")
    ap.add_argument("--no-reload", action="store_true", help="do not reload the tab after attaching")
    ap.add_argument("--save-urls", action="store_true", help="write full (temporary-credential) stream URLs to a 0600 local file")
    ap.add_argument("--max-body", type=int, default=262144)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--probe-live", action="store_true",
                    help="probe each new .flv/.m3u8 URL once, in the background, as a second HTTP client (implies urls.local.json)")
    ap.add_argument("--probe-seconds", type=float, default=5)
    ap.add_argument("--lifecycle", action="store_true",
                    help="after a successful probe and once the player stops, probe the same URL at T+5/15/30/60/120s")
    ap.add_argument("--stop-after", type=float, default=0,
                    help="with --lifecycle: close the player tab after N seconds instead of waiting for you")
    a = ap.parse_args()
    a.probe_live = a.probe_live or a.lifecycle
    return asyncio.run(run(a))


if __name__ == "__main__":
    sys.exit(main())
