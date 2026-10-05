#!/usr/bin/env python3
"""End-to-end self-test of the tooling against a LOCAL fake camera site (no 360 account involved).

Serves: device list -> play API -> HLS playlist/segment, HTTP-FLV stream, WS binary (FLV) stream, and a
page that creates an RTCPeerConnection offer. Runs headless Chrome + capture_360 + analyze + probe_stream.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import websockets

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture_360  # noqa: E402

TOKEN = secrets.token_hex(20)
HTTP_PORT, WS_PORT, CDP_PORT = 18765, 18766, 19222
LIFECYCLE = "--lifecycle" in sys.argv  # also exercises capture_360 --lifecycle (adds ~2 min)


def tag(ttype: int, ts: int, body: bytes) -> bytes:
    h = bytes([ttype]) + len(body).to_bytes(3, "big") + (ts & 0xFFFFFF).to_bytes(3, "big") + bytes([ts >> 24]) + b"\0\0\0"
    return h + body + (11 + len(body)).to_bytes(4, "big")


FLV_HEAD = b"FLV\x01\x05\x00\x00\x00\x09\x00\x00\x00\x00"
PAGE = f"""<!doctype html><title>fake cam</title><script>
const q = (u, o) => fetch(u, o);
(async () => {{
  await new Promise(r => setTimeout(r, 800));
  const dev = await (await q('/api/devices')).json();
  const sn = dev.data.list[0].sn;
  const play = await (await q('/api/play?sn=' + sn)).json();
  const pl = await (await q(play.data.hls)).text();
  const seg = pl.split('\\n').find(l => l && l[0] !== '#');
  await q(new URL(seg, play.data.hls).href).then(r => r.arrayBuffer());
  const ws = new WebSocket(play.data.ws); ws.binaryType = 'arraybuffer';
  ws.onopen = () => ws.send(JSON.stringify({{cmd: 'start', sn}}));
  const flv = await q(play.data.flv); const rd = flv.body.getReader();
  for (let i = 0; i < 3; i++) await rd.read();
  const pc = new RTCPeerConnection({{iceServers: []}});
  pc.addTransceiver('video', {{direction: 'recvonly'}});
  await pc.setLocalDescription(await pc.createOffer());
}})();
</script>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, code, body: bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/":
            return self._send(200, PAGE.encode(), "text/html")
        if path == "/api/devices":
            return self._send(200, json.dumps({"code": 0, "data": {"list": [{"sn": "SN12345678", "name": "cam"}]}}).encode())
        if path == "/api/play":
            exp = int(time.time()) + 300
            base = f"http://127.0.0.1:{HTTP_PORT}"
            d = {"hls": f"{base}/live/a.m3u8?token={TOKEN}&expires={exp}", "flv": f"{base}/live/a.flv?token={TOKEN}&expires={exp}",
                 "ws": f"ws://127.0.0.1:{WS_PORT}/ws?ticket={TOKEN}", "expire_in": 300}
            return self._send(200, json.dumps({"code": 0, "data": d}).encode())
        if path.startswith("/live/"):
            if TOKEN not in query or not self.headers.get("Referer"):
                return self._send(403, b"denied", "text/plain")
            if path.endswith(".m3u8"):
                pl = "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:2\n#EXT-X-MEDIA-SEQUENCE:%d\n" % int(time.time() / 2)
                pl += "#EXTINF:2.0,\nseg.ts?token=%s\n" % TOKEN
                return self._send(200, pl.encode(), "application/vnd.apple.mpegurl")
            if path.endswith(".ts"):
                return self._send(200, (b"\x47" + b"\x1f" * 187) * 200, "video/mp2t")
            if path.endswith(".flv"):
                self.send_response(200)
                self.send_header("Content-Type", "video/x-flv")
                self.end_headers()
                self.wfile.write(FLV_HEAD)
                try:
                    for i in range(12):
                        self.wfile.write(tag(9, i * 500, b"\x17\x01\x00\x00\x00" + b"\x00" * 800))
                        self.wfile.flush()
                        time.sleep(0.5)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
        self._send(404, b"nf", "text/plain")


async def ws_handler(ws):
    if TOKEN not in ws.request.path:
        await ws.close(1008)
        return
    await ws.recv()
    await ws.send(FLV_HEAD)
    for i in range(10):
        await ws.send(tag(9, i * 500, b"\x17\x01\x00\x00\x00" + b"\x00" * 800))
        await asyncio.sleep(0.5)


async def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    out, profile = tempfile.mkdtemp(prefix="cam-selftest-"), tempfile.mkdtemp(prefix="cam-profile-")
    async with websockets.serve(ws_handler, "127.0.0.1", WS_PORT):
        args = Namespace(port=CDP_PORT, url=f"http://127.0.0.1:{HTTP_PORT}/", match="127.0.0.1", profile=profile,
                         launch=True, headless=True, out=out, duration=200 if LIFECYCLE else 30, no_reload=False, chrome_arg=["--no-proxy-server"], save_urls=True,
                         max_body=262144, verbose=False, probe_live=True, probe_seconds=3, lifecycle=LIFECYCLE, stop_after=0)
        rc = await capture_360.run(args)
        subprocess.run(["pkill", "-f", "--", f"--user-data-dir={profile}"], check=False)
        run_dir = sorted(Path(out).iterdir())[-1]
        report = (run_dir / "report.txt").read_text()
        cands = json.loads((run_dir / "urls.local.json").read_text())
        probe = Path(__file__).with_name("probe_stream.py")
        for i, c in enumerate(cands):
            if any(x in c["url"] for x in ("a.m3u8", "a.flv", "/ws?")) and c["source"].startswith(("r", "ws")) and "r4:" not in c["source"]:
                print(f"\n----- probe candidate {i}: {c['source']}")
                p = await asyncio.create_subprocess_exec(
                    sys.executable, str(probe), "--from-file", str(run_dir / "urls.local.json"), "--index", str(i),
                    "--seconds", "5", "--matrix", *(["--ws-send", '{"cmd": "start", "sn": "SN12345678"}'] if c["url"].startswith("ws") else []))
                await p.wait()
    srv.shutdown()
    must = ["HLS (m3u8)", "HTTP-FLV", "WebSocket binary stream carrying", "RTCPeerConnection", "produced by response", "expires="]
    missing = [m for m in must if m not in report]
    probes = [json.loads(l) for l in (run_dir / "events.jsonl").read_text().splitlines() if '"live.probe"' in l]
    if not any(p["result"] == "LIVE STREAM OK" and p["container"] == "FLV" and p["second_client"] == "PASS" for p in probes):
        missing.append(f"live.probe FLV second client PASS (got {[(p['container'], p['result'], p['second_client']) for p in probes]})")
    if any(TOKEN in json.dumps(p) for p in probes):
        missing.append("live.probe event leaks the token")
    print("\nSELFTEST", "PASS" if not missing and rc == 0 else f"FAIL missing={missing}")
    return 1 if missing or rc else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
