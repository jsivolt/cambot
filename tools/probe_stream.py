#!/usr/bin/env python3
"""Validate a stream URL captured from YOUR OWN camera: protocol, container, liveness, required headers.

Credentials are never taken from the command line history: use --from-file (0600 file written by
capture_360.py --save-urls), or env STREAM_URL / COOKIE_HEADER. Does not bypass any auth: it only replays
the exact request the browser made for you, to learn which headers matter.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import EXPIRY_KEY_RE, redact_url, sniff  # noqa: E402

VCODEC = {7: "H.264/AVC", 12: "H.265/HEVC", 2: "Sorenson H.263", 4: "VP6"}
ACODEC = {10: "AAC", 2: "MP3", 7: "G.711 A-law", 8: "G.711 mu-law", 11: "Speex"}


def fetch(url: str, headers: dict[str, str], seconds: float, max_bytes: int = 4_000_000, timeout: float = 10) -> dict:
    res: dict = {"status": None, "ctype": "", "data": b"", "chunks": [], "err": None, "final": url}
    req = urllib.request.Request(url, headers=headers)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res.update(status=r.status, ctype=r.headers.get("Content-Type", ""), final=r.geturl(),
                       clen=r.headers.get("Content-Length"))
            buf = bytearray()
            while time.monotonic() - t0 < seconds and len(buf) < max_bytes:
                chunk = r.read(16384)
                if not chunk:
                    break
                buf += chunk
                res["chunks"].append((time.monotonic() - t0, len(chunk)))
            res["data"] = bytes(buf)
    except urllib.error.HTTPError as e:
        res.update(status=e.code, err=f"HTTP {e.code} {e.reason}", data=e.read(512))
    except Exception as e:  # network errors are results here, not crashes
        res["err"] = f"{type(e).__name__}: {e}"
    res["elapsed"] = time.monotonic() - t0
    return res


def scan_flv(d: bytes) -> dict:
    out = {"audio": bool(d[4] & 4), "video": bool(d[4] & 1), "tags": {}, "vcodec": set(), "acodec": set(), "keyframes": 0, "ts": []}
    pos = int.from_bytes(d[5:9], "big")
    while pos + 15 <= len(d):
        pos += 4
        ttype, size = d[pos], int.from_bytes(d[pos + 1:pos + 4], "big")
        ts = int.from_bytes(d[pos + 4:pos + 7], "big") | (d[pos + 7] << 24)
        if pos + 11 + size > len(d):
            break
        body = d[pos + 11:pos + 11 + size]
        name = {8: "audio", 9: "video", 18: "script"}.get(ttype, f"type{ttype}")
        out["tags"][name] = out["tags"].get(name, 0) + 1
        if body:
            if ttype == 9:
                if body[0] & 0x80 and len(body) >= 5:
                    out["vcodec"].add(f"ext:{body[1:5].decode('latin1')}")
                else:
                    out["vcodec"].add(VCODEC.get(body[0] & 0xF, f"id{body[0] & 0xF}"))
                    out["keyframes"] += (body[0] >> 4) == 1
            elif ttype == 8:
                out["acodec"].add(ACODEC.get(body[0] >> 4, f"id{body[0] >> 4}"))
        if ttype in (8, 9):
            out["ts"].append(ts)
        pos += 11 + size
    return out


def rate(res: dict) -> str:
    n = sum(c for _, c in res["chunks"])
    return f"{n} bytes in {res['elapsed']:.1f}s ({n / max(res['elapsed'], 0.001) / 1024:.1f} KiB/s, {len(res['chunks'])} reads)"


def describe(res: dict, label: str) -> None:
    print(f"  {label}: status={res['status']} content-type={res['ctype'] or '-'} {('ERR ' + res['err']) if res['err'] else ''}")


def probe_hls(url: str, headers: dict, res: dict, secs: float) -> None:
    text = res["data"].decode("utf-8", "replace")
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if any(l.startswith("#EXT-X-STREAM-INF") for l in lines):
        variants = [urljoin(res["final"], l) for l in lines if not l.startswith("#")]
        print(f"  master playlist, {len(variants)} variant(s); using first: {redact_url(variants[0])}")
        res = fetch(variants[0], headers, secs)
        describe(res, "media playlist")
        text = res["data"].decode("utf-8", "replace")
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        url = variants[0]

    def info(ls: list[str]) -> tuple[int, int | None, bool, list[str]]:
        seq = next((int(l.split(":")[1]) for l in ls if l.startswith("#EXT-X-MEDIA-SEQUENCE")), 0)
        td = next((int(float(l.split(":")[1])) for l in ls if l.startswith("#EXT-X-TARGETDURATION")), None)
        return seq, td, any(l.startswith("#EXT-X-ENDLIST") for l in ls), [l for l in ls if not l.startswith("#")]

    seq, td, ended, segs = info(lines)
    print(f"  media-sequence={seq} target-duration={td}s segments={len(segs)} endlist={ended} -> {'VOD (not live)' if ended else 'LIVE sliding window'}")
    if not ended and td:
        time.sleep(min(td, 6))
        r2 = fetch(url, headers, secs)
        seq2, _, _, segs2 = info([l.strip() for l in r2["data"].decode("utf-8", "replace").splitlines() if l.strip()])
        print(f"  after {min(td, 6)}s: media-sequence={seq2} ({'advancing: live OK' if seq2 > seq else 'NOT advancing'})")
    if segs:
        seg = urljoin(url, segs[-1])
        r = fetch(seg, headers, secs, max_bytes=1_500_000)
        print(f"  last segment {redact_url(seg)[:110]}: status={r['status']} {sniff(r['data'][:512])} {rate(r)}")


def probe_http(url: str, headers: dict, secs: float, save: str | None) -> None:
    res = fetch(url, headers, secs)
    describe(res, "GET")
    print(f"  sniff: {sniff(res['data'][:512])}   |  {rate(res)}")
    d = res["data"]
    if d[:7] == b"#EXTM3U":
        probe_hls(url, headers, res, secs)
    elif d[:3] == b"FLV":
        f = scan_flv(d)
        dur = (f["ts"][-1] - f["ts"][0]) / 1000 if len(f["ts"]) > 1 else 0
        print(f"  FLV: audio={f['audio']} video={f['video']} tags={f['tags']} video-codec={sorted(f['vcodec'])} "
              f"audio-codec={sorted(f['acodec'])} keyframes={f['keyframes']} media-time={dur:.1f}s "
              f"vs wall={res['elapsed']:.1f}s -> {'real-time live stream' if dur and abs(dur - res['elapsed']) < 3 and res['elapsed'] > 2 else 'bursty/VOD-like'}")
    elif len(d) >= 188 * 3 and d[0] == 0x47:
        ok = sum(1 for i in range(0, len(d) - 187, 188) if d[i] == 0x47)
        print(f"  MPEG-TS sync bytes aligned: {ok}/{len(d) // 188} packets")
    if save and d:
        Path(save).write_bytes(d)
        os.chmod(save, 0o600)
        print(f"  saved {len(d)} bytes -> {save} (try: ffplay {save})")


async def ws_collect(url: str, headers: dict, secs: float, send: str | None) -> tuple[str | None, list]:
    import websockets
    h = {k: v for k, v in headers.items() if k.lower() not in ("origin", "user-agent")}
    kw: dict = {"origin": headers.get("Origin"), "max_size": None, "open_timeout": 10}
    kw["additional_headers" if int(websockets.__version__.split(".")[0]) >= 14 else "extra_headers"] = h
    if "User-Agent" in headers:
        kw["user_agent_header"] = headers["User-Agent"]
    frames: list[tuple[float, bytes | str]] = []
    t0 = time.monotonic()
    try:
        async with websockets.connect(url, **kw) as ws:
            if send:
                await ws.send(send)
            while time.monotonic() - t0 < secs:
                try:
                    frames.append((time.monotonic() - t0, await asyncio.wait_for(ws.recv(), 2)))
                except asyncio.TimeoutError:
                    continue
    except Exception as e:
        if type(e).__name__ == "ConnectionClosedOK":
            return None, frames
        return f"{type(e).__name__}: {e}", frames
    return None, frames


async def probe_ws(url: str, headers: dict, secs: float, save: str | None, send: str | None) -> None:
    t0 = time.monotonic()
    err, frames = await ws_collect(url, headers, secs, send)
    print(f"  handshake/stream: {'ERR ' + err if err else 'OK'}")
    binf = [f for _, f in frames if isinstance(f, bytes)]
    print(f"  frames={len(frames)} binary={len(binf)} bytes={sum(len(f) for f in binf)} in {time.monotonic() - t0:.1f}s")
    if frames and not binf:
        print("  only text frames received; stream may need a start command: pass --ws-send '<text frame the page sent>'")
    if not frames and not err and not send:
        print("  no frames: the server may wait for a client message first; pass --ws-send '<text frame the page sent>'")
    for t, f in frames[:3]:
        print(f"   t={t:.2f}s " + (f"{len(f)}B -> {sniff(f[:256], len(f))} head={f[:16].hex()}" if isinstance(f, bytes) else f"text {f[:80]!r}"))
    if save and binf:
        Path(save).write_bytes(b"".join(binf))
        os.chmod(save, 0o600)
        print(f"  saved concatenated binary frames -> {save}")


def run_ffprobe(url: str, headers: dict) -> None:
    if url.startswith(("ws://", "wss://")):
        print("  ffprobe cannot read WebSocket URLs.")
        return
    exe = shutil.which("ffprobe")
    if not exe:
        print("  ffprobe not installed (sudo apt install ffmpeg). Python probe above is used instead.")
        return
    hdr = "".join(f"{k}: {v}\r\n" for k, v in headers.items() if k.lower() in ("referer", "origin", "cookie"))
    cmd = [exe, "-v", "error", "-hide_banner", "-timeout", "15000000", "-show_entries",
           "stream=codec_type,codec_name,width,height,r_frame_rate", "-of", "compact", "-headers", hdr, "-i", url]
    if "user-agent" in {k.lower() for k in headers}:
        cmd[1:1] = ["-user_agent", next(v for k, v in headers.items() if k.lower() == "user-agent")]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        print("  ffprobe rc=%d\n    %s" % (p.returncode, (p.stdout.strip() or p.stderr.strip())[:600].replace("\n", "\n    ")))
    except subprocess.TimeoutExpired:
        print("  ffprobe timed out")


def quick(url: str, headers: dict, ws_send: str | None = None) -> str:
    if url.startswith(("ws://", "wss://")):
        err, frames = asyncio.run(ws_collect(url, headers, 3, ws_send))
        first = frames[0][1] if frames else None
        what = "no frame" if first is None else (sniff(first[:256], len(first)) if isinstance(first, bytes) else "text frame")
        return f"ERR {err}" if err else f"handshake OK, {len(frames)} frame(s), first: {what}"
    r = fetch(url, headers, 3, max_bytes=2048)
    return f"status={r['status']} {sniff(r['data'][:512]) if r['status'] in (200, 206) else (r['err'] or '')}"


def matrix(url: str, headers: dict, ws_send: str | None) -> None:
    print("\n[header matrix] which headers are REQUIRED (same URL, headers removed one at a time)")
    variants = {"all headers": headers}
    for h in list(headers):
        variants[f"without {h}"] = {k: v for k, v in headers.items() if k != h}
    variants["no headers at all"] = {}
    for name, hs in variants.items():
        print(f"  {name:<28} -> {quick(url, hs, ws_send)}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url")
    ap.add_argument("--from-file", help="urls.local.json from capture_360.py --save-urls")
    ap.add_argument("--index", type=int, help="candidate index in --from-file (default: list them)")
    ap.add_argument("--referer")
    ap.add_argument("--origin")
    ap.add_argument("--ua")
    ap.add_argument("--cookie-env", help="name of an env var holding a Cookie header value (only if the URL needs it)")
    ap.add_argument("--seconds", type=float, default=8)
    ap.add_argument("--ws-send", help="text frame to send after the WebSocket handshake (copy from the page's own first sent frame)")
    ap.add_argument("--save", help="write received bytes here (0600)")
    ap.add_argument("--matrix", action="store_true")
    ap.add_argument("--recheck-after", type=float, default=0, help="re-request after N seconds to observe expiry")
    ap.add_argument("--no-ffprobe", action="store_true")
    a = ap.parse_args()

    url = a.url or os.environ.get("STREAM_URL")
    headers: dict[str, str] = {}
    if a.from_file:
        cands = json.loads(Path(a.from_file).read_text())
        if a.index is None:
            for i, c in enumerate(cands):
                print(f"[{i}] {c['source']:<24} cookie_sent={c.get('cookie_sent')}  {redact_url(c['url'])[:130]}")
            return 0
        c = cands[a.index]
        url = c["url"]
        headers = {k.title() if k != "user-agent" else "User-Agent": v for k, v in c.get("headers", {}).items()}
    if not url:
        ap.error("need --url, STREAM_URL or --from-file")
    if a.referer:
        headers["Referer"] = a.referer
    if a.origin:
        headers["Origin"] = a.origin
    if a.ua:
        headers["User-Agent"] = a.ua
    if a.cookie_env:
        headers["Cookie"] = os.environ[a.cookie_env]
    headers.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")

    print(f"URL: {redact_url(url)}")
    for k, v in parse_qsl(urlsplit(url).query):
        if EXPIRY_KEY_RE.search(k):
            print(f"  expiry-like param {k}={v}" + (f" -> {time.strftime('%F %T', time.localtime(int(v) // (1000 if len(v) == 13 else 1)))}" if v.isdigit() and len(v) in (10, 13) else ""))
    print(f"sending headers: {sorted(headers)}")
    t_start = time.time()
    if url.startswith(("ws://", "wss://")):
        asyncio.run(probe_ws(url, headers, a.seconds, a.save, a.ws_send))
    elif url.startswith(("rtmp", "rtsp")):
        print("  RTMP/RTSP: validate with ffprobe/ffplay only.")
    else:
        probe_http(url, headers, a.seconds, a.save)
    if not a.no_ffprobe:
        run_ffprobe(url, headers)
    if a.matrix:
        matrix(url, headers, a.ws_send)
    if a.recheck_after:
        wait = a.recheck_after - (time.time() - t_start)
        if wait > 0:
            print(f"\n[expiry] waiting {wait:.0f}s then re-requesting the same URL ...")
            time.sleep(wait)
        print(f"  after {a.recheck_after:.0f}s: {quick(url, headers, a.ws_send)}")
    print("\nPlay locally (URL in env var so it stays out of shell history):\n"
          "  export STREAM_URL='...'   # from urls.local.json\n"
          "  ffplay -fflags nobuffer -headers $'Referer: <referer>\\r\\nOrigin: <origin>\\r\\n' \"$STREAM_URL\"\n"
          "  mpv --http-header-fields='Referer: <referer>' \"$STREAM_URL\"")
    return 0


if __name__ == "__main__":
    sys.exit(main())
