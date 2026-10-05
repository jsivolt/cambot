#!/usr/bin/env python3
"""Open the live HTTP-FLV stream of YOUR OWN 360 camera without the camera UI.

authenticated browser context (persistent Chrome profile, you logged in once)
  -> same-origin fetch GET /app/playV2?sn=..&mode=0   (the browser attaches its own cookie; this script never reads,
     prints or stores cookies/passwords/tokens)
  -> relayStream / flashUrl -> HTTPS HTTP-FLV -> probe | ffplay | ffprobe | stdout pipe

The full stream URL is never printed or put in argv. Sensitive playV2 fields are shown only as sha256[:8].
No login bypass: if the profile is not logged in the script stops and tells you to log in manually.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from urllib.parse import urlsplit  # noqa: E402

from capture_360 import DEFAULT_URL, launch_chrome, wait_endpoint  # noqa: E402
from cdp import CDPClient  # noqa: E402
from common import redact_url  # noqa: E402
from fetch_live import ORIGIN, PLAY_JS, sn_from_captures  # noqa: E402
from live_probe import (  # noqa: E402
    LIFECYCLE_MARKS, default_headers, fmt_bytes, format_report, hold_stream, lifecycle, lifecycle_summary,
    normalize_url, open_stream, probe_url,
)

FIELDS = ("playKey", "relay", "relayId", "relaySig", "relayStream", "flashUrl")
ROOT = Path(__file__).resolve().parent.parent


def fp8(v) -> str:
    return "-" if v in (None, "") else hashlib.sha256(str(v).encode()).hexdigest()[:8]


class PlayError(RuntimeError):
    pass


class PlaySession:
    """Attach to (or launch) Chrome with the logged-in profile and call playV2 from inside the page."""

    def __init__(self, port: int, profile: str, headed: bool) -> None:
        self.port, self.profile, self.headed = port, Path(os.path.expanduser(profile)), headed
        self.proc: subprocess.Popen | None = None
        self.cdp: CDPClient | None = None
        self.sid = ""
        self.ua = ""

    async def __aenter__(self) -> "PlaySession":
        try:
            ver = await wait_endpoint(self.port, 1.5)
        except Exception:
            self.proc = launch_chrome(self.port, self.profile, "about:blank", not self.headed, [])
            ver = await wait_endpoint(self.port, 40)
        self.cdp = await CDPClient.connect(ver["webSocketDebuggerUrl"])
        try:
            targets = (await self.cdp.send("Target.getTargets"))["targetInfos"]
            page = next((t for t in targets if t["type"] == "page" and "jia.360.cn" in t["url"]), None) or \
                next((t for t in targets if t["type"] == "page"), None)
            tid = page["targetId"] if page else (await self.cdp.send("Target.createTarget", {"url": "about:blank"}))["targetId"]
            self.sid = (await self.cdp.send("Target.attachToTarget", {"targetId": tid, "flatten": True}))["sessionId"]
            await self.cdp.send("Page.enable", None, self.sid)
            self.ua = (await self.cdp.send("Browser.getVersion"))["userAgent"].replace("HeadlessChrome", "Chrome")
            await self.cdp.send("Network.setUserAgentOverride", {"userAgent": self.ua}, self.sid)
            await self.ensure_on_site()
        except BaseException:
            await self.__aexit__(None, None, None)
            raise
        return self

    async def __aexit__(self, *exc) -> None:
        if self.cdp:
            await self.cdp.close()
        if self.proc:
            self.proc.terminate()

    async def _eval(self, expr: str, timeout: float = 40):
        r = await self.cdp.send("Runtime.evaluate", {"expression": expr, "awaitPromise": True, "returnByValue": True},
                                self.sid, timeout=timeout)
        if "exceptionDetails" in r:
            raise PlayError(r["exceptionDetails"].get("exception", {}).get("description", "evaluate failed")[:300])
        return r["result"].get("value")

    async def ensure_on_site(self) -> None:
        href = await self._eval("location.href")
        if not href.startswith(ORIGIN):
            await self.cdp.send("Page.navigate", {"url": DEFAULT_URL}, self.sid, timeout=90)
        for _ in range(120):
            v = await self._eval("location.href + ' ' + document.readyState", 10)
            href, _, state = v.rpartition(" ")
            if state == "complete" and href.startswith(ORIGIN):
                break
            await asyncio.sleep(0.5)
        if not urlsplit(href).path.startswith("/web/myList"):
            raise PlayError("Not on the camera list: the profile is not logged in. Log in once manually with "
                            "`tools/capture_360.py --launch` (headed), then rerun.")
        await asyncio.sleep(1)

    async def play(self, sn: str) -> dict:
        """One playV2 call. Returns the response body; callers must not print it."""
        v = await self._eval(PLAY_JS % json.dumps(sn))
        resp = json.loads(v)
        body = resp["body"]
        if resp["status"] != 200 or body.get("errorCode") != 0 or not body.get("flashUrl"):
            msg = next((str(body[k])[:80] for k in ("errorMsg", "errmsg", "msg", "message") if body.get(k)), "-")
            raise PlayError(f"playV2 failed: http={resp['status']} errorCode={body.get('errorCode')} msg={msg} "
                            f"keys={sorted(body)} (camera offline/busy or session invalid)")
        return body

    def headers(self, url: str) -> dict[str, str]:
        return default_headers(normalize_url(url), {"user-agent": self.ua})


def describe(body: dict) -> str:
    return "  ".join(f"{k}={fp8(body.get(k))}" for k in FIELDS)


def compare(b1: dict, b2: dict) -> dict[str, bool]:
    print("field         run1      run2      changed")
    changed = {}
    for k in FIELDS:
        a, b = b1.get(k), b2.get(k)
        changed[k] = a != b
        print(f"{k:<13} {fp8(a):<9} {fp8(b):<9} {'yes' if changed[k] else 'no'}")
    return changed


# ---- sinks -------------------------------------------------------------------------------------------------------
def stream_into(write, url: str, headers: dict, seconds: float, stop: threading.Event | None = None) -> int:
    """Copy the FLV body into write(bytes) for `seconds` (0 = until stop/EOF). Returns bytes copied."""
    stop = stop or threading.Event()
    sock, resp, _ = open_stream(normalize_url(url), headers, {})
    n, end = 0, time.monotonic() + seconds if seconds else None
    try:
        while not stop.is_set() and (end is None or time.monotonic() < end):
            sock.settimeout(2.0)
            try:
                chunk = resp.read1(65536)
            except TimeoutError:
                continue
            if not chunk:
                break
            write(chunk)
            n += len(chunk)
    finally:
        sock.close()
    return n


def run_ffmpeg_tool(tool: str, args: list[str], url: str, headers: dict, seconds: float) -> None:
    exe = shutil.which(tool)
    if not exe:
        print(f"{tool}: NOT INSTALLED (sudo apt install ffmpeg) - skipped")
        return
    # URL goes through stdin, not argv, so it never shows up in `ps`.
    proc = subprocess.Popen([exe, *args, "-i", "-"], stdin=subprocess.PIPE)
    try:
        n = stream_into(proc.stdin.write, url, headers, seconds)
        print(f"{tool}: fed {fmt_bytes(n)} of FLV through stdin")
    except (BrokenPipeError, OSError):
        print(f"{tool}: closed its input early")
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
    print(f"{tool}: exit code {proc.returncode}")


def av_check(url: str, headers: dict, seconds: float = 6.0) -> str:
    """Decode with libav (PyAV) as an ffmpeg stand-in when no ffmpeg CLI is installed."""
    try:
        import av
    except ImportError:
        return "PyAV not installed"
    buf = io.BytesIO()
    stream_into(buf.write, url, headers, seconds)
    buf.seek(0)
    try:
        with av.open(buf, format="flv") as c:
            info = [f"{s.type}:{s.codec_context.name}" + (f" {s.codec_context.width}x{s.codec_context.height}" if s.type == "video" else "")
                    for s in c.streams]
            frames = 0
            for _ in c.decode(video=0):
                frames += 1
                if frames >= 5:
                    break
        return f"libav decoded {frames} video frame(s); streams: {', '.join(info)}"
    except Exception as e:
        return f"libav decode failed: {type(e).__name__}: {str(e)[:120]}"


def decode_snapshot(data: bytes, path: Path) -> str:
    """Save the first decodable video frame of an FLV byte string as an image (format by file extension)."""
    try:
        import av
    except ImportError:
        return "PyAV not installed (pip install av pillow)"
    try:
        with av.open(io.BytesIO(data), format="flv") as c:
            for frame in c.decode(video=0):
                img = frame.to_image()
                path.parent.mkdir(parents=True, exist_ok=True)
                img.save(path)
                path.chmod(0o600)
                return f"snapshot saved: {path} ({img.width}x{img.height}, {path.stat().st_size} bytes)"
    except Exception as e:
        return f"snapshot failed: {type(e).__name__}: {str(e)[:120]}"
    return "snapshot failed: no decodable video frame (need a keyframe; try a larger --seconds)"


def do_snapshot(url: str, headers: dict, path: Path, seconds: float) -> str:
    buf = io.BytesIO()
    n = stream_into(buf.write, url, headers, max(seconds, 3.0))
    if n == 0:
        return "snapshot failed: stream returned no bytes"
    return decode_snapshot(buf.getvalue(), path)


def do_record(url: str, headers: dict, path: Path, seconds: float) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        n = stream_into(f.write, url, headers, seconds or 10.0)
    return f"recorded {fmt_bytes(n)} of raw FLV -> {path} (play: ffplay {path})"


# ---- experiment -------------------------------------------------------------------------------------------------
async def experiment(sess: PlaySession, sn: str, a: argparse.Namespace) -> dict:
    res: dict = {}
    marks = LIFECYCLE_MARKS
    print("== run1: playV2 (no camera UI) ==")
    b1 = await sess.play(sn)
    url1 = b1["flashUrl"]
    hdr = sess.headers(url1)
    print(f"playV2 run1: {describe(b1)}\nstream: {redact_url(normalize_url(url1))}")

    stop, stats = threading.Event(), {}
    holder = asyncio.create_task(asyncio.to_thread(hold_stream, url1, hdr, stop, stats))
    for _ in range(100):
        if stats.get("bytes") or stats.get("err") or holder.done():
            break
        await asyncio.sleep(0.1)
    print(f"client A (stands in for the web page): open={stats.get('open')} HTTP={stats.get('status')} "
          f"bytes={fmt_bytes(stats.get('bytes', 0))} err={stats.get('err')}")
    a_before = stats.get("bytes", 0)
    pb = await asyncio.to_thread(probe_url, url1, hdr, 5.0)
    print(format_report(pb))
    a_alive = not stats.get("err") and not stats.get("eof") and stats.get("bytes", 0) > a_before
    res["second_client"] = "PASS" if pb["result"] == "LIVE STREAM OK" and a_alive else "FAIL"
    print(f"client A still receiving while B read: {a_alive}\nSECOND_CLIENT_STREAM = {res['second_client']}")

    samples, t_hold = [], time.monotonic()
    while time.monotonic() - t_hold < a.hold:
        await asyncio.sleep(5)
        samples.append(stats.get("bytes", 0))
    rates = [b - a_ for a_, b in zip([a_before, *samples], samples)]
    res["valid_while_playing"] = bool(rates) and all(r > 0 for r in rates)
    print(f"URL valid while playing ({a.hold:g}s, per-5s bytes): {[fmt_bytes(r) for r in rates]} -> "
          f"{'continuous' if res['valid_while_playing'] else 'INTERRUPTED'}; A err={stats.get('err')} eof={stats.get('eof')}")

    print("\n== stop playback (close client A); NO playV2 call; probe the SAME url ==")
    stop.set()
    await holder
    t_stop = time.monotonic()
    rows = await asyncio.to_thread(lifecycle, url1, hdr, t_stop, marks, 3.0, lambda s: print(s, flush=True))
    res["lifecycle"] = {f"T+{m}s": ("media" if r["media"] else "no-media") for m, r in rows}
    print(lifecycle_summary(rows))

    print("\n== run2: playV2 again ==")
    b2 = await sess.play(sn)
    url2 = b2["flashUrl"]
    print(f"playV2 run2: {describe(b2)}")
    res["changed"] = compare(b1, b2)
    old = await asyncio.to_thread(probe_url, url1, hdr, 3.0)
    new = await asyncio.to_thread(probe_url, url2, sess.headers(url2), 5.0)
    print(f"old URL after run2: {old['result']} (HTTP {old['status']}, {fmt_bytes(old['bytes'])})")
    print(format_report(new))
    res["old_after_run2"], res["new_after_run2"] = old["result"], new["result"]
    res["restored"] = new["result"] == "LIVE STREAM OK"
    return res


async def run(a: argparse.Namespace) -> int:
    sn = a.device or sn_from_captures(ROOT / "captures")
    if not sn or not sn.isdigit():
        print("Need --device <sn> (digits); none found in earlier captures.")
        return 2
    try:
        async with PlaySession(a.port, a.profile, a.headed) as sess:
            if a.experiment:
                res = await experiment(sess, sn, a)
                out = ROOT / "captures" / time.strftime("experiment-%Y%m%d-%H%M%S.json")
                out.write_text(json.dumps(res, indent=1))
                out.chmod(0o600)
                print(f"\nsummary (no secrets) -> {out}")
                return 0
            body = await sess.play(sn)
            if a.compare:
                print(f"run1: {describe(body)}")
                if a.gap:
                    print(f"waiting {a.gap:g}s ...")
                    await asyncio.sleep(a.gap)
                body2 = await sess.play(sn)
                print(f"run2: {describe(body2)}")
                compare(body, body2)
                return 0
            url = body["flashUrl"]
            hdr = sess.headers(url)
    except PlayError as e:
        print(e)
        return 3
    print(f"playV2 ok: {describe(body)}\nstream: {redact_url(normalize_url(url))}")
    if a.url_file:
        p = Path(a.url_file)
        p.write_text(normalize_url(url) + "\n")
        p.chmod(0o600)
        print(f"full URL written to {p} (0600)")
    if a.pipe:
        out = sys.stdout.buffer
        try:
            stream_into(out.write, url, hdr, a.seconds)
            out.flush()
        except BrokenPipeError:
            pass
        return 0
    if a.ffplay:
        run_ffmpeg_tool("ffplay", ["-hide_banner", "-fflags", "nobuffer", "-autoexit"], url, hdr, a.seconds)
    if a.ffprobe:
        run_ffmpeg_tool("ffprobe", ["-hide_banner", "-show_entries", "stream=codec_type,codec_name,width,height"], url, hdr, 6)
    if a.av_check:
        print(await asyncio.to_thread(av_check, url, hdr))
    if a.record:
        print(await asyncio.to_thread(do_record, url, hdr, Path(a.record), a.seconds))
    if a.snapshot:
        print(await asyncio.to_thread(do_snapshot, url, hdr, Path(a.snapshot), a.seconds))
    if not (a.ffplay or a.ffprobe or a.av_check or a.url_file or a.record or a.snapshot):
        res = await asyncio.to_thread(probe_url, url, hdr, a.seconds)
        print(format_report(res))
        return 0 if res["result"] == "LIVE STREAM OK" else 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--device", help="camera sn (digits); default: taken from the latest capture")
    ap.add_argument("--port", type=int, default=9222)
    ap.add_argument("--profile", default="~/.360cam-debug")
    ap.add_argument("--headed", action="store_true", help="show the browser (needs a display)")
    ap.add_argument("--seconds", type=float, default=5, help="probe/ffplay/pipe duration (pipe/ffplay: 0 = until closed)")
    ap.add_argument("--ffplay", action="store_true", help="play via ffplay (FLV is fed through stdin)")
    ap.add_argument("--ffprobe", action="store_true", help="inspect via ffprobe (stdin)")
    ap.add_argument("--av-check", action="store_true", help="decode a few frames with PyAV/libav (no ffmpeg CLI needed)")
    ap.add_argument("--snapshot", help="decode the first video frame and save it (.jpg/.png), e.g. out/snap.jpg")
    ap.add_argument("--record", help="save raw FLV for --seconds (default 10) to this file")
    ap.add_argument("--pipe", action="store_true", help="write raw FLV to stdout, e.g. | ffplay -i -")
    ap.add_argument("--url-file", help="write the full URL to this file (0600) for ffplay -i \"$(cat file)\"")
    ap.add_argument("--compare", action="store_true", help="call playV2 twice and print sha256[:8] / changed=yes|no")
    ap.add_argument("--gap", type=float, default=0, help="seconds between the two calls of --compare")
    ap.add_argument("--experiment", action="store_true",
                    help="full test: second client, hold, stop, lifecycle T+5..120s, playV2 again (about 3 minutes)")
    ap.add_argument("--hold", type=float, default=20, help="--experiment: seconds client A plays before stopping")
    return asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
