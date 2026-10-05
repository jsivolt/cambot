#!/usr/bin/env python3
"""Fetch a few seconds of live video from one of YOUR cameras using the existing logged-in Chrome profile.

The playV2 call runs inside the page (same-origin, the browser attaches the session cookie itself), so no cookie
value is ever read or stored here. The FLV is then read with the same headers the browser used and validated.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from capture_360 import DEFAULT_URL, launch_chrome, wait_endpoint  # noqa: E402
from cdp import CDPClient, CDPError  # noqa: E402
from common import SENSITIVE_KEY_RE, mask, redact_url, sniff  # noqa: E402
from probe_stream import fetch, scan_flv  # noqa: E402

ORIGIN = "https://my.jia.360.cn"
PLAY_JS = """(async () => {
  const q = new URLSearchParams({taskid: String(Date.now()), from: 'mpc_ipcam_web', sn: %s, mode: '0'});
  const r = await fetch('/app/playV2?' + q, {credentials: 'include'});
  return JSON.stringify({status: r.status, body: await r.json()});
})()"""


def sn_from_captures(root: Path) -> str | None:
    for ev_file in sorted(root.glob("*/events.jsonl"), reverse=True):
        for line in ev_file.read_text().splitlines():
            if "/app/playV2" in line:
                m = re.search(r"[?&]sn=(\d+)", line)
                if m:
                    return m.group(1)
    return None


def summarize(body: dict) -> str:
    out = {}
    for k, v in body.items():
        if isinstance(v, str) and (SENSITIVE_KEY_RE.search(k) or len(v) > 40):
            out[k] = redact_url(v) if v.startswith("http") else mask(v)
        elif isinstance(v, list):
            out[k] = f"<{len(v)} items>"
        else:
            out[k] = v
    return json.dumps(out, ensure_ascii=False)


async def run(a: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parent.parent
    sn = a.sn or sn_from_captures(root / "captures")
    if not sn or not sn.isdigit():
        print("Need --sn <your camera sn> (digits); none found in previous captures.")
        return 2
    proc = None
    try:
        ver = await wait_endpoint(a.port, 1.5)
    except Exception:
        proc = launch_chrome(a.port, Path(os.path.expanduser(a.profile)), "about:blank", not a.headed, [])
        ver = await wait_endpoint(a.port, 40)
    cdp = await CDPClient.connect(ver["webSocketDebuggerUrl"])
    try:
        targets = (await cdp.send("Target.getTargets"))["targetInfos"]
        page = next((t for t in targets if t["type"] == "page" and "jia.360.cn" in t["url"]), None) or \
            next((t for t in targets if t["type"] == "page"), None)
        if page is None:
            page = {"targetId": (await cdp.send("Target.createTarget", {"url": "about:blank"}))["targetId"]}
        sid = (await cdp.send("Target.attachToTarget", {"targetId": page["targetId"], "flatten": True}))["sessionId"]
        await cdp.send("Page.enable", None, sid)
        ua = (await cdp.send("Browser.getVersion"))["userAgent"].replace("HeadlessChrome", "Chrome")
        await cdp.send("Network.setUserAgentOverride", {"userAgent": ua}, sid)
        await cdp.send("Page.navigate", {"url": DEFAULT_URL}, sid, timeout=90)

        href = ""
        for _ in range(120):
            r = await cdp.send("Runtime.evaluate", {"expression": "location.href + ' ' + document.readyState"}, sid, timeout=10)
            href, _, state = r["result"].get("value", " ").rpartition(" ")
            if state == "complete" and href.startswith(ORIGIN):
                break
            await asyncio.sleep(0.5)
        print(f"page: {redact_url(href)}")
        if not urlsplit(href).path.startswith("/web/myList"):
            print("Not on the camera list: the profile is not logged in. Log in once with "
                  "`tools/capture_360.py --launch` (headed), then rerun.")
            return 3
        await asyncio.sleep(2)

        r = await cdp.send("Runtime.evaluate", {"expression": PLAY_JS % json.dumps(sn), "awaitPromise": True,
                                                 "returnByValue": True}, sid, timeout=40)
        if "exceptionDetails" in r:
            print("playV2 call failed:", r["exceptionDetails"].get("exception", {}).get("description", "")[:300])
            return 4
        resp = json.loads(r["result"]["value"])
        body = resp["body"]
        print(f"playV2: http={resp['status']} {summarize(body)}")
        url = body.get("flashUrl")
        if body.get("errorCode") != 0 or not url:
            print("No stream URL returned (camera offline/busy or session invalid).")
            return 5
        if url.startswith("http://"):
            url = "https://" + url[len("http://"):]  # the browser used https for this host
        headers = {"Referer": ORIGIN + "/", "Origin": ORIGIN, "User-Agent": ua}
        print(f"reading {redact_url(url)} for {a.seconds:.0f}s ...")
        res = await asyncio.to_thread(fetch, url, headers, a.seconds, 40_000_000, 15)
    finally:
        await cdp.close()
        if proc:
            proc.terminate()

    data, secs = res["data"], max(res["elapsed"], 0.001)
    print(f"status={res['status']} content-type={res['ctype'] or '-'} err={res['err']}")
    print(f"received {len(data)} bytes in {secs:.1f}s ({len(data) / secs / 1024:.1f} KiB/s), first bytes: {sniff(data[:512])}")
    if data[:3] != b"FLV":
        return 6
    f = scan_flv(data)
    ts = f["ts"]
    media = (ts[-1] - ts[0]) / 1000 if len(ts) > 1 else 0
    print(f"FLV: audio={f['audio']} video={f['video']} tags={f['tags']} video-codec={sorted(f['vcodec'])} "
          f"audio-codec={sorted(f['acodec'])} keyframes={f['keyframes']} media-time={media:.1f}s")
    out = Path(a.out or root / "captures" / time.strftime("live-%Y%m%d-%H%M%S.flv"))
    out.write_bytes(data)
    out.chmod(0o600)
    print(f"saved {out}   (play: ffplay '{out}'  |  mpv '{out}')")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sn", help="camera sn (default: taken from the latest capture)")
    ap.add_argument("--seconds", type=float, default=10)
    ap.add_argument("--port", type=int, default=9222)
    ap.add_argument("--profile", default="~/.360cam-debug")
    ap.add_argument("--headed", action="store_true", help="show the browser window (needs a display)")
    ap.add_argument("--out", help="output .flv path (default captures/live-<time>.flv)")
    return asyncio.run(run(ap.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
