#!/usr/bin/env python3
"""Probe a live HTTP-FLV / HLS URL of YOUR OWN camera: timings, headers, first bytes, FLV header + real payload.

Pure stdlib (socket/ssl/http.client). Never prints the full URL: only a masked form. Full URLs are read from
a 0600 urls.local.json (or env STREAM_URL), never from the command line.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import redact_url  # noqa: E402
from probe_stream import scan_flv  # noqa: E402

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
ORIGIN_360 = "https://my.jia.360.cn"
SCAN_CAP = 16 * 1024 * 1024  # bytes kept in memory for FLV tag scanning; the rest is only counted
FLV_MAGIC = bytes.fromhex("464c56")
LIFECYCLE_MARKS = (5, 15, 30, 60, 120)


def normalize_url(url: str) -> str:
    """The browser reaches *.360.cn FLV hosts over HTTPS even though playV2 returns http://."""
    p = urlsplit(url)
    if p.scheme == "http" and (p.hostname or "").endswith(".360.cn"):
        return "https" + url[4:]
    return url


def url_key(url: str) -> str:
    """Identity of a stream URL ignoring http/https."""
    p = urlsplit(url)
    return f"{p.hostname}{p.path}?{p.query}"


def default_headers(url: str, captured: dict | None = None) -> dict[str, str]:
    h = {"User-Agent": DEFAULT_UA, "Accept": "*/*", "Connection": "close"}
    if (urlsplit(url).hostname or "").endswith(".360.cn"):
        h.update(Referer=ORIGIN_360 + "/", Origin=ORIGIN_360)
    for k, v in (captured or {}).items():
        if v and k.lower() in ("referer", "origin", "user-agent"):
            h[k.title() if k.lower() != "user-agent" else "User-Agent"] = v
    return h


def parse_flv_header(b: bytes) -> dict:
    flags = b[4]
    return {"signature": b[:3].decode("latin1"), "version": b[3], "audio": bool(flags & 4), "video": bool(flags & 1),
            "data_offset": int.from_bytes(b[5:9], "big"), "flags": flags}


def probe_url(url: str, headers: dict[str, str] | None = None, seconds: float = 5.0, connect_timeout: float = 10.0,
              header_timeout: float = 15.0) -> dict:
    """One GET, read for `seconds`, never raises. Timings are seconds; ttfb is measured from the request being sent."""
    url = normalize_url(url)
    p = urlsplit(url)
    headers = headers or default_headers(url)
    r: dict = {"stream": redact_url(url), "status": None, "connect": None, "tls": None, "ttfb": None,
               "first_data": None, "ctype": None, "transfer_encoding": None, "content_length": None,
               "first32": b"", "bytes": 0, "seconds": seconds, "err": None, "kind": "unknown", "flv": None,
               "media": False, "tags": {}, "vcodec": [], "acodec": [], "keyframes": 0, "media_time": 0.0,
               "started": time.time()}
    sock = None
    try:
        sock, resp, t_req = open_stream(url, headers, r, connect_timeout, header_timeout)
        deadline = t_req + seconds
        buf = bytearray()
        try:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                sock.settimeout(left)
                chunk = resp.read1(65536)
                if not chunk:
                    r["eof"] = True
                    break
                if r["first_data"] is None:
                    r["first_data"] = time.monotonic() - t_req
                r["bytes"] += len(chunk)
                if len(buf) < SCAN_CAP:
                    buf += chunk
        except (socket.timeout, TimeoutError):
            pass  # idle until the deadline: what was received so far is the result
        except (http.client.HTTPException, OSError) as e:
            r["err"] = f"{type(e).__name__} while reading: {redact_text(str(e), url)}"
        r["first32"] = bytes(buf[:32])
        analyze_payload(r, bytes(buf))
    except Exception as e:  # network failures are probe results, not crashes
        r["err"] = f"{type(e).__name__}: {redact_text(str(e), url)}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    r["ended"] = time.time()
    r["result"] = classify(r)
    return r


def open_stream(url: str, headers: dict[str, str], timings: dict, connect_timeout: float = 10.0,
                header_timeout: float = 15.0):
    """TCP + TLS + GET; returns (sock, response, t_request_sent). Fills connect/tls/ttfb/status/ctype in `timings`."""
    p = urlsplit(url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    t0 = time.monotonic()
    sock = socket.create_connection((host, port), timeout=connect_timeout)
    try:
        t1 = time.monotonic()
        timings["connect"] = t1 - t0
        if p.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            timings["tls"] = time.monotonic() - t1
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(host, port)
        else:
            conn = http.client.HTTPConnection(host, port)
        conn.sock = sock
        sock.settimeout(header_timeout)
        conn.request("GET", (p.path or "/") + (f"?{p.query}" if p.query else ""), headers=headers)
        t_req = time.monotonic()
        resp = conn.getresponse()
        timings["ttfb"] = time.monotonic() - t_req
        timings.update(status=resp.status, ctype=resp.getheader("Content-Type"),
                       transfer_encoding=resp.getheader("Transfer-Encoding"),
                       content_length=resp.getheader("Content-Length"))
        return sock, resp, t_req
    except BaseException:
        sock.close()
        raise


def hold_stream(url: str, headers: dict[str, str], stop, stats: dict) -> None:
    """Long-lived reader standing in for the web page: reads until `stop` (threading.Event) is set. Never raises."""
    url = normalize_url(url)
    sock = None
    try:
        sock, resp, _ = open_stream(url, headers, stats)
        stats["open"] = True
        while not stop.is_set():
            sock.settimeout(1.0)
            try:
                chunk = resp.read1(65536)
            except (socket.timeout, TimeoutError):
                continue
            if not chunk:
                stats["eof"] = True
                break
            stats["bytes"] = stats.get("bytes", 0) + len(chunk)
            stats["last_data"] = time.monotonic()
    except Exception as e:
        stats["err"] = f"{type(e).__name__}: {redact_text(str(e), url)}"
    finally:
        stats["closed"] = time.monotonic()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def redact_text(text: str, url: str) -> str:
    p = urlsplit(url)
    for secret in filter(None, (p.path, p.query, url)):
        text = text.replace(secret, "<url>")
    return text[:200]


def analyze_payload(r: dict, data: bytes) -> None:
    if data[:3] == FLV_MAGIC and len(data) >= 9:
        r["kind"] = "FLV"
        r["flv"] = parse_flv_header(data)
        if len(data) >= 13:
            try:
                f = scan_flv(data)
            except (IndexError, ValueError):
                f = None
            if f:
                r["tags"] = f["tags"]
                r["vcodec"], r["acodec"] = sorted(f["vcodec"]), sorted(f["acodec"])
                r["keyframes"] = f["keyframes"]
                ts = f["ts"]
                r["media_time"] = (ts[-1] - ts[0]) / 1000 if len(ts) > 1 else 0.0
                r["media"] = (f["tags"].get("video", 0) + f["tags"].get("audio", 0)) > 0
    elif data[:7] == b"#EXTM3U":
        r["kind"] = "HLS"
        segs = [ln for ln in data.decode("utf-8", "replace").splitlines() if ln.strip() and not ln.startswith("#")]
        r["tags"] = {"segments": len(segs)}
        r["media"] = bool(segs)


def classify(r: dict) -> str:
    if r["err"] and r["status"] is None:
        return "CONNECT/REQUEST FAILED"
    if r["status"] not in (200, 206):
        return f"HTTP {r['status']}"
    if r["kind"] == "FLV":
        return "LIVE STREAM OK" if r["media"] else "NO MEDIA (FLV header/metadata only)"
    if r["kind"] == "HLS":
        return "LIVE STREAM OK" if r["media"] else "NO MEDIA (empty playlist)"
    return "NO MEDIA (connected, no data)" if r["bytes"] == 0 else "UNKNOWN PAYLOAD (not FLV/HLS)"


def fmt_bytes(n: int) -> str:
    return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{n / 1024:.1f} KB" if n >= 1024 else f"{n} B"


def fmt_t(v: float | None) -> str:
    return "-" if v is None else f"{v:.2f}s"


def format_report(r: dict) -> str:
    hexb = " ".join(f"{b:02x}" for b in r["first32"]) or "-"
    out = ["[LIVE PROBE]", f"stream: {r['stream']}", f"HTTP: {r['status'] if r['status'] is not None else '-'}",
           f"connect: {fmt_t(r['connect'])}   TLS: {fmt_t(r['tls'])}   TTFB: {fmt_t(r['ttfb'])}   first data: {fmt_t(r['first_data'])}",
           f"Content-Type: {r['ctype'] or '-'}   Transfer-Encoding: {r['transfer_encoding'] or '-'}"
           + (f"   Content-Length: {r['content_length']}" if r["content_length"] else ""),
           f"first bytes: {hexb}"]
    if r["kind"] == "FLV":
        h = r["flv"]
        out += ["Detected: FLV",
                f"  Signature={h['signature']} Version={h['version']} TypeFlagsAudio={int(h['audio'])} "
                f"TypeFlagsVideo={int(h['video'])} DataOffset={h['data_offset']}",
                f"  tags={r['tags']} video={r['vcodec']} audio={r['acodec']} keyframes={r['keyframes']} "
                f"media-time={r['media_time']:.1f}s"]
    elif r["kind"] == "HLS":
        out += ["Detected: HLS playlist", f"  {r['tags']}"]
    out.append(f"received: {fmt_bytes(r['bytes'])} / {r['seconds']:g} sec")
    if r["err"]:
        out.append(f"error: {r['err']}")
    out.append(f"RESULT: {r['result']}")
    return "\n".join(out)


def event_summary(r: dict) -> dict:
    """JSON-safe, secret-free subset of a probe result (stream URL already masked)."""
    keys = ("stream", "status", "connect", "tls", "ttfb", "first_data", "ctype", "transfer_encoding", "bytes",
            "seconds", "kind", "media", "tags", "vcodec", "acodec", "keyframes", "media_time", "err", "result")
    d = {k: (round(r[k], 3) if isinstance(r[k], float) else r[k]) for k in keys}
    d["container"] = d.pop("kind")
    d["first32"] = r["first32"].hex()
    d["flv"] = r["flv"]
    return d


def lifecycle(url: str, headers: dict[str, str], t_stop: float, marks=LIFECYCLE_MARKS, window: float = 3.0,
              log=print) -> list[tuple[int, dict]]:
    """Probe the SAME url at t_stop+mark seconds (t_stop = time.monotonic() when playback stopped). Blocking."""
    rows = []
    for m in marks:
        wait = t_stop + m - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        res = probe_url(url, headers, window)
        rows.append((m, res))
        log(f"T+{m}s".ljust(8) + ("media" if res["media"] else "no-media").ljust(10)
            + f"{res['result']} (HTTP {res['status']}, {fmt_bytes(res['bytes'])}, ttfb {fmt_t(res['ttfb'])})")
    return rows


def lifecycle_summary(rows: list[tuple[int, dict]]) -> str:
    lines = [f"T+{m}s".ljust(8) + ("media" if r["media"] else "no-media") for m, r in rows]
    last_media = [m for m, r in rows if r["media"]]
    lines.append(f"last mark with media: {'T+%ds' % max(last_media) if last_media else 'none'}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--from-file", help="urls.local.json written by capture_360.py")
    ap.add_argument("--index", type=int)
    ap.add_argument("--seconds", type=float, default=5)
    ap.add_argument("--lifecycle", action="store_true", help="probe at T+5/15/30/60/120s after NOW (call it when the page stopped)")
    a = ap.parse_args()
    url, hdrs = os.environ.get("STREAM_URL"), None
    if a.from_file:
        cands = json.loads(Path(a.from_file).read_text())
        if a.index is None:
            for i, c in enumerate(cands):
                print(f"[{i}] {c['source']:<20} {redact_url(c['url'])[:120]}")
            return 0
        url, hdrs = cands[a.index]["url"], cands[a.index].get("headers")
    if not url:
        ap.error("need --from-file/--index or env STREAM_URL")
    h = default_headers(normalize_url(url), hdrs)
    if a.lifecycle:
        rows = lifecycle(url, h, time.monotonic())
        print(lifecycle_summary(rows))
        return 0
    res = probe_url(url, h, a.seconds)
    print(format_report(res))
    return 0 if res["result"] == "LIVE STREAM OK" else 1


if __name__ == "__main__":
    sys.exit(main())
