#!/usr/bin/env python3
"""Analyze a capture (events.jsonl from capture_360.py, or a Chrome DevTools .har) and report the
video protocol, the device-list -> play call chain, temp-credential origin, expiry and headers."""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    EXPIRY_KEY_RE, MEDIA_EXT_RE, MEDIA_MIME_RE, SENSITIVE_KEY_RE, STREAM_SCHEME_RE, fp, json_fingerprints,
    parse_json_maybe, redact_headers, redact_json, redact_url, sniff, tags_for, url_params,
)

STATIC = {"Image", "Font", "Stylesheet", "Script", "Ping", "Manifest", "TextTrack", "Document"}
STREAM_TAGS = {"live", "stream", "play", "video", "m3u8", "flv", "webrtc", "offer", "answer", "candidate"}


# ---- loading -------------------------------------------------------------
def load_events(path: Path) -> list[dict]:
    if path.suffix.lower() == ".har":
        return har_to_events(json.loads(path.read_text()))
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def har_to_events(har: dict) -> list[dict]:
    out: list[dict] = []
    entries = har["log"]["entries"]
    t0 = None
    for i, e in enumerate(entries, 1):
        ts = time.mktime(time.strptime(e["startedDateTime"][:19], "%Y-%m-%dT%H:%M:%S"))
        t0 = ts if t0 is None else t0
        rq, rs = e["request"], e["response"]
        rid = f"h{i}"
        url = rq["url"]
        sp = urlsplit(url)
        post = None
        pfps: dict = {}
        txt = (rq.get("postData") or {}).get("text")
        if txt:
            js = parse_json_maybe(txt)
            if js is not None:
                post, pfps = redact_json(js), json_fingerprints(js)
        hdrs = {h["name"]: h["value"] for h in rq.get("headers", [])}
        rtype = e.get("_resourceType", "other").capitalize()
        rtype = {"Xhr": "XHR"}.get(rtype, rtype)
        is_ws = url.startswith(("ws://", "wss://"))
        if is_ws:
            out.append({"t": ts - t0, "wall": ts, "kind": "ws.created", "id": rid, "url": redact_url(url),
                        "tags": tags_for(url), "params": url_params(url), "url_fp": fp(url)})
            for j, m in enumerate(e.get("_webSocketMessages", []), 1):
                op = m.get("opcode", 1)
                data = m.get("data", "")
                raw = b""
                if op == 2:
                    try:
                        raw = base64.b64decode(data)
                    except ValueError:
                        pass
                ev = {"t": m.get("time", 0), "kind": "ws.frame", "id": rid, "dir": "sent" if m["type"] == "send" else "recv",
                      "n": j, "opcode": op, "len": len(raw or data), "magic": sniff(raw[:256]) if op == 2 else "text"}
                if op == 2:
                    ev["head"] = raw[:24].hex()
                out.append(ev)
            continue
        out.append({"t": ts - t0, "wall": ts, "kind": "request", "id": rid, "method": rq["method"], "url": redact_url(url),
                    "host": sp.netloc, "rtype": rtype, "tags": tags_for(sp.path + "?" + sp.query), "params": url_params(url),
                    "url_fp": fp(url), "post": post, "post_fps": pfps, "req_headers": redact_headers(hdrs)})
        out.append({"t": ts - t0, "kind": "response", "id": rid, "status": rs["status"],
                    "mime": rs.get("content", {}).get("mimeType", ""), "resp_headers": {}})
        body = rs.get("content", {}).get("text")
        if body:
            js = parse_json_maybe(body)
            ev = {"t": ts - t0, "kind": "body", "id": rid, "size": len(body), "magic": sniff(body[:256].encode())}
            if js is not None:
                from common import harvest_urls
                ev["json"], ev["fps"] = redact_json(js), json_fingerprints(js)
                ev["urls"] = [{"path": p, "url": redact_url(u)} for p, u in harvest_urls(js)]
            elif body.startswith("#EXTM3U"):
                ev["playlist"] = body.splitlines()[:60]
            out.append(ev)
    return out


# ---- analysis ------------------------------------------------------------
def walk(obj: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk(v, f"{prefix}[{i}]")
    else:
        yield prefix, obj


def epoch_info(v: Any, ref: float) -> str | None:
    s = str(v)
    if not s.isdigit():
        return None
    n = int(s)
    if len(s) == 13:
        n //= 1000
    elif len(s) != 10:
        return f"{n} (relative seconds? ~{n / 60:.1f} min)" if 10 <= n <= 86400 * 2 else None
    return f"epoch {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(n))} = {n - ref:+.0f}s from request"


def analyze(events: list[dict]) -> dict:
    reqs: dict[str, dict] = {}
    order: list[str] = []
    ws: dict[str, dict] = {}
    hooks: list[dict] = []
    for ev in events:
        k, i = ev["kind"], ev.get("id")
        if k == "request":
            reqs[i] = {"req": ev}
            order.append(i)
        elif k in ("response", "body", "finish", "request.extra", "stream.head") and i in reqs:
            reqs[i][k] = ev
        elif k == "ws.created":
            ws[i] = {"created": ev, "frames": [], "order": len(order)}
            order.append(i)
        elif k.startswith("ws.") and i in ws:
            if k == "ws.frame":
                ws[i]["frames"].append(ev)
            else:
                ws[i][k] = ev
        elif k == "hook":
            hooks.append(ev)

    # ---- protocol evidence
    ev_: dict[str, list[str]] = {n: [] for n in ("HLS", "HTTP-FLV", "DASH", "WebRTC", "WebSocket-binary", "RTMP/RTSP", "MSE", "WASM/WebCodecs", "Progressive-MP4/other")}
    unknown_streams: list[str] = []
    for i in order:
        if i in ws:
            continue
        r = reqs[i]
        rq = r["req"]
        url, mime = rq["url"], r.get("response", {}).get("mime", "")
        path = urlsplit(url).path.lower()
        head = r.get("stream.head", {}).get("magic", "")
        body_magic = r.get("body", {}).get("magic", "")
        if path.endswith(".m3u8") or "mpegurl" in mime.lower() or body_magic.startswith("HLS"):
            ev_["HLS"].append(f"{i} {rq['method']} {url} (mime={mime or '?'})")
        elif path.endswith((".ts", ".m4s")) and ev_["HLS"]:
            ev_["HLS"].append(f"{i} segment {url} magic={head or '?'}")
        if path.endswith(".flv") or "x-flv" in mime.lower() or head == "FLV":
            ev_["HTTP-FLV"].append(f"{i} {rq['method']} {url} (mime={mime or '?'}, first bytes={head or '?'})")
        if path.endswith(".mpd") or "dash+xml" in mime:
            ev_["DASH"].append(f"{i} {url}")
        if (rq["rtype"] == "Media" or MEDIA_MIME_RE.search(mime)) and not (path.endswith((".m3u8", ".flv", ".ts", ".m4s", ".mpd")) or "mpegurl" in mime or "flv" in mime):
            ev_["Progressive-MP4/other"].append(f"{i} {url} mime={mime} first bytes={head or '?'}")
            if head.startswith("unknown"):
                unknown_streams.append(f"{i} {url}: {head}")
        for u in [rq["url"]] + [x["url"] for x in r.get("body", {}).get("urls", [])]:
            if re.match(r"^(rtmps?|rtsps?)://", u, re.I):
                ev_["RTMP/RTSP"].append(f"{i} {u}")
            if re.search(r"(whep|whip|webrtc|/rtc/|sdp)", u, re.I) and u.startswith("http"):
                ev_["WebRTC"].append(f"{i} possible signaling endpoint {u}")
        for u in r.get("body", {}).get("urls", []):
            if ".m3u8" in u["url"].lower():
                ev_["HLS"].append(f"{i} URL in response body at {u['path']}: {u['url']}")
            if ".flv" in u["url"].lower():
                ev_["HTTP-FLV"].append(f"{i} URL in response body at {u['path']}: {u['url']}")
            if u["url"].lower().startswith(("ws://", "wss://")):
                ev_["WebSocket-binary"].append(f"{i} WS URL handed out by API at {u['path']}: {u['url']}")
    for i, w in ws.items():
        bin_frames = [f for f in w["frames"] if f["opcode"] == 2]
        magics = Counter((f["dir"], f["magic"]) for f in bin_frames)
        summ = w.get("ws.summary")
        if bin_frames or (summ and summ["bytes"]["recv"] > 8192):
            labels = ", ".join(f"{d}:{m} x{c}" for (d, m), c in magics.items()) or "see summary"
            frames_n = summ["frames"] if summ else {}
            ev_["WebSocket-binary"].append(f"{i} {w['created']['url']} frames={frames_n} magics=[{labels}]")
            for (d, m), _ in magics.items():
                if m == "FLV" or m.startswith(("FLV tag", "MPEG-TS", "fMP4", "H.26")):
                    ev_["WebSocket-binary"].append(f"{i} container inside WS frames: {m}")
                if m.startswith(("unknown", "RTP")):
                    unknown_streams.append(f"{i} WS {w['created']['url']}: {m}")
        txt = [f for f in w["frames"] if f["opcode"] == 1 and set(f.get("tags", [])) & {"offer", "answer", "candidate"}]
        if txt:
            ev_["WebRTC"].append(f"{i} WS carries signaling-like text frames (offer/answer/candidate) x{len(txt)}")
    rtc = [h for h in hooks if h["name"].startswith("rtc.")]
    rtc_seq: list[str] = []
    stats_bytes = 0
    for h in rtc:
        d = h["data"] or {}
        if h["name"] in ("rtc.new", "rtc.createOffer", "rtc.createAnswer.result", "rtc.createOffer.result",
                         "rtc.setLocalDescription", "rtc.setRemoteDescription", "rtc.icecandidate.local",
                         "rtc.addIceCandidate", "rtc.track", "rtc.connectionstatechange"):
            rtc_seq.append(f"t={h['t']:.2f}s {h['name']} {json.dumps(d, ensure_ascii=False)[:150]}")
        if h["name"] == "rtc.stats":
            stats_bytes += sum((x.get("bytes") or 0) for x in d.get("inbound", []))
            ev_["WebRTC"].append(f"stats: {json.dumps(d)}")
    if rtc:
        ev_["WebRTC"].insert(0, f"RTCPeerConnection used ({sum(1 for h in rtc if h['name'] == 'rtc.new')} instance(s)); inbound bytes seen={stats_bytes}")
    for h in hooks:
        d = h["data"] or {}
        if h["name"] == "mse.addSourceBuffer":
            ev_["MSE"].append(f"SourceBuffer mime={d.get('mime')}")
        elif h["name"] == "mse.append" and d.get("n") == 1:
            ev_["MSE"].append(f"first appended segment: {sniff(bytes.fromhex(d['head']))} ({d['len']} bytes)")
        elif h["name"].startswith(("webcodecs", "wasm")):
            ev_["WASM/WebCodecs"].append(f"{h['name']} {json.dumps(d)}")

    # ---- call chain
    producers: dict[str, tuple[str, str]] = {}
    chain: list[dict] = []
    stream_ids = set()
    for i in order:
        if i in ws:
            c = ws[i]["created"]
            step = {"id": i, "t": c["t"], "method": "WS", "url": c["url"], "status": ws[i].get("ws.handshake.response", {}).get("status"),
                    "tags": c.get("tags", []), "rtype": "WebSocket", "params": c.get("params", {}), "wall": c.get("wall"),
                    "fps": {"url": c.get("url_fp"), **{k: v["h"] for k, v in c.get("params", {}).items()}}}
            hs = ws[i].get("ws.handshake.request", {}).get("req_headers", {})
            step["headers"] = hs
            step["recv_fps"] = {k: v for f in ws[i]["frames"] if f["dir"] == "recv" for k, v in (f.get("fps") or {}).items()}
            step["is_stream"] = True
        else:
            r = reqs[i]
            rq = r["req"]
            if rq["rtype"] in STATIC and not (set(rq["tags"]) & STREAM_TAGS):
                continue
            mime = r.get("response", {}).get("mime", "")
            step = {"id": i, "t": rq["t"], "method": rq["method"], "url": rq["url"], "status": r.get("response", {}).get("status"),
                    "tags": rq["tags"], "rtype": rq["rtype"], "params": rq.get("params", {}), "wall": rq.get("wall"),
                    "fps": {"url": rq.get("url_fp"), "path": rq.get("path_fp") if len(urlsplit(url).path) >= 6 else None,
                            **{k: v["h"] for k, v in rq.get("params", {}).items()}, **(rq.get("post_fps") or {})},
                    "headers": {**rq.get("req_headers", {}), **r.get("request.extra", {}).get("req_headers", {})},
                    "post": rq.get("post"), "mime": mime, "recv_fps": r.get("body", {}).get("fps", {}),
                    "body": r.get("body", {}).get("json"), "magic": r.get("stream.head", {}).get("magic"),
                    "cookie_sent": r.get("request.extra", {}).get("cookie_sent")}
            step["is_stream"] = bool(rq["rtype"] == "Media" or MEDIA_EXT_RE.search(rq["url"]) or MEDIA_MIME_RE.search(mime)
                                      or (step["magic"] or "").startswith(("FLV", "MPEG-TS", "fMP4", "H.26", "Matroska")))
        step["deps"] = []
        for name, h in step["fps"].items():
            if h in producers and producers[h][0] != step["id"]:
                step["deps"].append({"param": name, "from": producers[h][0], "path": producers[h][1]})
        for path, h in step["recv_fps"].items():
            producers.setdefault(h, (step["id"], path))
        chain.append(step)
        if step["is_stream"]:
            stream_ids.add(step["id"])
    first_stream = next((n for n, s in enumerate(chain) if s["is_stream"]), None)
    return {"chain": chain, "evidence": ev_, "rtc_seq": rtc_seq, "unknown": unknown_streams, "first_stream": first_stream,
            "n_requests": len(reqs), "n_ws": len(ws), "hooks": hooks}


def verdict(a: dict) -> list[str]:
    e = a["evidence"]
    out = []
    rtc_ok = any("inbound bytes seen=" in x and not x.endswith("=0") for x in e["WebRTC"]) or \
        any("rtc.track" in x for x in a["rtc_seq"])
    if rtc_ok:
        out.append("WebRTC (RTCPeerConnection received media)")
    elif e["WebRTC"]:
        out.append("RTCPeerConnection present but no inbound media observed (signaling only / failed / not the video path)")
    if e["HLS"]:
        out.append("HLS (m3u8)")
    if e["HTTP-FLV"]:
        out.append("HTTP-FLV")
    if e["DASH"]:
        out.append("DASH")
    if e["WebSocket-binary"]:
        inner = sorted({x.split("frames: ")[1] for x in e["WebSocket-binary"] if "frames: " in x})
        out.append("WebSocket binary stream" + (f" carrying {', '.join(inner)}" if inner else ""))
    if e["RTMP/RTSP"]:
        out.append("RTMP/RTSP URLs present (browsers cannot play these natively; check if they are for a gateway)")
    if a["unknown"]:
        out.append("PRIVATE / unrecognized framing (see unknown streams)")
    return out or ["no media transport detected - did live playback actually start?"]


def render(a: dict) -> str:
    L: list[str] = []
    L.append("=" * 78)
    L.append(f"requests={a['n_requests']}  websockets={a['n_ws']}  hook events={len(a['hooks'])}")
    L.append("\n[1] VIDEO PROTOCOL VERDICT")
    for v in verdict(a):
        L.append(f"  * {v}")
    for name, items in a["evidence"].items():
        if items:
            L.append(f"  -- evidence: {name}")
            L.extend(f"       {x[:230]}" for x in items[:12])
    if a["unknown"]:
        L.append("  -- unrecognized streams:")
        L.extend(f"       {x[:230]}" for x in a["unknown"][:10])
    if a["rtc_seq"]:
        L.append("\n  WebRTC signaling/ICE order:")
        L.extend(f"       {x}" for x in a["rtc_seq"][:40])

    L.append("\n[2] CALL CHAIN (device list -> play). 'deps' = value first appeared in an earlier response")
    chain = a["chain"]
    end = (a["first_stream"] + 3) if a["first_stream"] is not None else len(chain)
    for n, s in enumerate(chain[:end]):
        if s["rtype"] in ("Other",) and not s["tags"] and not s["is_stream"]:
            continue
        flag = " <== MEDIA/STREAM" if s["is_stream"] else ""
        L.append(f"  #{n:<3} ({s['id']}) t={s['t']:7.2f}s {s['method']:<4} {s['status']} {s['rtype']:<9} [{','.join(s['tags'])}]{flag}")
        L.append(f"        {s['url'][:200]}")
        if s["params"]:
            L.append("        query: " + ", ".join(f"{k}={v['v']}" for k, v in list(s["params"].items())[:12]))
        if s.get("post"):
            L.append("        body : " + json.dumps(s["post"], ensure_ascii=False)[:220])
        for d in s["deps"][:8]:
            L.append(f"        deps : {d['param']} <- response of {d['from']} at '{d['path']}'")
        if s.get("body") and (s["tags"] or s["is_stream"] or n < 12):
            L.append("        resp : " + json.dumps(s["body"], ensure_ascii=False)[:1500 if set(s["tags"]) & STREAM_TAGS else 260])

    L.append("\n[3] TEMPORARY CREDENTIALS FOR STREAM REQUESTS")
    streams = [s for s in chain if s["is_stream"]]
    if not streams:
        L.append("  (no stream request found)")
    for s in streams[:6]:
        cred = {k: v["v"] for k, v in s["params"].items() if SENSITIVE_KEY_RE.search(k) or "***" in v["v"]}
        L.append(f"  {s['id']} {s['url'][:120]}")
        L.append(f"     credential-like params: {cred or 'none in query (check headers / path / cookies)'}")
        for k in cred:
            src = [d for d in s["deps"] if d["param"] == k]
            L.append(f"       {k}: " + (f"produced by response {src[0]['from']} at JSON path '{src[0]['path']}'" if src else
                                         "NOT found in any earlier response (computed client-side, or sent by Cookie/header)"))
        if s["deps"]:
            L.append("     all deps: " + "; ".join(f"{d['param']}<-{d['from']}:{d['path']}" for d in s["deps"][:8]))

    L.append("\n[4] EXPIRY HINTS")
    seen = False
    for s in streams[:6]:
        for k, v in s["params"].items():
            if EXPIRY_KEY_RE.search(k):
                info = epoch_info(v["v"], s.get("wall") or time.time())
                L.append(f"  {s['id']} query {k}={v['v']}  {info or ''}")
                seen = True
    for s in chain:
        for path, val in walk(s.get("body") or {}):
            if EXPIRY_KEY_RE.search(path.rsplit(".", 1)[-1]) and isinstance(val, (int, float, str)) and not isinstance(val, bool):
                L.append(f"  {s['id']} response {path}={val}  {epoch_info(val, s.get('wall') or time.time()) or ''}")
                seen = True
    if not seen:
        L.append("  none visible; test empirically: python tools/probe_stream.py ... --recheck-after 120")

    L.append("\n[5] HEADERS SEEN ON STREAM REQUESTS (redacted; use probe_stream.py --matrix to learn which are REQUIRED)")
    for s in streams[:6]:
        h = s.get("headers") or {}
        L.append(f"  {s['id']} referer={h.get('referer', '-')} origin={h.get('origin', '-')} "
                 f"user-agent={'yes' if 'user-agent' in h else 'no'} cookie={h.get('cookie', 'none')} "
                 f"authorization={'yes' if 'authorization' in h else 'no'} range={h.get('range', '-')}")
    L.append("=" * 78)
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", help="events.jsonl or DevTools .har")
    args = ap.parse_args()
    print(render(analyze(load_events(Path(args.path)))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
