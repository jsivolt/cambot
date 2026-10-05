"""Shared helpers: redaction, keyword tagging, payload sniffing."""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit, quote

KEYWORDS = (
    "live", "stream", "play", "video", "camera", "device", "token", "sign",
    "m3u8", "flv", "webrtc", "offer", "answer", "candidate",
)

SENSITIVE_KEY_RE = re.compile(
    r"(token|sign|signature|^sig$|_sig$|auth|secret|passw|pwd|cookie|session|ticket|"
    r"credential|api_?key|access_?key|^key$|_key$|^sid$|_sid$|csrf|nonce|^ak$|^sk$|"
    r"bearer|jwt|ice-pwd|ufrag|userinfo|user_?name|^qid$|mobile|phone|email|nick)",
    re.I,
)
PHONE_RE = re.compile(r"^1[3-9]\d{9}$")  # CN mobile; 13-digit ms timestamps must not match
URL_RE = re.compile(r"^(?:https?|wss?|rtmps?|rtsps?|webrtc)://\S+$", re.I)
OPAQUE_RE = re.compile(r"^[A-Za-z0-9_\-+/=.%~]{20,}$")
EXPIRY_KEY_RE = re.compile(r"(expire|expires|^exp$|deadline|ttl|valid|timeout|^e$|^ts$|^t$|timestamp)", re.I)
MEDIA_EXT_RE = re.compile(r"\.(m3u8|flv|ts|m4s|mp4|mpd|webm)(?:$|[?#])", re.I)
MEDIA_MIME_RE = re.compile(r"(mpegurl|x-flv|mp2t|^video/|^audio/|dash\+xml|x-mpegts)", re.I)
STREAM_SCHEME_RE = re.compile(r"^(rtmps?|rtsps?|wss?|webrtc)://", re.I)


def mask(value: Any) -> str:
    s = str(value)
    if len(s) <= 8:
        return f"***<{len(s)}>"
    return f"{s[:3]}***{s[-2:]}<{len(s)}>"


def fp(value: Any) -> str:
    """Short fingerprint so values can be correlated across requests without storing them."""
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:10]


def tags_for(text: str) -> list[str]:
    low = text.lower()
    return [k for k in KEYWORDS if k in low]


def _is_opaque(v: str) -> bool:
    return bool(OPAQUE_RE.match(v)) and not v.isdigit()


def _mask_seg(seg: str) -> str:
    base, dot, ext = seg.rpartition(".")
    if dot and base and 1 <= len(ext) <= 5 and ext.isalnum():
        return mask(base) + "." + ext
    return mask(seg)


def redact_param(key: str, value: str) -> str:
    if SENSITIVE_KEY_RE.search(key) or _is_opaque(value) or PHONE_RE.match(value):
        return mask(value)
    return value if len(value) <= 120 else value[:120] + "..."


def redact_url(url: str) -> str:
    """Mask credentials, sensitive/opaque query values and long opaque path segments."""
    try:
        p = urlsplit(url)
    except ValueError:
        return mask(url)
    netloc = p.hostname or ""
    if p.port:
        netloc += f":{p.port}"
    path = "/".join(_mask_seg(seg) if len(seg) >= 24 and OPAQUE_RE.match(seg) else seg for seg in p.path.split("/"))
    q = "&".join(
        f"{quote(k, safe='')}={redact_param(k, v)}" for k, v in parse_qsl(p.query, keep_blank_values=True)
    )
    frag = mask(p.fragment) if p.fragment else ""
    return urlunsplit((p.scheme, netloc, path, q, frag))


def url_params(url: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    try:
        items = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return out
    for k, v in items:
        out[k] = {"v": redact_param(k, v), "h": fp(v)}
    return out


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, v in (headers or {}).items():
        ln = name.lower()
        v = str(v)
        if ln in ("cookie", "set-cookie"):
            names = sorted({c.split("=", 1)[0].strip() for c in re.split(r"[;\n]", v) if "=" in c})
            out[ln] = "<names: " + ",".join(names) + ">"
        elif ln == "authorization":
            out[ln] = mask(v)
        elif ln in ("referer", "location", "origin"):
            out[ln] = redact_url(v)
        elif SENSITIVE_KEY_RE.search(ln):
            out[ln] = mask(v)
        else:
            out[ln] = v if len(v) <= 200 else v[:200] + "..."
    return out


def redact_json(obj: Any, key: str = "", depth: int = 0) -> Any:
    if depth > 12:
        return "<deep>"
    if isinstance(obj, dict):
        return {k: redact_json(v, str(k), depth + 1) for k, v in list(obj.items())[:80]}
    if isinstance(obj, list):
        items = [redact_json(v, key, depth + 1) for v in obj[:20]]
        if len(obj) > 20:
            items.append(f"<+{len(obj) - 20} more>")
        return items
    if isinstance(obj, str):
        if SENSITIVE_KEY_RE.search(key):
            return mask(obj)
        if URL_RE.match(obj):
            return redact_url(obj)
        if _is_opaque(obj) or PHONE_RE.match(obj):
            return mask(obj)
        return obj if len(obj) <= 200 else obj[:200] + "..."
    if isinstance(obj, (int, float)) and not isinstance(obj, bool) and SENSITIVE_KEY_RE.search(key):
        return mask(obj)
    return obj


def json_fingerprints(obj: Any, prefix: str = "", out: dict[str, str] | None = None, limit: int = 500) -> dict[str, str]:
    """path -> fingerprint for scalar values (>=6 chars); URL values also contribute their query params."""
    out = {} if out is None else out
    if len(out) >= limit:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            json_fingerprints(v, f"{prefix}.{k}" if prefix else str(k), out, limit)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            json_fingerprints(v, f"{prefix}[{i}]", out, limit)
    elif isinstance(obj, (str, int)) and not isinstance(obj, bool):
        s = str(obj)
        if len(s) >= 6:
            out[prefix] = fp(s)
            if isinstance(obj, str) and URL_RE.match(s):
                path = urlsplit(s).path
                if len(path) >= 6:
                    out[f"{prefix}#path"] = fp(path)
                for k, v in parse_qsl(urlsplit(s).query, keep_blank_values=True):
                    if len(v) >= 6:
                        out[f"{prefix}?{k}"] = fp(v)
    return out


def harvest_urls(obj: Any, prefix: str = "", out: list | None = None) -> list[tuple[str, str]]:
    """(json path, full url) for stream-looking URL strings inside a JSON body. Full values: keep local only."""
    out = [] if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            harvest_urls(v, f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:50]):
            harvest_urls(v, f"{prefix}[{i}]", out)
    elif isinstance(obj, str):
        for m in re.finditer(r"(?:https?|wss?|rtmps?|rtsps?|webrtc)://[^\s\"'<>]+", obj, re.I):
            u = m.group(0)
            if STREAM_SCHEME_RE.match(u) or MEDIA_EXT_RE.search(u) or tags_for(u):
                out.append((prefix, u))
    return out


def shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


def sniff(b: bytes, total: int | None = None) -> str:
    """Identify a container/codec from the leading bytes of a payload (total = full payload length, if known)."""
    if not b:
        return "empty"
    if b[:3] == b"FLV":
        return "FLV"
    if total and len(b) >= 11 and b[0] in (8, 9, 18) and b[8:11] == b"\x00\x00\x00":
        size = int.from_bytes(b[1:4], "big")
        if total in (11 + size, 15 + size):
            return f"FLV tag (type {b[0]}: {({8: 'audio', 9: 'video', 18: 'script'})[b[0]]}) without FLV header"
    if b[:7] == b"#EXTM3U":
        return "HLS playlist (m3u8)"
    if len(b) >= 189 and b[0] == 0x47 and b[188] == 0x47:
        return "MPEG-TS"
    if len(b) >= 8 and b[4:8] in (b"ftyp", b"styp", b"moof", b"moov", b"mdat", b"sidx", b"free"):
        return f"fMP4/MP4 (box {b[4:8].decode()})"
    if b[:4] == b"\x1aE\xdf\xa3":
        return "Matroska/WebM"
    if b[:4] == b"OggS":
        return "Ogg"
    if b[:5] in (b"RTSP/", b"OPTIO", b"DESCR"):
        return "RTSP text"
    if b[:4] == b"\x00\x00\x00\x01" or b[:3] == b"\x00\x00\x01":
        off = 4 if b[:4] == b"\x00\x00\x00\x01" else 3
        if len(b) > off:
            nal = b[off]
            h264, h265 = nal & 0x1F, (nal >> 1) & 0x3F
            if h264 in (1, 5, 6, 7, 8, 9):
                return f"H.264 Annex-B (NAL type {h264})"
            if h265 in (1, 19, 20, 32, 33, 34, 35, 39, 40):
                return f"H.265 Annex-B (NAL type {h265})"
        return "Annex-B start code (codec unknown)"
    if b[:3] == b"ID3" or (len(b) > 1 and b[0] == 0xFF and (b[1] & 0xF6) == 0xF0):
        return "AAC/MP3 (ADTS/ID3)"
    if b[:1] in (b"{", b"[") or (len(b) >= 4 and all(32 <= c < 127 or c in (9, 10, 13) for c in b[:32])):
        return "text/JSON"
    if len(b) >= 12 and b[0] >> 6 == 2 and 96 <= (b[1] & 0x7F) <= 127:
        return "RTP-like"
    ent = shannon_entropy(b[:256])
    if len(b) >= 64 and ent > 7.2:
        return f"unknown binary, high entropy {ent:.2f} (encrypted/compressed/private)"
    return "unknown binary (private framing?)"


def parse_json_maybe(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None
