# cambot: analyze the live-view transport of your own 360 camera web page

Observes the page `https://my.jia.360.cn/web/myList?...` in a Chrome tab you are logged into with your own
account, and reports: video protocol, device-list -> play call chain, where temporary credentials come from,
expiry hints, headers, and a way to verify the stream locally.

It does not log in for you, does not break tokens/signatures/encryption, and only replays requests the browser
already made for your own camera. Cookies are never saved (only cookie *names*); tokens/signatures are masked in
all logs.

## Setup

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
sudo apt install ffmpeg        # optional: ffprobe/ffplay (tools fall back to a pure-Python probe)
```

## Capture (run on the Linux desktop session, needs a display for the first manual login)

```bash
.venv/bin/python tools/capture_360.py --launch --save-urls
# or start Chrome yourself and just attach:
google-chrome --user-data-dir="$HOME/.360cam-debug" --remote-debugging-port=9222 \
  'https://my.jia.360.cn/web/myList?from=mpc_ipcam_web&cate=all'
.venv/bin/python tools/capture_360.py --save-urls
```

1. Log in manually in that Chrome window if prompted (first time only; the profile keeps the session).
2. The script reloads the tab, so the device-list request is recorded from the start.
3. Click ONE of your cameras to start live view, wait 20-30 s, press Ctrl-C.

Output goes to `captures/<timestamp>/` (git-ignored, dir 0700):

| file | content |
| --- | --- |
| `events.jsonl` | redacted request/response/WebSocket/WebRTC events |
| `report.txt` | analysis (also printed) |
| `urls.local.json`, `probe.local.sh` | only with `--save-urls`: full temporary stream URLs, 0600. Delete after use. |

What is captured: Fetch/XHR/Media (URL, status, type, initiator, redacted headers, redacted JSON bodies, value
fingerprints for chain linking), first bytes of media streams, WebSocket URL/handshake/frame metadata and magic
bytes, WebRTC (`RTCPeerConnection` offer/answer/ICE order, SDP codec summary, selected candidate type, inbound
bytes), MSE `SourceBuffer` mime/first segment, WebCodecs/WASM decoder use. Keywords flagged: live stream play video
camera device token sign m3u8 flv webrtc offer answer candidate.

Re-analyze: `.venv/bin/python tools/analyze_har.py captures/<ts>/events.jsonl` (a DevTools-exported `.har` also works,
with fewer details).

## Verify the stream

Stream URLs may be bound to a live relay session (no token in the URL): probe in a second terminal while the page is
still playing, because the same URL can hang once the page stops.

```bash
.venv/bin/python tools/probe_stream.py --from-file captures/<ts>/urls.local.json            # list candidates
.venv/bin/python tools/probe_stream.py --from-file captures/<ts>/urls.local.json --index N --matrix
.venv/bin/python tools/probe_stream.py ... --index N --recheck-after 300                    # expiry test
.venv/bin/python tools/probe_stream.py ... --index N --ws-send '<text frame the page sent first>'   # WS streams
```

The probe sniffs the container, parses HLS playlists (live vs VOD, sequence advancing), scans FLV tags (codec, media
time vs wall time), checks MPEG-TS sync, reads WS frames, and `--matrix` shows which of Referer/Origin/User-Agent/
Cookie are required. If a Cookie is needed, put it in an env var and use `--cookie-env NAME` (never on the command line).

Local playback (keep the URL out of shell history):

```bash
export STREAM_URL='...'    # from urls.local.json
ffplay -fflags nobuffer -headers $'Referer: https://my.jia.360.cn/\r\nOrigin: https://my.jia.360.cn\r\n' "$STREAM_URL"
mpv --http-header-fields='Referer: https://my.jia.360.cn/' "$STREAM_URL"
```

ffplay/ffmpeg cannot read WebSocket URLs, WebRTC, or private framing. For WS-carried FLV/TS use
`probe_stream.py --save out.bin` and play the file, or pipe the frames into ffplay yourself.

## Live probe, lifecycle and re-activation (own camera only)

```bash
# 1. probe every new .flv/.m3u8 in the background while the page plays (second HTTP client, 5 s window)
.venv/bin/python tools/capture_360.py --launch --probe-live
# 2. + after the player stops, probe the SAME url at T+5/15/30/60/120s without calling playV2
#    (stop playback yourself, or --stop-after 30 closes the tab for you)
.venv/bin/python tools/capture_360.py --launch --probe-live --lifecycle [--stop-after 30]
# 3. no camera UI: playV2 through the logged-in browser, then probe / ffplay / ffprobe / libav decode / pipe
.venv/bin/python tools/open_360_stream.py --device <sn>                 # probe report
.venv/bin/python tools/open_360_stream.py --device <sn> --ffplay        # needs ffmpeg
.venv/bin/python tools/open_360_stream.py --device <sn> --pipe --seconds 0 | ffplay -fflags nobuffer -i -
.venv/bin/python tools/open_360_stream.py --device <sn> --compare --gap 10    # sha256[:8] + changed=yes/no
.venv/bin/python tools/open_360_stream.py --device <sn> --experiment          # second client + lifecycle + replay (~3 min)
```

`open_360_stream.py` attaches to the Chrome on `127.0.0.1:9222` (or launches one with `~/.360cam-debug`). Login
cookies of that profile may be session-only: keep the logged-in Chrome running (`playV2` answers
`errorCode=452 "q or t empty"` when the profile is not logged in; log in manually, the tools never do it).

## Self-test (no 360 account needed)

```bash
.venv/bin/python tools/selftest.py     # ~90 s; headless Chrome against a local fake camera site
.venv/bin/python tools/selftest.py --lifecycle   # also runs the T+5..120s schedule (~4 min)
```

Exercises device list -> play API -> HLS / HTTP-FLV / WS-FLV / RTCPeerConnection, the analyzer's chain linking and the
probe's header matrix.

## Notes

- CDP is used on `127.0.0.1` only. Do not expose the debugging port.
- Chrome may stall a few seconds on a fresh profile; the script waits. If your network needs a proxy, Chrome uses it
  as usual (the self-test disables proxies only for its own local pages).
- Never commit `captures/`, `.venv/`, or `*.local.*` (all ignored by `.gitignore`).
