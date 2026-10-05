// Injected at document start. Emits console.debug('__CAM360__' + json) records; no SDP secrets,
// ICE credentials, cookies or request bodies are logged.
(() => {
  if (window.__cam360_hooked) return;
  Object.defineProperty(window, '__cam360_hooked', { value: true });
  const log = (name, data) => {
    try { console.debug('__CAM360__' + JSON.stringify({ name, data, page: location.origin + location.pathname })); } catch (e) {}
  };
  const bytesOf = (b) => {
    if (b instanceof ArrayBuffer) return new Uint8Array(b);
    if (ArrayBuffer.isView(b)) return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    return new Uint8Array(0);
  };
  const hex = (b, n = 24) => Array.from(bytesOf(b).subarray(0, n)).map((x) => x.toString(16).padStart(2, '0')).join('');

  // ---- WebRTC -------------------------------------------------------------
  const sdpSummary = (sdp) => {
    const out = { media: [], codecs: [], dirs: [], candidates: [], lines: 0 };
    String(sdp || '').split(/\r?\n/).forEach((l) => {
      out.lines++;
      if (l.startsWith('m=')) { const p = l.split(' '); out.media.push(p[0].slice(2) + ' ' + p[2]); }
      else if (l.startsWith('a=rtpmap:')) out.codecs.push(l.split(' ')[1]);
      else if (/^a=(sendrecv|recvonly|sendonly|inactive)/.test(l)) out.dirs.push(l.slice(2));
      else if (l.startsWith('a=candidate:')) { const p = l.split(' '); out.candidates.push(p[2] + '/' + p[7]); }
      else if (l.startsWith('a=ice-lite')) out.iceLite = true;
    });
    return out;
  };
  const iceSummary = (c) => {
    if (!c || !c.candidate) return { endOfCandidates: true };
    const p = c.candidate.split(' ');
    return { proto: p[2], type: p[7] };
  };
  const RPC = window.RTCPeerConnection;
  if (RPC) {
    let seq = 0;
    const wrap = (pc, id, name, pre, post) => {
      const orig = pc[name].bind(pc);
      pc[name] = async (...a) => {
        if (pre) log('rtc.' + name, { pc: id, ...pre(...a) });
        try {
          const r = await orig(...a);
          if (post) log('rtc.' + name + '.result', { pc: id, ...post(r) });
          return r;
        } catch (e) {
          log('rtc.' + name + '.error', { pc: id, error: String(e) });
          throw e;
        }
      };
    };
    const descSum = (d) => (d ? { type: d.type, ...sdpSummary(d.sdp) } : { implicit: true });
    const stats = async (pc, id) => {
      try {
        const rep = await pc.getStats();
        const byId = {}; rep.forEach((s) => { byId[s.id] = s; });
        const res = { inbound: [], pair: null };
        rep.forEach((s) => {
          if (s.type === 'inbound-rtp') {
            res.inbound.push({ kind: s.kind, codec: (byId[s.codecId] || {}).mimeType, bytes: s.bytesReceived,
              packets: s.packetsReceived, framesDecoded: s.framesDecoded, w: s.frameWidth, h: s.frameHeight });
          }
          if (s.type === 'candidate-pair' && (s.state === 'succeeded' && s.nominated)) {
            const l = byId[s.localCandidateId] || {}, r = byId[s.remoteCandidateId] || {};
            res.pair = { local: l.candidateType, remote: r.candidateType, proto: l.protocol };
          }
        });
        log('rtc.stats', { pc: id, ...res });
      } catch (e) { log('rtc.stats.error', { pc: id, error: String(e) }); }
    };
    class P extends RPC {
      constructor(...args) {
        super(...args);
        const id = ++seq;
        const cfg = args[0] || {};
        const servers = [].concat(...(cfg.iceServers || []).map((s) => [].concat(s.urls || [])));
        log('rtc.new', { pc: id, servers: servers.map(String), policy: cfg.iceTransportPolicy, bundle: cfg.bundlePolicy });
        wrap(this, id, 'createOffer', null, (d) => descSum(d));
        wrap(this, id, 'createAnswer', null, (d) => descSum(d));
        wrap(this, id, 'setLocalDescription', (d) => descSum(d));
        wrap(this, id, 'setRemoteDescription', (d) => descSum(d));
        wrap(this, id, 'addIceCandidate', (c) => iceSummary(c));
        this.addEventListener('icecandidate', (e) => log('rtc.icecandidate.local', { pc: id, ...iceSummary(e.candidate) }));
        this.addEventListener('track', (e) => log('rtc.track', { pc: id, kind: e.track && e.track.kind }));
        this.addEventListener('datachannel', (e) => log('rtc.datachannel', { pc: id, label: e.channel.label }));
        ['connectionstatechange', 'iceconnectionstatechange', 'signalingstatechange'].forEach((ev) =>
          this.addEventListener(ev, () => {
            log('rtc.' + ev, { pc: id, state: this.connectionState + '/' + this.iceConnectionState + '/' + this.signalingState });
            if (ev === 'connectionstatechange' && this.connectionState === 'connected') setTimeout(() => stats(this, id), 3000);
          }));
      }
    }
    window.RTCPeerConnection = P;
    if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = P;
  }

  // ---- MSE (flv.js / hls.js / mpegts.js style players) ---------------------
  if (window.MediaSource && window.SourceBuffer) {
    const addSB = MediaSource.prototype.addSourceBuffer;
    MediaSource.prototype.addSourceBuffer = function (mime) {
      log('mse.addSourceBuffer', { mime });
      return addSB.call(this, mime);
    };
    const app = SourceBuffer.prototype.appendBuffer;
    SourceBuffer.prototype.appendBuffer = function (buf) {
      const n = (this.__cam_n = (this.__cam_n || 0) + 1);
      if (n <= 3) log('mse.append', { n, len: buf.byteLength, head: hex(buf) });
      else if (n % 200 === 0) log('mse.append.count', { n });
      return app.call(this, buf);
    };
  }
  document.addEventListener('loadstart', (e) => {
    if (e.target && e.target.tagName === 'VIDEO') log('media.loadstart', { src: String(e.target.currentSrc).split('?')[0].slice(0, 200) });
  }, true);
  document.addEventListener('playing', (e) => {
    if (e.target && e.target.tagName === 'VIDEO') log('media.playing', { w: e.target.videoWidth, h: e.target.videoHeight });
  }, true);

  // ---- WebCodecs / WASM decoders (private protocol players) ----------------
  if (window.VideoDecoder) {
    const cfg = VideoDecoder.prototype.configure;
    VideoDecoder.prototype.configure = function (c) { log('webcodecs.configure', { codec: c && c.codec, w: c && c.codedWidth, h: c && c.codedHeight }); return cfg.call(this, c); };
  }
  if (window.WebAssembly) {
    ['instantiate', 'instantiateStreaming', 'compile', 'compileStreaming'].forEach((k) => {
      const o = WebAssembly[k];
      if (typeof o !== 'function') return;
      let once = false;
      WebAssembly[k] = function (src, ...r) {
        if (!once) { once = true; log('wasm.' + k, { len: src && src.byteLength }); }
        return o.call(this, src, ...r);
      };
    });
  }
})();
