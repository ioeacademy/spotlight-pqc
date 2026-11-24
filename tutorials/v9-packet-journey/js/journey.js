/* journey.js — the IKEv2 Packet Journey in the labs' format:
   steps on the left (one per phase of the capture), the topology on top right, the capture and the
   event list as console tabs below it, transport controls in the bottom bar.
   The replay, the display-filter language and the Wireshark-style decode are v8's, unchanged.
   Data: DATA and META from captures.js; tutorial text: window.JOURNEY (journey-steps.js). */
(function () {
  'use strict';
  const J = window.JOURNEY;
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const fmt = (n) => Number(n).toLocaleString('en-US');
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  const KCOL = { ARP: '--arp', IKE_SA_INIT: '--ike', IKE_INTERMEDIATE: '--pqc', IKE_AUTH: '--auth', ESP: '--esp',
    CREATE_CHILD_SA: '--ike', IKE_FOLLOWUP_KE: '--pqc', INFORMATIONAL: '--info' };
  const cvar = (k) => `var(${KCOL[k]})`;
  const GROUP = (k) => (k === 'ARP' ? 'ARP' : k === 'ESP' ? 'ESP' : 'IKE');
  const PATHS = {
    'R1>R3': [[null, 'R1'], ['R1', 'R2', 1], ['R2', 'R3']],
    'R3>R1': [[null, 'R3'], ['R3', 'R2'], ['R2', 'R1', 1]],
    'R1>R2': [[null, 'R1'], ['R1', 'R2', 1]],
    'R2>R1': [[null, 'R2'], ['R2', 'R1', 1]],
  };
  const FILE = { classic: '01-classical-x25519.pcapng', hybrid: '02-hybrid-x25519-mlkem768.pcapng' };
  const SCN = { classic: { badge: 'Classical', name: 'classical' }, hybrid: { badge: 'Hybrid PQC', name: 'hybrid post-quantum' } };

  /* topology geometry: the labs' three routers in a row (viewBox 60 -4 840 298) */
  const X = { R1: 150, R2: 480, R3: 810 };
  const Y = 205, TOP = Y - 20, LANE = Y - 62, TAP_X = 400;

  const track = (new URLSearchParams(location.search).get('track') || '').toLowerCase();
  const S = { sc: track === 'classic' ? 'classic' : 'hybrid', keys: false, e: -1, playing: false, run: 0, until: null, speed: 1,
    show: { ARP: true, IKE: true, ESP: true }, follow: true, sel: null, filter: '', filterErr: '', node: null, nodeKey: null, src: 0, animating: false, tab: 'cap' };
  let EV = [], CAPIDX = [], LASTIDX = [], FIRSTIDX = [];
  const EXPANDED = new Set(['isakmp', 'esp', 'arp']);
  let openMap = null, openFrameKey = null;
  const PROG = { classic: { intro: false, done: new Set(), finished: false }, hybrid: { intro: false, done: new Set(), finished: false } };

  const meta = () => META[S.sc];
  const frames = () => meta().frames;
  const fdata = (i) => { const d = DATA[S.sc]; return (S.keys && d.keys[i]) || d.nokeys[i]; };
  const short = (m) => (m.kind === 'ESP' ? 'ESP ' + m.title.split(' · ')[1] : m.title.split(' · ')[0]);

  function buildEvents() {
    EV = []; CAPIDX = []; LASTIDX = []; FIRSTIDX = [];
    frames().forEach((m, i) => {
      const p = PATHS[m.dir];
      FIRSTIDX[i] = EV.length;
      p.forEach((h, j) => {
        if (h[2]) CAPIDX[i] = EV.length;
        EV.push({ fi: i, j, from: h[0], to: h[1], cap: !!h[2], last: j === p.length - 1 });
      });
      LASTIDX[i] = EV.length - 1;
    });
  }
  const visibleEv = (k) => S.show[GROUP(frames()[EV[k].fi].kind)];
  // first and last event of a phase
  function phaseRange(pi) {
    const fr = frames(), idx = fr.map((m, i) => (m.phase === pi ? i : -1)).filter((i) => i >= 0);
    return { frames: idx, first: FIRSTIDX[idx[0]], last: LASTIDX[idx[idx.length - 1]] };
  }

  /* ---------- state derived from the event index ---------- */
  function derive(e) {
    const st = { ike: null, child: null, childSpis: null, rekeyChild: false, rekeyIke: false, setupB: 0, rtt: 0, capN: 0, capB: 0 };
    const espFirst = meta().spis.first, espLast = meta().spis.last;
    frames().forEach((m, i) => {
      if (CAPIDX[i] <= e) {
        st.capN++; st.capB += m.len;
        if (['IKE_SA_INIT', 'IKE_INTERMEDIATE', 'IKE_AUTH'].includes(m.kind)) st.setupB += m.len;
      }
      if (LASTIDX[i] <= e) {
        if (m.dir === 'R3>R1' && ['IKE_SA_INIT', 'IKE_INTERMEDIATE', 'IKE_AUTH'].includes(m.kind)) st.rtt++;
        const fx = m.fx || {};
        if (fx.ike === 'x25519' || fx.ike === 'x25519-pending' || fx.ike === 'hybrid') st.ike = fx.ike;
        if (fx.ike === 'rekeyed') st.rekeyIke = true;
        if (fx.child === 'up') { st.child = 'up'; st.childSpis = espFirst; }
        if (fx.child === 'rekeyed') { st.rekeyChild = true; st.childSpis = espLast; }
      }
    });
    return st;
  }

  /* ═══════════════════════ Topology ═══════════════════════ */
  const SVGNS = 'http://www.w3.org/2000/svg';
  const svg = $('#topo');
  const el = (tag, attrs = {}, parent) => { const n = document.createElementNS(SVGNS, tag); for (const [a, v] of Object.entries(attrs)) n.setAttribute(a, v); if (parent) parent.appendChild(n); return n; };
  const fsScale = () => +getComputedStyle(document.documentElement).getPropertyValue('--fs') || 1;
  let gTun, tunSig = '';
  const pkt = {}, cap = {}, tap = {};
  const LINKS = [
    { a: ['R1', 'r1-g1', '198.51.100.1'], b: ['R2', 'r2-g1', '198.51.100.2'], net: '198.51.100.0/30' },
    { a: ['R2', 'r2-g2', '203.0.113.1'], b: ['R3', 'r3-g1', '203.0.113.2'], net: '203.0.113.0/30' },
  ];
  const ROLE = { R1: 'Initiator', R2: 'Transit · no IPsec', R3: 'Responder' };
  function drawStatic() {
    svg.innerHTML = '';
    const defs = el('defs', {}, svg);
    const gr = el('linearGradient', { id: 'g-router', x1: 0, y1: 0, x2: 1, y2: 1 }, defs);
    el('stop', { offset: '0%', 'stop-color': '#009de2' }, gr); el('stop', { offset: '100%', 'stop-color': '#0a60ff' }, gr);
    const lock = el('g', { id: 'lock' }, defs);
    el('rect', { x: -4.5, y: -1, width: 9, height: 7, rx: 1.5, fill: 'currentColor' }, lock);
    el('path', { d: 'M-2.8 -1v-2.2a2.8 2.8 0 0 1 5.6 0v2.2', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.5 }, lock);
    gTun = el('g', { id: 'g-tun' }, svg);
    const gL = el('g', { id: 'g-links' }, svg);
    const txt = (cls, x, y, s, anchor, title) => { const t = el('text', { class: cls, x, y, 'text-anchor': anchor }, gL); t.textContent = s; if (title) el('title', {}, t).textContent = title; return t; };
    for (const l of LINKS) {
      const x1 = X[l.a[0]] + 50, x2 = X[l.b[0]] - 50;
      el('line', { class: 'link', x1, y1: Y, x2, y2: Y }, gL);
      el('circle', { class: 'dot-up', cx: x1 + 6, cy: Y, r: 4.5 }, gL);
      el('circle', { class: 'dot-up', cx: x2 - 6, cy: Y, r: 4.5 }, gL);
      txt('lbl-link', (x1 + x2) / 2, Y + 46, l.net, 'middle');
      for (const [end, x, an] of [[l.a, x1, 'start'], [l.b, x2, 'end']]) {
        txt('lbl-port', x, Y + 22, end[1], an);
        // the subnet is under the link; each end shows its host part (full address on hover)
        txt('lbl-ip', x, Y - 10, '.' + end[2].split('.').pop(), an, `${end[0]} ${end[1]} ${end[2]}`);
      }
    }
    // capture point on R2's interface r2-g1
    const gt = el('g', { id: 'tap', role: 'button', tabindex: 0, 'aria-label': 'Capture point on R2 r2-g1: show the capture' }, svg);
    el('rect', { class: 'tap-hit', x: TAP_X - 175, y: Y - 30, width: 190, height: 40 }, gt);
    tap.ring = el('circle', { class: 'tap-ring', cx: TAP_X, cy: Y, r: 9, opacity: 0 }, gt);
    el('circle', { class: 'tap-dot', cx: TAP_X, cy: Y, r: 6.5 }, gt);
    tap.label = el('text', { class: 'lbl-cap', x: TAP_X - 12, y: Y - 13, 'text-anchor': 'end' }, gt);
    tap.label.textContent = 'Capture point · r2-g1';
    el('title', {}, gt).textContent = 'dumpcap on R2, interface r2-g1 (toward R1): both directions of link R1–R2';
    gt.addEventListener('click', () => showTab('cap'));
    gt.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); showTab('cap'); } });
    // routers: the labs' line icon (a cylinder, two arrows in, two out)
    for (const k of ['R1', 'R2', 'R3']) {
      const x = X[k];
      const g = el('g', { class: 'router ' + k.toLowerCase() }, svg);
      const RX = 42, RY = 15, cy = Y - 9, H = 24;
      el('rect', { class: 'ring', x: x - RX - 9, y: cy - RY - 8, width: 2 * RX + 18, height: H + 2 * RY + 16, rx: 12 }, g);
      el('path', { class: 'r-body', d: `M${x - RX},${cy} v${H} a${RX},${RY} 0 0 0 ${2 * RX},0 v${-H}` }, g);
      el('ellipse', { class: 'r-top', cx: x, cy, rx: RX, ry: RY }, g);
      const ar = (d) => el('path', { class: 'r-arrow', d }, g);
      ar(`M${x - RX + 8},${cy + 1} H${x - 13} m-5,-4.5 l5,4.5 l-5,4.5`);
      ar(`M${x + RX - 8},${cy - 1} H${x + 13} m5,-4.5 l-5,4.5 l5,4.5`);
      ar(`M${x - 4},${cy - 1} V${cy - 12} m-4.5,4.5 l4.5,-4.5 l4.5,4.5`);
      ar(`M${x + 4},${cy + 1} V${cy + 12} m-4.5,-4.5 l4.5,4.5 l4.5,-4.5`);
      el('text', { class: 'host', x, y: Y + 56, 'text-anchor': 'middle' }, g).textContent = k;
      el('text', { class: 'role', x, y: Y + 75, 'text-anchor': 'middle' }, g).textContent = ROLE[k];
      if (k === 'R2') {
        g.setAttribute('role', 'button'); g.setAttribute('tabindex', 0); g.setAttribute('aria-label', 'R2: show the capture taken on r2-g1');
        g.addEventListener('click', () => showTab('cap'));
        g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); showTab('cap'); } });
      }
    }
    // the moving packet and its caption
    const gp = el('g', { id: 'g-pkt', class: 'pkt' }, svg);
    cap.g = el('g', { opacity: 0 }, gp);
    cap.rect = el('rect', { class: 'cap-bg', x: 0, y: LANE - 61, width: 10, height: 26, rx: 7 }, cap.g);
    cap.tip = el('path', { class: 'cap-bg', d: '' }, cap.g);
    cap.text = el('text', { class: 'cap-text', x: 0, y: LANE - 43, 'text-anchor': 'middle' }, cap.g);
    pkt.g = el('g', { opacity: 0 }, gp); pkt.g.style.color = '#fff';
    pkt.rect = el('rect', { x: -40, y: -15, width: 80, height: 30, rx: 6 }, pkt.g);
    pkt.lock = el('use', { href: '#lock', class: 'pkt-lock', x: 0, y: 0 }, pkt.g);
    pkt.label = el('text', { class: 'pkt-label', x: 0, y: 4.5, 'text-anchor': 'middle' }, pkt.g);
    pkt.size = el('text', { class: 'pkt-size', x: 0, y: 30, 'text-anchor': 'middle' }, pkt.g);
  }
  function setPacket(x, m, show = true) {
    if (!m || !show) { pkt.g.setAttribute('opacity', '0'); return; }
    const enc = !(m.kind === 'ARP' || m.kind === 'IKE_SA_INIT');
    if (pkt.label.textContent !== m.label) { pkt.label.textContent = m.label; pkt.tw = 0; try { pkt.tw = pkt.label.getComputedTextLength(); } catch (e) { } }
    // width grows with the frame size, and always fits the label (plus the lock when encrypted)
    const w = Math.round(Math.max(64 + Math.min(m.len, 1300) / 1300 * 70, (pkt.tw || m.label.length * 7.3) + (enc ? 34 : 20)));
    pkt.rect.setAttribute('x', -w / 2); pkt.rect.setAttribute('width', w); pkt.rect.setAttribute('fill', cvar(m.kind));
    pkt.label.setAttribute('x', enc ? 7 : 0);
    pkt.lock.setAttribute('opacity', enc ? '1' : '0'); pkt.lock.setAttribute('x', -w / 2 + 11); pkt.lock.setAttribute('y', -1);
    pkt.size.textContent = fmt(m.len) + ' B';
    pkt.g.setAttribute('transform', `translate(${x} ${LANE})`);
    pkt.g.setAttribute('opacity', '1');
  }
  function caption(x, text) {
    if (!text) { cap.g.setAttribute('opacity', '0'); return; }
    cap.text.textContent = text;
    const w = Math.max(60, text.length * 7 + 24);
    const cx = Math.min(900 - w / 2 - 6, Math.max(60 + w / 2 + 6, x));
    cap.text.setAttribute('x', cx);
    cap.rect.setAttribute('x', cx - w / 2); cap.rect.setAttribute('width', w);
    cap.tip.setAttribute('d', `M${x - 6} ${LANE - 35}l6 7l6 -7z`);
    cap.g.setAttribute('opacity', '1');
  }
  function eventCaption(k) {
    const ev = EV[k], m = frames()[ev.fi], name = short(m);
    if (ev.j === 0) {
      if (m.kind === 'ESP') return ev.to === 'R1' ? 'R1 encrypts a ping into ESP' : 'R3 encrypts the reply into ESP';
      if (m.kind === 'ARP') return `${ev.to} sends an ARP ${name.includes('request') ? 'request' : name.includes('reply') ? 'reply' : 'message'}`;
      return `${ev.to} sends ${name}`;
    }
    if (!ev.last) return 'R2 routes it on (TTL − 1)';
    if (m.kind === 'ESP') return ev.to === 'R3' ? 'R3 decrypts ESP, delivers the ping' : 'R1 decrypts ESP, delivers the reply';
    return `${ev.to} receives ${name}`;
  }
  // the SA between R1 and R3, drawn as the labs draw a tunnel: an arc with a status badge
  function tunnelView(st) {
    if (!st.ike) return null;
    const hyb = st.ike === 'hybrid', pend = st.ike === 'x25519-pending';
    const keys = hyb ? 'X25519 + ML-KEM-768' : 'X25519';
    if (!st.child) return { kind: 'neg', st: 'NEGOTIATING', label: `IKE SA · ${keys} keys${pend ? ' · ML-KEM round next' : ''}` };
    return { kind: S.sc === 'classic' ? 'classic' : 'pqc', st: 'UP', label: `ESP ${st.childSpis[0]} ⇄ ${st.childSpis[1]} · ${keys}${st.rekeyChild || st.rekeyIke ? ' · rekeyed' : ''}` };
  }
  function renderTunnel(st) {
    const v = tunnelView(st), fs = fsScale(), sig = JSON.stringify([v, fs]);
    if (sig === tunSig) return; tunSig = sig;
    gTun.innerHTML = '';
    if (!v) return;
    const x1 = X.R1, x2 = X.R3, mx = (x1 + x2) / 2, h = 150, d = `M${x1},${TOP} Q${mx},${TOP - 2 * h} ${x2},${TOP}`, apex = [mx, TOP - h];
    const g = el('g', { class: 'tun-g', 'data-key': 'sa', role: 'button', tabindex: 0, 'aria-label': `Inspect the SA: ${v.st} · ${v.label}` }, gTun);
    el('path', { class: 'tun-hit', d }, g);
    el('path', { class: 'tun ' + v.kind, d }, g);
    const lg = el('g', { class: 'tun-label' }, g), col = `var(--${v.kind})`;
    const rect = el('rect', { x: apex[0] - 100, y: apex[1] - 14 * fs, width: 200, height: 28 * fs, rx: 8, stroke: col }, lg);
    const ty = apex[1] + 5 * fs;
    const tx = el('text', { x: apex[0] + 7, y: ty, 'text-anchor': 'middle' }, lg);
    el('tspan', { class: 'st' }, tx).textContent = v.st;
    el('tspan', {}, tx).textContent = ` · ${v.label}`;
    const dot = el('circle', { cx: 0, cy: ty - 5 * fs, r: 5, fill: col }, lg);
    let tw = 0; try { tw = tx.getComputedTextLength(); } catch (e) { }
    if (!tw) tw = (v.st.length + v.label.length + 3) * 8.6 * fs;
    rect.setAttribute('x', apex[0] - (tw + 40) / 2); rect.setAttribute('width', tw + 40);
    dot.setAttribute('cx', apex[0] + 7 - tw / 2 - 11);
    g.addEventListener('click', openModal);
    g.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openModal(); } });
  }
  function renderStats(st) {
    const p = $('#qpill'), t = $('#qtext');
    p.className = 'stat';
    if (!st.ike) t.textContent = 'No keys yet';
    else if (S.sc === 'classic') { p.classList.add('q-danger'); t.textContent = 'X25519 only · record now, decrypt later'; }
    else if (st.ike === 'hybrid') { p.classList.add('q-ok'); t.textContent = 'X25519 + ML-KEM-768 · quantum-resistant'; }
    else { p.classList.add('q-pending'); t.textContent = 'X25519 · ML-KEM round pending'; }
    const m = meta();
    $('#setupB').textContent = `${fmt(st.setupB)} / ${fmt(m.setupBytes)} B`;
    $('#setupM').style.width = `${(st.setupB / m.setupBytes) * 100}%`;
    $('#rtt').textContent = `${st.rtt} / ${m.setupRtt}`;
    $('#capN').textContent = `${st.capN} frame${st.capN === 1 ? '' : 's'} · ${fmt(st.capB)} B`;
  }
  function restingStage() {
    const st = derive(S.e);
    renderTunnel(st); renderStats(st);
    if (S.e < 0) { setPacket(0, null); caption(0, ''); return; }
    const ev = EV[S.e], m = frames()[ev.fi];
    setPacket(X[ev.to], m);
    caption(X[ev.to], eventCaption(S.e));
  }

  /* ═══════════════════════ Event list (console tab) ═══════════════════════ */
  function renderEventList() {
    const body = $('#evBody');
    body.innerHTML = '';
    const frag = document.createDocumentFragment();
    EV.forEach((ev, k) => {
      const m = frames()[ev.fi], d = DATA[S.sc].nokeys[ev.fi];
      const tr = document.createElement('tr');
      const info = ev.j === 0 ? esc(short(m)) : ev.cap ? `<span class="cap-mark">Captured · frame #${m.n}</span>` : ev.last ? `Delivered to ${ev.to}` : 'Reaches R2, routed on';
      tr.innerHTML = `<td>${k + 1}</td><td>${Number(d.row[1]).toFixed(6)}</td><td>${ev.from || '—'}</td><td>${ev.to}</td>` +
        `<td><span class="sq" style="background:${cvar(m.kind)}"></span>${m.kind === 'ARP' ? 'ARP' : m.kind === 'ESP' ? 'ESP' : 'ISAKMP'}</td><td class="info">${info}</td>`;
      tr.onclick = () => { stop(); jump(k); };
      frag.append(tr);
    });
    body.append(frag);
    markEventList();
  }
  function markEventList(scroll = true) {
    const rows = $('#evBody').children;
    for (let k = 0; k < rows.length; k++) rows[k].className = (k === S.e ? 'cur' : k < S.e ? 'past' : '') + (visibleEv(k) ? '' : ' hidden');
    const box = $('#t-ev');
    if (scroll && S.e >= 0 && box.clientHeight) {
      const r = rows[S.e];
      if (r && (r.offsetTop < box.scrollTop + 40 || r.offsetTop > box.scrollTop + box.clientHeight - 30)) box.scrollTop = r.offsetTop - box.clientHeight / 2;
    }
  }

  /* ═══════════════════════ Animation ═══════════════════════ */
  function tween(ms, fn) {
    return new Promise((res) => {
      // a hidden tab gets no animation frames: finish at once rather than stall the replay
      if (reduced || ms <= 0 || document.hidden) { fn(1); res(); return; }
      const t0 = performance.now();
      let done = false;
      const tick = (t) => { if (done) return; const p = Math.min(1, (t - t0) / ms); fn(p); if (p < 1) requestAnimationFrame(tick); else { done = true; res(); } };
      requestAnimationFrame(tick);
      setTimeout(() => { if (!done) { done = true; fn(1); res(); } }, ms + 400);
    });
  }
  const ease = (p) => (p < 0.5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2);
  let tapTimer = null;
  function flashTap(m) {
    tap.label.textContent = `captured as frame #${m.n}`; tap.label.classList.add('flash');
    clearTimeout(tapTimer);
    tapTimer = setTimeout(() => { tap.label.textContent = 'Capture point · r2-g1'; tap.label.classList.remove('flash'); }, reduced ? 1200 : 1100);
    tween(reduced ? 0 : 900, (p) => { tap.ring.setAttribute('r', 9 + p * 22); tap.ring.setAttribute('opacity', String(reduced ? 0 : 1 - p)); });
    if (S.tab !== 'cap') $('#tab-cap').classList.add('has-unread');
  }
  async function animateTo(k) {
    const ev = EV[k], m = frames()[ev.fi];
    S.animating = true;
    const dur = 1000 / S.speed;
    if (ev.j === 0) {
      caption(X[ev.to], eventCaption(k));
      await tween(dur * 0.45, (p) => { setPacket(X[ev.to], m); pkt.g.setAttribute('opacity', String(p)); });
    } else {
      const x0 = X[ev.from], x1 = X[ev.to];
      let flashed = false;
      caption(0, '');
      await tween(dur, (p) => {
        const x = x0 + (x1 - x0) * ease(p);
        setPacket(x, m);
        if (ev.cap && !flashed && ((x0 < x1 && x >= TAP_X) || (x0 > x1 && x <= TAP_X))) { flashed = true; flashTap(m); }
      });
      if (ev.cap && !flashed) flashTap(m);
    }
    S.animating = false;
  }

  /* ═══════════════════════ Navigation ═══════════════════════ */
  function nextVisible(from) { for (let k = from + 1; k < EV.length; k++) if (visibleEv(k)) return k; return -1; }
  function prevVisible(from) { for (let k = from - 1; k >= 0; k--) if (visibleEv(k)) return k; return -1; }
  async function stepForward() {
    if (S.animating) return false;
    const k = nextVisible(S.e);
    if (k < 0) { stop(); return false; }
    S.e = k - 1;   // hidden events in between happen instantly
    await animateTo(k);
    S.e = k;
    update(true);
    return true;
  }
  function jump(k) { S.e = Math.max(-1, Math.min(EV.length - 1, k)); update(true); }
  function back() { if (S.animating) return; jump(prevVisible(S.e)); }
  async function play(until = null) {
    if (S.playing) { stop(); return; }
    if (nextVisible(S.e) < 0) jump(-1);
    const my = ++S.run;
    S.playing = true; S.until = until; setPlayButton();
    while (S.playing && S.run === my) {
      const ok = await stepForward();
      if (!ok || S.run !== my) break;
      if (S.until !== null && S.e >= S.until) break;
      await sleep(320 / S.speed);
    }
    if (S.run === my) { S.playing = false; S.until = null; setPlayButton(); }
  }
  function stop() { S.run++; S.playing = false; S.until = null; setPlayButton(); }
  function setPlayButton() {
    const t = $('#playText'); if (!t) return;
    t.textContent = S.playing ? 'Pause' : 'Play';
    $('#playIcon').innerHTML = S.playing ? '<path d="M3 2h4v12H3zM9 2h4v12H9z"/>' : '<path d="M4 2v12l10-6z"/>';
  }
  function playPhase(pi) {
    stop();
    const r = phaseRange(pi);
    jump(r.first - 1);
    play(r.last);
  }
  function update(inspector = true) {
    restingStage();
    markEventList();
    if (inspector) renderInspector();
    syncSteps();
    updateBar();
    if (!$('#modal-bg').hidden) renderModal();
  }

  /* ═══════════════════════ Display filter (a small subset of Wireshark's language) ═══════════════════════ */
  let KNOWN = null;
  function knownFields() {
    if (KNOWN) return KNOWN;
    KNOWN = new Set(Object.keys(DATA.fieldNames));
    for (const sc of ['classic', 'hybrid']) for (const md of ['nokeys', 'keys']) for (const f of DATA[sc][md]) if (f) {
      Object.keys(f.f).forEach((k) => { KNOWN.add(k); const parts = k.split('.'); for (let i = 1; i < parts.length; i++) KNOWN.add(parts.slice(0, i).join('.')); });
      (f.f['frame.protocols'] || [''])[0].split(':').forEach((p) => KNOWN.add(p));
    }
    DATA.names.fields.forEach((n) => KNOWN.add(n));
    return KNOWN;
  }
  let PROTOS = null;
  function isKnown(name) {
    if (knownFields().has(name)) return true;
    PROTOS = PROTOS || new Set(DATA.names.protocols);
    // fields of protocols that are not in these captures: accept "proto.field" for any Wireshark protocol
    return PROTOS.has(name) || (PROTOS.has(name.split('.')[0]) && name.includes('.'));
  }
  function tokenize(s) {
    const re = /\s*(&&|\|\||==|!=|>=|<=|>|<|!|\(|\)|\{|\}|,|"(?:[^"\\]|\\.)*"|[A-Za-z0-9_.:\-\/]+)/y;
    const out = []; let m; re.lastIndex = 0;
    while (re.lastIndex < s.length) {
      if (/^\s*$/.test(s.slice(re.lastIndex))) break;
      const at = re.lastIndex;
      m = re.exec(s);
      if (!m) throw new Error(`"${s.slice(at).trim()[0]}" was unexpected in this context.`);
      out.push(m[1]);
    }
    return out;
  }
  function parseFilter(s) {
    const t = tokenize(s); let i = 0;
    const peek = () => t[i], next = () => t[i++];
    const OPS = { '==': 'eq', eq: 'eq', '!=': 'ne', ne: 'ne', '>': 'gt', gt: 'gt', '<': 'lt', lt: 'lt', '>=': 'ge', ge: 'ge', '<=': 'le', le: 'le', contains: 'contains' };
    function or() { let l = and(); while (peek() === '||' || peek() === 'or') { next(); l = { op: 'or', l, r: and() }; } return l; }
    function and() { let l = not(); while (peek() === '&&' || peek() === 'and') { next(); l = { op: 'and', l, r: not() }; } return l; }
    function not() { if (peek() === '!' || peek() === 'not') { next(); return { op: 'not', e: not() }; } return prim(); }
    function prim() {
      const tk = next();
      if (tk === undefined) throw new Error('Unexpected end of filter expression.');
      if (tk === '(') { const e = or(); if (next() !== ')') throw new Error('Missing ")".'); return e; }
      if (!/^[a-z][a-z0-9_.\-]*$/i.test(tk)) throw new Error(`"${tk}" was unexpected in this context.`);
      if (!isKnown(tk)) throw new Error(`"${tk}" is neither a field nor a protocol name.`);
      const o = peek();
      if (OPS[o]) { next(); const v = next(); if (v === undefined) throw new Error('Unexpected end of filter expression.'); return { op: OPS[o], f: tk, v: v.replace(/^"|"$/g, '') }; }
      if (o === 'in') {
        next(); if (next() !== '{') throw new Error('Expected "{" after "in".');
        const vals = [];
        while (peek() !== '}') { const v = next(); if (v === undefined) throw new Error('Missing "}".'); if (v !== ',') vals.push(v); }
        next(); return { op: 'in', f: tk, vals };
      }
      return { op: 'has', f: tk };
    }
    const e = or();
    if (i < t.length) throw new Error(`"${t[i]}" was unexpected in this context.`);
    return e;
  }
  const num = (s) => { if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16); if (/^-?\d+(\.\d+)?$/.test(s)) return parseFloat(s); if (s === 'True') return 1; if (s === 'False') return 0; return null; };
  const normStr = (s) => String(s).toLowerCase().replace(/:/g, '');
  function cmp(a, b, op) {
    const na = num(a), nb = num(b);
    if (op === 'contains') return normStr(a).includes(normStr(b));
    if (na !== null && nb !== null) return op === 'eq' ? na === nb : op === 'gt' ? na > nb : op === 'lt' ? na < nb : op === 'ge' ? na >= nb : op === 'le' ? na <= nb : false;
    const x = normStr(a), y = normStr(b);
    return op === 'eq' ? x === y : op === 'gt' ? x > y : op === 'lt' ? x < y : op === 'ge' ? x >= y : op === 'le' ? x <= y : false;
  }
  function evalFilter(e, fd) {
    const f = fd.f, protos = (f['frame.protocols'] || [''])[0].split(':');
    const vals = (name) => f[name] || [];
    switch (e.op) {
      case 'or': return evalFilter(e.l, fd) || evalFilter(e.r, fd);
      case 'and': return evalFilter(e.l, fd) && evalFilter(e.r, fd);
      case 'not': return !evalFilter(e.e, fd);
      case 'has': return protos.includes(e.f) || e.f in f || Object.keys(f).some((k) => k.startsWith(e.f + '.'));
      case 'ne': return vals(e.f).length > 0 && !vals(e.f).some((v) => cmp(v, e.v, 'eq'));
      case 'in': return vals(e.f).some((v) => e.vals.some((s) => {
        const r = s.split('..'); if (r.length === 2 && num(r[0]) !== null) { const n = num(v); return n !== null && n >= num(r[0]) && n <= num(r[1]); }
        return cmp(v, s, 'eq'); }));
      default: return vals(e.f).some((v) => cmp(v, e.v, e.op));
    }
  }
  let FILTER_AST = null;
  function applyFilter() {
    const s = $('#wsFilter').value.trim();
    const box = $('#fbox');
    box.classList.remove('ok', 'bad');
    S.filterErr = '';
    if (!s) { FILTER_AST = null; S.filter = ''; }
    else {
      try { FILTER_AST = parseFilter(s); S.filter = s; box.classList.add('ok'); }
      catch (err) { box.classList.add('bad'); S.filterErr = err.message; $('#wsField').textContent = err.message; return; }
    }
    renderInspector();
  }
  function setFilter(f) { $('#wsFilter').value = f; applyFilter(); showTab('cap'); }

  /* ═══════════════════════ Capture (Wireshark-style decode) ═══════════════════════ */
  function selectedFrame() {
    if (S.follow) return S.e >= 0 ? EV[S.e].fi : null;
    return S.sel;
  }
  function renderInspector() {
    const fi = selectedFrame();
    renderList(fi);
    renderBanner(fi);
    renderDetails(fi);
    renderStepNotes(fi);
    $('#wsTitle').textContent = nextVisible(S.e) < 0 && S.e >= 0 ? FILE[S.sc] : 'Capturing from r2-g1';
    // Guide: a pulsing dot on "Decryption keys" when the keys would reveal more of this frame
    const more = G.on && !S.keys && fi !== null && guideHitsFor(fi, true).length > guideHitsFor(fi, false).length;
    $('#keys').classList.toggle('g-attn', more);
    $('#keys').title = more ? 'Guide: load the lab keys to see what is encrypted in this frame' : 'Decrypt with the published lab keys';
  }
  function setFollow(on) {
    S.follow = on; $('#follow').setAttribute('aria-pressed', String(on));
    if (on) { S.node = null; S.src = 0; }
  }
  function renderList(fi) {
    const body = $('#plBody');
    body.innerHTML = '';
    const n = frames().length;
    let captured = 0, shown = 0;
    const frag = document.createDocumentFragment();
    for (let i = 0; i < n; i++) {
      if (CAPIDX[i] > S.e) continue;
      captured++;
      const fd = fdata(i);
      if (FILTER_AST && !evalFilter(FILTER_AST, fd)) continue;
      shown++;
      const r = fd.row;
      const tr = document.createElement('tr');
      tr.style.background = fd.bg; tr.style.color = fd.fg;
      if (i === fi) tr.className = 'sel';
      [r[0], r[1], r[2], r[3], r[4], r[5], r[6]].forEach((v, c) => {
        const td = document.createElement('td'); td.textContent = v;
        if (c === 0 || c === 5) td.className = 'r';
        tr.append(td);
      });
      tr.onclick = () => { setFollow(false); S.sel = i; S.node = null; renderInspector(); syncFrameRows(); };
      frag.append(tr);
    }
    if (!captured) {
      const tr = document.createElement('tr'); tr.className = 'empty';
      tr.innerHTML = '<td colspan="7">Waiting for packets on r2-g1 … press Step or Play.</td>'; frag.append(tr);
    }
    body.append(frag);
    const sel = body.querySelector('tr.sel');
    if (sel) { const box = $('#wsList'); if (sel.offsetTop < box.scrollTop + 22 || sel.offsetTop > box.scrollTop + box.clientHeight - 20) box.scrollTop = sel.offsetTop - box.clientHeight / 2; }
    $('#wsCount').textContent = captured ? `Packets: ${captured} · Displayed: ${shown} (${((shown / captured) * 100).toFixed(1)}%)` : 'No Packets';
    if (S.filterErr) $('#wsField').textContent = S.filterErr;
  }
  function renderBanner(fi) {
    const b = $('#banner');
    b.className = 'banner';
    if (fi === null) return;
    const m = frames()[fi];
    if (CAPIDX[fi] > S.e) {
      b.textContent = `Frame #${m.n} has not reached the capture point yet. The decode below is the copy r2-g1 will record when it gets there` +
        (m.dir === 'R3>R1' ? ', after R2 has lowered the TTL by one and rewritten the MAC addresses.' : '.');
      b.classList.add('show');
    } else if (S.e >= 0 && EV[S.e].fi === fi && EV[S.e].from === 'R2' && EV[S.e].to === 'R3') {
      b.textContent = 'This packet is now on link R2–R3, which was not captured. There its TTL is one lower and the MAC addresses differ; the decode below is the copy recorded on r2-g1.';
      b.classList.add('show');
    }
  }
  const nodeKey = (n) => n[4] || n[0].replace(/[:(\[].*$/, '');
  function renderDetails(fi) {
    const tree = $('#tree');
    tree.innerHTML = '';
    $('#hex').innerHTML = ''; $('#srcTabs').innerHTML = '';
    if (fi === null) { tree.innerHTML = '<div class="empty">No packet selected.</div>'; if (!S.filterErr) $('#wsField').textContent = ''; return; }
    const fd = fdata(fi);
    const fkey = `${S.sc}/${S.keys}/${fi}`;
    if (openFrameKey !== fkey) { openMap = new Map(); openFrameKey = fkey; }
    const rows = [];
    const walk = (nodes, depth, path) => nodes.forEach((n, idx) => {
      const p = path + '/' + idx;
      const kids = n[5];
      if (kids && !openMap.has(p)) openMap.set(p, EXPANDED.has(nodeKey(n)));
      rows.push({ n, depth, p });
      if (kids && openMap.get(p)) walk(kids, depth + 1, p);
    });
    walk(fd.tree, 0, '');
    const hits = guideHits(fi), hitAt = new Map(hits.map((h) => [h.p, h]));
    const frag = document.createDocumentFragment();
    let selRow = null;
    rows.forEach(({ n, depth, p }) => {
      const d = document.createElement('div');
      d.className = 'n' + (p === S.node ? ' sel' : '');
      d.style.paddingLeft = depth * 16 + 2 + 'px';
      d.dataset.p = p;
      const ar = document.createElement('span');
      ar.className = 'ar' + (n[5] && openMap.get(p) ? ' open' : '');
      if (n[5]) ar.innerHTML = '<i></i>';
      d.append(ar);
      const t = document.createElement('span'); t.textContent = n[0]; d.append(t);
      // Guide: important fields get the guide colour and a "?"; a closed branch hiding one gets a pulsing dot
      if (hitAt.has(p)) {
        d.classList.add('g-hit');
        const c = document.createElement('span'); c.className = 'g-chip'; c.textContent = '?'; c.title = 'Guide: what is this, and why does it matter?'; d.append(c);
      }
      let dot = null;
      if (n[5] && !openMap.get(p) && hits.some((h) => h.p.startsWith(p + '/'))) {
        dot = document.createElement('span'); dot.className = 'gdot'; dot.title = 'Guide: open this to explore what is inside'; d.append(dot);
      }
      d.onclick = (ev) => {
        if (n[5] && (ev.target === ar || ev.target.parentNode === ar || ev.target === dot)) toggle(p, n);
        else selectNode(p, n);
      };
      d.ondblclick = () => { if (n[5]) toggle(p, n); };
      frag.append(d);
      if (p === S.node) selRow = { n, d };
    });
    if (!selRow && S.nodeKey) {
      const hit = rows.find((r) => nodeKey(r.n) === S.nodeKey);
      if (hit) { S.node = hit.p; tree.innerHTML = ''; return renderDetails(fi); }
    }
    tree.append(frag);
    if (selRow && selRow.n[2] > 0 && selRow.n[3] !== S.src && openFrameKey === fkey && S.srcFor !== fkey + S.node) { S.src = selRow.n[3]; S.srcFor = fkey + S.node; }
    renderBytes(fd, selRow ? selRow.n : null);
    if (!S.filterErr) $('#wsField').textContent = selRow ? fieldStatus(selRow.n) : '';
    renderGuidePanel();
  }
  function toggle(p, n) {
    const open = !openMap.get(p);
    openMap.set(p, open);
    if (open) EXPANDED.add(nodeKey(n)); else EXPANDED.delete(nodeKey(n));
    const keep = $('#wsTree').scrollTop;
    renderDetails(selectedFrame());
    $('#wsTree').scrollTop = keep;
  }
  function selectNode(p, n) {
    S.node = p; S.nodeKey = nodeKey(n);
    if (n[2] > 0) S.src = n[3];
    document.querySelectorAll('#tree .n.sel').forEach((r) => r.classList.remove('sel'));
    const row = document.querySelector(`#tree .n[data-p="${p}"]`);
    if (row) row.classList.add('sel');
    renderBytes(fdata(selectedFrame()), n);
    if (!S.filterErr) $('#wsField').textContent = fieldStatus(n);
    G.closed = null; renderGuidePanel();
  }
  function fieldStatus(n) {
    const name = DATA.fieldNames[n[4]];
    const bytes = n[2] ? `, ${n[2]} byte(s)` : '';
    if (name) return `${name} (${n[4]})${bytes}`;
    return n[2] ? `${n[2]} byte(s)` : '';
  }
  function findNodeAt(fd, src, off) {
    let best = null, bestPath = null, bestDepth = -1;
    const walk = (nodes, depth, path) => nodes.forEach((n, idx) => {
      const p = path + '/' + idx;
      if (n[3] === src && n[2] > 0 && off >= n[1] && off < n[1] + n[2] && depth >= bestDepth) { best = n; bestPath = p; bestDepth = depth; }
      if (n[5]) walk(n[5], depth + 1, p);
    });
    walk(fd.tree, 0, '');
    return best ? { n: best, p: bestPath } : null;
  }
  function renderBytes(fd, node) {
    const srcs = fd.src;
    if (S.src >= srcs.length) S.src = 0;
    const hex = srcs[S.src][1];
    const lo = node && node[3] === S.src && node[2] > 0 ? node[1] : -1, hi = lo >= 0 ? node[1] + node[2] : -1;
    // Guide: the bytes of the highlighted fields (short fields only, so whole payloads do not flood the view)
    const gr = guideHits(selectedFrame()).filter((h) => h.n[3] === S.src && h.n[2] > 0 && h.n[2] <= 64).map((h) => [h.n[1], h.n[1] + h.n[2]]);
    const inG = (o) => gr.some(([a, b]) => o >= a && o < b);
    const out = [];
    const nb = hex.length / 2;
    for (let off = 0; off < nb; off += 16) {
      let h = '', a = '';
      for (let i = 0; i < 16; i++) {
        const o = off + i;
        if (o >= nb) { h += '   ' + (i === 7 ? ' ' : ''); continue; }
        const byte = parseInt(hex.substr(o * 2, 2), 16);
        const cls = o >= lo && o < hi ? 'b h' : inG(o) ? 'b g' : 'b';
        const ch = byte >= 32 && byte < 127 ? String.fromCharCode(byte).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]) : '.';
        h += `<span class="${cls}" data-o="${o}">${hex.substr(o * 2, 2)}</span>` + (i === 7 ? '  ' : ' ');
        a += `<span class="${cls}" data-o="${o}">${ch}</span>`;
      }
      out.push(`<span class="off">${off.toString(16).padStart(4, '0')}</span>  ${h} ${a}`);
    }
    const hx = $('#hex');
    hx.innerHTML = out.join('\n');
    hx.onclick = (ev) => {
      const o = ev.target.dataset && ev.target.dataset.o;
      if (o === undefined) return;
      const hit = findNodeAt(fd, S.src, Number(o));
      if (!hit) return;
      // open every ancestor so the field is visible
      const parts = hit.p.split('/').slice(1);
      for (let i = 1; i < parts.length; i++) openMap.set('/' + parts.slice(0, i).join('/'), true);
      S.node = hit.p; S.nodeKey = nodeKey(hit.n); S.src = hit.n[3];
      const keep = $('#wsTree').scrollTop;
      renderDetails(selectedFrame());
      $('#wsTree').scrollTop = keep;
      const row = $(`#tree .n[data-p="${hit.p}"]`); if (row) row.scrollIntoView({ block: 'nearest' });
    };
    const hl = hx.querySelector('.h'); if (hl) { const r = hl.offsetTop; if (r < hx.scrollTop || r > hx.scrollTop + hx.clientHeight - 18) hx.scrollTop = r - 36; }
    const tabs = $('#srcTabs');
    tabs.innerHTML = '';
    if (srcs.length > 1) srcs.forEach((s, i) => {
      const b = document.createElement('button');
      b.textContent = s[0]; b.className = i === S.src ? 'on' : '';
      b.onclick = () => { S.src = i; renderBytes(fd, node); };
      tabs.append(b);
    });
  }

  /* ═══════════════════════ Guide: highlighted fields, floating explanations, pulsing dots ═══════════════════════ */
  const G = { on: true, closed: null, cache: new Map() };
  try { G.on = localStorage.getItem('spq-pj-guide') !== 'off'; } catch (e) { }
  // every guided field of a frame, in tree order, with its path (the same "/i/j" paths renderDetails uses)
  function guideHitsFor(fi, keys) {
    const k = `${S.sc}/${keys}/${fi}`;
    if (G.cache.has(k)) return G.cache.get(k);
    const d = DATA[S.sc], fd = (keys && d.keys[fi]) || d.nokeys[fi], m = frames()[fi], out = [];
    const walk = (nodes, path, anc) => nodes.forEach((n, idx) => {
      const p = path + '/' + idx, ctx = { m, sc: S.sc, keys, anc };
      const r = window.JOURNEY_GUIDE.match(n, ctx);
      if (r) out.push({ p, n, r, ctx });
      if (n[5]) walk(n[5], p, anc.concat(n[0]));
    });
    walk(fd.tree, '', []);
    G.cache.set(k, out);
    return out;
  }
  const guideHits = (fi) => (G.on && fi !== null && fi !== undefined ? guideHitsFor(fi, S.keys) : []);
  const gp = document.createElement('div');
  gp.className = 'g-panel'; gp.hidden = true; gp.setAttribute('role', 'dialog'); gp.setAttribute('aria-label', 'Guide');
  document.body.appendChild(gp);
  function currentHit() {
    const fi = selectedFrame();
    if (!G.on || fi === null || !S.node) return null;
    const hits = guideHits(fi), i = hits.findIndex((h) => h.p === S.node);
    return i < 0 ? null : { hits, i, fi, key: `${S.sc}/${S.keys}/${fi}${S.node}` };
  }
  function renderGuidePanel() {
    const c = currentHit();
    if (!c || G.closed === c.key || S.tab !== 'cap') { gp.hidden = true; return; }
    const h = c.hits[c.i], t = window.JOURNEY_GUIDE.text(h.r, h.n, h.ctx);
    gp.innerHTML = `<div class="g-head"><span class="g-badge">Guide</span><b>${t.title}</b><button type="button" class="g-x" aria-label="Close the guide note" title="Close (Esc)">✕</button></div>
      <div class="g-sec"><span>What it is</span>${t.what}</div>
      <div class="g-sec"><span>Why it matters</span>${t.why}</div>
      <div class="g-nav"><button type="button" data-gstep="-1" ${c.i ? '' : 'disabled'}>‹ Previous</button><span>${c.i + 1} of ${c.hits.length} in this frame</span><button type="button" data-gstep="1" ${c.i < c.hits.length - 1 ? '' : 'disabled'}>Next ›</button></div>`;
    gp.dataset.key = c.key;
    gp.hidden = false;
    placeGuide();
  }
  // floats over the packet details, under the selected field (above it near the bottom of the window)
  function placeGuide() {
    if (gp.hidden) return;
    const row = document.querySelector(`#tree .n[data-p="${S.node}"]`), pane = $('#wsTree');
    if (!row || !pane.offsetParent) { gp.hidden = true; return; }
    const r = row.getBoundingClientRect(), P = pane.getBoundingClientRect();
    gp.style.visibility = r.bottom < P.top || r.top > P.bottom ? 'hidden' : '';
    const w = gp.offsetWidth, h = gp.offsetHeight;
    const left = Math.max(8, Math.max(P.left + 8, Math.min(P.right - w - 12, innerWidth - w - 8)));
    // below the field, else above it; always inside the Wireshark window (it sits on the right, clear of the field names)
    const W = $('#ws').getBoundingClientRect(), lo = Math.max(8, W.top + 4), hi = Math.min(innerHeight, W.bottom) - h - 4;
    let top = r.bottom + 6;
    if (top > hi) top = r.top - h - 6;
    gp.style.left = left + 'px'; gp.style.top = Math.max(lo, Math.min(top, Math.max(lo, hi))) + 'px';
  }
  function closeGuide() { G.closed = gp.dataset.key; gp.hidden = true; }
  function goToHit(i) {
    const fi = selectedFrame(), hits = guideHits(fi), h = hits[i];
    if (!h) return;
    const parts = h.p.split('/').slice(1);
    for (let k = 1; k < parts.length; k++) openMap.set('/' + parts.slice(0, k).join('/'), true);
    S.node = h.p; S.nodeKey = nodeKey(h.n); if (h.n[2] > 0) S.src = h.n[3];
    G.closed = null;
    renderDetails(fi);
    const row = document.querySelector(`#tree .n[data-p="${h.p}"]`), pane = $('#wsTree');
    if (row) { const rt = row.offsetTop - pane.offsetTop; if (rt < pane.scrollTop || rt > pane.scrollTop + pane.clientHeight - 20) pane.scrollTop = rt - 30; }
    placeGuide();
  }
  gp.addEventListener('click', (e) => {
    if (e.target.closest('.g-x')) return closeGuide();
    const s = e.target.closest('[data-gstep]'); if (s) { const c = currentHit(); if (c) goToHit(c.i + Number(s.dataset.gstep)); }
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !gp.hidden && !e.target.closest('.ink-editor')) closeGuide(); });
  $('#wsTree').addEventListener('scroll', placeGuide);
  $('#t-cap').addEventListener('scroll', placeGuide);
  window.addEventListener('resize', placeGuide);
  function setGuide(on) {
    G.on = on; G.closed = null;
    try { localStorage.setItem('spq-pj-guide', on ? 'on' : 'off'); } catch (e) { }
    $('#guide').setAttribute('aria-pressed', String(on));
    document.body.classList.toggle('guide-on', on);
    renderInspector();
  }
  $('#guide').addEventListener('click', () => setGuide(!G.on));
  $('#guide').setAttribute('aria-pressed', String(G.on));
  document.body.classList.toggle('guide-on', G.on);

  /* ═══════════════════════ Packet notes (inside the phase's step) ═══════════════════════ */
  function anatomy(fi) {
    const fd = DATA[S.sc].nokeys[fi], m = frames()[fi];
    const segs = [];
    for (const n of fd.tree) {
      if (n[3] !== 0 || !n[2] || n[0].startsWith('Frame ')) continue;
      const l = n[0];
      if (l.startsWith('Ethernet')) segs.push(['Ethernet', n[2], 'hdr']);
      else if (l.startsWith('Internet Protocol')) segs.push(['IPv4', n[2], 'hdr']);
      else if (l.startsWith('User Datagram')) segs.push(['UDP ' + (fd.f['udp.srcport'] || [''])[0], n[2], 'hdr']);
      else if (l.startsWith('UDP Encapsulation')) segs.push(['non-ESP', n[2], 'hdr']);
      else if (l.startsWith('Address Resolution')) segs.push(['ARP', n[2], 'arp']);
      else if (l.startsWith('Internet Security')) {
        segs.push(['IKE hdr', 28, 'hdr']);
        const rest = n[2] - 28;
        if (m.kind === 'IKE_SA_INIT') segs.push(['SA · KE · Nonce · Notify (clear)', rest, 'clear']);
        else if (m.kind === 'IKE_INTERMEDIATE' || m.kind === 'IKE_FOLLOWUP_KE') segs.push([m.label.includes('ct') ? 'encrypted · ML-KEM ciphertext' : 'encrypted · ML-KEM key part', rest, 'pqc']);
        else segs.push(['encrypted payloads', rest, 'enc']);
      } else if (l.startsWith('Encapsulating Security')) {
        segs.push(['SPI·seq', 8, 'hdr']); segs.push(['IV', 8, 'hdr']);
        segs.push(['encrypted ping', n[2] - 32, 'enc']); segs.push(['ICV', 16, 'hdr']);
      }
    }
    const bar = segs.map(([t, b, c]) => `<div class="seg ${c}" style="flex:${Math.max(b, 1)} 1 0" title="${t}: ${b} bytes">${b >= 40 || segs.length < 4 ? t : ''}</div>`).join('');
    const legend = segs.filter(([, b]) => b < 40 && segs.length >= 4).map(([t, b]) => `${t} ${b}`).join(' · ');
    return `<div class="anat"><div class="lab">On the wire · ${fmt(m.len)} bytes</div><div class="bar">${bar}</div>` +
      (legend ? `<div class="key" style="font-family:var(--font-mono)">${legend} bytes</div>` : '') +
      `<div class="key"><span style="--k:var(--tint);">headers an observer reads</span>${segs.some((s) => s[2] === 'enc' || s[2] === 'pqc') ? '<span style="--k:var(--ink)">encrypted</span>' : ''}${segs.some((s) => s[2] === 'pqc') ? '<span style="--k:var(--pqc)">post-quantum material</span>' : ''}${segs.some((s) => s[2] === 'clear') ? '<span style="--k:var(--ike)">readable by anyone</span>' : ''}</div></div>`;
  }
  function noteHtml(fi) {
    const m = frames()[fi], d = DATA[S.sc].nokeys[fi];
    const facts = m.facts.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('');
    const refs = m.refs.map((r) => `<a href="${META.rfc[r].u}" target="_blank" rel="noopener">${META.rfc[r].t}</a>`).join('');
    return `<span class="nlabel">This packet</span>` +
      `<div class="kicker"><span class="kind" style="background:${cvar(m.kind)}">${m.kind}</span>Frame #${m.n} · ${d.row[1]} s · ${m.dir.replace('>', ' → ')}</div>` +
      `<h5>${m.title}</h5><p>${m.text}</p>${anatomy(fi)}<dl class="facts">${facts}</dl><div class="refs">${refs}</div>` + guideInvite(fi);
  }
  function guideInvite(fi) {
    const n = guideHits(fi).length;
    return n ? `<button type="button" class="btn ghost g-explore" data-guide-explore><span class="gdot" aria-hidden="true"></span>Guide: explore ${n} highlighted field${n > 1 ? 's' : ''} in the capture</button>` : '';
  }
  const IDLE_NOTE = '<span class="nlabel">This packet</span>Step through this phase: each packet is explained here, with its size on the wire and the RFCs behind it.';
  function renderStepNotes(fi) {
    const pi = fi === null ? -1 : frames()[fi].phase;
    STEPS.forEach((s, i) => {
      if (s.pi === undefined) return;
      const box = $('#note-' + i); if (!box) return;
      const key = s.pi === pi ? `${S.sc}/${fi}/${G.on}/${S.keys}` : 'idle';
      if (box.dataset.key === key) return;
      box.dataset.key = key;
      box.classList.toggle('idle', key === 'idle');
      box.innerHTML = key === 'idle' ? IDLE_NOTE : noteHtml(fi);
    });
  }

  /* ═══════════════════════ Tutorial steps ═══════════════════════ */
  let STEPS = [], cur = -1;
  const P = () => PROG[S.sc];
  function stepCtx() {
    const M = META[S.sc], O = META[S.sc === 'hybrid' ? 'classic' : 'hybrid'];
    const bytesIn = (mm, name) => { const pi = mm.phases.findIndex((p) => p.name === name); return pi < 0 ? 0 : mm.frames.filter((f) => f.phase === pi).reduce((a, f) => a + f.len, 0); };
    return { M, bytes: (n) => bytesIn(M, n), otherBytes: (n) => bytesIn(O, n), setup: (sc) => META[sc].setupBytes, rtt: (sc) => META[sc].setupRtt };
  }
  function renderSteps() {
    const ol = $('#steps');
    ol.querySelectorAll(':scope > li').forEach((li) => li.remove());
    const ctx = stepCtx();
    STEPS = [{ def: J.INTRO }].concat(meta().phases.map((p, pi) => ({ def: J.PHASES[p.name] || { title: p.name, part: 'ike', html: () => '' }, pi, name: p.name })));
    const before = ol.querySelector('.ink-layer');
    STEPS.forEach((s, i) => {
      const d = s.def, [tagTxt, tagCls] = J.PART[d.part] || ['', ''];
      const li = document.createElement('li'); li.className = 'step'; li.id = 'step-' + i; li.dataset.status = 'locked';
      let body = d.goal ? `<div class="goal"><span class="goal-label">Goal</span>${d.goal}</div>` : '';
      body += d.html(S.sc, ctx);
      if (s.pi !== undefined) {
        const r = phaseRange(s.pi);
        body += `<table class="t frames"><thead><tr><th class="num">#</th><th>Path</th><th class="num">Bytes</th><th>Message</th></tr></thead><tbody>` +
          r.frames.map((fi) => { const m = frames()[fi]; return `<tr data-fi="${fi}"><td class="num">${m.n}</td><td class="dir">${m.dir.replace('>', ' → ')}</td><td class="num">${fmt(m.len)}</td><td>${esc(m.title)}</td></tr>`; }).join('') +
          `</tbody></table><p class="step-sum">${r.frames.length} frame${r.frames.length > 1 ? 's' : ''} · ${fmt(r.frames.reduce((a, fi) => a + frames()[fi].len, 0))} bytes on r2-g1 · click a frame to jump to it</p>` +
          `<div class="pkt-note idle" id="note-${i}" data-key="idle" aria-live="polite">${IDLE_NOTE}</div>`;
        if (d.after) body += d.after(S.sc, ctx);
      }
      li.innerHTML = `
        <button class="step-head" aria-expanded="false" aria-controls="step-body-${i}">
          <span class="step-num"><span>${i + 1}</span></span><span class="step-title">${esc(d.title)}</span>${tagTxt ? `<span class="tag ${tagCls}">${tagTxt}</span>` : ''}
        </button>
        <div class="step-body" id="step-body-${i}">${body}
          <div class="step-actions">
            ${s.pi === undefined ? '<button class="btn" data-continue>Start the journey</button>' : `<button class="btn success" data-play="${s.pi}">▶ Play this phase</button>`}
            <span class="step-done">✓ Step complete</span>
          </div>
        </div>`;
      li.querySelector('.step-head').addEventListener('click', () => toggleStep(i));
      ol.insertBefore(li, before);
    });
    const fin = document.createElement('li'); fin.className = 'finish'; fin.id = 'finish'; ol.insertBefore(fin, before);
    buildStepNav();
    cur = -1;
    syncSteps(true);
    if (P().finished) renderFinish(false);
  }
  $('#steps').addEventListener('click', (e) => {
    const fc = e.target.closest('.fchip'); if (fc) return setFilter(fc.dataset.f);
    if (e.target.closest('[data-guide-explore]')) { showTab('cap'); return goToHit(0); }
    const sc = e.target.closest('[data-sc]'); if (sc) return setScenario(sc.dataset.sc);
    const pl = e.target.closest('[data-play]'); if (pl) return playPhase(+pl.dataset.play);
    if (e.target.closest('[data-continue]')) { P().intro = true; syncSteps(); return; }
    if (e.target.closest('[data-replay]')) { stop(); jump(-1); activate(1); return; }
    const row = e.target.closest('.t.frames tbody tr');
    if (row) { stop(); setFollow(true); jump(CAPIDX[+row.dataset.fi]); }
  });
  function buildStepNav() {
    const old = $('#step-nav'); if (old) old.remove();
    const nav = document.createElement('ol'); nav.className = 'step-nav'; nav.id = 'step-nav'; nav.setAttribute('aria-label', 'Steps');
    STEPS.forEach((s, i) => {
      const li = document.createElement('li'); const b = document.createElement('button');
      b.type = 'button'; b.textContent = i + 1; b.setAttribute('aria-label', `Step ${i + 1}: ${s.def.title}`); b.dataset.status = 'locked';
      b.addEventListener('click', () => { toggleStep(i, true); $('#step-' + i).scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' }); });
      // collapsed pane: a double click plays that phase
      b.addEventListener('dblclick', () => { if (!collapsed()) return; if (s.pi !== undefined) playPhase(s.pi); else { P().intro = true; syncSteps(); } });
      li.appendChild(b); nav.appendChild(li);
    });
    const head = $('.tut-head'), tg = $('#tut-collapse');
    head.insertBefore(nav, tg || null);
    if (!tg) {
      const t = document.createElement('button');
      t.type = 'button'; t.className = 'tut-collapse'; t.id = 'tut-collapse';
      t.addEventListener('click', () => setCollapsed(!collapsed(), true));
      head.appendChild(t);
      let saved = false; try { saved = localStorage.getItem('spq-tut-collapsed') === '1'; } catch (e) { }
      setCollapsed(saved, false);
    } else setCollapsed(collapsed(), false);
  }
  const collapsed = () => $('#tutorial').classList.contains('collapsed');
  function setCollapsed(on, save) {
    $('#tutorial').classList.toggle('collapsed', on);
    const tg = $('#tut-collapse'), lbl = on ? 'Expand the instructions' : 'Collapse the instructions to the step numbers';
    tg.textContent = on ? '»' : '«'; tg.title = lbl; tg.setAttribute('aria-label', lbl); tg.setAttribute('aria-expanded', String(!on));
    document.querySelectorAll('#step-nav button').forEach((b, i) => {
      const s = STEPS[i]; b.title = on ? `${i + 1}. ${s.def.title} · double-click: ${s.pi !== undefined ? 'play this phase' : 'start'}` : `${i + 1}. ${s.def.title}`;
    });
    if (save) try { localStorage.setItem('spq-tut-collapsed', on ? '1' : '0'); } catch (e) { }
  }
  function toggleStep(i, force) {
    const li = $('#step-' + i); if (!li) return;
    const open = force !== undefined ? force : !li.classList.contains('open');
    li.classList.toggle('open', open); li.querySelector('.step-head').setAttribute('aria-expanded', String(open));
  }
  const stepDone = (i) => (STEPS[i].pi === undefined ? P().intro : P().done.has(STEPS[i].name));
  function activate(i, scroll = true) {
    cur = i;
    STEPS.forEach((_, j) => { $('#step-' + j).dataset.status = stepDone(j) ? 'done' : j === i ? 'active' : 'locked'; toggleStep(j, j === i); });
    const li = $('#step-' + i);
    if (li && scroll) li.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
    updateProgress();
  }
  // progress follows the replay: a phase is complete once its last packet has arrived
  function syncSteps(force) {
    const pr = P();
    if (S.e >= 0) pr.intro = true;
    meta().phases.forEach((p, pi) => { if (S.e >= 0 && S.e >= phaseRange(pi).last) pr.done.add(p.name); });
    const pi = S.e >= 0 ? frames()[EV[S.e].fi].phase : -1;
    const want = pi >= 0 ? pi + 1 : pr.intro ? 1 : 0;
    if (want !== cur || force) activate(want, !force || want > 0);
    else STEPS.forEach((_, j) => { $('#step-' + j).dataset.status = stepDone(j) ? 'done' : j === cur ? 'active' : 'locked'; });
    updateProgress();
    syncFrameRows();
    if (!pr.finished && pr.done.size === meta().phases.length) { pr.finished = true; renderFinish(true); }
  }
  function syncFrameRows() {
    const fi = selectedFrame();
    document.querySelectorAll('.t.frames tbody tr').forEach((tr) => {
      const f = +tr.dataset.fi;
      tr.className = (f === fi ? 'cur' : '') + (CAPIDX[f] > S.e ? ' ahead' : '');
    });
  }
  function updateProgress() {
    document.querySelectorAll('#step-nav button').forEach((b, i) => { b.dataset.status = stepDone(i) ? 'done' : i === cur ? 'active' : 'locked'; b.setAttribute('aria-current', String(i === cur)); });
    const n = STEPS.filter((_, i) => stepDone(i)).length, tot = STEPS.length;
    $('#nav-progress').textContent = `${n} / ${tot}`;
    $('#progress-fill').style.width = (n / tot * 100) + '%';
  }
  function renderFinish(scroll) {
    const el = $('#finish'); if (!el) return;
    const C = META.classic, H = META.hybrid;
    const ph = (mm, name) => { const pi = mm.phases.findIndex((p) => p.name === name); return mm.frames.filter((f) => f.phase === pi).reduce((a, f) => a + f.len, 0); };
    const big = (mm) => Math.max(...mm.frames.map((f) => f.len));
    const other = S.sc === 'hybrid' ? 'classic' : 'hybrid';
    el.innerHTML = `<h3>🎉 Journey complete: the ${SCN[S.sc].name} capture</h3>
      <p>Both captures side by side. The post-quantum cost is paid when SAs are created and rekeyed; the traffic itself costs the same.</p>
      <table class="t"><tr><th></th><th>Classical</th><th>Hybrid PQC</th></tr>
        <tr><td>SA setup</td><td>${fmt(C.setupBytes)} B · ${C.setupRtt} round trips</td><td>${fmt(H.setupBytes)} B · ${H.setupRtt} round trips</td></tr>
        <tr><td>Largest frame</td><td>${fmt(big(C))} B</td><td>${fmt(big(H))} B (IKE-fragmented)</td></tr>
        <tr><td>ESP packet</td><td>162 B</td><td>162 B</td></tr>
        <tr><td>CHILD SA rekey</td><td>${fmt(ph(C, 'CHILD SA rekey'))} B</td><td>${fmt(ph(H, 'CHILD SA rekey'))} B</td></tr>
        <tr><td>IKE SA rekey</td><td>${fmt(ph(C, 'IKE SA rekey'))} B</td><td>${fmt(ph(H, 'IKE SA rekey'))} B</td></tr>
        <tr><td>Recorded today, broken by a quantum computer later?</td><td><b>Exposed</b>: X25519 only</td><td><b>Protected</b>: X25519 + ML-KEM-768</td></tr></table>
      <div class="step-actions"><button class="btn" data-sc="${other}">Follow the ${SCN[other].name} capture</button><button class="btn ghost" data-replay>Replay from the start</button></div>`;
    el.classList.add('show');
    if (scroll) setTimeout(() => el.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'nearest' }), 300);
  }

  /* ═══════════════════════ Scenario ═══════════════════════ */
  function setScenario(sc) {
    if (sc !== 'classic' && sc !== 'hybrid') return;
    stop();
    const curPhase = S.e >= 0 ? meta().phases[frames()[EV[S.e].fi].phase].name : null;
    const same = sc === S.sc;
    S.sc = sc;
    document.body.classList.toggle('hybrid', sc === 'hybrid');
    document.querySelectorAll('[data-sc][role="radio"]').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.sc === sc)));
    $('#nav-badge').textContent = SCN[sc].badge;
    document.title = `IKEv2 Packet Journey · ${SCN[sc].badge}`;
    if (same) return;
    const u = new URL(location.href); u.searchParams.set('track', sc); history.replaceState(null, '', u);
    buildEvents();
    S.node = null; S.nodeKey = null; S.src = 0; S.sel = null; setFollow(true); tunSig = '';
    renderEventList();
    let target = -1;
    if (curPhase) {
      const pi = meta().phases.findIndex((p) => p.name === curPhase);
      if (pi >= 0) target = phaseRange(pi).first;
    }
    S.e = target;
    renderSteps();
    update(true);
  }

  /* ═══════════════════════ Tunnel inspector (modal) ═══════════════════════ */
  function openModal() { $('#modal-bg').hidden = false; seqNow = null; $('#modal-body').scrollTop = 0; renderModal(); $('#modal-close').focus(); }
  function closeModal() { $('#modal-bg').hidden = true; }
  function renderModal() {
    const st = derive(S.e), v = tunnelView(st), hyb = S.sc === 'hybrid', m = meta();
    $('#modal-title').textContent = 'IKE SA R1 (198.51.100.1) ⇄ R3 (203.0.113.2)';
    const chip = !v ? 'NO SA YET' : v.st === 'UP' ? (hyb ? 'UP · ML-KEM' : 'UP · CLASSICAL') : 'NEGOTIATING';
    const keys = !st.ike ? '—' : st.ike === 'hybrid' ? 'X25519 + ML-KEM-768 (RFC 9370)' : st.ike === 'x25519-pending' ? 'X25519 · ML-KEM-768 round pending' : 'X25519';
    let h = `<p><span class="status-chip">${chip}</span></p><dl class="kv">
      <dt>Capture</dt><dd>${FILE[S.sc]}</dd>
      <dt>Initiator → responder</dt><dd>R1 → R3 (R2 is transit)</dd>
      <dt>IKE SA</dt><dd>AES-GCM-256 · PRF HMAC-SHA2-384 · X25519${hyb ? ' + ADDKE1 ML-KEM-768' : ''}</dd>
      <dt>Keys from</dt><dd>${keys}</dd>
      <dt>Child SA (ESP)</dt><dd>${st.child ? `AES-GCM-256 · SPIs ${st.childSpis[0]} / ${st.childSpis[1]}` : 'not yet'}</dd>
      <dt>Setup so far</dt><dd>${fmt(st.setupB)} of ${fmt(m.setupBytes)} B · ${st.rtt} of ${m.setupRtt} round trips</dd>
      <dt>Rekeys</dt><dd>CHILD SA ${st.rekeyChild ? '✓' : '—'} · IKE SA ${st.rekeyIke ? '✓' : '—'}</dd></dl>`;
    h += '<h4>IKEv2 exchange</h4>' + sequenceDiagram();
    h += `<div class="verdict">
      <div><b>Key exchange</b><br>${hyb ? '<span class="ok">✓ Hybrid X25519 + ML-KEM-768</span>' : '<span class="no">✗ X25519 only: exposed to "record now, decrypt later"</span>'}</div>
      <div><b>Data plane</b><br><span class="ok">✓ AES-GCM-256: ample margin against Grover</span></div></div>`;
    const body = $('#modal-body'), keep = body.scrollTop;
    body.innerHTML = h;
    body.scrollTop = keep;
    // keep the current message in view as the replay moves on
    const now = body.querySelector('.seq-row.now');
    if (now && seqNow !== now.dataset.fi) {
      seqNow = now.dataset.fi;
      const b = body.getBoundingClientRect(), r = now.getBoundingClientRect();
      if (r.top < b.top + 20 || r.bottom > b.bottom - 20) body.scrollTop += r.top - b.top - b.height / 2;
    }
  }
  let seqNow = null;
  /* the whole exchange as a sequence diagram: R1 (initiator) and R3 (responder) as two lifelines, one arrow per
     message from sender to receiver, a brace per phase; ESP runs folded into one two-way arrow; the current
     message marked "now", messages not sent yet faded */
  function sequenceDiagram() {
    const fr = frames(), ph = meta().phases, curFi = S.e >= 0 ? EV[S.e].fi : -1;
    const PHN = { 'IKE_INTERMEDIATE · ML-KEM': 'ML-KEM round', 'ESP traffic': 'Traffic', 'ESP on new SAs': 'Traffic, new SAs' };
    const rows = [];
    fr.forEach((f, i) => {
      if (f.kind === 'ARP') return;
      const last = rows[rows.length - 1];
      if (f.kind === 'ESP' && last && last.esp && last.phase === f.phase) { last.fis.push(i); return; }
      rows.push({ f, fis: [i], esp: f.kind === 'ESP', phase: f.phase });
    });
    const sent = (i) => LASTIDX[i] <= S.e;
    const W = 770, XL = 200, XR = 680, MID = (XL + XR) / 2, RH = 32, GAP = 12, TOP = 88;
    let y = TOP, svg = '', braces = '';
    const groups = [];
    rows.forEach((r, k) => {
      if (k && rows[k - 1].phase !== r.phase) y += GAP;
      r.y = y; y += RH;
      const g = groups[groups.length - 1];
      if (g && g.phase === r.phase) g.rows.push(r); else groups.push({ phase: r.phase, rows: [r] });
    });
    const H = y + 34;
    const arrowDefs = Object.keys(KCOL).map((k) => `<marker id="sq-${k}" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M1 1L9 5L1 9z" style="fill:${cvar(k)}"/></marker>`).join('');
    for (const r of rows) {
      const f = r.f, nSent = r.fis.filter(sent).length, isNow = r.fis.includes(curFi);
      const state = isNow ? 'now' : nSent === r.fis.length ? 'sent' : 'ahead';
      const pq = f.kind === 'IKE_INTERMEDIATE' || f.kind === 'IKE_FOLLOWUP_KE';
      const label = r.esp
        ? `ESP · ${nSent && nSent < r.fis.length ? `${nSent} of ${r.fis.length}` : r.fis.length} packets, both directions · 162 B each`
        : `${f.title.replace(/ML-KEM for the (CHILD|IKE) SA rekey, /, 'ML-KEM key, ')} · ${fmt(f.len)} B`;
      const ay = r.y + 10, ltr = f.dir === 'R1>R3';
      const x1 = r.esp ? XL + 3 : ltr ? XL + 2 : XR - 2, x2 = r.esp ? XR - 3 : ltr ? XR - 3 : XL + 3;
      const w = pq ? 3 : r.esp ? 2 : 1.6;
      svg += `<g class="seq-row ${state}" data-fi="${r.fis[r.esp && state !== 'ahead' ? Math.max(0, nSent - 1) : 0]}" role="button" tabindex="0" aria-label="${esc(label)}${state === 'ahead' ? ' (not sent yet)' : ''}: jump to it">
        <rect class="seq-hit" x="${XL}" y="${r.y - 12}" width="${XR - XL}" height="${RH}"/>
        <text class="seq-lbl" x="${MID}" y="${r.y + 1}" text-anchor="middle">${esc(label)}</text>
        <line x1="${x1}" y1="${ay}" x2="${x2}" y2="${ay}" style="stroke:${cvar(f.kind)};stroke-width:${w}" ${r.esp ? `stroke-dasharray="7 4" marker-start="url(#sq-ESP)"` : ''} marker-end="url(#sq-${f.kind})"/>
        ${isNow ? `<rect class="seq-now" x="${XR + 8}" y="${ay - 11}" width="46" height="22" rx="11"/><text class="seq-now-t" x="${XR + 31}" y="${ay + 4}" text-anchor="middle">now</text>` : ''}
      </g>`;
    }
    for (const g of groups) {
      const y1 = g.rows[0].y - 12, y2 = g.rows[g.rows.length - 1].y + RH - 14, m = (y1 + y2) / 2, half = Math.max(0, (y2 - y1) / 2 - 12);
      const ahead = g.rows.every((r) => !r.fis.some(sent) && !r.fis.includes(curFi));
      braces += `<g class="seq-brace${ahead ? ' ahead' : ''}"><path d="M${XL - 26} ${y1} q-8 0 -8 8 v${half} q0 4 -6 4 q6 0 6 4 v${half} q0 8 8 8"/>` +
        `<text x="${XL - 46}" y="${m + 4}" text-anchor="end">${esc(PHN[ph[g.phase].name] || ph[g.phase].name)}</text></g>`;
    }
    const box = (x, a, b) => `<rect class="seq-end" x="${x - 75}" y="8" width="150" height="50" rx="8"/><text class="seq-end-t" x="${x}" y="29" text-anchor="middle">${a}</text><text class="seq-end-s" x="${x}" y="47" text-anchor="middle">${b}</text>`;
    return `<svg class="seq" viewBox="0 0 ${W} ${H}" role="img" aria-label="IKEv2 exchange between R1, the initiator, and R3, the responder">
      <defs>${arrowDefs}</defs>
      ${box(XL, 'R1 · initiator', '198.51.100.1')}${box(XR, 'R3 · responder', '203.0.113.2')}
      <line class="seq-life" x1="${XL}" y1="58" x2="${XL}" y2="${H - 26}"/><line class="seq-life" x1="${XR}" y1="58" x2="${XR}" y2="${H - 26}"/>
      ${braces}${svg}
      <text class="seq-key" x="${MID}" y="${H - 6}" text-anchor="middle">Gray: classical IKE · blue, thick: ML-KEM · green, dashed: ESP · faded: not sent yet · click a message to jump to it</text>
    </svg>`;
  }
  $('#modal-body').addEventListener('click', (e) => {
    const r = e.target.closest('.seq-row'); if (!r) return;
    stop(); setFollow(true); jump(CAPIDX[+r.dataset.fi]);
  });
  $('#modal-body').addEventListener('keydown', (e) => {
    const r = e.target.closest && e.target.closest('.seq-row');
    if (r && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); e.stopPropagation(); stop(); setFollow(true); jump(CAPIDX[+r.dataset.fi]); }
  });
  $('#modal-close').addEventListener('click', closeModal);
  $('#modal-bg').addEventListener('click', (e) => { if (e.target.id === 'modal-bg') closeModal(); });

  /* ═══════════════════════ Console tabs ═══════════════════════ */
  function showTab(t) {
    S.tab = t;
    for (const k of ['cap', 'ev']) {
      $('#tab-' + k).setAttribute('aria-selected', String(k === t));
      $('#t-' + k).classList.toggle('active', k === t);
      $('#tools-' + k).hidden = k !== t;
    }
    if (t === 'cap') $('#tab-cap').classList.remove('has-unread');
    if (t === 'ev') markEventList(true);
    renderInk();
    renderGuidePanel();
  }
  $('#tab-cap').addEventListener('click', () => showTab('cap'));
  $('#tab-ev').addEventListener('click', () => showTab('ev'));
  $('#keys').addEventListener('click', () => { S.keys = !S.keys; $('#keys').setAttribute('aria-pressed', String(S.keys)); S.node = null; S.src = 0; renderInspector(); });
  $('#follow').addEventListener('click', () => { setFollow(!S.follow); renderInspector(); syncFrameRows(); });
  $('#tools-ev').addEventListener('click', (e) => {
    const b = e.target.closest('[data-g]'); if (!b) return;
    const g = b.dataset.g; S.show[g] = !S.show[g];
    if (!Object.values(S.show).some(Boolean)) S.show[g] = true;
    b.setAttribute('aria-pressed', String(S.show[g]));
    markEventList(false);
  });
  $('#wsFilter').addEventListener('keydown', (e) => { if (e.key === 'Enter') applyFilter(); });
  $('#wsFilter').addEventListener('input', () => {
    const s = $('#wsFilter').value.trim(), box = $('#fbox');
    box.classList.remove('ok', 'bad');
    if (!s) return;
    try { parseFilter(s); box.classList.add('ok'); } catch (err) { box.classList.add('bad'); }
  });
  $('#fApply').onclick = applyFilter;
  ['isakmp', 'isakmp.exchangetype == 43', 'esp', 'frame.len > 1000', '!arp', ''].forEach((f) => {
    const b = document.createElement('button'); b.type = 'button'; b.className = 'fchip'; b.dataset.f = f; b.textContent = f || 'clear';
    if (f === 'isakmp.exchangetype == 43') b.dataset.only = 'hybrid';
    $('#fchips').appendChild(b);
  });
  $('#fchips').addEventListener('click', (e) => { const b = e.target.closest('.fchip'); if (b) setFilter(b.dataset.f); });
  $('#wsTree').addEventListener('keydown', (e) => {
    const rows = [...document.querySelectorAll('#tree .n')];
    if (!rows.length) return;
    let i = rows.findIndex((r) => r.classList.contains('sel'));
    const fd = fdata(selectedFrame());
    const nodeAt = (p) => { let arr = fd.tree, n = null; for (const idx of p.split('/').slice(1)) { n = arr[Number(idx)]; arr = n[5] || []; } return n; };
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      i = Math.max(0, Math.min(rows.length - 1, i + (e.key === 'ArrowDown' ? 1 : -1)));
      const p = rows[i].dataset.p; selectNode(p, nodeAt(p));
      const r = $(`#tree .n[data-p="${p}"]`); if (r) r.scrollIntoView({ block: 'nearest' });
    } else if ((e.key === 'ArrowRight' || e.key === 'ArrowLeft') && i >= 0) {
      e.preventDefault();
      const p = rows[i].dataset.p, n = nodeAt(p);
      if (n[5] && (e.key === 'ArrowRight') !== !!openMap.get(p)) toggle(p, n);
    }
  });

  /* ═══════════════════════ Text size (A A A) ═══════════════════════ */
  const FS = { s: 1, m: 1.15, l: 1.3 };
  function setFont(k, save) {
    if (!FS[k]) k = 's';
    document.documentElement.style.setProperty('--fs', FS[k]);
    document.querySelectorAll('.fs-btn').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.fs === k)));
    if (save) try { localStorage.setItem('spq-fs', k); } catch (e) { }
    tunSig = ''; if (gTun) restingStage();
    renderInk();
  }
  document.querySelectorAll('.fs-btn').forEach((b) => b.addEventListener('click', () => setFont(b.dataset.fs, true)));

  /* ═══════════════════════ Whiteboard and zoom (as in the labs) ═══════════════════════ */
  const INK = [['ink', 'Black', 'var(--ink)'], ['blue', 'Blue', '#0a60ff'], ['red', 'Red', 'var(--danger)']];
  const ink = { color: 'ink', tool: 'pen', strokes: [], hist: [], cur: null, start: null, drew: false, layer: null, all: false };
  let gInk = null, inkReady = false;
  function svgPoint(e) { const p = svg.createSVGPoint(); p.x = e.clientX; p.y = e.clientY; const m = svg.getScreenCTM(); return m ? p.matrixTransform(m.inverse()) : p; }
  const inkD = (pts) => pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
  const LAYERS = {};
  LAYERS.topo = { id: 'topo', get svg() { return svg; }, get g() { if (!gInk || !gInk.isConnected) gInk = el('g', { id: 'g-ink' }, svg); return gInk; },
    host: () => $('#topo-wrap'), point: (e) => svgPoint(e), perPx: () => { const m = svg.getScreenCTM(); return m ? 1 / m.a : 1; },
    editorAt: (e) => { const r = $('#topo-wrap').getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; }, edScale: () => 1 };
  function overlayLayer(id, hostEl) {
    const o = document.createElementNS(SVGNS, 'svg'); o.setAttribute('class', 'ink-layer'); hostEl.appendChild(o);
    const scale = () => { const r = o.getBoundingClientRect(), w = parseFloat(o.getAttribute('width')) || 1; return r.width / w || 1; };
    const L = { id, svg: o, g: o, host: () => hostEl,
      fit() { if (!hostEl.clientWidth) return; o.setAttribute('width', 0); o.setAttribute('height', 0); o.setAttribute('width', Math.max(hostEl.scrollWidth, hostEl.clientWidth)); o.setAttribute('height', Math.max(hostEl.scrollHeight, hostEl.clientHeight)); },
      point(e) { L.fit(); const r = o.getBoundingClientRect(), k = scale(); return { x: (e.clientX - r.left) / k, y: (e.clientY - r.top) / k }; },
      perPx: () => 1 / scale(), editorAt: (e, p) => [p.x, p.y], edScale: () => scale() };
    L.fit(); LAYERS[id] = L; bindInk(L); return L;
  }
  const inkAdd = (item) => { ink.strokes.push(item); ink.hist.push({ op: 'add', item }); };
  function inkUndo() {
    const h = ink.hist.pop(); if (!h) return;
    if (h.op === 'add') { const i = ink.strokes.indexOf(h.item); if (i >= 0) ink.strokes.splice(i, 1); }
    else if (h.op === 'erase') for (const { item, index } of [...h.items].reverse()) ink.strokes.splice(index, 0, item);
    else if (h.op === 'clear') ink.strokes = h.items.slice();
    renderInk();
  }
  function renderInk() {
    if (!inkReady) return;
    for (const L of Object.values(LAYERS)) {
      if (L.id === 'topo') svg.appendChild(L.g); else L.fit();
      L.g.innerHTML = '';
    }
    for (const st of ink.strokes) {
      const L = LAYERS[st.layer || 'topo']; if (!L) continue;
      const col = INK.find((c) => c[0] === st.color)[2];
      if (st.type === 'text') {
        const t = el('text', { class: 'ink-text', x: st.x, y: st.y, fill: col, style: `font-size:${st.size}px` }, L.g);
        st.lines.forEach((ln, i) => { const sp = el('tspan', { x: st.x, dy: i ? '1.25em' : 0 }, t); sp.textContent = ln || ' '; });
      } else el('path', { class: 'ink-stroke', d: inkD(st.pts), stroke: col, style: `stroke-width:${st.w || 3.5}` }, L.g);
    }
    document.querySelectorAll('[data-act="undo"]').forEach((u) => { u.disabled = !ink.hist.length; });
    document.querySelectorAll('[data-act="clear"]').forEach((c) => { c.hidden = !ink.strokes.length; });
  }
  function eraseAt(L, p) {
    const r = 10 * L.perPx(), d2 = (ax, ay, bx, by) => { const dx = bx - ax, dy = by - ay, Q = dx * dx + dy * dy, t = Q ? Math.max(0, Math.min(1, ((p.x - ax) * dx + (p.y - ay) * dy) / Q)) : 0; return Math.hypot(p.x - ax - t * dx, p.y - ay - t * dy); };
    const hit = (st) => {
      if (st.type === 'text') { const w = Math.max(...st.lines.map((l) => l.length)) * st.size * 0.62, h = (st.lines.length - 1) * 1.25 * st.size;
        return p.x >= st.x - r && p.x <= st.x + w + r && p.y >= st.y - st.size - r && p.y <= st.y + h + st.size * 0.3 + r; }
      const pts = st.pts; if (pts.length === 1) return Math.hypot(p.x - pts[0][0], p.y - pts[0][1]) <= r + (st.w || 3.5) / 2;
      for (let i = 1; i < pts.length; i++) if (d2(pts[i - 1][0], pts[i - 1][1], pts[i][0], pts[i][1]) <= r + (st.w || 3.5) / 2) return true;
      return false;
    };
    let gone = false;
    for (let i = ink.strokes.length - 1; i >= 0; i--) if ((ink.strokes[i].layer || 'topo') === L.id && hit(ink.strokes[i])) {
      if (!ink.eraseOp) { ink.eraseOp = { op: 'erase', items: [] }; ink.hist.push(ink.eraseOp); }
      ink.eraseOp.items.push({ item: ink.strokes[i], index: i }); ink.strokes.splice(i, 1); gone = true;
    }
    if (gone) { ink.drew = true; renderInk(); }
    if (!ink.dot || !ink.dot.isConnected || ink.dot.ownerSVGElement !== L.svg) { if (ink.dot) ink.dot.remove(); ink.dot = el('circle', { class: 'ink-eraser' }, L.svg); } else L.svg.appendChild(ink.dot);
    ink.dot.setAttribute('cx', p.x); ink.dot.setAttribute('cy', p.y); ink.dot.setAttribute('r', r);
  }
  function inkDown(L, e) {
    ink.start = L.point(e); ink.layer = L; ink.cur = null; ink.drew = false; ink.pid = e.pointerId; ink.eraseOp = null;
    if (ink.tool === 'eraser') eraseAt(L, ink.start);
  }
  function inkMove(L, e) {
    if (!ink.start || ink.layer !== L || e.pointerId !== ink.pid) return;
    const p = L.point(e), far = Math.hypot(p.x - ink.start.x, p.y - ink.start.y) >= 4 * L.perPx();
    const grab = () => { try { L.svg.setPointerCapture(e.pointerId); } catch (err) { } L.svg.classList.add('inking'); document.body.classList.add('inking'); const sel = window.getSelection && window.getSelection(); if (sel) sel.removeAllRanges(); };
    if (ink.tool === 'eraser') { if (far && !ink.drew) { ink.drew = true; grab(); } return eraseAt(L, p); }
    if (!ink.cur) {
      if (!far) return;
      ink.cur = { layer: L.id, color: ink.color, pts: [[ink.start.x, ink.start.y]], w: 3.5 * L.perPx() }; inkAdd(ink.cur); ink.drew = true; grab();
    }
    ink.cur.pts.push([p.x, p.y]); renderInk();
  }
  function inkUp(L) {
    ink.start = null; ink.cur = null; ink.eraseOp = null; ink.layer = null;
    L.svg.classList.remove('inking'); document.body.classList.remove('inking'); if (ink.dot) ink.dot.remove();
  }
  function bindInk(L) {
    L.svg.addEventListener('pointerdown', (e) => { if (e.button === 0) { e.preventDefault(); inkDown(L, e); } });
    L.svg.addEventListener('pointermove', (e) => inkMove(L, e));
    L.svg.addEventListener('pointerup', () => inkUp(L)); L.svg.addEventListener('pointercancel', () => inkUp(L));
    L.svg.addEventListener('dblclick', (e) => { e.preventDefault(); openTextEditor(e, L); });
  }
  function openTextEditor(e, L = LAYERS.topo) {
    const host = L.host(), p = L.point(e), k = L.edScale(), color = ink.color, col = INK.find((c) => c[0] === color)[2];
    const px = 16 * fsScale(), [ex, ey] = L.editorAt(e, p);
    const ta = document.createElement('textarea');
    ta.className = 'ink-editor'; ta.rows = 1; ta.setAttribute('aria-label', 'Note: Escape when done');
    Object.assign(ta.style, { left: `${ex}px`, top: `${ey}px`, fontSize: `${px / k}px`, color: col });
    host.appendChild(ta); ta.focus({ preventScroll: true });
    const grow = () => { ta.style.height = 'auto'; ta.style.height = ta.scrollHeight + 'px'; ta.style.width = 'auto'; ta.style.width = Math.max(80, ta.scrollWidth + 4) + 'px'; };
    ta.addEventListener('input', grow); grow();
    const size = px * L.perPx();
    let done = false;
    const commit = () => {
      if (done) return; done = true;
      const text = ta.value.replace(/\s+$/, ''); ta.remove();
      if (!text) return;
      inkAdd({ type: 'text', layer: L.id, color, x: p.x, y: p.y + size * 0.85, size, lines: text.split('\n') }); renderInk();
    };
    ta.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); commit(); } });
    ta.addEventListener('pointerdown', (ev) => ev.stopPropagation());
    ta.addEventListener('blur', commit);
  }
  function setDrawAll(on) {
    ink.all = on; document.body.classList.toggle('ink-all', on);
    document.querySelectorAll('[data-act="all"]').forEach((b) => { b.setAttribute('aria-pressed', String(on)); b.title = on ? 'Drawing on the whole page: Esc or click to stop' : 'Draw on the instructions and the capture too'; });
    if (on) renderInk();
  }
  function mountInkTools(parent, before) {
    const tools = document.createElement('span'); tools.className = 'ink-tools'; tools.setAttribute('role', 'group'); tools.setAttribute('aria-label', 'Drawing');
    tools.innerHTML = `<button type="button" class="ink-btn ink-all-btn" data-act="all" aria-pressed="${ink.all}" aria-label="Draw on the instructions and the capture too" title="Draw on the instructions and the capture too">✎</button>${INK.map(([k, n, c]) => `<button type="button" class="ink-sw" data-ink="${k}" aria-pressed="${ink.tool === 'pen' && k === ink.color}" title="${n} pen" aria-label="${n} pen" style="--sw:${c}"></button>`).join('')}<button type="button" class="ink-btn ink-eraser-btn" data-tool="eraser" aria-pressed="${ink.tool === 'eraser'}" title="Eraser: drag over drawings and notes to remove them" aria-label="Eraser"><svg viewBox="0 0 20 20" width="16" height="16" aria-hidden="true"><path d="M8.5 16.5h8M3.6 11.7l6.9-6.9a1.6 1.6 0 0 1 2.3 0l3 3a1.6 1.6 0 0 1 0 2.3l-6.4 6.4H6.3l-2.7-2.6a1.6 1.6 0 0 1 0-2.2z M7.2 8.2l5.2 5.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg></button>
      <button type="button" class="ink-btn" data-act="undo" title="Undo" aria-label="Undo" ${ink.hist.length ? '' : 'disabled'}>↶</button><button type="button" class="ink-link" data-act="clear" ${ink.strokes.length ? '' : 'hidden'}>Clear all</button>`;
    parent.insertBefore(tools, before);
    tools.addEventListener('click', (e) => {
      const sw = e.target.closest('[data-ink]'), er = e.target.closest('[data-tool="eraser"]');
      if (e.target.closest('[data-act="all"]')) setDrawAll(!ink.all);
      if (sw) { ink.color = sw.dataset.ink; ink.tool = 'pen'; }
      if (er) ink.tool = 'eraser';
      if (sw || er) {
        document.querySelectorAll('.ink-tools [data-ink]').forEach((b) => b.setAttribute('aria-pressed', String(ink.tool === 'pen' && b.dataset.ink === ink.color)));
        document.querySelectorAll('.ink-tools [data-tool]').forEach((b) => b.setAttribute('aria-pressed', String(ink.tool === 'eraser')));
        document.body.classList.toggle('ink-erasing', ink.tool === 'eraser');
      }
      if (e.target.closest('[data-act="undo"]')) inkUndo();
      if (e.target.closest('[data-act="clear"]') && ink.strokes.length) { ink.hist.push({ op: 'clear', items: ink.strokes.slice() }); ink.strokes = []; renderInk(); }
    });
    return tools;
  }
  const ZMIN = 0.25, ZMAX = 4;
  const zoom = { base: null, vb: null, touches: new Map(), pinch: null };
  function setVB() {
    const B = zoom.base, v = zoom.vb;
    v.w = Math.min(B.w / ZMIN, Math.max(B.w / ZMAX, v.w)); v.h = v.w * B.h / B.w;
    v.x = Math.min(B.x + 3 * B.w - v.w, Math.max(B.x - 2 * B.w, v.x)); v.y = Math.min(B.y + 3 * B.h - v.h, Math.max(B.y - 2 * B.h, v.y));
    svg.setAttribute('viewBox', `${v.x} ${v.y} ${v.w} ${v.h}`);
    const z = B.w / v.w, pct = $('#zoom-pct'); if (pct) { pct.textContent = `${Math.round(z * 100)}%`; pct.title = Math.abs(z - 1) < 0.01 ? 'Zoom 100%' : 'Back to 100%'; }
    const zi = $('#zoom-in'), zo = $('#zoom-out'); if (zi) zi.disabled = z >= ZMAX - 0.001; if (zo) zo.disabled = z <= ZMIN + 0.001;
  }
  function zoomAt(clientX, clientY, factor) {
    const p = svgPoint({ clientX, clientY }), v = zoom.vb, w = Math.min(zoom.base.w / ZMIN, Math.max(zoom.base.w / ZMAX, v.w / factor)), k = w / v.w;
    v.x = p.x - (p.x - v.x) * k; v.y = p.y - (p.y - v.y) * k; v.w = w; setVB();
  }
  function panBy(dxPx, dyPx) { const m = svg.getScreenCTM(); if (!m) return; zoom.vb.x -= dxPx / m.a; zoom.vb.y -= dyPx / m.d; setVB(); }
  const pinchState = () => { const [a, b] = [...zoom.touches.values()]; return { d: Math.hypot(a[0] - b[0], a[1] - b[1]) || 1, mx: (a[0] + b[0]) / 2, my: (a[1] + b[1]) / 2 }; };
  function startPinch() {
    if (ink.cur) { ink.strokes.splice(ink.strokes.indexOf(ink.cur), 1); ink.hist = ink.hist.filter((h) => h.item !== ink.cur); renderInk(); }
    ink.start = null; ink.cur = null; ink.drew = false; zoom.pinch = pinchState();
  }
  function movePinch() { const n = pinchState(), o = zoom.pinch; zoomAt(n.mx, n.my, n.d / o.d); panBy(n.mx - o.mx, n.my - o.my); zoom.pinch = n; }
  function setupZoom() {
    const [x, y, w, h] = svg.getAttribute('viewBox').split(/[\s,]+/).map(Number);
    zoom.base = { x, y, w, h }; zoom.vb = { x, y, w, h };
    const zc = document.createElement('div'); zc.className = 'zoom-ctl'; zc.setAttribute('role', 'group'); zc.setAttribute('aria-label', 'Topology zoom');
    zc.innerHTML = '<button type="button" id="zoom-out" title="Zoom out" aria-label="Zoom out">−</button><button type="button" id="zoom-pct" aria-label="Reset zoom to 100%">100%</button><button type="button" id="zoom-in" title="Zoom in" aria-label="Zoom in">+</button>';
    $('#topo-wrap').appendChild(zc);
    const mid = (f) => { const r = svg.getBoundingClientRect(); zoomAt(r.left + r.width / 2, r.top + r.height / 2, f); };
    zc.addEventListener('click', (e) => {
      if (e.target.closest('#zoom-in')) mid(1.25); else if (e.target.closest('#zoom-out')) mid(0.8);
      else if (e.target.closest('#zoom-pct')) { Object.assign(zoom.vb, zoom.base); setVB(); }
    });
    const hint = $('.topo-hint'); if (hint) hint.textContent += ' · pinch: zoom';
    setVB();
    svg.addEventListener('wheel', (e) => {
      if (e.ctrlKey) { e.preventDefault(); zoomAt(e.clientX, e.clientY, Math.exp(-e.deltaY * 0.01)); }
      else if (Math.abs(zoom.vb.w - zoom.base.w) > 0.5) { e.preventDefault(); panBy(-e.deltaX, -e.deltaY); }
    }, { passive: false });
    let gs = 1;
    svg.addEventListener('gesturestart', (e) => { e.preventDefault(); gs = 1; });
    svg.addEventListener('gesturechange', (e) => { e.preventDefault(); zoomAt(e.clientX, e.clientY, e.scale / gs); gs = e.scale; });
    svg.addEventListener('gestureend', (e) => e.preventDefault());
  }
  function setupWhiteboard() {
    const fsg = $('.fs-group');
    mountInkTools(fsg.parentNode, fsg);
    const hint = $('.topo-hint'); if (hint) hint.title = 'Click the tunnel to inspect the SA, or the capture point to show the capture. Drag to draw, double-click empty space to write, pinch to zoom. ✎ draws on the instructions and the capture too.';
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && ink.all && !(e.target.closest && e.target.closest('.ink-editor'))) setDrawAll(false); });
    overlayLayer('steps', $('#steps'));
    overlayLayer('t-cap', $('#t-cap'));
    overlayLayer('t-ev', $('#t-ev'));
    const L = LAYERS.topo;
    svg.addEventListener('pointerdown', (e) => {
      if (e.button !== 0) return;
      if (e.pointerType === 'touch') { zoom.touches.set(e.pointerId, [e.clientX, e.clientY]); if (zoom.touches.size >= 2) return startPinch(); }
      inkDown(L, e);
    });
    svg.addEventListener('pointermove', (e) => {
      if (zoom.touches.has(e.pointerId)) { zoom.touches.set(e.pointerId, [e.clientX, e.clientY]); if (zoom.pinch) return movePinch(); }
      inkMove(L, e);
    });
    const end = (e) => { zoom.touches.delete(e.pointerId); if (zoom.touches.size < 2) zoom.pinch = null; inkUp(L); };
    svg.addEventListener('pointerup', end); svg.addEventListener('pointercancel', end);
    setupZoom();
    // the click that ends a drawing must not open the inspector or switch tabs
    svg.addEventListener('click', (e) => { if (ink.drew) { ink.drew = false; e.stopPropagation(); e.preventDefault(); } }, true);
    svg.addEventListener('dblclick', (e) => {
      if (e.target.closest('.router.r2, [data-key], #tap, .ink-text')) return;
      e.preventDefault(); const sel = window.getSelection && window.getSelection(); if (sel) sel.removeAllRanges();
      openTextEditor(e, L);
    });
    inkReady = true; renderInk();
    window.addEventListener('resize', () => renderInk());
  }

  /* ═══════════════════════ Resizers ═══════════════════════ */
  function dragger(handle, onMove) {
    handle.addEventListener('pointerdown', (e) => {
      e.preventDefault(); handle.classList.add('drag'); handle.setPointerCapture(e.pointerId);
      const mv = (ev) => { onMove(ev); placeGuide(); }; const up = () => { handle.classList.remove('drag'); handle.removeEventListener('pointermove', mv); handle.removeEventListener('pointerup', up); renderInk(); placeGuide(); };
      handle.addEventListener('pointermove', mv); handle.addEventListener('pointerup', up);
    });
  }
  dragger($('#divider'), (e) => { const w = Math.max(300, Math.min(window.innerWidth * 0.7, e.clientX)); $('#tutorial').style.width = w + 'px'; });
  dragger($('#hresizer'), (e) => { const top = $('#topo-wrap').getBoundingClientRect().top; $('#topo-wrap').style.height = Math.max(180, Math.min(window.innerHeight * 0.7, e.clientY - top)) + 'px'; });
  $('#divider').addEventListener('keydown', (e) => { const t = $('#tutorial'); const w = t.getBoundingClientRect().width; if (e.key === 'ArrowLeft') t.style.width = Math.max(300, w - 30) + 'px'; if (e.key === 'ArrowRight') t.style.width = Math.min(window.innerWidth * 0.7, w + 30) + 'px'; });

  /* ═══════════════════════ Bottom bar: transport, drawing, where you are ═══════════════════════ */
  const bottom = document.createElement('footer'); bottom.className = 'bottombar'; bottom.setAttribute('aria-label', 'Replay controls and status');
  bottom.innerHTML = `<span class="transport" role="group" aria-label="Replay">
      <button class="tp" id="bReset" title="Back to the start"><svg viewBox="0 0 16 16"><path d="M3 2h2v12H3zM14 2v12L6 8z"/></svg>Start</button>
      <button class="tp" id="bBack" title="Previous event (←)"><svg viewBox="0 0 16 16"><path d="M10 2v12L3 8z"/></svg>Back</button>
      <button class="tp play" id="bPlay" title="Play or pause (Space)"><svg viewBox="0 0 16 16" id="playIcon"><path d="M4 2v12l10-6z"/></svg><span id="playText">Play</span></button>
      <button class="tp" id="bStep" title="Next event (→)">Step<svg viewBox="0 0 16 16"><path d="M6 2v12l7-6z"/></svg></button>
      <label class="speed" for="speed">Speed <input type="range" id="speed" min="0.5" max="3" step="0.25" value="1"><span id="speedV">1×</span></label>
    </span><span class="bb-now" id="bb-now" aria-live="polite"></span><span class="bb-step" id="bb-step"></span>`;
  document.body.appendChild(bottom);
  $('#bPlay').onclick = () => play();
  $('#bStep').onclick = () => { stop(); stepForward(); };
  $('#bBack').onclick = () => { stop(); back(); };
  $('#bReset').onclick = () => { stop(); jump(-1); };
  $('#speed').oninput = (e) => { S.speed = Number(e.target.value); $('#speedV').textContent = S.speed + '×'; };
  function updateBar() {
    const n = $('#bb-now');
    if (S.e < 0) n.innerHTML = 'Ready · press <b>Step</b> (<kbd>→</kbd>) or <b>Play</b> (<kbd>Space</kbd>)';
    else {
      const ev = EV[S.e], m = frames()[ev.fi];
      n.innerHTML = `Event <b>${S.e + 1}</b> of ${EV.length} · frame #${m.n} · ${esc(short(m))} · ${ev.j === 0 ? 'at ' + ev.to : ev.from + ' → ' + ev.to}${ev.cap ? ' · <b>captured on r2-g1</b>' : ''}`;
    }
    const s = STEPS[cur];
    $('#bb-step').textContent = s ? `Step ${cur + 1} of ${STEPS.length} · ${s.def.title}` : '';
  }

  /* ═══════════════════════ Keyboard, reset ═══════════════════════ */
  document.addEventListener('keydown', (e) => {
    if (e.target.closest && e.target.closest('input, textarea, select, #wsTree')) return;
    if (!$('#modal-bg').hidden) { if (e.key === 'Escape') closeModal(); return; }
    if (e.key === ' ') { if (e.target.closest('button, a, label, [role="button"]')) return; e.preventDefault(); play(); }
    else if (e.key === 'ArrowRight') { if (e.target.closest('#divider')) return; e.preventDefault(); stop(); stepForward(); }
    else if (e.key === 'ArrowLeft') { if (e.target.closest('#divider')) return; e.preventDefault(); stop(); back(); }
  });
  $('#btn-reset').addEventListener('click', () => {
    stop();
    for (const k of ['classic', 'hybrid']) PROG[k] = { intro: false, done: new Set(), finished: false };
    S.e = -1; setFollow(true); S.sel = null;
    renderSteps(); update(true);
    $('#steps').scrollTop = 0;
  });
  document.querySelectorAll('.seg [data-sc]').forEach((b) => b.addEventListener('click', () => setScenario(b.dataset.sc)));

  /* ═══════════════════════ Boot ═══════════════════════ */
  drawStatic();
  buildEvents();
  document.body.classList.toggle('hybrid', S.sc === 'hybrid');
  document.querySelectorAll('[data-sc][role="radio"]').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.sc === S.sc)));
  $('#nav-badge').textContent = SCN[S.sc].badge;
  document.title = `IKEv2 Packet Journey · ${SCN[S.sc].badge}`;
  renderEventList();
  renderSteps();
  setupWhiteboard();
  mountInkTools(bottom, $('#bb-now')).classList.add('bb-ink');
  let fsSaved = 's'; try { fsSaved = localStorage.getItem('spq-fs') || 's'; } catch (e) { }
  setFont(fsSaved, false);
  update(true);
})();
