/* app.js — UI for the 3-router PQC IPsec lab: steps, consoles, live topology, handshake inspector */
(function () {
  'use strict';
  const { Lab, PQC_LABEL, DH_LABEL, DH_KE_BYTES, MLKEM_SIZES, ifShort } = window.PqcLab;
  const TOPO = window.LAB_TOPOLOGY;
  // ?track=classic | full (default)
  const TRACKS = window.TUTORIAL.TRACKS;
  const TRACK_ID = (new URLSearchParams(location.search).get('track') || window.TUTORIAL.DEFAULT_TRACK || 'full').toLowerCase();
  const TRACK = TRACKS[TRACK_ID] || TRACKS[window.TUTORIAL.DEFAULT_TRACK] || TRACKS.full || Object.values(TRACKS)[0];
  const STEPS = TRACK.steps.map(id => window.TUTORIAL.BY_ID[id]);
  document.title = TRACK.title;
  document.querySelector('.nav-title').textContent = TRACK.title;
  document.querySelector('.badge').textContent = TRACK.badge;
  document.querySelector('.tut-kicker').textContent = TRACK.kicker;
  const DEVS = Object.keys(TOPO.devices);
  const lab = new Lab(TOPO);
  const $ = s => document.querySelector(s);
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const reduceMotion = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ═══════════════════════ Consoles ═══════════════════════ */
  const T = {}; let activeDev = 'r1'; let busy = false;
  function buildConsoles() {
    const tabs = $('#tabs'), terms = $('#terms');
    for (const k of DEVS) {
      const def = TOPO.devices[k];
      const tab = document.createElement('button');
      tab.className = 'tab'; tab.setAttribute('role', 'tab'); tab.id = 'tab-' + k;
      tab.innerHTML = `${def.hostname}<span class="role">${esc(def.role)}</span><span class="unread"></span>`;
      tab.addEventListener('click', () => selectDev(k, true));
      tabs.appendChild(tab);
      const term = document.createElement('div');
      term.className = 'term'; term.setAttribute('role', 'tabpanel'); term.setAttribute('aria-labelledby', tab.id);
      const lines = document.createElement('div');
      const row = document.createElement('div'); row.className = 'term-input';
      const pr = document.createElement('span');
      const inp = document.createElement('input');
      inp.type = 'text'; inp.spellcheck = false; inp.autocomplete = 'off'; inp.setAttribute('autocapitalize', 'off'); inp.setAttribute('aria-label', `${def.hostname} command line`);
      row.append(pr, inp); term.append(lines, row); terms.appendChild(term);
      term.addEventListener('mouseup', () => { if (!String(window.getSelection())) inp.focus(); });
      T[k] = { tab, term, lines, pr, inp, hist: -1, draft: '' };
      inp.addEventListener('keydown', e => onKey(k, e));
      // "?" typed via IME/paste (no keydown): IOS always treats it as a help request
      inp.addEventListener('input', () => { const i = inp.value.indexOf('?'); if (i >= 0) { inp.value = inp.value.slice(0, i); showHelp(k); } });
      line(k, `${def.hostname} con0 is now available — Cisco ${def.model}, IOS XE 26.2 (simulated)`, 'term-banner');
      line(k, 'Educational simulator: output may differ from real routers. Not for validating configurations.', 'term-banner');
      line(k, `Type "?" for help. Tab completes, ↑/↓ recall history, Ctrl+Z leaves config mode.`, 'term-banner');
      line(k, '', '');
      setPrompt(k);
    }
    selectDev('r1', false);
  }
  function line(k, text, cls) {
    const d = document.createElement('div'); d.className = 'ln' + (cls ? ' ' + cls : ''); d.textContent = text;
    T[k].lines.appendChild(d);
    const n = T[k].lines.childElementCount; if (n > 1500) T[k].lines.firstChild.remove();
  }
  const scroll = k => { T[k].term.scrollTop = T[k].term.scrollHeight; };
  const setPrompt = k => { T[k].pr.textContent = lab.prompt(k); };
  function selectDev(k, focus) {
    activeDev = k;
    if (!T[k]) return;
    for (const d of DEVS) {
      const on = d === k;
      T[d].tab.setAttribute('aria-selected', on); T[d].term.classList.toggle('active', on);
      if (on) T[d].tab.classList.remove('has-unread');
    }
    document.querySelectorAll('#topo .router').forEach(g => g.classList.toggle('active', g.dataset.dev === k));
    scroll(k);
    if (focus) T[k].inp.focus({ preventScroll: true });
  }
  function flushLogs() {
    for (const q of lab.drainLogs()) {
      line(q.dev, q.text, q.cls); scroll(q.dev);
      if (q.dev !== activeDev) T[q.dev].tab.classList.add('has-unread');
    }
  }
  function submit(k, cmd) {
    line(k, lab.prompt(k) + cmd, 'cmd');
    const r = lab.exec(k, cmd);
    for (const l of r.lines) for (const part of String(l.text).split('\n')) line(k, part, l.cls);
    setPrompt(k); flushLogs(); scroll(k);
    if (r.meta && r.meta.kind === 'ping') animatePath(r.meta);
    const last = lab.cmdLog[lab.cmdLog.length - 1];
    onCommand(k, last ? last.canon : cmd, cmd);
    refresh();
  }
  function onKey(k, e) {
    const t = T[k], inp = t.inp, hist = lab.history(k);
    if (e.key === 'Enter') { e.preventDefault(); const v = inp.value; inp.value = ''; t.hist = -1; submit(k, v); }
    else if (e.key === '?') { e.preventDefault(); showHelp(k); }
    else if (e.key === 'Tab') { e.preventDefault(); inp.value = lab.complete(k, inp.value); }
    else if (e.key === 'ArrowUp') {
      e.preventDefault(); if (!hist.length) return;
      if (t.hist === -1) { t.draft = inp.value; t.hist = hist.length; }
      t.hist = Math.max(0, t.hist - 1); inp.value = hist[t.hist];
    } else if (e.key === 'ArrowDown') {
      e.preventDefault(); if (t.hist === -1) return;
      t.hist++; if (t.hist >= hist.length) { t.hist = -1; inp.value = t.draft; } else inp.value = hist[t.hist];
    } else if ((e.ctrlKey && (e.key === 'z' || e.key === 'Z'))) { e.preventDefault(); inp.value = ''; submit(k, 'end'); }
    else if (e.ctrlKey && (e.key === 'c' || e.key === 'C') && !String(window.getSelection())) { e.preventDefault(); line(k, lab.prompt(k) + inp.value + '^C', 'cmd'); inp.value = ''; scroll(k); }
  }
  function showHelp(k) {
    const v = T[k].inp.value;
    line(k, lab.prompt(k) + v + '?', 'cmd');
    for (const l of lab.help(k, v)) line(k, l.text, l.cls);
    scroll(k);
  }
  async function typeCmd(k, cmd) {
    selectDev(k, false);
    const inp = T[k].inp; inp.value = '';
    const per = Math.max(4, Math.min(14, 260 / Math.max(1, cmd.length)));
    if (!reduceMotion) for (const ch of cmd) { inp.value += ch; await sleep(per); }
    inp.value = ''; submit(k, cmd);
    await sleep(110);
  }

  /* ═══════════════════════ Tutorial ═══════════════════════ */
  const stepListeners = [];
  let cur = 0; const done = new Set(); let since = 0; const usedShowMe = new Set(); const t0 = Date.now();
  const PART = { intro: 'Intro', base: 'Baseline', verify: 'Verify', ppk: 'PPK', pqc: 'ML-KEM', hub: 'Hub & spoke' };
  function renderSteps() {
    const ol = $('#steps');
    STEPS.forEach((s, i) => {
      const li = document.createElement('li'); li.className = 'step'; li.id = 'step-' + i; li.dataset.status = 'locked';
      const info = !s.run.length;
      li.innerHTML = `
        <button class="step-head" aria-expanded="false" aria-controls="step-body-${i}">
          <span class="step-num">${i + 1}</span><span class="step-title">${esc(s.title)}</span><span class="tag ${s.part}">${PART[s.part]}</span>
        </button>
        <div class="step-body" id="step-body-${i}">
          ${s.html}
          <div class="step-hint" id="hint-${i}" role="status"></div>
          <div class="step-actions">
            ${info ? `<button class="btn" data-continue="${i}">${i === STEPS.length - 1 ? 'Finish' : 'Start the lab'}</button>` : `<button class="btn success" data-showme="${i}">▶ Show Me</button>`}
            <span class="step-done">✓ Step complete</span>
          </div>
        </div>`;
      li.querySelector('.step-head').addEventListener('click', () => toggleStep(i));
      addSnippetButtons(li);
      ol.appendChild(li);
    });
    const fin = document.createElement('li'); fin.className = 'finish'; fin.id = 'finish'; ol.appendChild(fin);
    ol.addEventListener('click', e => {
      const run = e.target.closest('.cfg-run'); if (run) return runSnippet(run);
      const sm = e.target.closest('[data-showme]'), ct = e.target.closest('[data-continue]');
      if (sm) showMe(+sm.dataset.showme);
      if (ct) complete(+ct.dataset.continue);
    });
  }
  function toggleStep(i, force) {
    const li = $('#step-' + i); const open = force !== undefined ? force : !li.classList.contains('open');
    li.classList.toggle('open', open); li.querySelector('.step-head').setAttribute('aria-expanded', open);
  }
  function activate(i) {
    cur = i; since = lab.lastSeq;
    STEPS.forEach((_, j) => { const li = $('#step-' + j); li.dataset.status = done.has(j) ? 'done' : j === i ? 'active' : 'locked'; toggleStep(j, j === i); });
    const li = $('#step-' + i);
    if (li) li.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    const s = STEPS[i]; if (s && s.devices.length) selectDev(s.devices[0], false);
    for (const fn of stepListeners) try { fn(i, s); } catch (e) { console.warn(e); }
    updateProgress();
    checkStep();
  }
  function complete(i) {
    if (done.has(i)) return;
    done.add(i); $('#step-' + i).dataset.status = 'done';
    updateProgress();
    if (i === STEPS.length - 1) return finish();
    if (i === cur) setTimeout(() => activate(i + 1), 650);
  }
  function checkStep() {
    const s = STEPS[cur];
    if (!s || !s.run.length || done.has(cur)) return;
    let ok = false; try { ok = s.validate({ lab, since }); } catch (e) { console.warn(e); }
    if (ok) complete(cur);
  }
  function onCommand(k, canon, raw) {
    const s = STEPS[cur]; if (!s) return;
    for (const h of s.hints) {
      let hit = false; try { hit = h.when(k, canon, raw, lab); } catch (e) { }
      if (hit) { const el = $('#hint-' + cur); el.innerHTML = '💡 ' + h.text; el.classList.add('show'); break; }
    }
    checkStep();
  }
  async function showMe(i) {
    if (busy) return;
    const s = STEPS[i]; busy = true; usedShowMe.add(i);
    const btn = document.querySelector(`[data-showme="${i}"]`); btn.disabled = true; btn.textContent = '⏳ Typing…';
    let prev = null;
    for (const [k, cmd] of s.run) {
      const d = lab.dev(k);
      if (k !== prev) {
        if (d.mode === 'exec' && cmd !== 'enable') await typeCmd(k, 'enable');
        else if (!['exec', 'priv'].includes(d.mode) && (cmd === 'configure terminal' || /^(show|ping|clear|traceroute|debug)/.test(cmd))) await typeCmd(k, 'end');
      }
      if (lab.dev(k).mode === 'priv' && cmd === 'enable') { prev = k; continue; }
      await typeCmd(k, cmd); prev = k;
    }
    btn.textContent = '▶ Show Me again'; btn.disabled = false; busy = false;
    T[activeDev].inp.focus({ preventScroll: true });
  }
  /* ── per-snippet ▶: run one config snippet on its router ── */
  const EXEC_RE = /^(show|ping|traceroute|clear|debug|undebug|write|copy|enable|disable)\b/;
  function addSnippetButtons(li) {
    li.querySelectorAll('.cfg').forEach(box => {
      const chip = box.querySelector('.dev-chip'), pre = box.querySelector('pre');
      const dev = chip && [...chip.classList].map(c => /^dev-(r\d)$/.exec(c)).find(Boolean);
      // only real commands: skip illustrative snippets (ellipses, prose)
      if (!dev || !pre || !TOPO.devices[dev[1]] || /…|\.\.\.same/.test(pre.textContent)) return;
      const b = document.createElement('button');
      b.className = 'cfg-run'; b.type = 'button'; b.dataset.dev = dev[1];
      b.title = `Run this snippet on ${TOPO.devices[dev[1]].hostname}`; b.setAttribute('aria-label', b.title);
      b.textContent = '▶';
      box.classList.add('runnable'); box.appendChild(b);
    });
  }
  async function runSnippet(btn) {
    if (busy) return;
    const k = btn.dataset.dev, lines = btn.parentElement.querySelector('pre').textContent.split('\n');
    busy = true; btn.disabled = true; btn.classList.add('running');
    try {
      const mode = () => lab.dev(k).mode;
      if (mode() === 'exec') await typeCmd(k, 'enable');
      if (!['exec', 'priv'].includes(mode())) await typeCmd(k, 'end');
      let inCfg = false, depth = 0;
      for (const raw of lines) {
        const t = raw.trim(); if (!t || t === '!') continue;
        const ind = raw.length - raw.trimStart().length;
        if (t === 'configure terminal') { if (!inCfg) await typeCmd(k, t); inCfg = true; depth = 0; continue; }
        if (t === 'end') { if (inCfg) await typeCmd(k, 'end'); inCfg = false; depth = 0; continue; }
        if (t === 'enable' && mode() !== 'exec') continue;
        if (EXEC_RE.test(t)) { if (inCfg) { await typeCmd(k, 'end'); inCfg = false; } await typeCmd(k, t); continue; }
        if (!inCfg) { await typeCmd(k, 'configure terminal'); inCfg = true; depth = 0; }
        // indentation = sub-mode depth: leave sub-modes the way the snippet's layout implies
        for (; depth > ind; depth--) await typeCmd(k, 'exit');
        await typeCmd(k, t); depth = ind;
      }
      if (inCfg) await typeCmd(k, 'end');
    } finally {
      busy = false; btn.disabled = false; btn.classList.remove('running'); btn.classList.add('ran');
      T[k].inp.focus({ preventScroll: true });
    }
  }
  function updateProgress() {
    const n = done.size, tot = STEPS.length;
    $('#nav-progress').textContent = `${n} / ${tot}`;
    $('#progress-fill').style.width = (n / tot * 100) + '%';
  }
  function finish() {
    const mins = Math.max(1, Math.round((Date.now() - t0) / 60000));
    const el = $('#finish');
    el.innerHTML = `<h3>🎉 ${esc(TRACK.finish || 'Lab complete — quantum-safe key exchange on all tunnels')}</h3>
      <p>Time: <b>${mins} min</b> · Steps solved without <i>Show Me</i>: <b>${STEPS.filter(s => s.run.length).length - [...usedShowMe].length}</b> of ${STEPS.filter(s => s.run.length).length}</p>
      <p>Keep exploring: the routers stay live. Try a wrong pre-shared key, drop the fragmentation, or turn on <code>debug crypto ikev2</code> and clear the SAs.</p>`;
    el.classList.add('show'); el.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'center' });
  }

  /* ═══════════════════════ Text size (A A A) ═══════════════════════ */
  const FS = { s: 1, m: 1.15, l: 1.3 }; let topoReady = false;
  function setFont(k, save) {
    if (!FS[k]) k = 's';
    document.documentElement.style.setProperty('--fs', FS[k]);
    document.querySelectorAll('.fs-btn').forEach(b => b.setAttribute('aria-pressed', b.dataset.fs === k));
    if (save) try { localStorage.setItem('spq-fs', k); } catch (e) { }
    if (topoReady) { tunSig = ''; refresh(); }
  }
  document.querySelectorAll('.fs-btn').forEach(b => b.addEventListener('click', () => setFont(b.dataset.fs, true)));

  /* ═══════════════════════ Topology ═══════════════════════ */
  const SVGNS = 'http://www.w3.org/2000/svg';
  const POS = { r1: 150, r2: 480, r3: 810 }; const Y = 205; const TOP = Y - 20;
  const svg = $('#topo');
  const el = (tag, attrs = {}, parent) => { const n = document.createElementNS(SVGNS, tag); for (const [a, v] of Object.entries(attrs)) n.setAttribute(a, v); if (parent) parent.appendChild(n); return n; };
  let gLinks, gTun, gPkt, tunSig = '';
  function drawStatic() {
    svg.innerHTML = '';
    gTun = el('g', { id: 'g-tun' }, svg);
    gLinks = el('g', { id: 'g-links' }, svg);
    for (const l of TOPO.links) {
      const [a, b] = [l.a, l.b]; const x1 = POS[a[0]] + 42, x2 = POS[b[0]] - 42;
      el('line', { class: 'link', x1, y1: Y, x2, y2: Y }, gLinks);
      el('circle', { class: 'dot-up', cx: x1 + 6, cy: Y, r: 4.5, 'data-port': a.join(':') }, gLinks);
      el('circle', { class: 'dot-up', cx: x2 - 6, cy: Y, r: 4.5, 'data-port': b.join(':') }, gLinks);
      const t = el('text', { class: 'lbl-link', x: (x1 + x2) / 2, y: Y + 34, 'text-anchor': 'middle' }, gLinks); t.textContent = `${l.label} · ${l.speed}`;
      for (const [end, x, anchor] of [[a, x1, 'start'], [b, x2, 'end']]) {
        const dv = TOPO.devices[end[0]]; const port = dv.interfaces[end[1]]; const ip = port.vlan ? (dv.interfaces['Vlan' + port.vlan] || {}).ip : port.ip;
        const p = el('text', { class: 'lbl-port', x, y: Y + 16, 'text-anchor': anchor }, gLinks); p.textContent = ifShort(end[1]);
        const q = el('text', { class: 'lbl-ip', x, y: Y - 9, 'text-anchor': anchor }, gLinks); q.textContent = ip;
      }
    }
    for (const k of DEVS) {
      const x = POS[k], def = TOPO.devices[k];
      const g = el('g', { class: 'router', 'data-dev': k, tabindex: 0, role: 'button', 'aria-label': `Open ${def.hostname} console` }, svg);
      el('rect', { class: 'ring', x: x - 46, y: Y - 26, width: 92, height: 92, rx: 12 }, g);
      el('path', { d: `M${x - 36},${Y - 6} v16 a36,11 0 0 0 72,0 v-16`, fill: 'var(--router-body)' }, g);
      el('ellipse', { cx: x, cy: Y - 6, rx: 36, ry: 11, fill: 'var(--router-top)' }, g);
      const ar = (d) => el('path', { d, stroke: '#fff', 'stroke-width': 2.2, fill: 'none', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, g);
      ar(`M${x - 22},${Y - 9} l9,0 m-3,-3 l3,3 l-3,3`); ar(`M${x + 22},${Y - 3} l-9,0 m3,-3 l-3,3 l3,3`);
      ar(`M${x - 4},${Y - 14} l0,0 M${x - 6},${Y - 12} l4,-4 l4,4`); ar(`M${x - 6},${Y + 0} l4,4 l4,-4`);
      const h = el('text', { class: 'host', x, y: Y + 42, 'text-anchor': 'middle' }, g); h.textContent = def.hostname;
      const r = el('text', { class: 'role', x, y: Y + 57, 'text-anchor': 'middle' }, g); r.textContent = def.role;
      g.addEventListener('click', () => selectDev(k, true));
      g.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectDev(k, true); } });
    }
    gPkt = el('g', { id: 'g-pkt' }, svg);
  }
  const arcPath = (a, b) => {
    const x1 = POS[a], x2 = POS[b]; const span = Math.abs(x2 - x1);
    const h = span > 400 ? 150 : 88; const mx = (x1 + x2) / 2;
    // point on the quadratic curve at parameter u (0 = a, 1 = b)
    const at = u => [(1 - u) ** 2 * x1 + 2 * (1 - u) * u * mx + u * u * x2, (1 - u) ** 2 * TOP + 2 * (1 - u) * u * (TOP - 2 * h) + u * u * TOP];
    return { d: `M${x1},${TOP} Q${mx},${TOP - 2 * h} ${x2},${TOP}`, apex: [mx, TOP - h], at };
  };
  // tunnel overlay addressing, read live from the routers' configuration
  const ip2n = ip => ip.split('.').reduce((a, o) => a * 256 + +o, 0);
  const n2ip = n => [24, 16, 8, 0].map(b => Math.floor(n / 2 ** b) % 256).join('.');
  const tunAddr = (dev, ifn) => { const i = lab.dev(dev).ifaces[ifn]; return i && i.ip ? i : null; };
  const subnetOf = i => { const m = ip2n(i.mask), len = i.mask.split('.').reduce((a, o) => a + (+o).toString(2).split('1').length - 1, 0); return `${n2ip(ip2n(i.ip) - ip2n(i.ip) % (2 ** 32 - m))}/${len}`; };
  const fsScale = () => +getComputedStyle(document.documentElement).getPropertyValue('--fs') || 1;
  function tunnelView(t) {
    if (t.state === 'up' && t.half) return { kind: 'fail', label: `${ifShort(t.a.if)} · ⚠ half-open: ${lab.dev(t.half).hostname} has no SA` };
    if (t.state === 'up' && t.sa.child.down) return { kind: 'fail', label: `${ifShort(t.a.if)} · IKE up · ✕ no IPsec SA` };
    if (t.state === 'up') {
      const p = t.params; const kind = p.pqc ? 'pqc' : p.ppk ? 'ppk' : 'classic';
      const what = p.pqc ? `${PQC_LABEL[p.pqc]} + DH ${p.group}` : p.ppk ? `DH ${p.group} + PPK` : `DH ${p.group} + PSK`;
      return { kind, label: `${ifShort(t.a.if)} · ${what}` };
    }
    if (t.state === 'fail') return { kind: 'fail', label: `${ifShort(t.a.if)} · ✕ ${t.code}` };
    return { kind: 'neg', label: `${ifShort(t.a.if)} · negotiating…` };
  }
  function drawTunnels() {
    const tuns = lab.tunnels();
    const halves = lab.halfTunnels().filter(h => h.protected && !h.shutdown && h.mode === 'ipsec ipv4');
    const ownerOf = ip => DEVS.find(k => Object.values(lab.dev(k).ifaces).some(i => i.ip === ip && i.kind !== 'tunnel'));
    const sig = JSON.stringify([fsScale(), tuns.map(t => t.half), tuns.map(t => [tunAddr(t.a.dev, t.a.if), tunAddr(t.b.dev, t.b.if)].map(i => i && i.ip + '/' + i.mask)), tuns.map(t => [t.key, t.state, t.code, t.params && [t.params.pqc, t.params.ppk], t.sa && t.sa.child.down]), halves.map(h => [h.dev, h.if, h.dest])]);
    if (sig === tunSig) return; tunSig = sig;
    gTun.innerHTML = '';
    const items = tuns.map(t => ({ key: t.key, a: t.a.dev, b: t.b.dev, ends: [[t.a.dev, t.a.if], [t.b.dev, t.b.if]], ...tunnelView(t) }));
    for (const h of halves) { const o = ownerOf(h.dest); if (o && o !== h.dev) items.push({ key: 'half:' + h.dev + ':' + h.if, a: h.dev, b: o, ends: [[h.dev, h.if]], kind: 'half', label: `${ifShort(h.if)} on ${lab.dev(h.dev).hostname} · waiting for ${lab.dev(o).hostname}` }); }
    const fs = fsScale();
    for (const it of items) {
      const { d, apex, at } = arcPath(it.a, it.b);
      const g = el('g', { 'data-key': it.key, role: 'button', tabindex: 0, 'aria-label': `Inspect tunnel: ${it.label}` }, gTun);
      el('path', { class: 'tun-hit', d }, g);
      el('path', { class: 'tun ' + it.kind, d, id: 'tun-' + cssId(it.key) }, g);
      const lg = el('g', { class: 'tun-label' }, g);
      const w = it.label.length * 6.3 * fs + 18;
      // tunnel interface addresses where the arc leaves each router, overlay subnet under the pill
      const addrs = it.ends.map(([dv, ifn]) => ({ dv, i: tunAddr(dv, ifn) })).filter(x => x.i);
      for (const { dv, i } of addrs) {
        const left = POS[dv] === Math.min(POS[it.a], POS[it.b]);
        // inside the arc, so the two addresses that meet at a hub never collide
        const [px, py] = at(left === (POS[it.a] < POS[it.b]) ? 0.15 : 0.85);
        const t = el('text', { class: 'lbl-tun', x: px + (left ? 8 : -8), y: py + 4, 'text-anchor': left ? 'start' : 'end' }, g);
        t.textContent = i.ip;
      }
      const net = addrs.length ? `overlay ${subnetOf(addrs[0].i)}` : '';
      const h2 = net ? 13 * fs : 0, wb = Math.max(w, net.length * 5.9 * fs + 18);
      el('rect', { x: apex[0] - wb / 2, y: apex[1] - 11 * fs - h2 / 2, width: wb, height: 22 * fs + h2, rx: 11 * fs, stroke: `var(--${it.kind === 'half' ? 'neg' : it.kind})` }, lg);
      if (net) { const sn = el('text', { class: 'lbl-tun-net', x: apex[0], y: apex[1] + 4 * fs + h2 / 2 + 1, 'text-anchor': 'middle' }, lg); sn.textContent = net; }
      const tx = el('text', { x: apex[0], y: apex[1] + 4 * fs - h2 / 2, 'text-anchor': 'middle', fill: `var(--${it.kind === 'half' ? 'neg' : it.kind})` }, lg); tx.textContent = it.label;
      tx.style.fill = `var(--${it.kind === 'half' ? 'neg' : it.kind})`;
      g.addEventListener('click', () => openInspector(it.key));
      g.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openInspector(it.key); } });
    }
  }
  const cssId = s => s.replace(/[^a-zA-Z0-9]/g, '_');
  function drawPorts() {
    gLinks.querySelectorAll('circle[data-port]').forEach(c => { const [d, p] = c.dataset.port.split(':'); c.setAttribute('class', lab.portUp(d, p) ? 'dot-up' : 'dot-down'); });
  }
  function refresh() { drawTunnels(); drawPorts(); }

  // packet animation along the path a ping took
  async function animatePath(meta) {
    if (reduceMotion || !meta.path) return;
    const hops = [...meta.path.fwd, ...(meta.ok ? meta.path.back : [])];
    for (const h of hops) {
      let pathEl, reverse = false, color = 'var(--cisco-primary)';
      if (h.via === 'tunnel') {
        pathEl = document.getElementById('tun-' + cssId(h.key)); if (!pathEl) continue;
        reverse = POS[h.from] > POS[h.to];
        const cls = pathEl.getAttribute('class'); color = cls.includes('pqc') ? 'var(--pqc)' : cls.includes('ppk') ? 'var(--ppk)' : 'var(--classic)';
      } else {
        pathEl = el('path', { d: `M${POS[h.from]},${Y} L${POS[h.to]},${Y}`, fill: 'none', stroke: 'none' }, gPkt);
      }
      await movePacket(pathEl, reverse, color, h.via === 'tunnel');
      if (h.via !== 'tunnel') pathEl.remove();
    }
    if (!meta.ok) {
      const at = meta.path.fwd.length ? meta.path.fwd[meta.path.fwd.length - 1].to : null;
      const x = POS[at || Object.keys(POS)[0]];
      const xMark = el('text', { x: x, y: Y - 34, 'text-anchor': 'middle', 'font-size': 22, fill: 'var(--fail)', class: 'pkt' }, gPkt); xMark.textContent = '✕';
      setTimeout(() => xMark.remove(), 900);
    }
  }
  function movePacket(pathEl, reverse, color, esp) {
    return new Promise(res => {
      const len = pathEl.getTotalLength(); const dur = Math.max(260, len * 0.9);
      const g = el('g', { class: 'pkt' }, gPkt);
      el('circle', { r: esp ? 7 : 5.5, fill: color, stroke: '#fff', 'stroke-width': 1.5 }, g);
      if (esp) { const t = el('text', { 'text-anchor': 'middle', y: 3.5, 'font-size': 8, fill: '#fff', 'font-weight': 700 }, g); t.textContent = '🔒'; t.setAttribute('font-size', 7); }
      const t0 = performance.now();
      const step = now => {
        const f = Math.min(1, (now - t0) / dur); const pt = pathEl.getPointAtLength((reverse ? 1 - f : f) * len);
        g.setAttribute('transform', `translate(${pt.x},${pt.y})`);
        if (f < 1) requestAnimationFrame(step); else { g.remove(); res(); }
      };
      requestAnimationFrame(step);
    });
  }

  /* ═══════════════════════ Inspector ═══════════════════════ */
  let inspKey = null;
  function openInspector(key) { inspKey = key; renderInspector(); $('#modal-bg').hidden = false; $('#modal-close').focus(); }
  function closeInspector() { inspKey = null; $('#modal-bg').hidden = true; }
  function renderInspector() {
    if (!inspKey) return;
    const body = $('#modal-body'); const H = (s) => lab.dev(s).hostname;
    if (inspKey.startsWith('half:')) {
      const [, dv, ifn] = inspKey.split(':'); const i = lab.dev(dv).ifaces[ifn];
      $('#modal-title').textContent = `${H(dv)} ${ifn} → ${i ? i.tunnel.dest : '?'}`;
      body.innerHTML = `<p><span class="status-chip" style="background:var(--neg)">WAITING FOR PEER</span></p>
        <p>${esc(H(dv))} has a protected tunnel towards <code>${esc(i ? i.tunnel.dest : '')}</code>, but no router has a matching tunnel back: its <code>tunnel destination</code> must be ${esc(H(dv))}'s source address and its <code>tunnel source</code> must be <code>${esc(i ? i.tunnel.dest : '')}</code>.</p>
        <p>IKEv2 cannot start until both ends exist. Configure the other side.</p>`;
      return;
    }
    const t = lab.tunnels().find(x => x.key === inspKey);
    if (!t) { body.innerHTML = '<p>This tunnel no longer exists.</p>'; $('#modal-title').textContent = 'Handshake inspector'; return; }
    const A = t.a, B = t.b;
    const ipA = lab.dev(A.dev).ifaces[A.if] ? srcOf(A) : '', ipB = srcOf(B);
    $('#modal-title').textContent = `${H(A.dev)} ${A.if} (${ipA}) ⇄ ${H(B.dev)} ${B.if} (${ipB})`;
    const chip = t.state === 'up' && t.half ? ['fail', 'HALF-OPEN'] : t.state === 'up' ? (t.params.pqc ? ['pqc', 'UP · ML-KEM'] : t.params.ppk ? ['ppk', 'UP · PPK'] : ['classic', 'UP · CLASSICAL']) : t.state === 'fail' ? ['fail', 'FAILED · ' + t.code] : ['neg', 'NEGOTIATING'];
    let html = `<p><span class="status-chip" style="background:var(--${chip[0]})">${chip[1]}</span></p>`;
    if (t.state === 'fail') html += `<div class="err-box"><b>Why:</b> ${esc(t.err)}</div><p>IKEv2 retries every few seconds; traffic (a ping through the tunnel) retries immediately. Fix the configuration and the tunnel comes up on its own.</p>`;
    if (t.state === 'neg') html += `<p>IKEv2 is (re)negotiating. Send traffic through the tunnel, or wait a moment.</p>`;
    if (t.state === 'up' && t.half) { const ok = t.half === A.dev ? B.dev : A.dev; html += `<div class="err-box"><b>Half-open:</b> ${esc(H(ok))} completed IKE_AUTH and is READY, but ${esc(H(t.half))} (the initiator) rejected ${esc(H(ok))}'s identity after ${esc(H(ok))} had installed its SAs. ${esc(H(ok))} encrypts; ${esc(H(t.half))} has no SA and drops the packets (<code>%CRYPTO-4-RECVD_PKT_INV_SPI</code>). Check <code>match identity remote address</code> on ${esc(H(t.half))}, and always look at both peers.</div>`; }
    const sa = t.sa;
    if (sa && sa.child.down) html += `<div class="err-box"><b>Child SA down:</b> ${esc(sa.child.err)}</div>`;
    if (sa) {
      const p = sa.params; const age = Math.round((Date.now() - sa.establishedAt) / 1000);
      html += `<dl class="kv">
        <dt>Initiator → responder</dt><dd>${H(sa.initiator)} → ${H(sa.initiator === A.dev ? B.dev : A.dev)}</dd>
        <dt>Proposals matched</dt><dd>${esc(p.propA)} (${H(A.dev)}) ⇄ ${esc(p.propB)} (${H(B.dev)})</dd>
        <dt>IKE SA</dt><dd>${p.enc.toUpperCase()} · PRF ${p.prf.toUpperCase()} · DH group ${p.group} (${DH_LABEL[p.group] || ''})</dd>
        <dt>Post-quantum KE</dt><dd>${p.pqc ? `${PQC_LABEL[p.pqc]} (FIPS 203) — ${A.dev === sa.initiator ? '' : ''}${esc(p.pqcModeA || '')} / ${esc(p.pqcModeB || '')}` : 'none'}</dd>
        <dt>PPK (RFC 8784)</dt><dd>${p.ppk ? esc(p.ppk) : 'none'}</dd>
        <dt>Fragmentation</dt><dd>${p.frag ? `enabled · MTU in use ${p.fragMtu - 28} B` : 'disabled'}</dd>
        <dt>Authentication</dt><dd>PSK (both directions)</dd>
        <dt>Child SA (ESP)</dt><dd>${esc(p.esp)} · tunnel mode</dd>
        <dt>Child SA PFS</dt><dd>${sa.child.down ? '✕ rekey failed' : sa.child.pfs ? `Y · ${sa.child.pfs.group}${sa.child.pfs.pqc ? ' + ' + PQC_LABEL[sa.child.pfs.pqc] : ''} (after ${sa.child.rekeys} rekey${sa.child.rekeys > 1 ? 's' : ''})` : (sa.child.rekeys ? 'N (no PFS negotiated)' : 'N — first Child SA comes from IKE_AUTH; PFS applies from the first rekey')}</dd>
        <dt>Established</dt><dd>${age}s ago · Life ${p.lifetime}s</dd></dl>`;
      html += ladder(p, H(sa.initiator), H(sa.initiator === A.dev ? B.dev : A.dev));
      html += `<h4>Key derivation</h4><div class="formula">SKEYSEED = prf(Ni | Nr, g^ir)              ← ECDH ${DH_LABEL[p.group] || 'group ' + p.group} shared secret</div>`;
      if (p.pqc) html += `<div class="formula">SKEYSEED(1) = prf(SK_d, SS_mlkem | Ni | Nr)  ← RFC 9370: the final keys depend on BOTH secrets.
Breaking ECDH alone (Shor) is no longer enough.</div>`;
      if (p.ppk) html += `<div class="formula">SK_d'  = prf+(PPK, SK_d)
SK_pi' = prf+(PPK, SK_pi)    SK_pr' = prf+(PPK, SK_pr)   ← RFC 8784: PPK "${esc(p.ppk)}" never crosses the wire</div>`;
      const ke = p.pqc ? ['ok', `✓ Hybrid ECDH + ${PQC_LABEL[p.pqc]}`] : p.ppk ? ['ok', '✓ Quantum-resistant through the PPK (out-of-band secret)'] : ['no', '✗ Classical ECDH only — exposed to "harvest now, decrypt later"'];
      html += `<div class="verdict">
        <div><b>Key exchange</b><br><span class="${ke[0]}">${ke[1]}</span></div>
        <div><b>Authentication</b><br><span class="meh">PSK — a symmetric secret, so Shor doesn't break it, but per-tunnel keys don't scale. Part 10 moves to ML-DSA certificates.</span></div>
        <div><b>Data plane</b><br><span class="ok">✓ ${esc(p.esp)} — AES-256 keeps ample margin against Grover</span></div>
        <div><b>Fallback</b><br><span class="${(p.pqcModeA === 'required' || p.pqcModeB === 'required') ? 'ok' : 'meh'}">${(p.pqcModeA === 'required' || p.pqcModeB === 'required') ? '✓ PQC required — classical-only peers rejected' : p.pqc ? 'optional — a classical-only peer would still be accepted' : 'n/a'}</span></div>
      </div>`;
    } else if (t.lastAttempt && t.lastAttempt.trace && t.lastAttempt.trace.length) {
      html += `<h4>Last attempt</h4><div class="formula">${t.lastAttempt.trace.map(esc).join('\n')}\n✕ ${esc(t.lastAttempt.code || '')}</div>`;
    }
    body.innerHTML = html;
  }
  function srcOf(end) { const d = lab.dev(end.dev); const i = d.ifaces[end.if]; if (!i) return ''; const s = i.tunnel.source; return /^\d/.test(s) ? s : (d.ifaces[s] || {}).ip || ''; }
  function ladder(p, I, R) {
    const msg = (dir, name, chips, pq) => `<div class="msg ${dir}${pq ? ' pq' : ''}"><span></span><div class="arrow"><div class="name">${name}</div><div class="line"></div><div class="chips">${chips.map(c => `<span class="chip${c[1] ? ' ' + c[1] : ''}">${esc(c[0])}</span>`).join('')}</div></div><span></span></div>`;
    const ke = `KE: ${DH_LABEL[p.group] || 'DH ' + p.group} (${DH_KE_BYTES[p.group] || '?'} B)`;
    const sa1 = `SA: ${p.enc}/${p.integ || 'AEAD'}/DH${p.group}${p.pqc ? ' + ADDKE1=' + PQC_LABEL[p.pqc] : ''}`;
    const ntf = [p.frag && ['N(IKEV2_FRAGMENTATION_SUPPORTED)'], p.pqc && ['N(INTERMEDIATE_EXCHANGE_SUPPORTED)', 'pq'], p.ppk && ['N(USE_PPK)', 'ppk']].filter(Boolean);
    const [ek, ct] = p.pqc ? MLKEM_SIZES[p.pqc] : [0, 0];
    let h = `<h4>IKEv2 exchange</h4><div class="ladder"><div class="end">${I}</div><div></div><div class="end">${R}</div>`;
    h += msg('ltr', 'IKE_SA_INIT request', [[sa1, p.pqc ? 'pq' : ''], [ke], ['Ni'], ...ntf]);
    h += msg('rtl', 'IKE_SA_INIT response', [[sa1, p.pqc ? 'pq' : ''], [ke], ['Nr'], ...ntf]);
    if (p.pqc) {
      h += msg('ltr', 'IKE_INTERMEDIATE request', [[`KE: ${PQC_LABEL[p.pqc]} encapsulation key (${ek} B)`, 'pq'], [p.frag ? `fragmented · MTU ${p.fragMtu - 28} B` : 'unfragmented']], true);
      h += msg('rtl', 'IKE_INTERMEDIATE response', [[`KE: ${PQC_LABEL[p.pqc]} ciphertext (${ct} B)`, 'pq'], [p.frag ? `fragmented · MTU ${p.fragMtu - 28} B` : 'unfragmented']], true);
    }
    const auth = [['IDi/IDr'], ['AUTH: PSK'], ...(p.ppk ? [[`N(PPK_IDENTITY: ${p.ppk})`, 'ppk']] : []), [`SA: ${p.esp}`], ['TSi', ''], ['TSr', '']];
    h += msg('ltr', 'IKE_AUTH request', auth);
    h += msg('rtl', 'IKE_AUTH response', auth);
    return h + '</div>';
  }

  /* ═══════════════════════ Resizers ═══════════════════════ */
  function dragger(handle, onMove) {
    handle.addEventListener('pointerdown', e => {
      e.preventDefault(); handle.classList.add('drag'); handle.setPointerCapture(e.pointerId);
      const mv = ev => onMove(ev); const up = () => { handle.classList.remove('drag'); handle.removeEventListener('pointermove', mv); handle.removeEventListener('pointerup', up); };
      handle.addEventListener('pointermove', mv); handle.addEventListener('pointerup', up);
    });
  }
  dragger($('#divider'), e => { const w = Math.max(300, Math.min(window.innerWidth * 0.7, e.clientX)); $('#tutorial').style.width = w + 'px'; });
  dragger($('#hresizer'), e => { const top = $('#topo-wrap').getBoundingClientRect().top; $('#topo-wrap').style.height = Math.max(150, Math.min(window.innerHeight * 0.65, e.clientY - top)) + 'px'; });
  $('#divider').addEventListener('keydown', e => { const t = $('#tutorial'); const w = t.getBoundingClientRect().width; if (e.key === 'ArrowLeft') t.style.width = Math.max(300, w - 30) + 'px'; if (e.key === 'ArrowRight') t.style.width = Math.min(window.innerWidth * 0.7, w + 30) + 'px'; });

  /* ═══════════════════════ Boot ═══════════════════════ */
  $('#modal-close').addEventListener('click', closeInspector);
  $('#modal-bg').addEventListener('click', e => { if (e.target.id === 'modal-bg') closeInspector(); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && inspKey) closeInspector(); });
  $('#btn-reset').addEventListener('click', () => { if (confirm('Reset all three routers and your progress?')) location.reload(); });
  drawStatic();
  buildConsoles();
  renderSteps();
  refresh();
  activate(0);
  setInterval(() => { lab.tick(); flushLogs(); refresh(); checkStep(); if (inspKey) renderInspector(); }, 500);
  let fsSaved = 's'; try { fsSaved = localStorage.getItem('spq-fs') || 's'; } catch (e) { }
  topoReady = true; setFont(fsSaved, false);
  window.__lab = lab; // for debugging in the console
  // extension point for tutorial-specific widgets (e.g. the negotiation panel in v5-quickstart)
  if (typeof window.TUTORIAL.mount === 'function') window.TUTORIAL.mount({
    lab, typeCmd, selectDev, refresh, checkStep, track: TRACK_ID,
    isBusy: () => busy, setBusy: v => { busy = !!v; }, onStep: fn => stepListeners.push(fn), current: () => cur,
  });
})();
