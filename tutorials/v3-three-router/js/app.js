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
      // multi-line paste behaves like a terminal: every complete line is entered as a command,
      // a last line without a newline stays in the input for the learner to finish
      inp.addEventListener('paste', e => {
        const text = (e.clipboardData || window.clipboardData).getData('text');
        if (!/[\r\n]/.test(text)) return;
        e.preventDefault();
        const start = inp.selectionStart ?? inp.value.length, end = inp.selectionEnd ?? inp.value.length;
        const all = (inp.value.slice(0, start) + text + inp.value.slice(end)).replace(/\r\n?/g, '\n').replace(/\t/g, ' ');
        const lines = all.split('\n'); const rest = lines.pop();
        pasteLines(k, lines, rest);
      });
      line(k, `${def.hostname} con0 is now available — Cisco ${def.model}, IOS XE ${(def.version || '26.02.01').replace(/^(\d+)\.0?(\d+).*$/, '$1.$2')} (simulated)`, 'term-banner');
      line(k, 'Educational simulator: output may differ from real routers. Not for validating configurations.', 'term-banner');
      line(k, `Type "?" for help. Tab completes, ↑/↓ recall history, Ctrl+Z leaves config mode.`, 'term-banner');
      line(k, '', '');
      setPrompt(k);
    }
    const tools = document.createElement('div'); tools.className = 'term-tools';
    // syslog and debug messages always reach the console, as on a router's con0 (no filter)
    tools.innerHTML = '<button type="button" class="term-tool" id="tool-clear" title="Clear this console">Clear</button>';
    tabs.appendChild(tools);
    try { localStorage.removeItem('spq-logs'); } catch (e) { }
    tools.querySelector('#tool-clear').addEventListener('click', () => { T[activeDev].lines.textContent = ''; T[activeDev].inp.focus({ preventScroll: true }); });
    selectDev('r1', false);
  }
  const TS_RE = /^(\*\w{3}\s+\d+ \d{4} [\d:.]+:)(\s.*)$/s;
  const PR_RE = /^([A-Za-z0-9_-]+(?:\([^)]*\))?[>#])(.*)$/s;
  function line(k, text, cls) {
    const d = document.createElement('div'); d.className = 'ln' + (cls ? ' ' + cls : '');
    const m = (cls === 'log' || cls === 'debug') ? TS_RE.exec(text) : cls === 'cmd' ? PR_RE.exec(text) : null;
    if (m) { const a = document.createElement('span'); a.className = cls === 'cmd' ? 'pr' : 'ts'; a.textContent = m[1]; d.append(a, m[2]); }
    else d.textContent = text;
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
  async function pasteLines(k, lines, rest) {
    const t = T[k]; t.inp.value = ''; t.hist = -1;
    // drop the blank lines that editors add around a copied block, keep blank lines inside it
    while (lines.length && !lines[0].trim()) lines.shift();
    for (const l of lines) { submit(k, l.replace(/\s+$/, '')); await sleep(reduceMotion ? 0 : 25); }
    t.inp.value = rest.replace(/^\s+$/, '');
    t.inp.focus({ preventScroll: true });
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
          <span class="step-num"><span>${i + 1}</span></span><span class="step-title">${esc(s.title)}</span><span class="tag ${s.part}">${PART[s.part]}</span>
        </button>
        <div class="step-body" id="step-body-${i}">
          ${s.alt ? `<div class="variant v-main">${s.html}</div><div class="variant v-alt" hidden>${s.alt.html}</div>` : s.html}
          <div class="step-hint" id="hint-${i}" role="status"></div>
          <div class="step-actions">
            ${info ? `<button class="btn" data-continue="${i}">${i === STEPS.length - 1 ? 'Finish' : 'Start the lab'}</button>` : `<button class="btn success" data-showme="${i}">▶ Show Me</button>`}
            <span class="step-done">✓ Step complete</span>
          </div>
        </div>`;
      li.querySelector('.step-head').addEventListener('click', () => toggleStep(i));
      structureStep(li);
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
  // reading order inside a step: goal first, the "what each line does" tables folded away
  /* ── commands follow the learner's own object names ──
     Tutorials name their objects (CLASSICAL-KEYRING …). A learner who chose other names gets the
     snippets, Show Me and ▶ typed against THEIR objects, read live from the router. */
  const NAME_ROLES = window.TUTORIAL.NAME_ROLES || {};
  const reEsc = x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  function adaptCmds(dev, cmds) {
    if (!lab.dev(dev) || !Object.keys(NAME_ROLES).length) return cmds;
    const nm = lab.vpnNames(dev); let kr = null, changed = false;
    const out = cmds.map(raw => {
      let line = raw;
      for (const [canon, role] of Object.entries(NAME_ROLES)) {
        if (!line.includes(canon) || nm.exists[role](canon) || !nm[role] || nm[role] === canon) continue;
        line = line.replace(new RegExp(`(^|\\s)${reEsc(canon)}(?=$|\\s)`, 'g'), `$1${nm[role]}`);
      }
      const k = /^\s*crypto ikev2 keyring (\S+)/.exec(line); if (k) kr = k[1]; else if (/^\S/.test(line) && !/^\s*peer /.test(line)) kr = /^\s*(exit|!)/.test(line) ? kr : null;
      // `peer R3` inside the learner's keyring: use their peer entry for the tunnel peer
      const pm = /^(\s*)peer (\S+)$/.exec(line);
      if (pm && kr && lab.dev(dev).crypto.keyrings[kr]) {
        const peers = lab.dev(dev).crypto.keyrings[kr].peers;
        if (!peers[pm[2]]) { const names = Object.keys(peers); const pick = (nm.dest && Object.keys(peers).find(n => peers[n].address === nm.dest)) || (names.length === 1 ? names[0] : null); if (pick) line = `${pm[1]}peer ${pick}`; }
      }
      if (line !== raw) changed = true;
      return line;
    });
    out.changed = changed; return out;
  }
  function adaptRun(run) {
    const byDev = {}; run.forEach(([k, c], i) => (byDev[k] = byDev[k] || []).push(i));
    const res = run.map(x => x.slice());
    for (const [k, idx] of Object.entries(byDev)) { const a = adaptCmds(k, idx.map(i => run[i][1])); idx.forEach((i, j) => { res[i][1] = a[j]; }); }
    return res;
  }
  function adaptSnippets(li) {
    if (!li || !Object.keys(NAME_ROLES).length) return;
    li.querySelectorAll('.cfg').forEach(box => {
      const pre = box.querySelector('pre'), chip = box.querySelector('.dev-chip'); if (!pre || !chip) return;
      const dev = ([...chip.classList].map(c => /^dev-(r\d)$/.exec(c)).find(Boolean) || [])[1]; if (!dev) return;
      if (pre.dataset.orig == null) pre.dataset.orig = pre.textContent;
      const a = adaptCmds(dev, pre.dataset.orig.split('\n')); const txt = a.join('\n');
      if (pre.textContent !== txt) pre.textContent = txt;
      let tag = box.querySelector('.cfg-adapted');
      if (a.changed && !tag) { tag = document.createElement('span'); tag.className = 'cfg-adapted'; tag.textContent = 'uses your names'; tag.title = 'Object names in this snippet were taken from your configuration'; box.querySelector('.cfg-head').appendChild(tag); }
      if (!a.changed && tag) tag.remove();
    });
  }
  // which variant of a step applies right now (e.g. the smart-defaults version of the ML-KEM steps)
  const altOn = s => { try { return !!(s.alt && s.alt.when(lab)); } catch (e) { return false; } };
  const runOf = s => adaptRun(altOn(s) ? s.alt.run : s.run);
  function syncVariants() {
    document.querySelectorAll('.step.open').forEach(adaptSnippets);
    STEPS.forEach((s, i) => {
      if (!s.alt) return; const li = $('#step-' + i); if (!li) return;
      const on = altOn(s); li.querySelector('.v-main').hidden = on; li.querySelector('.v-alt').hidden = !on;
    });
  }
  function structureStep(li) {
    const bodies = li.querySelectorAll('.variant'); if (bodies.length) { bodies.forEach(structureBody); return; }
    structureBody(li.querySelector('.step-body'));
  }
  function structureBody(body) {
    if (!body) return;
    const goal = body.querySelector('.goal');
    if (goal) {
      goal.innerHTML = goal.innerHTML.replace(/^\s*Goal:\s*/, '');
      const lab = document.createElement('span'); lab.className = 'goal-label'; lab.textContent = 'Goal';
      goal.prepend(lab); body.prepend(goal);
    }
    body.querySelectorAll('table.t:not(.mono)').forEach(t => {
      const rows = [...t.rows]; if (!rows.length || t.querySelector('th')) return;
      if (!rows.every(r => r.cells[0] && r.cells[0].firstElementChild && r.cells[0].firstElementChild.tagName === 'CODE')) return;
      const d = document.createElement('details'); d.className = 'why';
      d.innerHTML = '<summary>What each line does</summary>';
      t.replaceWith(d); d.appendChild(t);
    });
  }
  function buildStepNav() {
    const nav = document.createElement('ol'); nav.className = 'step-nav'; nav.id = 'step-nav'; nav.setAttribute('aria-label', 'Steps');
    STEPS.forEach((s, i) => {
      const li = document.createElement('li'); const b = document.createElement('button');
      b.type = 'button'; b.textContent = i + 1; b.title = `${i + 1}. ${s.title}`; b.setAttribute('aria-label', `Step ${i + 1}: ${s.title}`); b.dataset.status = 'locked';
      b.addEventListener('click', () => { toggleStep(i, true); const el = $('#step-' + i); el.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' }); });
      // collapsed pane: a double click on the number does what the step's own button does (Show Me, or Continue)
      b.addEventListener('dblclick', () => { if (!collapsed()) return; if (STEPS[i].run.length) showMe(i); else complete(i); });
      li.appendChild(b); nav.appendChild(li);
    });
    $('.tut-head').appendChild(nav);
    // collapse the instructions to a column of step numbers
    const tg = document.createElement('button');
    tg.type = 'button'; tg.className = 'tut-collapse'; tg.id = 'tut-collapse';
    tg.addEventListener('click', () => setCollapsed(!collapsed(), true));
    $('.tut-head').appendChild(tg);
    let saved = false; try { saved = localStorage.getItem('spq-tut-collapsed') === '1'; } catch (e) { }
    setCollapsed(saved, false);
  }
  const collapsed = () => $('#tutorial').classList.contains('collapsed');
  function setCollapsed(on, save) {
    $('#tutorial').classList.toggle('collapsed', on);
    const tg = $('#tut-collapse'), lbl = on ? 'Expand the instructions' : 'Collapse the instructions to the step numbers';
    tg.textContent = on ? '»' : '«'; tg.title = lbl; tg.setAttribute('aria-label', lbl); tg.setAttribute('aria-expanded', !on);
    document.querySelectorAll('#step-nav button').forEach((b, i) => {
      const s = STEPS[i]; b.title = on ? `${i + 1}. ${s.title} · double-click: ${s.run.length ? 'Show Me' : 'continue'}` : `${i + 1}. ${s.title}`;
    });
    if (save) try { localStorage.setItem('spq-tut-collapsed', on ? '1' : '0'); } catch (e) { }
  }
  function syncStepNav() {
    document.querySelectorAll('#step-nav button').forEach((b, i) => { b.dataset.status = done.has(i) ? 'done' : i === cur ? 'active' : 'locked'; b.setAttribute('aria-current', i === cur); });
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
    const btn = document.querySelector(`[data-showme="${i}"]`), nb = document.querySelectorAll('#step-nav button')[i];
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Typing…'; } if (nb) nb.classList.add('running');
    let prev = null;
    for (const [k, cmd] of runOf(s)) {
      const d = lab.dev(k);
      if (k !== prev) {
        if (d.mode === 'exec' && cmd !== 'enable') await typeCmd(k, 'enable');
        else if (!['exec', 'priv'].includes(d.mode) && (cmd === 'configure terminal' || /^(show|ping|clear|traceroute|debug)/.test(cmd))) await typeCmd(k, 'end');
      }
      if (lab.dev(k).mode === 'priv' && cmd === 'enable') { prev = k; continue; }
      await typeCmd(k, cmd); prev = k;
    }
    if (btn) { btn.textContent = '▶ Show Me again'; btn.disabled = false; } if (nb) nb.classList.remove('running'); busy = false;
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
    syncStepNav();
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
  // `layout: 'triangle'` (GRE lab): R2 on top as the hub, inside a cloud that stands for the whole WAN; spokes below
  const TRI = TOPO.layout === 'triangle';
  const PT = TRI ? { r1: [150, 214], r2: [480, 80], r3: [810, 214] } : { r1: [150, Y], r2: [480, Y], r3: [810, Y] };
  const svg = $('#topo');
  const el = (tag, attrs = {}, parent) => { const n = document.createElementNS(SVGNS, tag); for (const [a, v] of Object.entries(attrs)) n.setAttribute(a, v); if (parent) parent.appendChild(n); return n; };
  let gLinks, gTun, gPkt, tunSig = '';
  function drawStatic() {
    svg.innerHTML = '';
    // router outline: the Spotlight deep blue gradient (Cisco Blue → Medium Blue)
    const defs = el('defs', {}, svg);
    const gr = el('linearGradient', { id: 'g-router', x1: 0, y1: 0, x2: 1, y2: 1 }, defs);
    el('stop', { offset: '0%', 'stop-color': '#009de2' }, gr); el('stop', { offset: '100%', 'stop-color': '#0a60ff' }, gr);
    gTun = el('g', { id: 'g-tun' }, svg);
    if (TRI) drawCloud();
    gLinks = el('g', { id: 'g-links' }, svg);
    if (TRI) drawTriangleLinks(); else for (const l of TOPO.links) {
      const [a, b] = [l.a, l.b]; const x1 = POS[a[0]] + 50, x2 = POS[b[0]] - 50;
      el('line', { class: 'link', x1, y1: Y, x2, y2: Y }, gLinks);
      el('circle', { class: 'dot-up', cx: x1 + 6, cy: Y, r: 4.5, 'data-port': a.join(':') }, gLinks);
      el('circle', { class: 'dot-up', cx: x2 - 6, cy: Y, r: 4.5, 'data-port': b.join(':') }, gLinks);
      const t = el('text', { class: 'lbl-link', x: (x1 + x2) / 2, y: Y + 46, 'text-anchor': 'middle' }, gLinks); t.textContent = `${l.label} · ${l.speed}`;
      for (const [end, x, anchor] of [[a, x1, 'start'], [b, x2, 'end']]) {
        const dv = TOPO.devices[end[0]]; const port = dv.interfaces[end[1]]; const ip = port.vlan ? (dv.interfaces['Vlan' + port.vlan] || {}).ip : port.ip;
        const p = el('text', { class: 'lbl-port', x, y: Y + 22, 'text-anchor': anchor }, gLinks); p.textContent = ifShort(end[1]);
        const q = el('text', { class: 'lbl-ip', x, y: Y - 10, 'text-anchor': anchor }, gLinks); q.textContent = ip;
      }
    }
    for (const k of DEVS) {
      const [x, Yr] = PT[k], def = TOPO.devices[k], Y = Yr, hub = TRI && k === 'r2';
      const g = el('g', { class: 'router', 'data-dev': k, tabindex: 0, role: 'button', 'aria-label': `Open ${def.hostname} console` }, svg);
      // Cisco router symbol as a line icon: a cylinder, two arrows meeting on the top face, two leaving it
      const RX = 42, RY = 15, cy = Y - 9, H = 24;
      el('rect', { class: 'ring', x: x - RX - 9, y: cy - RY - 8, width: 2 * RX + 18, height: H + 2 * RY + 16, rx: 12 }, g);
      el('path', { class: 'r-body', d: `M${x - RX},${cy} v${H} a${RX},${RY} 0 0 0 ${2 * RX},0 v${-H}` }, g);
      el('ellipse', { class: 'r-top', cx: x, cy, rx: RX, ry: RY }, g);
      const ar = d => el('path', { class: 'r-arrow', d }, g);
      ar(`M${x - RX + 8},${cy + 1} H${x - 13} m-5,-4.5 l5,4.5 l-5,4.5`);    // in, from the left
      ar(`M${x + RX - 8},${cy - 1} H${x + 13} m5,-4.5 l-5,4.5 l5,4.5`);    // in, from the right
      ar(`M${x - 4},${cy - 1} V${cy - 12} m-4.5,4.5 l4.5,-4.5 l4.5,4.5`);   // out, up
      ar(`M${x + 4},${cy + 1} V${cy + 12} m-4.5,-4.5 l4.5,4.5 l4.5,-4.5`);  // out, down
      const h = el('text', { class: 'host', x, y: Y + (hub ? 44 : TRI ? 52 : 56), 'text-anchor': 'middle' }, g); h.textContent = def.hostname;
      const r = el('text', { class: 'role', x, y: Y + (hub ? 62 : TRI ? 71 : 75), 'text-anchor': 'middle' }, g); r.textContent = def.role;
      g.addEventListener('click', () => selectDev(k, true));
      g.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectDev(k, true); } });
    }
    gPkt = el('g', { id: 'g-pkt' }, svg);
  }
  function drawCloud() {
    const cx = PT.r2[0], cy = PT.r2[1];
    el('path', { class: 'cloud', d: `M${cx - 150},${cy + 58} C${cx - 200},${cy + 58} ${cx - 205},${cy + 4} ${cx - 160},${cy - 6}
      C${cx - 168},${cy - 52} ${cx - 100},${cy - 74} ${cx - 64},${cy - 46} C${cx - 44},${cy - 82} ${cx + 44},${cy - 82} ${cx + 64},${cy - 46}
      C${cx + 100},${cy - 74} ${cx + 168},${cy - 52} ${cx + 160},${cy - 6} C${cx + 205},${cy + 4} ${cx + 200},${cy + 58} ${cx + 150},${cy + 58}
      C${cx + 120},${cy + 86} ${cx + 52},${cy + 84} ${cx + 32},${cy + 66} C${cx + 12},${cy + 84} ${cx - 12},${cy + 84} ${cx - 32},${cy + 66}
      C${cx - 52},${cy + 84} ${cx - 120},${cy + 86} ${cx - 150},${cy + 58} Z` }, svg);
    const t = (y, cls, txt) => { const n = el('text', { class: cls, x: cx - 184, y, 'text-anchor': 'end' }, svg); n.textContent = txt; };
    t(26, 'cloud-lbl', 'WAN'); t(44, 'cloud-note', 'R2 can stand for'); t(60, 'cloud-note', 'a whole provider network');
  }
  // underlay links from the top of each spoke into R2; every label on the outside of the triangle
  function drawTriangleLinks() {
    const txt = (x, y, cls, s, an) => { const n = el('text', { class: cls, x, y, 'text-anchor': an }, gLinks); n.textContent = s; };
    for (const l of TOPO.links) {
      const se = l.a[0] === 'r2' ? l.b : l.a, he = l.a[0] === 'r2' ? l.a : l.b, [sx, sy] = PT[se[0]], [hx, hy] = PT.r2, o = sx < hx ? -1 : 1, an = o < 0 ? 'end' : 'start';
      const S = [sx - o * 30, sy - 25], H = [hx + o * 44, hy - 2];
      el('line', { class: 'link', x1: S[0], y1: S[1], x2: H[0], y2: H[1] }, gLinks);
      el('circle', { class: 'dot-up', cx: S[0], cy: S[1], r: 4.5, 'data-port': se.join(':') }, gLinks);
      el('circle', { class: 'dot-up', cx: H[0], cy: H[1], r: 4.5, 'data-port': he.join(':') }, gLinks);
      const ipOf = e => { const dv = TOPO.devices[e[0]], p = dv.interfaces[e[1]]; return p.vlan ? (dv.interfaces['Vlan' + p.vlan] || {}).ip : p.ip; };
      txt(S[0] + o * 2, S[1] - 12, 'lbl-ip', ipOf(se), an); txt(S[0] + o * 2, S[1] - 31, 'lbl-port', ifShort(se[1]), an);
      txt(H[0] + o * 8, H[1] - 10, 'lbl-ip', ipOf(he), an); txt(H[0] + o * 8, H[1] - 29, 'lbl-port', ifShort(he[1]), an);
      txt((S[0] + H[0]) / 2 + o * 12, (S[1] + H[1]) / 2 - 14, 'lbl-link', `${l.label} · ${l.speed}`, an);
    }
  }
  // triangle tunnels: spoke to spoke straight along the base; spoke to hub on a curve inside the triangle.
  // Returns the path (drawn from `from`), the badge centre and where each end's tunnel address goes.
  const triPath = (a, b) => {
    if (a !== 'r2' && b !== 'r2') {
      const [l, r] = PT[a][0] < PT[b][0] ? [a, b] : [b, a], y0 = PT.r1[1] - 4, x1 = PT[l][0] + 48, x2 = PT[r][0] - 48;
      return { d: `M${x1},${y0} L${x2},${y0}`, from: l, badge: [(x1 + x2) / 2, y0], addr: { [l]: [x1 + 4, y0 + 24, 'start'], [r]: [x2 - 4, y0 + 24, 'end'] } };
    }
    const sp = a === 'r2' ? b : a, [sx, sy] = PT[sp], [hx, hy] = PT.r2, o = sx < hx ? 1 : -1, an = o > 0 ? 'start' : 'end';
    const x1 = sx + o * 46, y1 = sy - 8, x2 = hx - o * 44, y2 = hy + 6, qx = (x1 + x2) / 2 + o * 40, qy = (y1 + y2) / 2 + 40;
    const q = (u, p0, p1, p2) => (1 - u) ** 2 * p0 + 2 * (1 - u) * u * p1 + u * u * p2;
    return { d: `M${x1},${y1} Q${qx},${qy} ${x2},${y2}`, from: sp, badge: [q(0.5, x1, qx, x2), q(0.5, y1, qy, y2) + 8],
      addr: { [sp]: [x1 + o * 8, y1 + 22, an], r2: [q(0.75, x1, qx, x2) + o * 10, q(0.75, y1, qy, y2) + 12, an] } };
  };
  /* ── whiteboard: drag on the topology to draw; a plain click still opens consoles and inspectors ── */
  const INK = [['ink', 'Black', 'var(--ink)'], ['blue', 'Blue', '#0a60ff'], ['red', 'Red', 'var(--danger)']];
  const ink = { color: 'ink', strokes: [], cur: null, start: null, drew: false };
  let gInk = null;
  function svgPoint(e) { const p = svg.createSVGPoint(); p.x = e.clientX; p.y = e.clientY; const m = svg.getScreenCTM(); return m ? p.matrixTransform(m.inverse()) : p; }
  const inkD = pts => pts.map((p, i) => `${i ? 'L' : 'M'}${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' ');
  function renderInk() {
    if (!gInk || !gInk.isConnected) gInk = el('g', { id: 'g-ink' }, svg); else svg.appendChild(gInk);   // always on top
    gInk.innerHTML = '';
    for (const st of ink.strokes) {
      const col = INK.find(c => c[0] === st.color)[2];
      if (st.type === 'text') {
        const t = el('text', { class: 'ink-text', x: st.x, y: st.y, fill: col, style: `font-size:${st.size}px` }, gInk);
        st.lines.forEach((ln, i) => { const sp = el('tspan', { x: st.x, dy: i ? '1.25em' : 0 }, t); sp.textContent = ln || ' '; });
      } else el('path', { class: 'ink-stroke', d: inkD(st.pts), stroke: col, style: `stroke-width:${st.w || 3.5}` }, gInk);
    }
    const u = $('#ink-undo'), c = $('#ink-clear'); if (u) u.disabled = !ink.strokes.length; if (c) c.hidden = !ink.strokes.length;
  }
  function openTextEditor(e) {
    const wrap = $('#topo-wrap'), wr = wrap.getBoundingClientRect(), m = svg.getScreenCTM(); if (!m) return;
    const px = 16 * fsScale(), p = svgPoint(e), color = ink.color, col = INK.find(c => c[0] === color)[2];
    const ta = document.createElement('textarea');
    ta.className = 'ink-editor'; ta.rows = 1; ta.setAttribute('aria-label', 'Note on the topology: Escape when done');
    Object.assign(ta.style, { left: `${e.clientX - wr.left}px`, top: `${e.clientY - wr.top}px`, fontSize: `${px}px`, color: col });
    wrap.appendChild(ta); ta.focus();
    const grow = () => { ta.style.height = 'auto'; ta.style.height = ta.scrollHeight + 'px'; ta.style.width = 'auto'; ta.style.width = Math.max(80, ta.scrollWidth + 4) + 'px'; };
    ta.addEventListener('input', grow); grow();
    let done = false;
    const commit = () => {
      if (done) return; done = true;
      const text = ta.value.replace(/\s+$/, ''); ta.remove();
      if (!text) return;
      const size = px / m.a;   // the size it was typed at; it then zooms with the topology
      ink.strokes.push({ type: 'text', color, x: p.x, y: p.y + size * 0.85, size, lines: text.split('\n') }); renderInk();
    };
    ta.addEventListener('keydown', ev => { if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); commit(); } });
    ta.addEventListener('blur', commit);
  }
  function setupWhiteboard() {
    const fsg = $('.fs-group'), bar = $('.topo-toolbar'); if (!fsg && !bar) return;
    const tools = document.createElement('span'); tools.className = 'ink-tools'; tools.setAttribute('role', 'group'); tools.setAttribute('aria-label', 'Drawing on the topology');
    tools.innerHTML = `<span class="ink-lbl" aria-hidden="true" title="Drag on the topology to draw">✎</span>${INK.map(([k, n, c]) => `<button type="button" class="ink-sw" data-ink="${k}" aria-pressed="${k === ink.color}" title="${n} pen: drag on the topology to draw" aria-label="${n} pen" style="--sw:${c}"></button>`).join('')}
      <button type="button" class="ink-btn" id="ink-undo" title="Undo the last drawing" aria-label="Undo the last drawing" disabled>↶</button><button type="button" class="ink-link" id="ink-clear" hidden>Clear all</button>`;
    // next to the text-size and theme controls in the header
    if (fsg) fsg.parentNode.insertBefore(tools, fsg); else bar.appendChild(tools);
    const hint = $('.topo-hint'); if (hint) hint.textContent = 'Click a router for its console · click a tunnel to inspect it · drag to draw · double-click to write';
    tools.addEventListener('click', e => {
      const sw = e.target.closest('[data-ink]');
      if (sw) { ink.color = sw.dataset.ink; tools.querySelectorAll('[data-ink]').forEach(b => b.setAttribute('aria-pressed', b === sw)); }
      if (e.target.closest('#ink-undo')) { ink.strokes.pop(); renderInk(); }
      if (e.target.closest('#ink-clear')) { ink.strokes = []; renderInk(); }
    });
    svg.addEventListener('pointerdown', e => {
      if (e.button !== 0) return;
      if (e.pointerType === 'touch') { zoom.touches.set(e.pointerId, [e.clientX, e.clientY]); if (zoom.touches.size >= 2) return startPinch(); }
      ink.start = svgPoint(e); ink.cur = null; ink.drew = false; ink.pid = e.pointerId;
    });
    svg.addEventListener('pointermove', e => {
      if (zoom.touches.has(e.pointerId)) { zoom.touches.set(e.pointerId, [e.clientX, e.clientY]); if (zoom.pinch) return movePinch(); }
      if (!ink.start || e.pointerId !== ink.pid) return;
      const p = svgPoint(e);
      if (!ink.cur) {
        if (Math.hypot(p.x - ink.start.x, p.y - ink.start.y) < 4) return;   // still a click
        // the same on-screen width at any zoom while drawing; the stroke then scales with the topology
        ink.cur = { color: ink.color, pts: [[ink.start.x, ink.start.y]], w: 3.5 * (zoom.vb ? zoom.vb.w / zoom.base.w : 1) }; ink.strokes.push(ink.cur); ink.drew = true;
        try { svg.setPointerCapture(e.pointerId); } catch (err) { }
        svg.classList.add('inking'); document.body.classList.add('inking');
        const sel = window.getSelection && window.getSelection(); if (sel) sel.removeAllRanges();
      }
      ink.cur.pts.push([p.x, p.y]); renderInk();
    });
    const end = e => {
      zoom.touches.delete(e.pointerId); if (zoom.touches.size < 2) zoom.pinch = null;
      ink.start = null; ink.cur = null; svg.classList.remove('inking'); document.body.classList.remove('inking');
    };
    svg.addEventListener('pointerup', end); svg.addEventListener('pointercancel', end);
    setupZoom();
    // the click that ends a drawing must not open a console or an inspector
    svg.addEventListener('click', e => { if (ink.drew) { ink.drew = false; e.stopPropagation(); e.preventDefault(); } }, true);
    // double-click on empty space: type a note there (Enter = new line, Escape or a click elsewhere = done)
    svg.addEventListener('dblclick', e => {
      if (e.target.closest('.router, [data-key], .ink-text')) return;
      e.preventDefault(); const sel = window.getSelection && window.getSelection(); if (sel) sel.removeAllRanges();
      openTextEditor(e);
    });
    renderInk();
  }
  /* ── zoom: pinch (trackpad or two fingers) or − / + zooms around the gesture, 25%–400%; zoomed out, the topology
        shrinks into a large blank whiteboard; two-finger scroll or drag pans ── */
  const ZMIN = 0.25, ZMAX = 4;
  const zoom = { base: null, vb: null, touches: new Map(), pinch: null };
  function setVB() {
    const B = zoom.base, v = zoom.vb;
    v.w = Math.min(B.w / ZMIN, Math.max(B.w / ZMAX, v.w)); v.h = v.w * B.h / B.w;
    // the whiteboard reaches two topology-widths beyond each side
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
    if (ink.cur) { ink.strokes.splice(ink.strokes.indexOf(ink.cur), 1); renderInk(); }   // the first finger had started a stroke
    ink.start = null; ink.cur = null; ink.drew = false; zoom.pinch = pinchState();
  }
  function movePinch() {
    const n = pinchState(), o = zoom.pinch;
    zoomAt(n.mx, n.my, n.d / o.d); panBy(n.mx - o.mx, n.my - o.my); zoom.pinch = n;
  }
  function setupZoom() {
    const [x, y, w, h] = svg.getAttribute('viewBox').split(/[\s,]+/).map(Number);
    zoom.base = { x, y, w, h }; zoom.vb = { x, y, w, h };
    const bar = $('#topo-wrap');   // floats in the topology's corner, so the toolbar never grows
    if (bar) {
      const zc = document.createElement('div'); zc.className = 'zoom-ctl'; zc.setAttribute('role', 'group'); zc.setAttribute('aria-label', 'Topology zoom');
      zc.innerHTML = '<button type="button" id="zoom-out" title="Zoom out" aria-label="Zoom out">−</button><button type="button" id="zoom-pct" aria-label="Reset zoom to 100%">100%</button><button type="button" id="zoom-in" title="Zoom in" aria-label="Zoom in">+</button>';
      bar.appendChild(zc);
      const mid = f => { const r = svg.getBoundingClientRect(); zoomAt(r.left + r.width / 2, r.top + r.height / 2, f); };
      zc.addEventListener('click', e => {
        if (e.target.closest('#zoom-in')) mid(1.25); else if (e.target.closest('#zoom-out')) mid(0.8);
        else if (e.target.closest('#zoom-pct')) { Object.assign(zoom.vb, zoom.base); setVB(); }
      });
    }
    const hint = $('.topo-hint'); if (hint) hint.textContent += ' · pinch to zoom';
    setVB();
    // trackpad pinch arrives as ctrl + wheel (Chrome, Firefox, Edge, recent Safari); plain two-finger scroll pans once zoomed
    svg.addEventListener('wheel', e => {
      if (e.ctrlKey) { e.preventDefault(); zoomAt(e.clientX, e.clientY, Math.exp(-e.deltaY * 0.01)); }
      else if (Math.abs(zoom.vb.w - zoom.base.w) > 0.5) { e.preventDefault(); panBy(-e.deltaX, -e.deltaY); }
    }, { passive: false });
    // older Safari on macOS: gesture events
    let gs = 1;
    svg.addEventListener('gesturestart', e => { e.preventDefault(); gs = 1; });
    svg.addEventListener('gesturechange', e => { e.preventDefault(); zoomAt(e.clientX, e.clientY, e.scale / gs); gs = e.scale; });
    svg.addEventListener('gestureend', e => e.preventDefault());
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
    // status word first (never colour alone), then the interface and what protects the key exchange
    const tu = ifShort(t.a.if);
    if (t.state === 'up' && t.half) return { kind: 'fail', st: 'HALF-OPEN', label: `${tu} · ${lab.dev(t.half).hostname} has no SA` };
    if (t.state === 'up' && t.sa.child.down) return { kind: 'fail', st: 'NO IPSEC SA', label: `${tu} · IKE up` };
    if (t.state === 'up') {
      const p = t.params; const kind = p.pqc ? 'pqc' : p.ppk ? 'ppk' : 'classic';
      const what = p.pqc ? `${PQC_LABEL[p.pqc]} + DH ${p.group}` : p.ppk ? `DH ${p.group} + PPK` : `DH ${p.group} + PSK`;
      return { kind, st: 'UP', label: `${tu} · ${what}` };
    }
    if (t.state === 'fail') return { kind: 'fail', st: 'DOWN', label: `${tu} · ${t.code}` };
    return { kind: 'neg', st: 'NEGOTIATING', label: tu };
  }
  function drawTunnels() {
    const tuns = lab.tunnels();
    const halves = lab.halfTunnels().filter(h => h.protected && !h.shutdown && h.mode === 'ipsec ipv4');
    const ownerOf = ip => DEVS.find(k => Object.values(lab.dev(k).ifaces).some(i => i.ip === ip && i.kind !== 'tunnel'));
    const sig = JSON.stringify([fsScale(), lab.greTunnels().map(g => [g.key, g.upA, g.upB]), tuns.map(t => t.half), tuns.map(t => [tunAddr(t.a.dev, t.a.if), tunAddr(t.b.dev, t.b.if)].map(i => i && i.ip + '/' + i.mask)), tuns.map(t => [t.key, t.state, t.code, t.params && [t.params.pqc, t.params.ppk], t.sa && t.sa.child.down]), halves.map(h => [h.dev, h.if, h.dest])]);
    if (sig === tunSig) return; tunSig = sig;
    gTun.innerHTML = '';
    const items = tuns.map(t => ({ key: t.key, a: t.a.dev, b: t.b.dev, ends: [[t.a.dev, t.a.if], [t.b.dev, t.b.if]], ...tunnelView(t) }));
    for (const h of halves) { const o = ownerOf(h.dest); if (o && o !== h.dev) items.push({ key: 'half:' + h.dev + ':' + h.if, a: h.dev, b: o, ends: [[h.dev, h.if]], kind: 'half', st: 'WAITING', label: `${ifShort(h.if)} on ${lab.dev(h.dev).hostname} · no tunnel on ${lab.dev(o).hostname}` }); }
    for (const g of lab.greTunnels()) {
      const H = k => lab.dev(k).hostname, tu = ifShort(g.a.if);
      if (!g.b) { items.push({ key: g.key, a: g.a.dev, b: g.owner, ends: [[g.a.dev, g.a.if]], kind: g.upA ? 'gre' : 'fail', st: g.upA ? 'UP' : 'DOWN', label: `${tu} · GRE · no tunnel on ${H(g.owner)}` }); continue; }
      const ends = [[g.a.dev, g.a.if], [g.b.dev, g.b.if]];
      if (g.upA && g.upB) { items.push({ key: g.key, a: g.a.dev, b: g.b.dev, ends, kind: 'gre', st: 'UP', label: `${tu} · GRE · not encrypted` }); continue; }
      if (!g.upA && !g.upB) { items.push({ key: g.key, a: g.a.dev, b: g.b.dev, ends, kind: 'fail', st: 'DOWN', label: `${tu} · GRE · both ends down` }); continue; }
      // one end down, the other still up/up (no keepalive to notice): it keeps sending GRE packets that are dropped
      const [upE, dnE, why] = g.upA ? [g.a, g.b, g.reasonB] : [g.b, g.a, g.reasonA];
      items.push({ key: g.key, a: g.a.dev, b: g.b.dev, ends, kind: 'fail', st: `${H(upE.dev)} UP`, split: dnE.dev,
        label: `${H(dnE.dev)} ${ifShort(dnE.if)} ${why === 'shutdown' ? 'admin down' : 'down'} · traffic dropped` });
    }
    const fs = fsScale();
    for (const it of items) {
      const tp = TRI ? triPath(it.a, it.b) : null;
      const { d, apex, at } = tp ? { d: tp.d, apex: tp.badge, at: null } : arcPath(it.a, it.b);
      const g = el('g', { 'data-key': it.key, role: 'button', tabindex: 0, 'aria-label': `Inspect tunnel: ${it.label}` }, gTun);
      el('path', { class: 'tun-hit', d }, g);
      if (it.split) {
        // half and half: the up end's GRE line, the down end's half red and dashed (clipped at the badge)
        const right = PT[it.split][0] > apex[0], cid = 'clip-' + cssId(it.key), cd = cid + '-d', defs = el('defs', {}, g);
        el('rect', { x: right ? -2000 : apex[0], y: -2000, width: right ? apex[0] + 2000 : 4000, height: 4000 }, el('clipPath', { id: cid }, defs));
        el('rect', { x: right ? apex[0] : -2000, y: -2000, width: right ? 4000 : apex[0] + 2000, height: 4000 }, el('clipPath', { id: cd }, defs));
        el('path', { class: 'tun gre', d, id: 'tun-' + cssId(it.key), 'data-from': tp ? tp.from : it.a, 'clip-path': `url(#${cid})` }, g);
        el('path', { class: 'tun fail', d, 'clip-path': `url(#${cd})` }, g);
      } else el('path', { class: 'tun ' + it.kind, d, id: 'tun-' + cssId(it.key), 'data-from': tp ? tp.from : it.a }, g);
      const lg = el('g', { class: 'tun-label' }, g);
      const full = `${it.st} · ${it.label}`;
      const w = full.length * 8.6 * fs + 34;
      // tunnel interface addresses where the arc leaves each router, overlay subnet under the pill
      const addrs = it.ends.map(([dv, ifn]) => ({ dv, i: tunAddr(dv, ifn) })).filter(x => x.i);
      for (const { dv, i } of addrs) {
        if (tp) {   // triangle: positions come with the path; the hub end shows only the host part
          const [x, y, an] = tp.addr[dv], t = el('text', { class: 'lbl-tun', x, y, 'text-anchor': an }, g);
          t.textContent = dv === 'r2' || it.a === 'r2' || it.b === 'r2' ? '.' + i.ip.split('.').pop() : i.ip;
          const tt = el('title', {}, t); tt.textContent = `${lab.dev(dv).hostname} ${ifShort(it.ends.find(e => e[0] === dv)[1])} ${i.ip}`;
          continue;
        }
        const left = POS[dv] === Math.min(POS[it.a], POS[it.b]);
        // inside the arc, so the two addresses that meet at a hub never collide
        const [px, py] = at(left === (POS[it.a] < POS[it.b]) ? 0.15 : 0.85);
        const t = el('text', { class: 'lbl-tun', x: px + (left ? 10 : -10), y: py + 6, 'text-anchor': left ? 'start' : 'end' }, g);
        // short (adjacent) arcs have no room for two full addresses: show the host part, the badge carries the subnet
        const short = Math.abs(POS[it.a] - POS[it.b]) < 400;
        t.textContent = short ? '.' + i.ip.split('.').pop() : i.ip;
        const tt = el('title', {}, t); tt.textContent = `${lab.dev(dv).hostname} ${ifShort(it.ends.find(e => e[0] === dv)[1])} ${i.ip}`;
      }
      const net = addrs.length ? `overlay ${subnetOf(addrs[0].i)}` : '';
      const h2 = net ? 17 * fs : 0, wb = Math.max(w, net.length * 7.9 * fs + 22);
      const col = `var(--${it.kind === 'half' ? 'neg' : it.kind})`;
      const rect = el('rect', { x: apex[0] - wb / 2, y: apex[1] - 14 * fs - h2 / 2, width: wb, height: 28 * fs + h2, rx: 8, stroke: col }, lg);
      if (net) { const sn = el('text', { class: 'lbl-tun-net', x: apex[0], y: apex[1] + 5 * fs + h2 / 2 + 2, 'text-anchor': 'middle' }, lg); sn.textContent = net; }
      // status badge: coloured dot + bold status word + details, all in ink for contrast
      const ty = apex[1] + 5 * fs - h2 / 2;
      const tx = el('text', { x: apex[0] + 7, y: ty, 'text-anchor': 'middle' }, lg);
      const s1 = el('tspan', { class: 'st' }, tx); s1.textContent = it.st;
      const s2 = el('tspan', {}, tx); s2.textContent = ` · ${it.label}`;
      const dot = el('circle', { cx: 0, cy: ty - 5 * fs, r: 5, fill: col }, lg);
      // fit the badge to the rendered text when the browser can measure it
      let tw = 0; try { tw = tx.getComputedTextLength(); } catch (e) { }
      if (!tw) tw = full.length * 8.6 * fs;
      const bw = Math.max(tw + 40, net ? net.length * 7.9 * fs + 22 : 0);
      rect.setAttribute('x', apex[0] - bw / 2); rect.setAttribute('width', bw);
      dot.setAttribute('cx', apex[0] + 7 - tw / 2 - 11);
      g.addEventListener('click', () => openInspector(it.key));
      g.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openInspector(it.key); } });
    }
  }
  const cssId = s => s.replace(/[^a-zA-Z0-9]/g, '_');
  function drawPorts() {
    gLinks.querySelectorAll('circle[data-port]').forEach(c => { const [d, p] = c.dataset.port.split(':'); c.setAttribute('class', lab.portUp(d, p) ? 'dot-up' : 'dot-down'); });
  }
  function refresh() { drawTunnels(); drawPorts(); syncVariants(); }

  // packet animation along the path a ping took
  async function animatePath(meta) {
    if (reduceMotion || !meta.path) return;
    const hops = [...meta.path.fwd, ...(meta.ok ? meta.path.back : [])];
    for (const h of hops) {
      let pathEl, reverse = false, color = 'var(--cisco-primary)';
      if (h.via === 'tunnel') {
        pathEl = document.getElementById('tun-' + cssId(h.key)); if (!pathEl) continue;
        reverse = pathEl.getAttribute('data-from') !== h.from;
        const cls = pathEl.getAttribute('class'); color = cls.includes('pqc') ? 'var(--pqc)' : cls.includes('ppk') ? 'var(--ppk)' : 'var(--classic)';
      } else {
        pathEl = el('path', { d: `M${PT[h.from][0]},${PT[h.from][1] - (TRI ? 20 : 0)} L${PT[h.to][0]},${PT[h.to][1] - (TRI ? 20 : 0)}`, fill: 'none', stroke: 'none' }, gPkt);
      }
      // fragmented on this hop (bigger than its IP MTU, no DF): two packets, one right behind the other
      if (h.frag) await Promise.all([movePacket(pathEl, reverse, color, h.via === 'tunnel'), new Promise(r => setTimeout(r, 160)).then(() => movePacket(pathEl, reverse, color, h.via === 'tunnel'))]);
      else await movePacket(pathEl, reverse, color, h.via === 'tunnel');
      if (h.via !== 'tunnel') pathEl.remove();
    }
    if (!meta.ok) {
      const drop = meta.path.drop;
      const at = drop ? drop.dev : meta.path.fwd.length ? meta.path.fwd[meta.path.fwd.length - 1].to : null;
      const k0 = at || Object.keys(PT)[0], [x0, yy] = PT[k0];
      // triangle: a spoke's labels sit above it, so the mark goes beside it, on the triangle's inner side
      const side = TRI && k0 !== 'r2' ? (x0 < PT.r2[0] ? 1 : -1) : 0, x = x0 + side * 62;
      const xMark = el('text', { x, y: side ? yy - 2 : yy - 34, 'text-anchor': 'middle', 'font-size': 22, fill: 'var(--fail)', class: 'pkt' }, gPkt); xMark.textContent = '✕';
      // DF set and too big: dropped before the hop, and "fragmentation needed" (M) goes back to the sender
      const note = drop ? el('text', side ? { x: x + side * 14, y: yy - 30, 'text-anchor': side > 0 ? 'start' : 'end', class: 'pkt lbl-drop' } : { x, y: yy - 58, 'text-anchor': 'middle', class: 'pkt lbl-drop' }, gPkt) : null;
      if (note) note.textContent = `M · ${ifShort(drop.if)} MTU ${drop.mtu}`;
      setTimeout(() => { xMark.remove(); if (note) note.remove(); }, drop ? 1800 : 900);
      if (drop) for (const h of [...meta.path.fwd].reverse()) {
        const pe = el('path', { d: `M${PT[h.to][0]},${PT[h.to][1] - (TRI ? 20 : 0)} L${PT[h.from][0]},${PT[h.from][1] - (TRI ? 20 : 0)}`, fill: 'none', stroke: 'none' }, gPkt);
        if (h.via === 'tunnel') { const tp = document.getElementById('tun-' + cssId(h.key)); if (tp) { await movePacket(tp, tp.getAttribute('data-from') === h.from, 'var(--fail)', false); pe.remove(); continue; } }
        await movePacket(pe, false, 'var(--fail)', false); pe.remove();
      }
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
    const gt = lab.greTunnels().find(x => x.key === inspKey);
    if (gt) {
      const R = { source: 'the tunnel source interface is down or has no IP address', destination: 'no tunnel destination is configured', route: 'there is no route to the tunnel destination', recursive: 'the route to the tunnel destination points into the tunnel itself (recursive routing, %TUN-5-RECURDOWN)', keepalive: 'keepalives are not answered', protection: 'GRE over IPsec (tunnel protection on a GRE tunnel) is not modelled in this simulator', shutdown: 'the interface is shut down' };
      const end = (dv, ifn, up, why) => `<li><b>${esc(H(dv))} ${esc(ifn)}</b>: line protocol <b>${up ? 'up' : 'down'}</b>${!up && why ? ` — ${esc(R[why] || why)}` : ''}</li>`;
      $('#modal-title').textContent = `GRE tunnel ${H(gt.a.dev)} ${gt.a.if}${gt.b ? ` ⇄ ${H(gt.b.dev)} ${gt.b.if}` : ''}`;
      const half = gt.b && gt.upA !== gt.upB, upD = half ? (gt.upA ? gt.a.dev : gt.b.dev) : null, dnD = half ? (gt.upA ? gt.b.dev : gt.a.dev) : null;
      body.innerHTML = `<p><span class="status-chip">${gt.upA && (!gt.b || gt.upB) ? 'UP · GRE' : half ? `${esc(H(upD))} UP · ${esc(H(dnD))} DOWN · GRE` : 'DOWN · GRE'}</span></p>
        <ul>${end(gt.a.dev, gt.a.if, gt.upA, gt.reasonA)}${gt.b ? end(gt.b.dev, gt.b.if, gt.upB, gt.reasonB) : ''}</ul>
        ${half ? `<div class="err-box"><b>${esc(H(upD))} still thinks the tunnel is up.</b> Without <code>keepalive</code>, a GRE tunnel's line protocol depends only on its own source and a route to the destination, so ${esc(H(upD))} stays up/up and keeps sending GRE packets that ${esc(H(dnD))} drops. With <code>keepalive</code> on ${esc(H(upD))}, unanswered keepalives would bring its tunnel down too (default every 10 s, down after 3 misses).</div>` : ''}
        ${gt.b ? '' : `<div class="err-box"><b>No tunnel on ${esc(H(gt.owner))}.</b> ${esc(H(gt.a.dev))}'s tunnel can be up/up — its destination is routable — but ${esc(H(gt.owner))} has no tunnel whose source and destination mirror it, so it drops the GRE packets. Without <code>keepalive</code>, IOS does not notice.</div>`}
        <p><b>GRE is not encrypted.</b> It only adds a GRE header and a new IP header; anyone on the path can read the original packets. To encrypt, use an IPsec VTI (<code>tunnel mode ipsec ipv4</code> + <code>tunnel protection ipsec profile …</code>).</p>
        <p class="src">Line protocol rules: Cisco TAC <i>Determine What Impacts GRE Tunnel Interface States</i> and <i>How GRE Keepalives Work</i>.</p>`;
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
  drawStatic(); setupWhiteboard();
  buildConsoles();
  renderSteps();
  buildStepNav();
  refresh();
  activate(0);
  setInterval(() => { lab.tick(); flushLogs(); refresh(); checkStep(); if (inspKey) renderInspector(); }, 500);
  let fsSaved = 's'; try { fsSaved = localStorage.getItem('spq-fs') || 's'; } catch (e) { }
  topoReady = true; setFont(fsSaved, false);
  window.__lab = lab; // for debugging in the console
  window.__adaptRun = adaptRun; // ditto: commands as Show Me would type them
  // extension point for tutorial-specific widgets (e.g. the negotiation panel in v5-quickstart)
  if (typeof window.TUTORIAL.mount === 'function') window.TUTORIAL.mount({
    lab, typeCmd, selectDev, refresh, checkStep, track: TRACK_ID,
    isBusy: () => busy, setBusy: v => { busy = !!v; }, onStep: fn => stepListeners.push(fn), current: () => cur,
  });
})();
