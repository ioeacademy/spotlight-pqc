/* negotiation-panel.js — "choose the parameters on each end, predict, apply, observe" widget for the
   ?track=negotiate quick lab. Outcomes come from the simulator engine, whose negotiation is checked
   against the vpn-negotiation-mismatch-teaching dataset (CML IOS XE 26.02 captures C0–C8, M1/M2/M4).

   Mounted through window.TUTORIAL.mount(api) — see app.js. Types real IOS commands into the consoles. */
(function () {
  'use strict';
  const T = window.TUTORIAL;
  const N = T.NEG;   // shared constants from quick-steps.js
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const clone = o => JSON.parse(JSON.stringify(o));

  const OPTS = {
    enc: ['aes-cbc-128', 'aes-cbc-256', 'aes-gcm-256'],
    integ: ['sha256', 'sha384', 'sha512'],
    group: [19, 20, 21],
    pqc: [['none', 'none'], ['mlkem768', 'ML-KEM-768'], ['mlkem1024', 'ML-KEM-1024'], ['mlkem768 mlkem1024', '768 + 1024']],
    ts: [['esp-gcm 256', 'esp-gcm 256'], ['esp-aes 256 esp-sha256-hmac', 'esp-aes 256 + sha256'], ['esp-aes 128 esp-sha-hmac', 'esp-aes 128 + sha1']],
  };
  const PREDICT = [['up-classic', 'Up, classical'], ['up-pqc', 'Up with ML-KEM'], ['retry', 'Up after a retry'], ['down', 'Down'], ['half', 'Half-open']];
  const LABEL = Object.fromEntries(PREDICT);

  function mount(api) {
    if (api.track !== 'negotiate') return;
    const { lab } = api;
    let applied = { r1: clone(N.BASE.r1), r3: clone(N.BASE.r3) };
    let cfg = { r1: clone(N.BASE.r1), r3: clone(N.BASE.r3) }, initiator = 'r1', prediction = null, running = false;

    const host = document.createElement('section');
    host.className = 'neg-panel'; host.id = 'neg-panel'; host.hidden = true;
    host.setAttribute('aria-label', 'Negotiation parameters');
    document.body.appendChild(host);   // moved into the active step's .neg-slot

    /* ---------- render ---------- */
    const chips = (dev, field) => {
      const sel = cfg[dev][field];
      return OPTS[field].map(v => {
        const i = sel.indexOf(v);
        return `<button type="button" class="neg-chip${i >= 0 ? ' on' : ''}" data-dev="${dev}" data-field="${field}" data-val="${v}" aria-pressed="${i >= 0}">${i >= 0 && sel.length > 1 ? `<b>${i + 1}</b>` : ''}${esc(String(v))}</button>`;
      }).join('');
    };
    const select = (dev, field, opts) => `<select class="neg-sel" data-dev="${dev}" data-field="${field}">${opts.map(([v, l]) => `<option value="${esc(v)}"${String(cfg[dev][field]) === v ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>`;
    const col = dev => {
      const c = cfg[dev], other = dev === 'r1' ? 'R3' : 'R1';
      return `<div class="neg-col">
        <div class="neg-col-head"><span class="dev-chip dev-${dev}">${dev.toUpperCase()}</span>${initiator === dev ? '<span class="neg-ini">initiator</span>' : '<span class="neg-resp">responder</span>'}</div>
        <div class="neg-row"><span class="neg-lbl">Encryption</span><span class="neg-chips">${chips(dev, 'enc')}</span></div>
        <div class="neg-row"><span class="neg-lbl">Integrity</span><span class="neg-chips">${chips(dev, 'integ')}</span></div>
        <div class="neg-row"><span class="neg-lbl">DH group</span><span class="neg-chips">${chips(dev, 'group')}</span></div>
        <div class="neg-row"><span class="neg-lbl">ML-KEM</span><span>${select(dev, 'pqc', OPTS.pqc)}${c.pqc !== 'none' ? `<label class="neg-opt"><input type="checkbox" data-dev="${dev}" data-field="optional"${c.optional ? ' checked' : ''}> optional</label>` : ''}</span></div>
        <div class="neg-row"><span class="neg-lbl">Transform set</span><span>${select(dev, 'ts', OPTS.ts)}</span></div>
        <div class="neg-row"><span class="neg-lbl">Pre-shared key</span><input class="neg-in" data-dev="${dev}" data-field="psk" value="${esc(c.psk)}" spellcheck="false" autocomplete="off"></div>
        <div class="neg-row"><span class="neg-lbl">Accepts ${other} as</span><input class="neg-in mono" data-dev="${dev}" data-field="peerId" value="${esc(c.peerId)}" spellcheck="false" autocomplete="off" aria-label="match identity remote address on ${dev.toUpperCase()}"></div>
      </div>`;
    };
    function render() {
      const cmds = commands();
      const match = N.SCENARIOS.find(sc => same(sc, cfg, initiator));
      host.innerHTML = `
        <div class="neg-head"><b>Negotiation parameters</b><span class="neg-sub">Change one setting at a time. The order of chips is the order on the router.</span></div>
        <div class="neg-presets"><span class="neg-lbl">Dataset scenarios</span>${N.SCENARIOS.map(sc => `<button type="button" class="neg-preset${match === sc ? ' on' : ''}" data-preset="${sc.id}" title="${esc(sc.title)}">${sc.id}</button>`).join('')}<button type="button" class="neg-preset reset" data-preset="C0" title="Back to the identical baseline">↺ baseline</button></div>
        ${match ? `<div class="neg-match">${esc(match.id)} · ${esc(match.title)} <span class="neg-label ${match.label}">${match.label === 'observed' ? 'captured on CML' : match.label}</span></div>` : ''}
        <div class="neg-cols">${col('r1')}${col('r3')}</div>
        <div class="neg-row neg-who"><span class="neg-lbl">Who starts?</span>
          ${['r1', 'r3'].map(d => `<label class="neg-radio"><input type="radio" name="neg-ini" value="${d}"${initiator === d ? ' checked' : ''}> ${d.toUpperCase()} initiates</label>`).join('')}
          <span class="neg-hint">The initiator's first DH group goes in its KE payload; the responder checks the proposal.</span></div>
        <div class="neg-predict" role="radiogroup" aria-label="Your prediction"><span class="neg-lbl">Predict first</span>
          ${PREDICT.map(([v, l]) => `<label class="neg-radio"><input type="radio" name="neg-pred" value="${v}"${prediction === v ? ' checked' : ''}> ${l}</label>`).join('')}</div>
        <details class="neg-cmds"${cmds.length ? '' : ' hidden'}><summary>${cmds.length ? `${cmds.reduce((n, c) => n + c.lines.length, 0)} IOS commands will be typed` : ''}</summary>${cmds.map(c => `<pre><span class="dev-chip dev-${c.dev}">${c.dev.toUpperCase()}</span>\n${esc(c.lines.join('\n'))}</pre>`).join('')}</details>
        <div class="neg-actions">
          <button type="button" class="btn" id="neg-apply"${running ? ' disabled' : ''}>${running ? '⏳ Negotiating…' : '▶ Apply & renegotiate'}</button>
          <span class="neg-note">${prediction ? '' : 'Pick a prediction to compare with the result.'}</span>
        </div>
        <div class="neg-result" id="neg-result" role="status" aria-live="polite"></div>`;
      if (lastResult) showResult(lastResult);
    }
    let lastResult = null;

    /* ---------- config diff → IOS commands ---------- */
    function commands() {
      return ['r1', 'r3'].map(dev => ({ dev, lines: N.commands(dev, applied[dev], cfg[dev]) })).filter(c => c.lines.length);
    }
    const valid = () => ['r1', 'r3'].every(d => cfg[d].enc.length && cfg[d].integ.length && cfg[d].group.length && cfg[d].psk.trim() && /^\d+\.\d+\.\d+\.\d+$/.test(cfg[d].peerId));
    const same = (sc, c, ini) => ['r1', 'r3'].every(d => JSON.stringify(N.apply(sc, d)) === JSON.stringify(c[d])) && (sc.initiator || 'r1') === ini;

    /* ---------- apply: type the commands, renegotiate from the chosen initiator, read the outcome ---------- */
    async function applyAll() {
      if (running || api.isBusy()) return;
      if (!valid()) { lastResult = { error: 'Every router needs at least one encryption, integrity and DH group, a key and a valid peer address.' }; return render(); }
      running = true; api.setBusy(true); lastResult = null; render();
      const resp = initiator === 'r1' ? 'r3' : 'r1';
      try {
        const type = async (dev, cmd) => api.typeCmd(dev, cmd);
        const toPriv = async dev => { const m = lab.dev(dev).mode; if (m === 'exec') await type(dev, 'enable'); else if (m !== 'priv') await type(dev, 'end'); };
        for (const { dev, lines } of commands()) {
          await toPriv(dev); await type(dev, 'configure terminal'); let depth = 0;
          for (const raw of lines) { const ind = raw.length - raw.trimStart().length; for (; depth > ind; depth--) await type(dev, 'exit'); await type(dev, raw.trim()); depth = ind; }
          await type(dev, 'end');
        }
        applied = clone(cfg);
        const seq0 = lab.lastSeq;
        await toPriv(resp); await toPriv(initiator);
        await type(resp, 'clear crypto ikev2 sa');
        await type(initiator, 'clear crypto ikev2 sa');
        await type(initiator, `ping ${N.TUN[resp]} repeat 3`);
        const first = lab.negLog.find(e => e.seq > seq0);
        const st = lab.pairBetween('r1', 'r3');
        // half-open: show what the router that kept its SA does with traffic
        if (first && first.half) { const owner = first.resp; await type(owner, `ping ${N.TUN[first.ini]} repeat 3`); }
        lastResult = classify(first, st);
      } catch (e) { lastResult = { error: e.message }; }
      running = false; api.setBusy(false); api.refresh(); api.checkStep(); render();
    }
    function classify(e, st) {
      if (!e) return { kind: 'down', title: 'No negotiation took place', why: 'Check that both tunnels are configured and the underlay is reachable.' };
      const H = d => d.toUpperCase();
      if (e.ok && e.half) return { kind: 'half', e, title: `Half-open: ${H(e.resp)} is READY, ${H(e.ini)} has no SA`, why: `${H(e.ini)} (the initiator) only checks the responder's identity after ${H(e.resp)} has installed its SAs. ${H(e.resp)} encrypts; ${H(e.ini)} drops the packets.`, look: [`${H(e.resp)}: show crypto ikev2 sa → READY, #pkts encaps increasing`, `${H(e.ini)}: : Failed to locate an item in the database / Auth exchange failed`, `${H(e.ini)}: %CRYPTO-4-RECVD_PKT_INV_SPI`], scen: 'C8' };
      if (e.ok && e.keRetry) return { kind: 'retry', e, title: 'Up, after an INVALID_KE_PAYLOAD retry', why: `${H(e.ini)} guessed its first DH group in the KE payload; ${H(e.resp)} picked another group from the overlap and asked for a new KE. One extra IKE_SA_INIT round trip, no failure.`, look: [`${H(e.resp)}: : The peer's KE payload contained the wrong DH group`, 'show crypto ikev2 stats exchange → IKE_SA_INIT +2, INVALID_KE_PAYLOAD'], scen: 'C4' };
      if (e.ok) {
        const sa = st && st.sa, p = sa ? sa.params : {};
        const offered = ['r1', 'r3'].some(d => applied[d].pqc !== 'none');
        if (e.pqc) return { kind: 'up-pqc', e, title: `Up with ${e.pqc === 'mlkem1024' ? 'ML-KEM-1024' : 'ML-KEM-768'} + DH ${p.group}`, why: 'Both ends offered a common ML-KEM parameter set, so the key exchange is hybrid.', look: ['show crypto ikev2 sa detailed → PQC Key Exchange: ML-KEM-…'] };
        return { kind: 'up-classic', e, title: `Up, classical (DH ${p.group || ''})`, why: offered ? 'ML-KEM was only optional on one side and the other did not offer it: the tunnel fell back to classical DH silently. The only evidence is the missing "PQC Key Exchange:" line.' : 'Encryption, integrity and DH group overlap; nothing else differs.', look: offered ? ['show crypto ikev2 sa → no "PQC Key Exchange:" line', 'no error is logged'] : ['show crypto ikev2 sa → READY'], scen: offered ? 'M2' : 'C0' };
      }
      const base = { kind: 'down', e };
      if (e.code === 'NO_PROPOSAL_CHOSEN' && e.stage === 'child') return { ...base, title: 'Down: Child SA failed in IKE_AUTH — IKE SA deleted too', why: 'The IKE proposal matched, but the IPsec transform sets have nothing in common. The first Child SA is negotiated inside IKE_AUTH; when it fails, IOS deletes the IKE SA as well.', look: [`${H(e.resp)}: Received Policies: … ESP: Proposal 1: …`, 'show crypto session → DOWN on both'], scen: 'C6' };
      if (e.code === 'NO_PROPOSAL_CHOSEN' && e.mlkem) return { ...base, title: 'Down: NO_PROPOSAL_CHOSEN (ML-KEM)', why: 'The classical algorithms match, but ML-KEM is required on one end and not available with the same parameter set on the other. Required ML-KEM behaves like any other proposal mismatch.', look: [`${H(e.resp)}: : Failed to find a matching policy`, `${H(e.ini)}: : Received no proposal chosen notify`], scen: 'M1 / M4' };
      if (e.code === 'NO_PROPOSAL_CHOSEN') return { ...base, title: 'Down: NO_PROPOSAL_CHOSEN in IKE_SA_INIT', why: 'Encryption, integrity and DH group each need at least one value in common. No SA is created.', look: [`${H(e.resp)} (responder): Received Policies vs Expected Policies — compare them`, `${H(e.ini)} (initiator): : Received no proposal chosen notify`], scen: 'C1–C3' };
      if (e.code === 'AUTHENTICATION_FAILED') return { ...base, title: 'Down: authentication failed in IKE_AUTH', why: 'The algorithms agree (IKE_SA_INIT succeeds), but the pre-shared keys differ, so the AUTH payloads do not verify.', look: ['both: : Failed to authenticate the IKE SA', 'both: : Auth exchange failed'], scen: 'C7' };
      if (e.code === 'NO_PROFILE') return { ...base, title: `Down: ${H(e.resp)} has no profile for ${H(e.ini)}`, why: `${H(e.resp)} (the responder) checks the initiator's identity before it answers IKE_AUTH, finds no matching "match identity", and refuses. Try the same setting with the other router initiating: the result changes to half-open.`, look: [`${H(e.resp)}: % IKEv2 profile not found / Auth exchange failed`] };
      return { ...base, title: `Down: ${e.code}`, why: e.reason || '' };
    }
    function showResult(r) {
      const el = host.querySelector('#neg-result'); if (!el) return;
      if (r.error) { el.innerHTML = `<div class="neg-out down"><b>${esc(r.error)}</b></div>`; return; }
      const verdict = prediction ? (prediction === r.kind ? `<span class="neg-ok">✓ You predicted “${esc(LABEL[prediction])}”</span>` : `<span class="neg-bad">✕ You predicted “${esc(LABEL[prediction])}”</span>`) : '';
      el.innerHTML = `<div class="neg-out ${r.kind}">
        <div class="neg-out-title">${esc(r.title)}</div>${verdict}
        <p>${esc(r.why)}</p>
        ${r.look ? `<div class="neg-look"><b>Where to look</b><ul>${r.look.map(x => `<li><code>${esc(x)}</code></li>`).join('')}</ul></div>` : ''}
        ${r.scen ? `<div class="neg-src">Same behaviour as dataset scenario ${esc(r.scen)}. Debug lines appear in the consoles (<code>debug crypto ikev2 error</code> is on).</div>` : ''}
      </div>`;
    }

    /* ---------- events ---------- */
    host.addEventListener('click', e => {
      const chip = e.target.closest('.neg-chip');
      if (chip) {
        const { dev, field } = chip.dataset; const v = field === 'group' ? +chip.dataset.val : chip.dataset.val;
        const list = cfg[dev][field]; const i = list.indexOf(v);
        if (i >= 0) list.splice(i, 1); else list.push(v);
        lastResult = null; return render();
      }
      const pre = e.target.closest('[data-preset]');
      if (pre) {
        const sc = N.SCENARIOS.find(x => x.id === pre.dataset.preset);
        cfg = { r1: N.apply(sc, 'r1'), r3: N.apply(sc, 'r3') }; initiator = sc.initiator || 'r1'; prediction = null; lastResult = null; return render();
      }
      if (e.target.closest('#neg-apply')) applyAll();
    });
    host.addEventListener('change', e => {
      const t = e.target;
      if (t.name === 'neg-ini') { initiator = t.value; lastResult = null; return render(); }
      if (t.name === 'neg-pred') { prediction = t.value; return; }
      const { dev, field } = t.dataset; if (!dev) return;
      if (field === 'optional') cfg[dev].optional = t.checked;
      else cfg[dev][field] = t.value;
      lastResult = null; render();
    });
    host.addEventListener('input', e => { const t = e.target; if (t.classList.contains('neg-in')) { cfg[t.dataset.dev][t.dataset.field] = t.value.trim(); const s = host.querySelector('.neg-cmds summary'); if (s) { const n = commands().reduce((k, c) => k + c.lines.length, 0); s.textContent = n ? `${n} IOS commands will be typed` : ''; host.querySelector('.neg-cmds').hidden = !n; } } });
    host.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.classList.contains('neg-in')) { e.preventDefault(); render(); } });

    // shown once the baseline exists (from the "experiments" steps on)
    const sync = i => {
      const s = T.BY_ID[(T.TRACKS.negotiate.steps || [])[i]];
      const slot = s && s.panel && document.querySelector(`#step-${i} .neg-slot`);
      if (slot) { slot.appendChild(host); host.hidden = false; } else host.hidden = true;
    };
    api.onStep(sync); sync(api.current());
    window.__neg = { get cfg() { return cfg; }, set initiator(v) { initiator = v; render(); }, preset: id => host.querySelector(`[data-preset="${id}"]`).click(), apply: applyAll, get result() { return lastResult; }, predict: v => { prediction = v; } };
    render();
  }

  const prev = T.mount;
  T.mount = api => { if (prev) prev(api); mount(api); };
})();
