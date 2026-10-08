/* Replays every quick-lab track's "Show Me" commands on a fresh lab and checks each step validates.
   usage: node test/run-tests.js */
const { Lab } = require('../../v3-three-router/js/ios-pqc-engine.js');
const TOPO = require('../../v3-three-router/js/lab-topology.js');
const { TRACKS, BY_ID } = require('../js/quick-steps.js');

let fails = 0;
const check = (cond, msg) => { if (!cond) fails++; console.log(`  ${cond ? '✓' : '✗'} ${msg}`); };
for (const [id, tr] of Object.entries(TRACKS)) {
  console.log(`\n=== ${id}: ${tr.title}`);
  let t = Date.UTC(2026, 9, 8, 10, 0, 0);
  const lab = new Lab(TOPO, { now: () => t });
  const advance = ms => { t += ms; lab.tick(); };
  const outs = {};
  for (const sid of tr.steps) {
    const s = BY_ID[sid]; const since = lab.lastSeq;
    if (s.panel && !s.run.length) { console.log(`  · ${s.title} (panel-driven: checked below)`); continue; }
    for (const [dev, cmd] of s.run) {
      const d = lab.dev(dev);
      if (d.mode === 'exec' && cmd !== 'enable') lab.exec(dev, 'enable');
      if (!['exec', 'priv'].includes(d.mode) && /^(configure|show|ping|clear)/.test(cmd)) lab.exec(dev, 'end');
      const r = lab.exec(dev, cmd); advance(150);
      const errs = r.lines.filter(l => l.cls === 'err');
      if (errs.length) { fails++; console.log(`  ✗ [${dev}] ${cmd}: ${errs.map(e => e.text).join(' / ')}`); }
      outs[`${sid}:${cmd}`] = r.lines.map(l => l.text).join('\n');
    }
    advance(2000);
    check(s.validate({ lab, since }), `${s.title}`);
  }
  if (id === 'migrate') {
    check(!/PQC Key Exchange/.test(outs['m-r1:show crypto ikev2 sa detailed | include PQC|DH Grp']) && /DH Grp:20/.test(outs['m-r1:show crypto ikev2 sa detailed | include PQC|DH Grp']), 'R1-only upgrade falls back to classical');
    check(/PQC Key Exchange: ML-KEM-768/.test(outs['m-r3:show crypto ikev2 sa detailed']), 'both upgraded → ML-KEM-768');
    check(/^ pqc mlkem768$/m.test(outs['m-enforce:show running-config | section CLASSIC-PROPOSAL']), 'enforced line in running-config');
  }
  if (id === 'pqc') check(/PFS \(Y\/N\): Y, DH group: group20, PQC Key Exchange: ML-KEM-768/.test(outs['p-rekey:show crypto ipsec sa detail | include PFS']), 'rekey uses DH + ML-KEM');
  if (id === 'classic') check(!/PQC/.test(outs['c-verify:show crypto ikev2 sa']), 'classic SA has no PQC');
}

// ── negotiation lab: every dataset scenario through the panel's command generator ──
{
  const { NEG } = require('../js/quick-steps.js');
  const EXPECT = { C0: 'up-classic', C1: 'down:init', C2: 'down:init', C3: 'down:init', C4: 'retry', C5: 'up-classic', C6: 'down:child', C7: 'down:AUTHENTICATION_FAILED', C8: 'half', M1: 'down:mlkem', M2: 'up-classic', M4: 'down:mlkem' };
  console.log('\n=== negotiate: dataset scenarios via the panel');
  let t = Date.UTC(2026, 9, 9, 10, 0, 0);
  const lab = new Lab(TOPO, { now: () => t });
  const advance = ms => { t += ms; lab.tick(); };
  const exec = (dev, cmd) => { const d = lab.dev(dev); if (d.mode === 'exec' && cmd !== 'enable') lab.exec(dev, 'enable'); const r = lab.exec(dev, cmd); advance(150); const e = r.lines.filter(l => l.cls === 'err'); if (e.length) { fails++; console.log(`  ✗ [${dev}] ${cmd}: ${e.map(x => x.text).join(' / ')}`); } return r.lines.map(l => l.text).join('\n'); };
  for (const [dev, cmd] of BY_ID['n-build'].run) exec(dev, cmd);
  advance(2000);
  check(BY_ID['n-build'].validate({ lab, since: 0 }), 'baseline up with debug on');
  let applied = { r1: NEG.apply(NEG.SCENARIOS[0], 'r1'), r3: NEG.apply(NEG.SCENARIOS[0], 'r3') };
  const go = (to, ini) => {
    for (const dev of ['r1', 'r3']) { const L = NEG.commands(dev, applied[dev], to[dev]); if (!L.length) continue; exec(dev, 'configure terminal'); let depth = 0; for (const raw of L) { const ind = raw.length - raw.trimStart().length; for (; depth > ind; depth--) exec(dev, 'exit'); exec(dev, raw.trim()); depth = ind; } exec(dev, 'end'); }
    applied = JSON.parse(JSON.stringify(to));
    const resp = ini === 'r1' ? 'r3' : 'r1', seq0 = lab.lastSeq;
    exec(resp, 'clear crypto ikev2 sa'); exec(ini, 'clear crypto ikev2 sa'); exec(ini, `ping ${NEG.TUN[resp]} repeat 3`);
    return lab.negLog.find(e => e.seq > seq0);
  };
  const kind = e => !e ? 'none' : e.ok ? (e.half ? 'half' : e.keRetry ? 'retry' : e.pqc ? 'up-pqc' : 'up-classic') : `down:${e.stage === 'child' ? 'child' : e.mlkem ? 'mlkem' : e.code === 'NO_PROPOSAL_CHOSEN' ? 'init' : e.code}`;
  const base = { r1: NEG.apply(NEG.SCENARIOS[0], 'r1'), r3: NEG.apply(NEG.SCENARIOS[0], 'r3') };
  for (const sc of NEG.SCENARIOS) {
    const e = go({ r1: NEG.apply(sc, 'r1'), r3: NEG.apply(sc, 'r3') }, sc.initiator);
    check(kind(e) === EXPECT[sc.id], `${sc.id} ${sc.title}: ${kind(e)}`);
    const back = go(base, 'r1'); advance(6000);
    check(back && back.ok && !!lab.saBetween('r1', 'r3'), `${sc.id} restore baseline: tunnel up again`);
  }
  // C8 with R1 initiating: the responder (R3) rejects the identity before answering → full failure, no half-open
  const e8 = go({ r1: NEG.apply(NEG.SCENARIOS[8], 'r1'), r3: NEG.apply(NEG.SCENARIOS[8], 'r3') }, 'r1');
  check(kind(e8) === 'down:NO_PROFILE', `C8 with R1 initiating: ${kind(e8)}`);
  go(base, 'r1');
  advance(6000);
  for (const id of ['n-one', 'n-lists', 'n-child', 'n-auth', 'n-pqc']) check(BY_ID[id].validate({ lab, since: 0 }), `step "${BY_ID[id].title}" validates after the experiments`);
}
console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED');
process.exit(fails ? 1 : 0);
