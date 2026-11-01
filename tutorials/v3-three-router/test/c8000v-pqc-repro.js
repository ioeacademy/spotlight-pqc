/* Repro for the C8000V pqcSupport gap (report: docs/issues/c8000v-pqc-support.md, local only)
   node tutorials/v3-three-router/test/c8000v-pqc-repro.js   → exit 0 when the engine honours pqcSupport: false

   R3 becomes a C8000V without PQC support. The tutorial's own "Show Me" commands are replayed
   up to the ML-KEM step (`pqc mlkem768 optional` on R1 and R3, then `clear crypto ikev2 sa`). */
const path = require('path');
const base = path.join(__dirname, '../js');
const { Lab } = require(path.join(base, 'ios-pqc-engine.js'));
const { STEPS } = require(path.join(base, 'tutorial-steps.js'));
const TOPO = JSON.parse(JSON.stringify(require(path.join(base, 'lab-topology.js'))));
Object.assign(TOPO.devices.r3, { model: 'C8000V', pqcSupport: false });

const WARN = ' Warning!! IKEv2 PQC is not supported on this platform.';
let t = Date.UTC(2026, 8, 1, 10, 0, 0), fails = 0;
const lab = new Lab(TOPO, { now: () => t });
const tick = ms => { t += ms; lab.tick(); };
const run = (dev, cmd) => {
  const d = lab.dev(dev);
  if (d.mode === 'exec' && cmd !== 'enable') lab.exec(dev, 'enable');
  if (cmd === 'configure terminal' && d.mode !== 'priv' && d.mode !== 'exec') lab.exec(dev, 'end');
  const r = lab.exec(dev, cmd); tick(150); return r.lines;
};
const text = lines => lines.map(l => l.text).join('\n');
const check = (ok, msg) => { if (!ok) fails++; console.log(`  ${ok ? '✓' : '✗'} ${msg}`); };

let r3PqcLines = [];
for (const s of STEPS) {
  for (const [dev, cmd] of s.run) { const l = run(dev, cmd); if (dev === 'r3' && /^pqc /.test(cmd)) r3PqcLines = l; }
  tick(2000);
  if (s.id === 'mlkem') break;
}

console.log('Case 1: R1 `pqc mlkem768 optional`, R3 (C8000V, no PQC) `pqc mlkem768 optional`');
console.log('  R3 output for `pqc mlkem768 optional`: ' + JSON.stringify(r3PqcLines.map(l => l.text)));
check(r3PqcLines.some(l => l.text === WARN), 'R3 prints the platform warning');
check(/Supports PQC: No/.test(text(run('r3', 'show crypto pqc-support'))), 'show crypto pqc-support → Supports PQC: No');
const sa = lab.saBetween('r1', 'r3');
console.log('  SA params.pqc = ' + JSON.stringify(sa && sa.params.pqc));
check(!!sa && !sa.params.pqc, 'tunnel is up and classical only');
const det = text(run('r1', 'show crypto ikev2 sa detailed'));
check(!/ML-KEM/.test(det), 'R1 "show crypto ikev2 sa detailed" has no ML-KEM lines');
const prop = text(run('r3', 'show crypto ikev2 proposal CLASSICAL-PROPOSAL'));
check(/PQC Key Exchange: none/.test(prop) && !/ML-KEM/.test(prop), 'R3 "show crypto ikev2 proposal CLASSICAL-PROPOSAL" → PQC Key Exchange: none');

console.log('Case 2: R1 mandatory `pqc mlkem768`, R3 unchanged');
for (const c of ['configure terminal', 'crypto ikev2 proposal CLASSICAL-PROPOSAL', 'pqc mlkem768', 'end', 'clear crypto ikev2 sa']) run('r1', c);
tick(2000);
const p = lab.pairBetween('r1', 'r3');
console.log('  pair.err = ' + JSON.stringify(p && p.err));
check(!lab.saBetween('r1', 'r3') && /NO_PROPOSAL_CHOSEN|requires ML-KEM/.test(String(p && p.err)), 'no SA: NO_PROPOSAL_CHOSEN (R3 does not offer ML-KEM)');

console.log(fails ? `\n${fails} CHECK(S) FAILED — gap reproduced` : '\nALL CHECKS PASSED');
process.exit(fails ? 1 : 0);
