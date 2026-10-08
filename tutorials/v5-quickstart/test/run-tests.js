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
console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED');
process.exit(fails ? 1 : 0);
