/* Replays the GRE quick lab's "Show Me" commands on a fresh lab and checks each step validates,
   plus the GRE behaviours the steps teach.   usage: node test/run-tests.js */
const { Lab } = require('../../v3-three-router/js/ios-pqc-engine.js');
const TOPO = require('../js/gre-topology.js');
const { TRACKS, BY_ID } = require('../js/gre-steps.js');
let fails = 0;
const check = (cond, msg) => { if (!cond) fails++; console.log(`  ${cond ? '✓' : '✗'} ${msg}`); };
let t = Date.UTC(2026, 9, 15, 10, 0, 0);
const lab = new Lab(TOPO, { now: () => t });
const adv = ms => { t += ms; lab.tick(); };
const outs = {};
const run = (dev, cmd) => {
  const d = lab.dev(dev);
  if (d.mode === 'exec' && cmd !== 'enable') lab.exec(dev, 'enable');
  if (!['exec', 'priv'].includes(d.mode) && /^(configure|show|ping|clear|traceroute)/.test(cmd)) lab.exec(dev, 'end');
  const r = lab.exec(dev, cmd); adv(200);
  const errs = r.lines.filter(l => l.cls === 'err'); if (errs.length) { fails++; console.log(`  ✗ [${dev}] ${cmd}: ${errs.map(e => e.text).join(' / ')}`); }
  return r.lines.map(l => l.text).join('\n');
};
console.log('=== GRE quick lab');
for (const sid of TRACKS.gre.steps) {
  const s = BY_ID[sid]; const since = lab.lastSeq;
  if (sid === 'g-r3') outs.beforeR3 = run('r1', 'ping 192.168.100.2');   // the step asks to try this first
  if (sid === 'g-r3') outs.r1Line = run('r1', 'show interfaces Tunnel0 | include line protocol');
  for (const [dev, cmd] of s.run) outs[`${sid}:${dev}:${cmd}`] = run(dev, cmd);
  adv(2000);
  check(s.validate({ lab, since }), s.title);
}
check(/line protocol is up/.test(outs.r1Line), 'Tunnel0 on R1 is up/up before R3 has a tunnel');
check(/Success rate is 0/.test(outs.beforeR3), 'ping to the far tunnel address fails while R3 has no tunnel');
check(/Tunnel protocol\/transport GRE\/IP/.test(outs['g-r1:r1:show interfaces Tunnel0 | include line protocol|Tunnel protocol|Keepalive']), 'show interfaces reports GRE/IP');
const tr = outs['g-lan:r1:traceroute 10.3.3.3'].split('\n').filter(l => /^\s+\d+ /.test(l));
check(tr.length === 1 && /10\.3\.3\.3/.test(tr[0]), 'traceroute LAN→LAN: one hop, straight to R3 (R2 hidden)');
check(/Success rate is 100/.test(outs['g-lan:r1:ping 10.3.3.3 source Loopback1']), 'LAN to LAN ping through the tunnel');
check(!run('r2', 'show ip route').includes('10.3.3.0') && !run('r2', 'show ip route').includes('10.1.1.0'), 'R2 never learns the LANs');
console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED');
process.exit(fails ? 1 : 0);
