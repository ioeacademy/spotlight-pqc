/* Node scenario test: replays every step's "Show Me" commands on a fake clock
   and checks each step validates, plus key show outputs from the blog. */
const { Lab } = require('../js/ios-pqc-engine.js');
const TOPO = require('../js/lab-topology.js');
const { STEPS } = require('../js/tutorial-steps.js');

let t = Date.UTC(2026, 8, 1, 10, 0, 0);
const lab = new Lab(TOPO, { now: () => t });
const advance = ms => { t += ms; lab.tick(); };
let fails = 0;
const check = (cond, msg) => { if (!cond) { fails++; console.log('  ✗ ' + msg); } else console.log('  ✓ ' + msg); };
const run = (dev, cmd) => {
  const d = lab.dev(dev);
  if (d.mode === 'exec' && cmd !== 'enable') lab.exec(dev, 'enable');
  if (cmd === 'configure terminal' && d.mode !== 'priv' && d.mode !== 'exec') lab.exec(dev, 'end');
  const r = lab.exec(dev, cmd); advance(150);
  const errs = r.lines.filter(l => l.cls === 'err');
  if (errs.length) { fails++; console.log(`  ✗ [${dev}] ${cmd}\n      ${errs.map(e => e.text).join('\n      ')}`); }
  return r.lines.map(l => l.text).join('\n');
};
const outputs = {};
STEPS.forEach((s, i) => {
  console.log(`\n${i + 1}. ${s.title}`);
  const since = lab.lastSeq;
  for (const [dev, cmd] of s.run) { const o = run(dev, cmd); outputs[`${s.id}:${dev}:${cmd}`] = o; }
  advance(2000);
  check(s.validate({ lab, since }), 'step validates');
});

const get = (k) => outputs[k] || '';
console.log('\n--- spot checks ---');
check(/Encr: AES-CBC, keysize: 256, PRF: SHA512, Hash: SHA512, DH Grp:20, Auth sign: PSK, Auth verify: PSK/.test(get('baseline:r1:show crypto ikev2 sa')), 'baseline SA line matches blog');
check(/^1         10\.0\.12\.1\/500         10\.0\.23\.2\/500         none\/none            READY/m.test(get('baseline:r1:show crypto ikev2 sa')), 'SA row formatting');
check(get('baseline:r2:show crypto ikev2 sa').trim() === '', 'R2 transit has no SA');
check(/Quantum-safe Encryption using Manual PPK/.test(get('ppk:r1:show crypto ikev2 sa detailed | include Quantum')), 'PPK detailed include');
check(/Sessions with Quantum Resistance: 1\s+Manual: 1\s+Dynamic: 0/.test(get('ppk:r1:show crypto ikev2 stats | include Quantum')), 'PPK stats line');
check(/^\.\.\.\.!/m.test(get('mlkem:r1:ping 192.168.100.2')), 'ML-KEM first ping shows ....!');
check(/PQC Key Exchange: ML-KEM-768/.test(get('mlkem:r1:show crypto ikev2 sa detailed')), 'ML-KEM in detailed');
check(/IETF Std Fragmentation MTU in use: 1372 bytes/.test(get('mlkem:r1:show crypto ikev2 sa detailed')), 'fragmentation MTU 1372');
const hub12 = get('spoke2:r2:show crypto ikev2 sa');
check(/1         10\.0\.12\.2\/500         10\.0\.12\.1\/500[\s\S]*PQC Key Exchange: ML-KEM-768[\s\S]*2         10\.0\.23\.1\/500         10\.0\.23\.2\/500/.test(hub12) && (hub12.match(/PQC Key Exchange/g) || []).length === 1, 'hub: tunnel 1 ML-KEM, tunnel 2 classical');
check((get('upgrade-r3:r2:show crypto ikev2 sa').match(/PQC Key Exchange: ML-KEM-768/g) || []).length === 2, 'hub: both ML-KEM after upgrade');
console.log(hub12);

// enforcement negative test
console.log('\n--- enforcement test ---');
run('r3', 'configure terminal'); run('r3', 'crypto ikev2 proposal SPOKE-PROPOSAL'); run('r3', 'no pqc mlkem768 optional'); run('r3', 'end');
run('r2', 'clear crypto ikev2 sa'); advance(2000);
check(!lab.saBetween('r2', 'r3') && !!lab.saBetween('r1', 'r2'), 'legacy R3 rejected, R1 still up');
console.log('  reason:', lab.pairBetween('r2', 'r3').err);
run('r3', 'configure terminal'); run('r3', 'crypto ikev2 proposal SPOKE-PROPOSAL'); run('r3', 'pqc mlkem768 optional'); run('r3', 'end'); advance(6000);
check(!!lab.saBetween('r2', 'r3'), 'R3 back after restoring pqc');

// guide-based checks
console.log('\n--- guide checks ---');
check(/PFS \(Y\/N\): Y, DH group: group20, PQC Key Exchange: ML-KEM-768/.test(get('pfs:r1:show crypto ipsec sa detail | include PFS')), 'set pfs inherits DH + ML-KEM on rekey');
run('r2', 'clear crypto ikev2 sa'); advance(2000);
check(/PFS \(Y\/N\): N/.test(run('r2', 'show crypto ipsec sa detail | include PFS')), 'child SA from IKE_AUTH has no PFS until rekey');
run('r3', 'configure terminal'); run('r3', 'crypto ipsec profile SPOKE-IPSEC'); run('r3', 'no set pfs'); run('r3', 'end');
run('r2', 'clear crypto sa'); advance(100);
const pf = lab.pairBetween('r2', 'r3');
check(pf.sa && pf.sa.child.down && /NO_PROPOSAL_CHOSEN/.test(pf.sa.child.err), 'PFS mismatch (initiator set pfs, responder none) fails rekey');
check(/Success rate is 0/.test(run('r2', 'ping 192.168.23.2')), 'traffic stops while child SA is down');
run('r3', 'configure terminal'); run('r3', 'crypto ipsec profile SPOKE-IPSEC'); run('r3', 'set pfs'); run('r3', 'end'); advance(2000);
check(!lab.pairBetween('r2', 'r3').sa.child.down && /!!!/.test(run('r2', 'ping 192.168.23.2')), 'rekey recovers after fixing PFS');
// fresh lab: no fragmentation, multiple ML-KEM algs, inline keys
const lab2 = new Lab(TOPO, { now: () => t });
const x = (d, c) => { const r = lab2.exec(d, c); const e = r.lines.filter(l => l.cls === 'err'); if (e.length) { fails++; console.log('  ✗ ' + c + ' → ' + e.map(z => z.text).join(' ')); } };
for (const [d, peer, src, tip, rt, nh] of [['r1', '10.0.23.2', 'TwoGigabitEthernet0/0/0', '192.168.9.1', '10.0.23.0', '10.0.12.2'], ['r3', '10.0.12.1', 'TwoGigabitEthernet0/0/0', '192.168.9.2', '10.0.12.0', '10.0.23.1']]) {
  for (const c of ['enable', 'configure terminal', `ip route ${rt} 255.255.255.0 ${nh}`, 'crypto ikev2 proposal prop', d === 'r1' ? 'pqc mlkem1024 mlkem768' : 'pqc mlkem768 optional', 'encryption aes-cbc-256', 'integrity sha512', 'group 21',
    'crypto ikev2 policy pol', 'match fvrf any', 'proposal prop', 'crypto ikev2 profile prof1', `match identity remote address ${peer} 255.255.255.255`, 'authentication remote pre-share key cisco123', 'authentication local pre-share key cisco123',
    'crypto ipsec transform-set tset1 esp-gcm 256', 'crypto ipsec profile gen', 'set transform-set tset1', 'set ikev2-profile prof1', 'set pfs',
    'interface Tunnel1', `ip address ${tip} 255.255.255.0`, `tunnel source ${src}`, 'tunnel mode ipsec ipv4', `tunnel destination ${peer}`, 'tunnel protection ipsec profile gen', 'end']) x(d, c);
}
t += 2000; lab2.tick();
const s2 = lab2.saBetween('r1', 'r3');
check(s2 && s2.params.pqc === 'mlkem768' && !s2.params.frag && s2.params.group === 21, 'guide sample: inline PSK, multi-alg pqc list, no fragmentation still negotiates (768 common)');
check(/Fragmentation not  configured\./.test(lab2.exec('r1', 'show crypto ikev2 sa detail').lines.map(l => l.text).join('\n')), 'detail shows "Fragmentation not configured."');
// fragmentation negative test on fresh lab
console.log('\n--- CLI checks ---');
const h = lab.help('r1', 'show crypto ikev2 ');
check(h.some(l => /sa/.test(l.text)) && h.some(l => /stats/.test(l.text)), 'help lists sa/stats');
check(lab.complete('r1', 'sh cry ikev2 st') === 'sh cry ikev2 stats ', 'tab completion');
const bad = lab.exec('r1', 'show crypto ikev3 sa'); check(bad.lines.some(l => /Invalid input/.test(l.text)), 'invalid input caret');
const amb = lab.exec('r1', 'c'); check(amb.lines.some(l => /Ambiguous|Invalid/.test(l.text)), 'ambiguous');
const ab = lab.exec('r1', 'sh ip int br'); check(/Tunnel1\s+192\.168\.12\.1/.test(ab.lines.map(l => l.text).join('\n')), 'abbreviations + Tunnel1 in brief');
console.log(ab.lines.map(l => l.text).join('\n'));
const sec = lab.exec('r2', 'show running-config | section crypto ikev2 proposal'); console.log(sec.lines.map(l => l.text).join('\n'));
check(/^ pqc mlkem768$/m.test(sec.lines.map(l => l.text).join('\n')), 'running-config: enforced = "pqc mlkem768" (no optional)');
check(lab.exec('r2', 'conf t') && lab.exec('r2', 'crypto ikev2 proposal HUB-PROPOSAL').lines.length === 0 && lab.exec('r2', 'pqc mlkem768 required').lines.some(l => /Invalid/.test(l.text)), '"required" keyword rejected (not in IOS XE syntax)');
lab.exec('r2', 'end');
// ---- classic track on a fresh lab: every step must validate, and ping alone must NOT satisfy the proof step
console.log('\n--- classic track ---');
{
  const { TRACKS, BY_ID } = require('../js/tutorial-steps.js');
  let tc = Date.UTC(2026, 9, 6, 10, 0, 0);
  const lc = new Lab(TOPO, { now: () => tc });
  const go = (dev, cmd) => { const d = lc.dev(dev); if (d.mode === 'exec' && cmd !== 'enable') lc.exec(dev, 'enable'); if (lc.dev(dev).mode === 'priv' && cmd === 'enable') return; const r = lc.exec(dev, cmd); tc += 150; lc.tick(); if (r.lines.some(l => l.cls === 'err')) { fails++; console.log('  ✗ [' + dev + '] ' + cmd); } return r.lines.map(l => l.text).join('\n'); };
  for (const id of TRACKS.classic.steps) {
    const st = BY_ID[id]; const since = lc.lastSeq;
    if (id === 'baseline') {
      go('r1', 'ping 192.168.100.2'); tc += 500; lc.tick();
      check(!st.validate({ lab: lc, since }), 'proof step NOT satisfied by ping alone');
    }
    const outs = st.run.map(([d, c]) => [c, go(d, c)]);
    tc += 2000; lc.tick();
    check(st.validate({ lab: lc, since }), `classic: ${st.title}`);
    if (id === 'baseline') {
      const counts = outs.filter(([c]) => /include pkts encaps/.test(c)).map(([, o]) => +(o.match(/encaps: (\d+)/) || [])[1]);
      check(counts.length === 3 && counts[1] > counts[0] && counts[2] === counts[1], `encaps ${counts.join(' → ')}: tunnel ping counted, WAN ping not`);
      check(/via Tunnel0/.test(outs.find(([c]) => /show ip route 192/.test(c))[1]), 'show ip route 192.168.100.2 → via Tunnel0');
    }
  }
}
console.log(`\n${fails ? fails + ' FAILURE(S)' : 'ALL PASSED'}`);
process.exit(fails ? 1 : 0);
