/* Negotiation-mismatch replay: runs every scenario of the vpn-negotiation-mismatch-teaching dataset
   (C0–C8 observed on CML, M1/M2/M4 inferred/derived) against the simulator and checks the outcome:
   IKE SA on R1, ping, Tunnel0 line protocol, the key `debug crypto ikev2 error` lines on each router,
   and the structure of every show command.

   usage: node test/negotiation-replay.js <dataset-dir> [--diff N] [--only C4]                   */
const fs = require('fs');
const path = require('path');
const { Lab } = require('../js/ios-pqc-engine.js');

const dir = process.argv[2];
if (!dir) { console.error('usage: node test/negotiation-replay.js <dataset-dir> [--diff N] [--only ID]'); process.exit(2); }
const arg = k => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : null; };
const diffN = +(arg('--diff') || 0), only = arg('--only');
const PSK = 'LabKey-123', WRONG = 'Other-Key-456';

const TOPO = () => ({
  devices: Object.fromEntries(['R1', 'R2', 'R3'].map(h => [h.toLowerCase(), { hostname: h, role: h === 'R2' ? 'Transit' : 'Peer', model: 'C8000V', startMode: 'priv', uptimeMin: 180,
    interfaces: { GigabitEthernet1: { shutdown: false }, GigabitEthernet2: { shutdown: false } } }])),
  links: [{ a: ['r1', 'GigabitEthernet1'], b: ['r2', 'GigabitEthernet1'] }, { a: ['r2', 'GigabitEthernet2'], b: ['r3', 'GigabitEthernet1'] }],
});
// the scenarios run on a CLASSICAL baseline: the CML routers ignored `pqc`, and M1/M2/M4 add ML-KEM to that baseline
const baseline = h => fs.readFileSync(path.join(dir, 'configs/baseline', h + '.txt'), 'utf8').split('\n')
  .filter(l => l.trim() && !/^\s*!/.test(l) && !/^(end|hostname)\b/.test(l.trim()) && !/^\s*pqc\b/.test(l)).map(l => l.replace('<redacted>', PSK));

const norm = s => String(s || '').split('\n').map(l => l.replace(/\s+$/, '')).join('\n').replace(/^\n+|\n+$/g, '');
const mask = s => norm(s).replace(/\b[0-9A-F]{16}\b/g, '<SPI>').replace(/0x[0-9A-F]+(\(\d+\))?/gi, '<SPI>')
  .replace(/Life\/Active Time: \d+\/\d+ sec/g, 'Life/Active Time: <n>/<n> sec').replace(/CE id: \d+, Session-id: \d+/g, 'CE id: <n>, Session-id: <n>')
  .replace(/Session ID: \d+/g, 'Session ID: <n>').replace(/SESSION ID = \d+,SA ID = \d+/g, 'SESSION ID = n,SA ID = n').replace(/^\*\w{3}\s+\d+ \d{4} [\d:.]+: /gm, '')
  .replace(/^\d+(\s+10\.0\.)/gm, '<id>$1').replace(/round-trip min\/avg\/max = [\d/]+ ms/g, '<rtt>').replace(/[ \t]+/g, ' ');
const layout = s => mask(s).replace(/\d+/g, '#');

// which router initiated in the capture: the one that got NO_PROPOSAL_CHOSEN back, or the peer of the one that logged responder-side errors
function observedInitiator(sid) {
  const dbg = h => { try { return fs.readFileSync(path.join(dir, 'scenarios', sid, `debug_${h}.txt`), 'utf8'); } catch (e) { return ''; } };
  const d = { R1: dbg('R1'), R3: dbg('R3') };
  const det = fs.readFileSync(path.join(dir, 'scenarios', sid, 'records.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l))
    .find(r => r.node === 'R1' && /^show crypto ikev2 sa detailed/.test(r.command) && /Initiator of SA/.test(r.output || ''));
  if (det) return /Initiator of SA : Yes/.test(det.output) ? 'R1' : 'R3';
  for (const h of ['R1', 'R3']) if (/Received no proposal chosen notify/.test(d[h])) return h;
  for (const h of ['R1', 'R3']) if (/Failed to locate an item/.test(d[h])) return h;   // the initiator rejects the responder's identity
  for (const h of ['R1', 'R3']) if (/Received Policies|KE payload contained/.test(d[h])) return h === 'R1' ? 'R3' : 'R1';
  for (const h of ['R1', 'R3']) if (/IKEv2 profile not found/.test(d[h])) return h === 'R1' ? 'R3' : 'R1';
  return 'R1';
}

const index = JSON.parse(fs.readFileSync(path.join(dir, 'scenarios/index.json'), 'utf8'));
let totalFail = 0; const summary = [];
for (const sc of index) {
  if (only && sc.id !== only) continue;
  let t = Date.UTC(2026, 9, 8, 12, 0, 0);
  const lab = new Lab(TOPO(), { now: () => t, disclaimer: false });
  const adv = ms => { for (let x = 0; x < ms; x += 500) { t += 500; lab.tick(); } };
  const logs = { R1: [], R3: [], R2: [] };
  const drain = () => { for (const q of lab.drainLogs()) logs[lab.dev(q.dev).hostname].push(q.text); };
  const exec = (h, c) => { const r = lab.exec(h.toLowerCase(), c); t += 300; lab.tick(); drain(); return r; };
  const apply = (h, lines) => {
    exec(h, 'configure terminal'); let depth = 0;
    for (const raw of lines) { const ind = raw.length - raw.trimStart().length; for (; depth > ind; depth--) exec(h, 'exit'); exec(h, raw.trim()); depth = ind; }
    exec(h, 'end');
  };
  for (const h of ['R1', 'R2', 'R3']) apply(h, baseline(h));
  adv(3000); exec('R1', 'ping 10.3.3.3 source Loopback0'); adv(2000);
  const base = lab.saBetween('r1', 'r3');

  const recs = fs.readFileSync(path.join(dir, 'scenarios', sc.id, 'records.jsonl'), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  const ini = observedInitiator(sc.id);
  const res = []; let windowLogs = { R1: [], R3: [] }, firstPing = null, firstTun = null, capSa;
  for (const rec of recs) {
    const h = rec.node, c = rec.command;
    if (/^\w+ R\d: 'clear crypto ikev2 sa'/.test(c)) {        // composite debug window: both ends cleared, then wait
      const resp = ini === 'R1' ? 'R3' : 'R1';
      logs.R1 = []; logs.R3 = [];
      exec(resp, 'clear crypto ikev2 sa'); exec(ini, 'clear crypto ikev2 sa');
      for (const st of lab.pairState.values()) st.initBy = ini.toLowerCase();
      adv(4000);
      if (/\+ ping/.test(c)) { exec('R1', 'ping 10.3.3.3 source Loopback0 repeat 3'); }
      adv(+((c.match(/\+ (\d+) s\b/) || [, 20])[1]) * 1000);
      windowLogs = { R1: logs.R1.slice(), R3: logs.R3.slice() };
      continue;
    }
    if (/same window|undebug all \(confirmed/.test(c)) { if (/undebug/.test(c)) exec(h, 'undebug all'); continue; }
    let cmd = c;
    if (/pre-shared-key <redacted>/.test(c)) cmd = c.replace('<redacted>', rec.step === 'apply' || rec.step === 'change' ? WRONG : PSK);
    const r = exec(h, cmd);
    const got = norm(r.lines.map(l => l.text).join('\n')), exp = norm(rec.output);
    if (rec.step && /apply|change|restore/.test(rec.step)) continue;   // config lines: nothing to compare
    if (/^(configure|end|clear|debug|undebug)/.test(c)) continue;
    if (/^ping/.test(c) && h === 'R1' && firstPing === null) firstPing = got;
    if (/^show crypto ikev2 sa$/.test(c) && h === 'R1' && capSa === undefined) { const p = lab.pairBetween('r1', 'r3'); capSa = p && lab._saOf(p, 'r1') ? JSON.parse(JSON.stringify(lab._saOf(p, 'r1'))) : null; }
    if (/^show interfaces Tunnel0/.test(c) && h === 'R1' && firstTun === null) firstTun = got;
    res.push({ h, c, label: rec.label, struct: mask(got) === mask(exp), lay: layout(got) === layout(exp), got, exp });
  }
  // expected outcome from the scenario index
  const r1sa = capSa;   // state at capture time (before the scenario's revert)
  const ex = sc.expected, checks = [];
  checks.push(['IKE SA on R1', (r1sa ? 'READY' : 'none') === ex.ike_sa, `${r1sa ? 'READY' : 'none'} vs ${ex.ike_sa}`]);
  if (ex.ike_sa === 'READY' && ex.encr) checks.push(['negotiated algorithms', !!r1sa && /DH Grp:(\d+)/.exec(ex.encr)[1] === String(r1sa.params.group) && !!r1sa.params.enc.includes(/keysize: (\d+)/.exec(ex.encr)[1]) && !r1sa.params.pqc === !/PQC/.test(ex.encr), r1sa ? `${r1sa.params.enc}/DH ${r1sa.params.group}${r1sa.params.pqc ? '/' + r1sa.params.pqc : ''}` : '-']);
  const pingOk = /100 percent/.test(firstPing || ''), pingExp = /^100%/.test(ex.ping);
  checks.push(['ping', pingOk === pingExp, `${pingOk ? '100%' : '0%'} vs ${ex.ping}`]);
  if (ex.tunnel0) checks.push(['Tunnel0 on R1', (firstTun || '').trim() === ex.tunnel0, `${(firstTun || '').trim()} vs ${ex.tunnel0}`]);
  for (const [h, line] of ex.errors || []) {
    const want = line.replace(/\s+<-.*$/, '').replace(/SESSION ID = n,SA ID = n/, 'SESSION ID = n,SA ID = n');
    const have = windowLogs[h].concat(logs[h]).map(x => mask(x).trim());
    const w = mask(want).trim();
    checks.push([`${h} logs "${want.slice(0, 70)}${want.length > 70 ? '…' : ''}"`, have.some(x => x === w || (w.includes('<SPI>') && x.startsWith(w.split('<SPI>')[0]))), '']);
  }
  const bad = checks.filter(x => !x[1]);
  const envCmd = r => /stats exchange|^show logging/.test(r.c);   // cumulative since boot / buffer history: environment, compare deltas instead
  const core = res.filter(r => !envCmd(r));
  const st = core.length, sOk = core.filter(r => r.struct).length, lOk = core.filter(r => r.lay).length;
  totalFail += bad.length;
  summary.push(`${sc.id.padEnd(3)} ${bad.length ? '✗' : '✓'} outcome ${checks.length - bad.length}/${checks.length}  show cmds ${st}: struct ${Math.round(sOk / st * 100)}% layout ${Math.round(lOk / st * 100)}%  (initiator ${ini}; baseline ${base ? 'up' : 'DOWN'})  ${sc.title}`);
  for (const b of bad) summary.push(`      ✗ ${b[0]} ${b[2]}`);
  if (diffN) for (const r of core.filter(r => !r.lay).slice(0, diffN)) summary.push(`\n    ── ${r.h} ${r.c} [${r.label}]\n    --- expected\n${r.exp}\n    --- simulator\n${r.got}\n`);
}
console.log(summary.join('\n'));
console.log(totalFail ? `\n${totalFail} outcome checks FAILED` : '\nALL SCENARIO OUTCOMES MATCH');
process.exit(totalFail ? 1 : 0);
