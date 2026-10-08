/* Ground-truth replay: runs the mlkem-required-dataset (CML C8000V + C8235-G2 derived)
   against the simulator engine and compares output / prompt / error type per label.

   usage: node test/groundtruth-replay.js <dataset-dir> [--diff N] [--json out.json]        */
const fs = require('fs');
const path = require('path');
const { Lab } = require('../js/ios-pqc-engine.js');

const dir = process.argv[2];
if (!dir) { console.error('usage: node test/groundtruth-replay.js <dataset-dir>'); process.exit(2); }
const diffN = +(process.argv[process.argv.indexOf('--diff') + 1] || 0) || 0;
const jsonOut = process.argv.includes('--json') ? process.argv[process.argv.indexOf('--json') + 1] : null;
const read = f => fs.readFileSync(path.join(dir, f), 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));

// dataset topology (topology.json): C8000V with GigabitEthernet1..4, routers start in privileged mode
const phys = n => Object.fromEntries(Array.from({ length: n }, (_, i) => [`GigabitEthernet${i + 1}`, { shutdown: false }]));
const TOPO = {
  devices: {
    r1: { hostname: 'R1', role: 'Spoke', model: 'C8000V', startMode: 'priv', uptimeMin: 184, interfaces: phys(4) },
    r2: { hostname: 'R2', role: 'Transit', model: 'C8000V', startMode: 'priv', uptimeMin: 184, interfaces: phys(4) },
    r3: { hostname: 'R3', role: 'Spoke', model: 'C8000V', startMode: 'priv', uptimeMin: 112, interfaces: phys(4) },
  },
  links: [
    { a: ['r1', 'GigabitEthernet1'], b: ['r2', 'GigabitEthernet1'] },
    { a: ['r2', 'GigabitEthernet2'], b: ['r3', 'GigabitEthernet1'] },
  ],
};
let t = Date.UTC(2026, 9, 8, 11, 18, 0);
const lab = new Lab(TOPO, { now: () => t, disclaimer: false });

const norm = s => String(s || '').split('\n').map(l => l.replace(/\s+$/, '')).join('\n').replace(/^\n+|\n+$/g, '');
// mask per-session values so structure can be compared
const mask = s => norm(s)
  .replace(/\b[0-9A-F]{16}\b/g, '<SPI>').replace(/0x[0-9A-F]+(\(\d+\))?/gi, '<SPI>')
  .replace(/Life\/Active Time: \d+\/\d+ sec/g, 'Life/Active Time: <n>/<n> sec')
  .replace(/CE id: \d+, Session-id: \d+/g, 'CE id: <n>, Session-id: <n>')
  .replace(/Session ID: \d+/g, 'Session ID: <n>').replace(/Session-id:\d+/g, 'Session-id:<n>')
  .replace(/ESP spi in\/out: \S+/g, 'ESP spi in/out: <SPI>').replace(/\w{3} \d+ \d{4} \d\d:\d\d:\d\d/g, '<date>')
  .replace(/(Last input|output|counters) \d\d:\d\d:\d\d/g, '$1 <t>').replace(/Uptime: [\d:]+/g, 'Uptime: <t>')
  .replace(/connid:\d+ lifetime:[\d:]+/g, 'connid:<n> lifetime:<t>').replace(/conn id: \d+, flow_id: CSR:\d+/g, 'conn id: <n>, flow_id: CSR:<n>')
  .replace(/\(sec\): \d+/g, '(sec): <n>').replace(/Disabled\/\d+/g, 'Disabled/<n>').replace(/uptime is .*/g, 'uptime is <t>')
  .replace(/^\*\w{3}\s+\d+ [\d:.]+/gm, '<ts>').replace(/round-trip min\/avg\/max = [\d/]+ ms/g, 'round-trip min/avg/max = <rtt> ms')
  .replace(/[ \t]+/g, ' ');
const errType = (lines) => {
  const txt = lines.map(l => l.text).join('\n');
  if (/Invalid input detected/.test(txt)) return 'invalid_input';
  if (/% Incomplete command/.test(txt)) return 'incomplete';
  if (/% Ambiguous command/.test(txt)) return 'ambiguous';
  if (/^Warning|WARNING/m.test(txt)) return 'warning';
  if (lines.some(l => l.cls === 'err')) return 'error';
  return null;
};

const results = [];
function run(rec) {
  const k = rec.node.toLowerCase();
  if (!lab.dev(k)) return;
  const r = lab.exec(k, rec.command);
  t += Math.min(rec.duration_ms || 300, 4000); lab.tick(); lab.drainLogs();
  const got = norm(r.lines.map(l => l.text).join('\n'));
  const exp = norm(rec.output);
  const res = {
    node: rec.node, phase: rec.phase, section: rec.section, command: rec.command, label: rec.label,
    exact: got === exp, structural: mask(got) === mask(exp), layout: mask(got).replace(/\d+/g, '#') === mask(exp).replace(/\d+/g, '#'),
    prompt_ok: r.prompt === rec.prompt_after, prompt_got: r.prompt, prompt_exp: rec.prompt_after,
    err_ok: (errType(r.lines) || null) === (rec.error_type || null), err_got: errType(r.lines), err_exp: rec.error_type || null,
    got, exp,
  };
  results.push(res);
}

for (const f of ['records/01_apply.jsonl', 'records/02_capture.jsonl']) {
  const recs = read(f);
  for (const rec of recs) {
    if (rec.kind && rec.kind !== 'exec') continue;
    // after config is applied, let IKE negotiate before the capture phase
    if (f.includes('02_') && rec === recs[0]) { t += 3000; lab.tick(); }
    run(rec);
  }
}

// report
const labels = [...new Set(results.map(r => r.label))];
const pct = (a, b) => b ? Math.round(a / b * 100) + '%' : '-';
console.log('label          n   exact  struct  layout  prompt  errtype');
for (const L of labels) {
  const rs = results.filter(r => r.label === L);
  console.log(`${L.padEnd(13)} ${String(rs.length).padStart(3)}  ${pct(rs.filter(r => r.exact).length, rs.length).padStart(5)}  ${pct(rs.filter(r => r.structural).length, rs.length).padStart(6)}  ${pct(rs.filter(r => r.layout).length, rs.length).padStart(6)}  ${pct(rs.filter(r => r.prompt_ok).length, rs.length).padStart(6)}  ${pct(rs.filter(r => r.err_ok).length, rs.length).padStart(7)}`);
}
const all = results;
console.log(`${'ALL'.padEnd(13)} ${String(all.length).padStart(3)}  ${pct(all.filter(r => r.exact).length, all.length).padStart(5)}  ${pct(all.filter(r => r.structural).length, all.length).padStart(6)}  ${pct(all.filter(r => r.layout).length, all.length).padStart(6)}  ${pct(all.filter(r => r.prompt_ok).length, all.length).padStart(6)}  ${pct(all.filter(r => r.err_ok).length, all.length).padStart(7)}`);
const fails = results.filter(r => !(r.label === 'environment' ? r.layout : r.structural) || !r.prompt_ok || !r.err_ok);
console.log(`\n${fails.length} records with a structural / prompt / error-type mismatch:`);
for (const r of fails) console.log(`  [${r.label}] ${r.node} ${r.command}${!r.prompt_ok ? `  prompt ${r.prompt_got} ≠ ${r.prompt_exp}` : ''}${!r.err_ok ? `  err ${r.err_got} ≠ ${r.err_exp}` : ''}${!r.structural ? '  (output)' : ''}`);
if (diffN) for (const r of fails.filter(x => !x.structural).slice(0, diffN)) {
  console.log(`\n────── ${r.node} ${r.command} [${r.label}]\n--- expected\n${r.exp}\n--- simulator\n${r.got}`);
}
if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify(results, null, 1));
