/* GRE ground-truth replay: runs a gre_cml_dataset run (real IOS-XE 26.02.1, C8000v in CML) against the simulator.
   Every record is replayed in time order on its router (the simulator clock follows the record timestamps, so the
   ~10 s periodic line-protocol check can be compared), and compared on:
     output  exact / structural (session values masked) / layout (all digits masked)
     prompt  prompt_after,   error type,
     syslog  per step and router: the multiset of messages (timestamps stripped).
   usage: node test/gre-replay.js <dataset-dir>/cml-run1 [--diff N] [--exp E1] [--json out.json] [--logs]   */
const fs = require('fs');
const path = require('path');
const { Lab } = require('../js/ios-pqc-engine.js');

const dir = process.argv[2];
if (!dir) { console.error('usage: node test/gre-replay.js <run-dir> [--diff N] [--exp E1]'); process.exit(2); }
const arg = k => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : null; };
const diffN = +(arg('--diff') || 0), onlyExp = arg('--exp'), jsonOut = arg('--json'), showLogs = process.argv.includes('--logs');

/* CML lab after `cml_clean.py clean`: C8000v, GigabitEthernet1-4 (1-2 cabled, with the lab's descriptions), Loopback1 on R1/R3 */
const gi = extra => ({ GigabitEthernet1: {}, GigabitEthernet2: {}, GigabitEthernet3: {}, GigabitEthernet4: {}, ...extra });
const TOPO = {
  devices: {
    r1: { hostname: 'R1', role: 'Spoke-1', model: 'C8000V', startMode: 'priv', uptimeMin: 300,
      interfaces: gi({ GigabitEthernet1: { ip: '10.0.12.1', mask: '255.255.255.0', desc: 'Underlay to R2' }, Loopback1: { ip: '10.1.1.1', mask: '255.255.255.0' } }) },
    r2: { hostname: 'R2', role: 'Hub/Transit', model: 'C8000V', startMode: 'priv', uptimeMin: 300,
      interfaces: gi({ GigabitEthernet1: { ip: '10.0.12.2', mask: '255.255.255.0', desc: 'To R1' }, GigabitEthernet2: { ip: '10.0.23.1', mask: '255.255.255.0', desc: 'To R3' } }) },
    r3: { hostname: 'R3', role: 'Spoke-2', model: 'C8000V', startMode: 'priv', uptimeMin: 300,
      interfaces: gi({ GigabitEthernet1: { ip: '10.0.23.2', mask: '255.255.255.0', desc: 'Underlay to R2' }, Loopback1: { ip: '10.3.3.3', mask: '255.255.255.0' } }) },
  },
  links: [{ a: ['r1', 'GigabitEthernet1'], b: ['r2', 'GigabitEthernet1'] }, { a: ['r2', 'GigabitEthernet2'], b: ['r3', 'GigabitEthernet1'] }],
};

const files = fs.readdirSync(dir).filter(f => f.endsWith('.jsonl')).sort();
let recs = [];
for (const f of files) recs.push(...fs.readFileSync(path.join(dir, f), 'utf8').split('\n').filter(Boolean).map(l => ({ ...JSON.parse(l), _file: f.replace('.jsonl', '') })));
const tsOf = r => Date.parse(r.timestamp);
recs.sort((a, b) => tsOf(a) - tsOf(b));

let t = tsOf(recs[0]) - 1000;
const lab = new Lab(TOPO, { now: () => t, disclaimer: false });
// the CML lab had been running before the capture: ARP entries between cabled neighbours are already cached
for (const l of TOPO.links) {
  const ipOf = ([k, n]) => TOPO.devices[k].interfaces[n].ip;
  lab.dev(l.a[0]).arp.add(`${l.a[0]}>${ipOf(l.b)}`); lab.dev(l.b[0]).arp.add(`${l.b[0]}>${ipOf(l.a)}`);
}
const advanceTo = ms => { while (t + 500 < ms) { t += 500; lab.tick(); } t = Math.max(t, ms); lab.tick(); };

const TS = /^\*\w{3}\s+\d+ \d{4} [\d:.]+: /;
const norm = s => String(s || '').replace(/\r/g, '').split('\n').map(l => l.replace(/\s+$/, '')).join('\n').replace(/^\n+|\n+$/g, '');
const mask = s => norm(s).replace(/^\*\w{3}\s+\d+ \d{4} [\d:.]+:/gm, '<TS>')
  .replace(/\w{3} \d+ \d{4} \d\d:\d\d:\d\d/g, '<DATE>').replace(/\b\d\d:\d\d:\d\d(\.\d+)?\b/g, '<TIME>')
  .replace(/(Last input|output|Last clearing of "show interface" counters) [^,\n]+/g, '$1 <AGE>')
  .replace(/round-trip min\/avg\/max = [\d/]+ ms/g, 'round-trip <RTT>').replace(/\d+ msec/g, 'N msec')
  .replace(/\d+ packets (input|output), \d+ bytes/g, 'N packets $1, N bytes').replace(/(input|output) rate \d+ bits\/sec, \d+ packets\/sec/g, '$1 rate <RATE>')
  .replace(/txload \d+\/255, rxload \d+\/255/g, 'txload N, rxload N').replace(/\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b/g, '<MAC>')
  .replace(/uptime is .*/g, 'uptime is <T>').replace(/[ \t]+/g, ' ');
const layout = s => mask(s).replace(/\d+/g, '#');
const errType = txt => /Invalid input detected/.test(txt) ? 'invalid' : /% Incomplete command/.test(txt) ? 'incomplete' : /% Ambiguous command/.test(txt) ? 'ambiguous' : /^%|\n%/.test(txt) ? 'percent' : null;
const logKey = l => l.replace(TS, '').replace(/\s+/g, ' ').trim();

const res = [], simLogs = {}, realLogs = {};
const addLogs = (store, key, lines) => { (store[key] = store[key] || []).push(...lines); };
let unsupported = 0;
for (const r of recs) {
  if (onlyExp && !r.experiment.startsWith(onlyExp) && !r._file.startsWith(onlyExp)) { continue; }
  const dev = r.router.toLowerCase(); if (!lab.dev(dev)) continue;
  const stepKey = `${r._file}|${r.router}|${r.step}`;
  advanceTo(tsOf(r));
  addLogs(realLogs, stepKey, (r.async_logs || []).map(logKey));
  if (r.kind === 'async') {   // idle console: only syslog/debug lines
    addLogs(realLogs, stepKey, norm(r.output).split('\n').filter(l => l && !(r.async_logs || []).includes(l)).map(logKey));
    for (const q of lab.drainLogs()) addLogs(simLogs, `${r._file}|${lab.dev(q.dev).hostname}|${r.step}`, [logKey(q.text)]);
    continue;
  }
  if (r.kind === 'skipped') continue;
  let got, prompt;
  if (r.kind === 'help') {
    const raw = r.command.replace(/\?$/, '');
    got = norm(lab.help(dev, raw).map(l => l.text).join('\n')); prompt = lab.prompt(dev);
  } else {
    const out = lab.exec(dev, r.command);
    got = norm(out.lines.map(l => l.text).join('\n')); prompt = out.prompt;
  }
  t += r.duration_ms || 300; lab.tick();
  for (const q of lab.drainLogs()) addLogs(simLogs, `${r._file}|${lab.dev(q.dev).hostname}|${r.step}`, [logKey(q.text)]);
  const exp = norm(r.output);   // IOS-XE echoes the command line on errors; the simulator does too
  const row = { file: r._file, step: r.step, router: r.router, kind: r.kind, cmd: r.command, got, exp,
    exact: got === exp, struct: mask(got) === mask(exp), layout: layout(got) === layout(exp),
    prompt: prompt === r.prompt_after, promptGot: prompt, promptExp: r.prompt_after,
    err: errType(got) === errType(exp), errGot: errType(got), errExp: errType(exp) };
  res.push(row);
}
// syslog per step
const logRows = [];
for (const k of new Set([...Object.keys(realLogs), ...Object.keys(simLogs)])) {
  const rl = (realLogs[k] || []).filter(x => !/SYS-5-CONFIG_I/.test(x)).sort(), sl = (simLogs[k] || []).filter(x => !/SYS-5-CONFIG_I/.test(x)).sort();
  logRows.push({ k, ok: JSON.stringify(rl) === JSON.stringify(sl), real: rl, sim: sl });
}

const pct = (a, b) => b ? `${Math.round(a / b * 100)}%`.padStart(5) : '    -';
console.log(`run ${path.basename(dir)}: ${res.length} commands compared\n`);
console.log('experiment        n   exact  struct  layout  prompt  errtype   syslog-steps');
for (const f of [...new Set(res.map(r => r.file))]) {
  const rs = res.filter(r => r.file === f), ls = logRows.filter(l => l.k.startsWith(f + '|'));
  console.log(`${f.padEnd(15)} ${String(rs.length).padStart(4)}  ${pct(rs.filter(r => r.exact).length, rs.length)}  ${pct(rs.filter(r => r.struct).length, rs.length)}  ${pct(rs.filter(r => r.layout).length, rs.length)}  ${pct(rs.filter(r => r.prompt).length, rs.length)}  ${pct(rs.filter(r => r.err).length, rs.length)}   ${ls.filter(l => l.ok).length}/${ls.length}`);
}
const all = res;
console.log(`${'ALL'.padEnd(15)} ${String(all.length).padStart(4)}  ${pct(all.filter(r => r.exact).length, all.length)}  ${pct(all.filter(r => r.struct).length, all.length)}  ${pct(all.filter(r => r.layout).length, all.length)}  ${pct(all.filter(r => r.prompt).length, all.length)}  ${pct(all.filter(r => r.err).length, all.length)}   ${logRows.filter(l => l.ok).length}/${logRows.length}`);
if (diffN) {
  const bad = res.filter(r => !r.layout || !r.prompt || !r.err).slice(0, diffN);
  for (const r of bad) console.log(`\n── [${r.file} ${r.step}] ${r.router} ${r.kind === 'help' ? r.cmd : r.cmd}${!r.prompt ? `  PROMPT ${r.promptGot} ≠ ${r.promptExp}` : ''}${!r.err ? `  ERR ${r.errGot} ≠ ${r.errExp}` : ''}\n--- real\n${r.exp}\n--- sim\n${r.got}`);
}
if (showLogs) for (const l of logRows.filter(x => !x.ok)) console.log(`\n## ${l.k}\n  real: ${l.real.join('\n        ') || '-'}\n  sim : ${l.sim.join('\n        ') || '-'}`);
if (jsonOut) fs.writeFileSync(jsonOut, JSON.stringify({ res, logRows }, null, 1));
