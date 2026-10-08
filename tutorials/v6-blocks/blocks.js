/* blocks.js — VPN Block Builder (v6).
   Learning design: chunking (Reach → Agree → Trust → Protect → Test), dual coding (topology + blocks + IOS),
   signalling (each row shows whether a value must MATCH, MIRROR or is LOCAL), worked example → completion →
   troubleshooting starts, and prediction before the simulator test. The test runs the real simulator engine
   (../v3-three-router/js/ios-pqc-engine.js), whose negotiation is checked against IOS XE 26.02 captures. */
(function () {
  'use strict';
  const $ = s => document.querySelector(s);
  const esc = s => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const clone = o => JSON.parse(JSON.stringify(o));
  const DEVS = ['r1', 'r3'], H = { r1: 'R1', r3: 'R3' }, PEER = { r1: 'r3', r3: 'r1' };

  /* ───────── IPv4 helpers ───────── */
  const isIp = s => /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(s) && s.split('.').every(o => +o <= 255);
  const n = ip => ip.split('.').reduce((a, o) => a * 256 + +o, 0);
  const isMask = m => { if (!isIp(m)) return false; const b = n(m).toString(2).padStart(32, '0'); return /^1*0*$/.test(b); };
  const len = m => n(m).toString(2).replace(/0/g, '').length;
  const net = (ip, m) => { const x = n(ip), mm = n(m); return (x - (x % (2 ** 32 - mm))); };
  const same = (a, b, m) => isIp(a) && isIp(b) && isMask(m) && net(a, m) === net(b, m);
  const toIp = x => [24, 16, 8, 0].map(s => Math.floor(x / 2 ** s) % 256).join('.');
  const IFACES = ['TwoGigabitEthernet0/0/0', 'TwoGigabitEthernet0/0/1', 'GigabitEthernet0/0/0', 'GigabitEthernet0/0/1'];
  const short = i => i.replace('TwoGigabitEthernet', 'Tw').replace('GigabitEthernet', 'Gi');

  /* ───────── the four steps ───────── */
  const CHUNKS = [
    { id: 'reach', n: 1, label: 'Reach', q: 'Can the two routers reach each other?', p: 'Each router needs an address on the WAN and a route to the other router\'s WAN address, outside the tunnel. The tunnel\'s endpoints are those WAN addresses.' },
    { id: 'agree', n: 2, label: 'Agree', q: 'Which algorithms protect the key exchange?', p: 'In IKE_SA_INIT each router offers its proposal. Encryption, integrity and DH group each need at least one value in common, otherwise the answer is NO_PROPOSAL_CHOSEN. The policy only says which proposal to use: its name is local.' },
    { id: 'trust', n: 3, label: 'Trust', q: 'How does each router prove who it is?', p: 'In IKE_AUTH both routers prove they know the same pre-shared key, and each checks that the peer\'s identity (its WAN address) is one it expects. Addresses mirror: R1\'s peer address is R3\'s own address, and the other way round.' },
    { id: 'protect', n: 4, label: 'Protect', q: 'How is the traffic itself encrypted?', p: 'The transform set chooses ESP encryption for the data. The IPsec profile bundles it with the IKEv2 profile, and the tunnel interface uses the IPsec profile: anything routed into the tunnel is encrypted.' },
  ];

  /* ───────── block definitions ─────────
     rel: how the row relates the two routers.  fields: f, label, type, opts, ref (target block), help  */
  const ENC = [['aes-cbc-128', 'aes-cbc-128'], ['aes-cbc-192', 'aes-cbc-192'], ['aes-cbc-256', 'aes-cbc-256']];
  const INTEG = [['sha256', 'sha256'], ['sha384', 'sha384'], ['sha512', 'sha512']];
  const GROUP = [['14', '14'], ['19', '19'], ['20', '20'], ['21', '21']];
  const PQC = [['none', 'none (classical)'], ['mlkem768', 'ML-KEM-768'], ['mlkem1024', 'ML-KEM-1024'], ['mlkem768 mlkem1024', 'ML-KEM-768, then 1024']];
  const ESP = [['esp-gcm 256', 'esp-gcm 256 (AES-GCM-256)'], ['esp-gcm 128', 'esp-gcm 128'], ['esp-aes 256 esp-sha256-hmac', 'esp-aes 256 + esp-sha256-hmac'], ['esp-aes 128 esp-sha-hmac', 'esp-aes 128 + esp-sha-hmac']];
  const BLOCKS = [
    { key: 'wan', chunk: 'reach', title: 'WAN interface and route', ios: 'interface · ip route', named: false,
      role: 'The router\'s address on the WAN, and a static route to the other site\'s WAN through R2.',
      fields: [{ f: 'ifname', label: 'Interface', type: 'select', opts: IFACES.map(x => [x, x]) }, { f: 'ip', label: 'IP address', type: 'ip' }, { f: 'mask', label: 'Mask', type: 'ip' },
        { f: 'net', label: 'Route to', type: 'ip', help: 'the peer\'s WAN network' }, { f: 'nmask', label: 'Route mask', type: 'ip' }, { f: 'nh', label: 'Next hop', type: 'ip', help: 'R2\'s address on this router\'s link' }] },
    { key: 'prop', chunk: 'agree', title: 'IKEv2 proposal', ios: 'crypto ikev2 proposal', named: true,
      role: 'The menu of algorithms this router offers for the IKE SA. Order is preference; the first DH group is also the router\'s guess for its key share.',
      fields: [{ f: 'enc', label: 'Encryption', type: 'chips', opts: ENC }, { f: 'integ', label: 'Integrity', type: 'chips', opts: INTEG }, { f: 'group', label: 'DH group', type: 'chips', opts: GROUP },
        { f: 'pqc', label: 'ML-KEM', type: 'select', opts: PQC }, { f: 'opt', label: 'If peer lacks it', type: 'check', text: 'optional (fall back to classical)', when: c => c.pqc !== 'none' },
        { f: 'frag', label: 'Fragmentation', type: 'check', text: 'crypto ikev2 fragmentation mtu 1400', help: 'global command; needed for large ML-KEM messages' }] },
    { key: 'pol', chunk: 'agree', title: 'IKEv2 policy', ios: 'crypto ikev2 policy', named: true,
      role: 'Says which proposal to use. It is chosen before the router knows who the peer is.',
      fields: [{ f: 'prop', label: 'Uses proposal', type: 'ref', ref: 'prop' }] },
    { key: 'keys', chunk: 'trust', title: 'Keyring', ios: 'crypto ikev2 keyring', named: true,
      role: 'Who the peer is (its WAN address) and the pre-shared key both routers must know.',
      fields: [{ f: 'peer', label: 'Peer label', type: 'text', help: 'any name, local' }, { f: 'addr', label: 'Peer address', type: 'ip' }, { f: 'psk', label: 'Pre-shared key', type: 'text', help: 'lab-only value' }] },
    { key: 'prof', chunk: 'trust', title: 'IKEv2 profile', ios: 'crypto ikev2 profile', named: true,
      role: 'Which peer identity this router accepts, how both sides authenticate, and where the key is.',
      fields: [{ f: 'id', label: 'Accepts peer', type: 'ip', help: 'match identity remote address' }, { f: 'keyring', label: 'Uses keyring', type: 'ref', ref: 'keys' }] },
    { key: 'ts', chunk: 'protect', title: 'Transform set', ios: 'crypto ipsec transform-set', named: true,
      role: 'How the data packets are encrypted (ESP). Negotiated inside IKE_AUTH for the first IPsec SA.',
      fields: [{ f: 'esp', label: 'ESP', type: 'select', opts: ESP }] },
    { key: 'ipsec', chunk: 'protect', title: 'IPsec profile', ios: 'crypto ipsec profile', named: true,
      role: 'Bundles the transform set with the IKEv2 profile, so the tunnel needs only one reference.',
      fields: [{ f: 'ts', label: 'Uses transform set', type: 'ref', ref: 'ts' }, { f: 'prof', label: 'Uses IKEv2 profile', type: 'ref', ref: 'prof' },
        { f: 'pfs', label: 'Rekeys', type: 'check', text: 'set pfs (fresh key exchange on every rekey)' }] },
    { key: 'tun', chunk: 'protect', title: 'Tunnel interface', ios: 'interface Tunnel', named: false,
      role: 'The virtual interface. Its source and destination are the WAN addresses; traffic routed into it gets encrypted.',
      fields: [{ f: 'name', label: 'Interface', type: 'select', opts: [['Tunnel0', 'Tunnel0'], ['Tunnel1', 'Tunnel1'], ['Tunnel10', 'Tunnel10']] }, { f: 'ip', label: 'Tunnel IP', type: 'ip' }, { f: 'mask', label: 'Mask', type: 'ip' },
        { f: 'src', label: 'Source', type: 'select', opts: IFACES.map(x => [x, x]) }, { f: 'dst', label: 'Destination', type: 'ip', help: 'the peer\'s WAN address' }, { f: 'ipsec', label: 'Uses IPsec profile', type: 'ref', ref: 'ipsec' }] },
  ];
  const BY = Object.fromEntries(BLOCKS.map(b => [b.key, b]));
  const NAMES = { prop: 'VPN-PROP', pol: 'VPN-POL', keys: 'VPN-KEYS', prof: 'VPN-PROF', ts: 'VPN-TS', ipsec: 'VPN-IPSEC' };
  const PSK = 'Lab-Only-Key-2026';

  /* ───────── starting points ───────── */
  const full = (me, peerWan, myTun, peerNet, nh, peerLabel, pqc) => ({
    wan: { ifname: 'TwoGigabitEthernet0/0/0', ip: me, mask: '255.255.255.0', net: peerNet, nmask: '255.255.255.0', nh },
    prop: { name: NAMES.prop, enc: ['aes-cbc-256'], integ: ['sha512'], group: ['20'], pqc: pqc ? 'mlkem768' : 'none', opt: false, frag: !!pqc },
    pol: { name: NAMES.pol, prop: NAMES.prop },
    keys: { name: NAMES.keys, peer: peerLabel, addr: peerWan, psk: PSK },
    prof: { name: NAMES.prof, id: peerWan, keyring: NAMES.keys },
    ts: { name: NAMES.ts, esp: 'esp-gcm 256' },
    ipsec: { name: NAMES.ipsec, ts: NAMES.ts, prof: NAMES.prof, pfs: !!pqc },
    tun: { name: 'Tunnel0', ip: myTun, mask: '255.255.255.0', src: 'TwoGigabitEthernet0/0/0', dst: peerWan, ipsec: NAMES.ipsec },
  });
  const R1 = pqc => full('10.0.12.1', '10.0.23.2', '192.168.100.1', '10.0.23.0', '10.0.12.2', 'R3', pqc);
  const R3 = pqc => full('10.0.23.2', '10.0.12.1', '192.168.100.2', '10.0.12.0', '10.0.23.1', 'R1', pqc);
  const EMPTY = () => ({
    wan: { ifname: 'TwoGigabitEthernet0/0/0', ip: '10.0.23.2', mask: '255.255.255.0', net: '', nmask: '', nh: '' },
    prop: { name: '', enc: [], integ: [], group: [], pqc: 'none', opt: false, frag: false }, pol: { name: '', prop: '' },
    keys: { name: '', peer: '', addr: '', psk: '' }, prof: { name: '', id: '', keyring: '' }, ts: { name: '', esp: 'esp-gcm 256' },
    ipsec: { name: '', ts: '', prof: '', pfs: false }, tun: { name: 'Tunnel0', ip: '', mask: '', src: 'TwoGigabitEthernet0/0/0', dst: '', ipsec: '' },
  });
  const STARTS = {
    example: { pqc: false, r1: () => R1(false), r3: () => R3(false), text: 'A complete, working configuration. Read each row from left to right, open 👁 to see the IOS, then change one value and watch what breaks.' },
    complete: { pqc: false, r1: () => R1(false), r3: EMPTY, text: 'R1 is done. Build R3 from the design sheet: same algorithms and key, mirrored addresses. Names are up to you.' },
    bugs: { pqc: false, r1: () => { const c = R1(false); c.ipsec.ts = 'VPN-TS1'; c.tun.dst = '10.0.23.1'; return c; },
      r3: () => { const c = R3(false); c.keys.psk = 'Lab-only-key-2026'; c.prof.id = '10.0.12.10'; c.prop.group = ['19']; return c; },
      text: 'Five mistakes are hidden in this configuration. Find and fix them. The step buttons show how many problems are left in each phase.' },
    pqc: { pqc: true, r1: () => R1(true), r3: () => R3(true), text: 'The worked example with a hybrid key exchange: ML-KEM-768 on top of DH group 20, IKEv2 fragmentation and PFS on both routers.' },
  };

  let cfg, r2 = { ip1: '10.0.12.2', ip2: '10.0.23.1' }, start = 'example', focus = null;
  const eyes = new Set();
  function load(name) {
    start = STARTS[name] ? name : 'example';
    cfg = { r1: STARTS[start].r1(), r3: STARTS[start].r3() };
    r2 = { ip1: '10.0.12.2', ip2: '10.0.23.1' };
    $('#r2-ip1').value = r2.ip1; $('#r2-ip2').value = r2.ip2;
    lastRun = null; $('#result').innerHTML = '';
    renderAll();
  }

  /* ───────── IOS for one block (values marked so they can be highlighted) ───────── */
  const V = x => `\u0001${x}\u0002`;
  function iosOf(dev, key) {
    const c = cfg[dev][key], L = [];
    const nm = c.name || '<name>';
    switch (key) {
      case 'wan': L.push(`interface ${V(c.ifname)}`, ` ip address ${V(c.ip || '<ip>')} ${V(c.mask || '<mask>')}`, ' no shutdown', '!', `ip route ${V(c.net || '<network>')} ${V(c.nmask || '<mask>')} ${V(c.nh || '<next-hop>')}`); break;
      case 'prop':
        if (c.frag) L.push(`crypto ikev2 fragmentation mtu ${V(1400)}`, '!');
        L.push(`crypto ikev2 proposal ${V(nm)}`);
        if (c.enc.length) L.push(` encryption ${c.enc.map(V).join(' ')}`);
        if (c.integ.length) L.push(` integrity ${c.integ.map(V).join(' ')}`);
        if (c.group.length) L.push(` group ${c.group.map(V).join(' ')}`);
        if (c.pqc !== 'none') L.push(` pqc ${c.pqc.split(' ').map(V).join(' ')}${c.opt ? ` ${V('optional')}` : ''}`);
        break;
      case 'pol': L.push(`crypto ikev2 policy ${V(nm)}`, ` proposal ${V(c.prop || '<proposal>')}`); break;
      case 'keys': L.push(`crypto ikev2 keyring ${V(nm)}`, ` peer ${V(c.peer || '<label>')}`, `  address ${V(c.addr || '<peer-ip>')}`, `  pre-shared-key ${V(c.psk || '<key>')}`); break;
      case 'prof': L.push(`crypto ikev2 profile ${V(nm)}`, ` match identity remote address ${V(c.id || '<peer-ip>')} 255.255.255.255`, ' authentication remote pre-share', ' authentication local pre-share', ` keyring local ${V(c.keyring || '<keyring>')}`); break;
      case 'ts': L.push(`crypto ipsec transform-set ${V(nm)} ${V(c.esp)}`, ' mode tunnel'); break;
      case 'ipsec': L.push(`crypto ipsec profile ${V(nm)}`, ` set transform-set ${V(c.ts || '<transform-set>')}`, ` set ikev2-profile ${V(c.prof || '<ikev2-profile>')}`); if (c.pfs) L.push(' set pfs'); break;
      case 'tun': L.push(`interface ${V(c.name)}`, ` ip address ${V(c.ip || '<ip>')} ${V(c.mask || '<mask>')}`, ` tunnel source ${V(c.src)}`, ` tunnel destination ${V(c.dst || '<peer-ip>')}`, ' tunnel mode ipsec ipv4', ` tunnel protection ipsec profile ${V(c.ipsec || '<ipsec-profile>')}`); break;
    }
    return L;
  }
  const plain = L => L.map(l => l.replace(/[\u0001\u0002]/g, ''));
  const htmlIos = L => esc(L.join('\n')).replace(/\u0001/g, '<span class="v">').replace(/\u0002/g, '</span>').replace(/^!$/gm, '<span class="c">!</span>');
  // forSim: leave out lines that still contain a placeholder, as a router would never receive them
  const fullConfig = (dev, forSim) => ['configure terminal', ...BLOCKS.flatMap(b => [...plain(iosOf(dev, b.key)).filter(l => !forSim || !/<[a-z-]+>/.test(l)), '!']), 'end'].join('\n');

  /* ───────── checks ─────────
     sev: bad = the tunnel won't work; warn = works now, breaks later or degrades; info = worth knowing */
  const R2IP = dev => dev === 'r1' ? r2.ip1 : r2.ip2;
  function analyze() {
    const rows = Object.fromEntries(BLOCKS.map(b => [b.key, { mid: [], msgs: [] }]));
    const local = { r1: {}, r3: {} }, bad = { r1: {}, r3: {} };
    const add = (key, line, msg) => { rows[key].mid.push(line); if (msg) rows[key].msgs.push(msg); };
    const flag = (dev, key, f) => { (bad[dev][key] = bad[dev][key] || new Set()).add(f); };
    const A = cfg.r1, B = cfg.r3;
    // local: every block named, every reference points to an existing block of the right kind
    for (const dev of DEVS) for (const b of BLOCKS) {
      const c = cfg[dev][b.key], issues = [];
      if (b.named && !c.name) { issues.push('needs a name'); flag(dev, b.key, 'name'); }
      for (const f of b.fields) {
        if (f.type === 'ref') { const t = cfg[dev][f.ref].name; if (!c[f.f] || c[f.f] !== t) { issues.push(`${f.label.toLowerCase()} "${c[f.f] || '—'}" not found`); flag(dev, b.key, f.f); } }
        if (f.type === 'ip' && c[f.f] && !isIp(c[f.f])) { issues.push(`${f.label.toLowerCase()} is not an IPv4 address`); flag(dev, b.key, f.f); }
        if (f.type === 'ip' && !c[f.f] && !(f.f === 'id' && false)) { issues.push(`${f.label.toLowerCase()} is empty`); flag(dev, b.key, f.f); }
        if (f.type === 'chips' && !c[f.f].length) { issues.push(`choose at least one ${f.label.toLowerCase()}`); flag(dev, b.key, f.f); }
        if (f.type === 'text' && !c[f.f]) { issues.push(`${f.label.toLowerCase()} is empty`); flag(dev, b.key, f.f); }
      }
      if (/mask/.test(b.key) || true) for (const f of b.fields) if (/mask/.test(f.f) && c[f.f] && isIp(c[f.f]) && !isMask(c[f.f])) { issues.push(`${f.label.toLowerCase()} is not a valid mask`); flag(dev, b.key, f.f); }
      local[dev][b.key] = issues;
    }
    const L = (rel, ok, t, sev = 'bad') => ({ rel, st: ok ? 'ok' : sev, t });
    // REACH
    for (const dev of DEVS) {
      const w = cfg[dev].wan, me = H[dev], peer = cfg[PEER[dev]].wan, r2ip = R2IP(dev);
      const onLink = same(w.ip, r2ip, w.mask) && w.ip !== r2ip;
      if (isIp(w.ip) && isMask(w.mask) && !onLink) { add('wan', null, { sev: 'bad', t: `${me}: ${w.ip}/${len(w.mask)} is not on R2's subnet (${r2ip}). The cable to R2 needs addresses in the same subnet.` }); flag(dev, 'wan', 'ip'); }
      if (w.nh && isIp(w.nh) && w.nh !== r2ip) { add('wan', null, { sev: 'bad', t: `${me}: the next hop must be R2's address on ${me}'s link, ${r2ip}.` }); flag(dev, 'wan', 'nh'); }
      if (isIp(w.net) && isMask(w.nmask) && isIp(peer.ip) && !same(w.net, peer.ip, w.nmask)) { add('wan', null, { sev: 'bad', t: `${me}: the route ${w.net}/${len(w.nmask)} does not cover ${H[PEER[dev]]}'s WAN address ${peer.ip}.` }); flag(dev, 'wan', 'net'); }
      if (isIp(w.net) && isMask(w.nmask) && net(w.net, w.nmask) !== n(w.net)) { add('wan', null, { sev: 'warn', t: `${me}: ${w.net} has host bits set for mask ${w.nmask}; IOS would reject it. Use ${toIp(net(w.net, w.nmask))}.` }); flag(dev, 'wan', 'net'); }
    }
    const reachOk = DEVS.every(d => !rows.wan.msgs.some(m => m.t.startsWith(H[d] + ':')) && !local[d].wan.length);
    add('wan', L('via R2', reachOk, reachOk ? 'each WAN reaches the other through R2' : 'fix the WAN addresses and routes'));
    // AGREE
    const ov = f => A.prop[f].filter(x => B.prop[f].includes(x));
    const eo = ov('enc'), io = ov('integ'), go = ov('group');
    add('prop', L('=', eo.length, eo.length ? `encryption: ${eo[0]}` : 'no common encryption'));
    add('prop', L('=', io.length, io.length ? `integrity: ${io[0]}` : 'no common integrity'));
    add('prop', L('=', go.length, go.length ? `DH group ${go[0]}` : 'no common DH group'));
    if (A.prop.enc.length && B.prop.enc.length && !eo.length) { add('prop', null, { sev: 'bad', t: `No encryption in common (R1: ${A.prop.enc.join(' ')}; R3: ${B.prop.enc.join(' ')}). The responder answers NO_PROPOSAL_CHOSEN and no SA is created.` }); DEVS.forEach(d => flag(d, 'prop', 'enc')); }
    if (A.prop.integ.length && B.prop.integ.length && !io.length) { add('prop', null, { sev: 'bad', t: 'No integrity algorithm in common: NO_PROPOSAL_CHOSEN.' }); DEVS.forEach(d => flag(d, 'prop', 'integ')); }
    if (A.prop.group.length && B.prop.group.length && !go.length) { add('prop', null, { sev: 'bad', t: 'No DH group in common: NO_PROPOSAL_CHOSEN.' }); DEVS.forEach(d => flag(d, 'prop', 'group')); }
    if (go.length && A.prop.group[0] !== go[0]) add('prop', null, { sev: 'info', t: `R1 starts the test and guesses DH group ${A.prop.group[0]} first, which R3 doesn't have. R3 answers INVALID_KE_PAYLOAD and R1 retries with group ${go[0]}: one extra round trip, no failure.` });
    const ka = A.prop.pqc === 'none' ? [] : A.prop.pqc.split(' '), kb = B.prop.pqc === 'none' ? [] : B.prop.pqc.split(' ');
    const kc = ka.filter(x => kb.includes(x)), reqA = ka.length && !A.prop.opt, reqB = kb.length && !B.prop.opt;
    if (ka.length || kb.length) {
      if (kc.length) add('prop', L('=', true, `hybrid ${kc[0] === 'mlkem1024' ? 'ML-KEM-1024' : 'ML-KEM-768'}`));
      else if (reqA || reqB) { add('prop', L('=', false, 'ML-KEM required, not shared')); add('prop', null, { sev: 'bad', t: `${reqA ? 'R1' : 'R3'} requires ML-KEM${ka.length && kb.length ? ', and the two routers offer different parameter sets' : ` but ${reqA ? 'R3' : 'R1'} doesn't offer it`}. That fails like any proposal mismatch.` }); DEVS.forEach(d => flag(d, 'prop', 'pqc')); }
      else { add('prop', L('=', false, 'classical fallback', 'warn')); add('prop', null, { sev: 'warn', t: 'ML-KEM is optional and not shared, so the tunnel comes up classical, silently. The only sign is a missing "PQC Key Exchange" line.' }); }
      if (kc.length && !(A.prop.frag && B.prop.frag)) { add('prop', null, { sev: 'warn', t: 'ML-KEM messages are large (a 1,184-byte key for ML-KEM-768). Enable IKEv2 fragmentation on both routers so they don\'t rely on IP fragmentation.' }); DEVS.filter(d => !cfg[d].prop.frag).forEach(d => flag(d, 'prop', 'frag')); }
    }
    add('pol', L('local', DEVS.every(d => !local[d].pol.length), 'points to the proposal by name', 'bad'));
    // TRUST
    for (const dev of DEVS) {
      const k = cfg[dev].keys, p = cfg[dev].prof, peerIp = cfg[PEER[dev]].wan.ip;
      if (isIp(k.addr) && k.addr !== peerIp) { add('keys', null, { sev: 'bad', t: `${H[dev]}'s keyring expects the peer at ${k.addr}, but ${H[PEER[dev]]}'s WAN address is ${peerIp}. No key is found for the real peer.` }); flag(dev, 'keys', 'addr'); }
      if (isIp(p.id) && p.id !== peerIp) {
        const t = dev === 'r1' ? `R1 accepts ${p.id}, but R3 identifies as ${peerIp}. R1 starts the test, so R3 installs its SAs and only then R1 rejects R3: a half-open tunnel (R3 READY, R1 none).`
          : `R3 accepts ${p.id}, but R1 identifies as ${peerIp}. R1 starts the test, so R3 finds no profile for R1 and refuses IKE_AUTH: no SA.`;
        add('prof', null, { sev: 'bad', t }); flag(dev, 'prof', 'id');
      }
    }
    const addrOk = DEVS.every(d => cfg[d].keys.addr === cfg[PEER[d]].wan.ip);
    add('keys', L('⇄', addrOk, addrOk ? 'peer address = the other\'s WAN' : 'peer address must mirror'));
    const pskOk = A.keys.psk && A.keys.psk === B.keys.psk;
    add('keys', L('=', pskOk, pskOk ? 'same pre-shared key' : 'keys differ'));
    if (A.keys.psk && B.keys.psk && !pskOk) { add('keys', null, { sev: 'bad', t: `The pre-shared keys differ${A.keys.psk.toLowerCase() === B.keys.psk.toLowerCase() ? ' (only in upper/lower case: keys are case-sensitive)' : ''}. IKE_SA_INIT succeeds, then IKE_AUTH fails: "Failed to authenticate the IKE SA".` }); DEVS.forEach(d => flag(d, 'keys', 'psk')); }
    const idOk = DEVS.every(d => cfg[d].prof.id === cfg[PEER[d]].wan.ip);
    add('prof', L('⇄', idOk, idOk ? 'accepts the other\'s WAN address' : 'identity must mirror'));
    add('prof', L('local', DEVS.every(d => !local[d].prof.some(x => /keyring/.test(x))), 'uses the keyring by name'));
    // PROTECT
    const tsOk = A.ts.esp === B.ts.esp;
    add('ts', L('=', tsOk, tsOk ? A.ts.esp : 'different ESP'));
    if (!tsOk) { add('ts', null, { sev: 'bad', t: `R1 offers ${A.ts.esp}, R3 ${B.ts.esp}. The IKE SA agrees, but the first IPsec SA fails inside IKE_AUTH, and IOS then deletes the IKE SA too.` }); DEVS.forEach(d => flag(d, 'ts', 'esp')); }
    add('ipsec', L('local', DEVS.every(d => !local[d].ipsec.some(x => /uses/.test(x))), 'bundles transform set + IKEv2 profile'));
    const pfsOk = A.ipsec.pfs === B.ipsec.pfs;
    add('ipsec', L('=', pfsOk, pfsOk ? (A.ipsec.pfs ? 'PFS on both' : 'no PFS on either') : 'PFS on one side only', 'warn'));
    if (!pfsOk) { add('ipsec', null, { sev: 'warn', t: '"set pfs" is on one router only. The tunnel comes up, but the first rekey fails with NO_PROPOSAL_CHOSEN and traffic stops until it is fixed.' }); DEVS.forEach(d => flag(d, 'ipsec', 'pfs')); }
    for (const dev of DEVS) {
      const t = cfg[dev].tun, w = cfg[dev].wan, peerIp = cfg[PEER[dev]].wan.ip;
      if (isIp(t.dst) && t.dst !== peerIp) { add('tun', null, { sev: 'bad', t: `${H[dev]}'s tunnel destination ${t.dst} is not ${H[PEER[dev]]}'s WAN address (${peerIp}).${t.dst === R2IP(dev) ? ' That is R2: the tunnel ends on the other VPN router, R2 only forwards.' : ''}` }); flag(dev, 'tun', 'dst'); }
      if (t.src !== w.ifname) { add('tun', null, { sev: 'bad', t: `${H[dev]}'s tunnel source is ${short(t.src)}, which has no address. Use the WAN interface, ${short(w.ifname)}.` }); flag(dev, 'tun', 'src'); }
    }
    const dstOk = DEVS.every(d => cfg[d].tun.dst === cfg[PEER[d]].wan.ip && cfg[d].tun.src === cfg[d].wan.ifname);
    add('tun', L('⇄', dstOk, dstOk ? 'destination = the other\'s WAN' : 'endpoints must mirror'));
    const tA = A.tun, tB = B.tun;
    if (isIp(tA.ip) && isIp(tB.ip) && isMask(tA.mask) && isMask(tB.mask)) {
      const ok = same(tA.ip, tB.ip, tA.mask) && tA.mask === tB.mask && tA.ip !== tB.ip;
      add('tun', L('=', ok, ok ? `overlay ${toIp(net(tA.ip, tA.mask))}/${len(tA.mask)}` : 'overlay subnet differs', 'warn'));
      if (!ok) { add('tun', null, { sev: 'warn', t: tA.ip === tB.ip ? 'Both tunnel interfaces use the same IP address.' : 'The two tunnel IPs are not in the same subnet. The tunnel can still come up, but pings to the peer\'s tunnel address fail.' }); DEVS.forEach(d => flag(d, 'tun', 'ip')); }
    }
    add('tun', L('local', DEVS.every(d => !local[d].tun.some(x => /uses/.test(x))), 'uses the IPsec profile by name'));
    // per-block local messages into the row
    for (const b of BLOCKS) for (const dev of DEVS) for (const x of local[dev][b.key]) rows[b.key].msgs.push({ sev: 'bad', t: `${H[dev]}: ${x}.` });
    return { rows, local, bad };
  }

  /* ───────── rendering ───────── */
  const fieldId = (dev, key, f) => `f-${dev}-${key}-${f}`;
  function fieldHtml(dev, b, f) {
    const c = cfg[dev][b.key], id = fieldId(dev, b.key, f.f), help = f.help ? ` title="${esc(f.help)}"` : '';
    if (f.when && !f.when(c)) return '';
    switch (f.type) {
      case 'select': return `<div class="fld"><label for="${id}"${help}>${esc(f.label)}</label><select id="${id}" data-dev="${dev}" data-b="${b.key}" data-f="${f.f}">${f.opts.map(([v, l]) => `<option value="${esc(v)}"${c[f.f] === v ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select></div>`;
      case 'check': return `<div class="fld"><span class="lbl"${help}>${esc(f.label)}</span><label class="chk" for="${id}"><input type="checkbox" id="${id}" data-dev="${dev}" data-b="${b.key}" data-f="${f.f}"${c[f.f] ? ' checked' : ''}> <span${f.f === 'frag' ? ' class="mono"' : ''}>${esc(f.text)}</span></label></div>`;
      case 'chips': return `<div class="fld"><span class="lbl">${esc(f.label)}</span><span class="chips" role="group" aria-label="${esc(H[dev] + ' ' + f.label)}">${f.opts.map(([v, l]) => { const i = c[f.f].indexOf(v); return `<button type="button" class="chip" data-dev="${dev}" data-b="${b.key}" data-f="${f.f}" data-v="${esc(v)}" aria-pressed="${i >= 0}">${i >= 0 && c[f.f].length > 1 ? `<span class="o">${i + 1}</span>` : ''}${esc(l)}</button>`; }).join('')}</span></div>`;
      case 'ref': return `<div class="fld"><label for="${id}">${esc(f.label)}</label><span class="ref"><input type="text" class="mono" id="${id}" data-dev="${dev}" data-b="${b.key}" data-f="${f.f}" data-ref="${f.ref}" value="${esc(c[f.f])}" spellcheck="false" autocomplete="off" placeholder="name of the ${esc(BY[f.ref].title.toLowerCase())}"><span class="link" id="${id}-st"></span></span></div>`;
      default: return `<div class="fld"><label for="${id}"${help}>${esc(f.label)}</label><input type="text" class="${f.type === 'ip' || f.f === 'psk' ? 'mono' : ''}" id="${id}" data-dev="${dev}" data-b="${b.key}" data-f="${f.f}" value="${esc(c[f.f])}" spellcheck="false" autocomplete="off"${f.type === 'ip' ? ' inputmode="decimal" placeholder="a.b.c.d"' : ''}></div>`;
    }
  }
  function blockHtml(dev, b) {
    const c = cfg[dev][b.key], id = `blk-${dev}-${b.key}`;
    const nameF = b.named ? `<div class="fld"><label for="${fieldId(dev, b.key, 'name')}">Name</label><input type="text" class="mono" id="${fieldId(dev, b.key, 'name')}" data-dev="${dev}" data-b="${b.key}" data-f="name" value="${esc(c.name)}" spellcheck="false" autocomplete="off" placeholder="e.g. ${NAMES[b.key]}"></div>` : '';
    return `<article class="blk" id="${id}" data-dev="${H[dev]}" style="--c: var(--${b.chunk})">
      <div class="blk-head"><span class="nm" id="${id}-nm"></span><span class="st" id="${id}-st"></span>
        <button type="button" class="eye" data-eye="${dev}:${b.key}" aria-pressed="${eyes.has(dev + ':' + b.key)}" aria-label="Show the IOS for ${H[dev]} ${esc(b.title)}" title="Show the IOS for this block">👁</button></div>
      <div class="blk-body" id="${id}-body">${nameF}${b.fields.map(f => fieldHtml(dev, b, f)).join('')}</div>
      <pre class="ios" id="${id}-ios"${eyes.has(dev + ':' + b.key) ? '' : ' hidden'}></pre>
    </article>`;
  }
  function renderAll() {
    const rows = $('#rows');
    rows.innerHTML = BLOCKS.map(b => {
      const ch = CHUNKS.find(x => x.id === b.chunk);
      return `<section class="row" id="row-${b.key}" data-chunk="${b.chunk}" aria-labelledby="rt-${b.key}">
        <div class="row-title"><h3 id="rt-${b.key}"><span class="ck ck-${b.chunk}" title="Step ${ch.n}: ${ch.label}">${ch.n}</span>${esc(b.title)}</h3><span class="ios-n">${esc(b.ios)}</span><span class="role">${esc(b.role)}</span></div>
        ${blockHtml('r1', b)}<div class="mid" id="mid-${b.key}"></div>${blockHtml('r3', b)}
        <div class="row-msgs" id="msgs-${b.key}"></div>
      </section>`;
    }).join('');
    renderSheet(); renderChunks(); renderPredict(); refresh();
  }
  function rerenderBlock(dev, key) {
    const el = $(`#blk-${dev}-${key}`); const tmp = document.createElement('div'); tmp.innerHTML = blockHtml(dev, BY[key]); el.replaceWith(tmp.firstElementChild);
  }

  function renderSheet() {
    const pq = STARTS[start].pqc;
    const r = (k, a, b) => `<tr><td class="k">${k}</td><td>${a}</td><td>${b}</td></tr>`;
    $('#sheet').innerHTML = `<thead><tr><th>Parameter</th><th>R1</th><th>R3</th></tr></thead><tbody>
      ${r('WAN interface', '<code>TwoGigabitEthernet0/0/0</code> <code>10.0.12.1/24</code>', '<code>TwoGigabitEthernet0/0/0</code> <code>10.0.23.2/24</code>')}
      ${r('Route to the peer', '<code>10.0.23.0/24</code> via R2 <code>10.0.12.2</code>', '<code>10.0.12.0/24</code> via R2 <code>10.0.23.1</code>')}
      ${r('IKE algorithms (both)', `<code>aes-cbc-256</code> · <code>sha512</code> · DH group <code>20</code>${pq ? ' · <span class="pq">ML-KEM-768</span> + fragmentation' : ''}`, 'same')}
      ${r('Authentication (both)', `pre-shared key <code>${PSK}</code> <span class="sub">lab-only value</span>`, 'same')}
      ${r('Data encryption (both)', `<code>esp-gcm 256</code>${pq ? ' · <span class="pq">set pfs</span>' : ''}`, 'same')}
      ${r('Tunnel', '<code>Tunnel0</code> <code>192.168.100.1/24</code> → <code>10.0.23.2</code>', '<code>Tunnel0</code> <code>192.168.100.2/24</code> → <code>10.0.12.1</code>')}
      ${r('Object names', 'your choice, e.g. <code>VPN-PROP</code>, <code>VPN-KEYS</code> …', 'your choice')}
    </tbody>`;
  }
  function renderChunks() {
    const all = `<button type="button" class="chunk" data-chunk="" aria-pressed="${!focus}"><span class="ck ck-all">∗</span>All blocks <span class="cnt" id="cnt-all"></span></button>`;
    $('#chunks').innerHTML = all + CHUNKS.map(c => `<button type="button" class="chunk" data-chunk="${c.id}" aria-pressed="${focus === c.id}"><span class="ck ck-${c.id}">${c.n}</span>${c.label} <span class="cnt" id="cnt-${c.id}"></span></button>`).join('')
      + `<button type="button" class="chunk" data-chunk="test"><span class="ck ck-test">5</span>Test</button>`;
    const c = CHUNKS.find(x => x.id === focus), card = $('#chunk-card');
    card.hidden = false;
    card.innerHTML = c ? `<b class="q">${c.n} · ${c.label}: ${esc(c.q)}</b><p>${esc(c.p)}</p>` : `<b class="q">${esc({ example: 'Worked example', complete: 'Your turn: complete R3', bugs: 'Troubleshooting', pqc: 'Quantum-safe worked example' }[start])}</b><p>${esc(STARTS[start].text)}</p>`;
    document.querySelectorAll('.row').forEach(r => r.classList.toggle('dim', !!focus && r.dataset.chunk !== focus));
  }
  function wiring(dev) {
    const c = cfg[dev];
    const node = (txt, ok) => `<span class="n${ok ? '' : ' broken'}">${esc(txt || '?')}</span>`;
    const ar = ok => `<span class="ar${ok ? '' : ' broken'}">${ok ? '→' : '⇥'}</span>`;
    const r = (a, b) => !!a && a === b;
    return `${node(c.tun.name, true)}${ar(r(c.tun.ipsec, c.ipsec.name))}${node(c.ipsec.name, r(c.tun.ipsec, c.ipsec.name))}${ar(r(c.ipsec.ts, c.ts.name))}${node(c.ts.name, r(c.ipsec.ts, c.ts.name))}
      <span class="ar">+</span>${node(c.prof.name, r(c.ipsec.prof, c.prof.name))}${ar(r(c.prof.keyring, c.keys.name))}${node(c.keys.name, r(c.prof.keyring, c.keys.name))}
      <span class="ar">·</span>${node(c.pol.name, !!c.pol.name)}${ar(r(c.pol.prop, c.prop.name))}${node(c.prop.name, r(c.pol.prop, c.prop.name))}`;
  }

  /* refresh everything derived from cfg, without re-rendering inputs (keeps focus) */
  let A = null;
  function refresh() {
    A = analyze();
    for (const dev of DEVS) {
      $(`#ch-${dev}`).innerHTML = `<span class="who">${H[dev]}</span><span class="wire" title="How ${H[dev]}'s blocks point to each other by name">${wiring(dev)}</span><button type="button" class="full" data-full="${dev}">Full IOS</button>`;
      for (const b of BLOCKS) {
        const id = `blk-${dev}-${b.key}`, c = cfg[dev][b.key];
        const nm = $(`#${id}-nm`); if (!nm) continue;
        nm.textContent = b.key === 'wan' ? `${short(c.ifname)} ${c.ip || ''}` : b.key === 'tun' ? `${c.name} → ${c.dst || '?'}` : (c.name || 'unnamed');
        const badSet = A.bad[dev][b.key] || new Set(), loc = A.local[dev][b.key];
        const st = $(`#${id}-st`);
        const incomplete = loc.some(x => /empty|needs a name|choose/.test(x));
        st.className = 'st ' + (incomplete ? 'todo' : badSet.size ? 'bad' : 'ok');
        st.textContent = incomplete ? 'to do' : badSet.size ? '✕ check' : '✓';
        for (const f of [...b.fields, { f: 'name' }]) {
          const el = $(`#${fieldId(dev, b.key, f.f)}`); if (!el || el.tagName !== 'INPUT' || el.type === 'checkbox') continue;
          el.classList.toggle('bad', badSet.has(f.f) && !!c[f.f]);
        }
        for (const f of b.fields.filter(x => x.type === 'ref')) {
          const s = $(`#${fieldId(dev, b.key, f.f)}-st`); if (!s) continue;
          const target = cfg[dev][f.ref].name, ok = !!c[f.f] && c[f.f] === target;
          s.className = 'link ' + (ok ? 'ok' : 'bad');
          s.innerHTML = ok ? '✓ linked' : target ? `✕ <button type="button" class="fix" data-fix="${dev}:${b.key}:${f.f}" title="Use ${esc(target)}">use ${esc(target)}</button>` : '✕ name it first';
        }
        const ios = $(`#${id}-ios`); if (ios && !ios.hidden) ios.innerHTML = htmlIos(iosOf(dev, b.key));
      }
    }
    for (const b of BLOCKS) {
      const r = A.rows[b.key];
      $(`#mid-${b.key}`).innerHTML = r.mid.filter(Boolean).map(l => `<div class="chk-line ${l.st}"><span class="rel ${l.rel === '=' ? 'eq' : l.rel === '⇄' ? 'mir' : 'loc'}">${esc(l.rel)}</span><span class="t">${esc(l.t)}</span></div>`).join('');
      const seen = new Set();
      $(`#msgs-${b.key}`).innerHTML = r.msgs.filter(m => !seen.has(m.t) && seen.add(m.t)).map(m => `<div class="msg ${m.sev}">${esc(m.t)}</div>`).join('');
    }
    // problem counts per step
    let total = 0;
    for (const c of CHUNKS) {
      const k = BLOCKS.filter(b => b.chunk === c.id).reduce((s, b) => s + A.rows[b.key].msgs.filter(m => m.sev === 'bad').length, 0);
      total += k; const el = $(`#cnt-${c.id}`); if (el) { el.textContent = k ? `${k} ✕` : '✓'; el.className = 'cnt ' + (k ? 'bad' : 'ok'); }
    }
    const ea = $('#cnt-all'); if (ea) { ea.textContent = total ? `${total} ✕` : '✓'; ea.className = 'cnt ' + (total ? 'bad' : 'ok'); }
    drawTopo(total);
  }

  /* ───────── topology (dual coding: the same values as the blocks) ───────── */
  function drawTopo(problems) {
    const X = { r1: 110, r2: 450, r3: 790 }, Y = 170;
    const w1 = cfg.r1.wan, w3 = cfg.r3.wan, t1 = cfg.r1.tun, t3 = cfg.r3.tun;
    const ok1 = same(w1.ip, r2.ip1, w1.mask) && w1.ip !== r2.ip1, ok3 = same(w3.ip, r2.ip2, w3.mask) && w3.ip !== r2.ip2;
    const run = lastRun && lastRun.kind;
    const cls = run ? ({ up: 'up', pqc: 'pqc', retry: 'up', half: 'half', down: 'err' })[run] : problems ? 'err' : 'ready';
    const lbl = run ? ({ up: 'UP · classical', pqc: 'UP · ML-KEM', retry: 'UP (after retry)', half: 'HALF-OPEN', down: 'DOWN' })[run] : problems ? `${problems} problem${problems > 1 ? 's' : ''}` : 'ready to test';
    const col = { up: 'var(--ok)', pqc: 'var(--pqc)', err: 'var(--bad)', half: 'var(--bad)', ready: 'var(--warn)' }[cls];
    const router = (k, name, role) => `<g><ellipse class="t-node" cx="${X[k]}" cy="${Y}" rx="38" ry="14"/><path class="t-node" d="M${X[k] - 38},${Y} v14 a38,14 0 0 0 76,0 v-14"/><ellipse class="t-node" cx="${X[k]}" cy="${Y}" rx="38" ry="14"/>
      <text class="t-host" x="${X[k]}" y="${Y + 48}" text-anchor="middle">${name}</text><text class="t-role" x="${X[k]}" y="${Y + 62}" text-anchor="middle">${role}</text></g>`;
    const link = (a, b, ipA, ifA, ipB, ifB, okA) => `<line class="t-link" x1="${X[a] + 40}" y1="${Y + 7}" x2="${X[b] - 40}" y2="${Y + 7}"/>
      <text class="t-ip${okA ? '' : ' bad'}" x="${X[a] + 46}" y="${Y - 4}">${esc(ipA)}</text><text class="t-if" x="${X[a] + 46}" y="${Y + 24}">${esc(short(ifA))}</text>
      <text class="t-ip" x="${X[b] - 46}" y="${Y - 4}" text-anchor="end">${esc(ipB)}</text><text class="t-if" x="${X[b] - 46}" y="${Y + 24}" text-anchor="end">${esc(short(ifB))}</text>`;
    const mx = X.r2, top = 30;
    const tun = `M${X.r1},${Y - 16} Q${mx},${top - 40} ${X.r3},${Y - 16}`;
    const tl = `${t1.name} ${t1.ip || '?'}  ⇄  ${t3.ip || '?'} ${t3.name}`, tw = tl.length * 7.3 + 24;
    $('#topo').innerHTML = `<title id="topo-t">R1, R2 and R3 in a row, with the tunnel between R1 and R3</title>
      <path class="t-tun ${cls}" d="${tun}"/>
      <rect class="t-pill" x="${mx - tw / 2}" y="${top - 6}" width="${tw}" height="24" rx="12" style="stroke:${col}"/>
      <text class="t-tunlbl" x="${mx}" y="${top + 10}" text-anchor="middle" style="fill:${col}">${esc(tl)}</text>
      <text class="t-net" x="${mx}" y="${top + 36}" text-anchor="middle">IPsec tunnel · ${esc(lbl)}</text>
      ${link('r1', 'r2', w1.ip || '?', w1.ifname, r2.ip1, 'TwoGigabitEthernet0/0/0', ok1)}
      ${link('r2', 'r3', r2.ip2, 'TwoGigabitEthernet0/0/1', w3.ip || '?', w3.ifname, true)}
      ${router('r1', 'R1', 'Site A')}${router('r2', 'R2', 'WAN (transit)')}${router('r3', 'R3', 'Site B')}`;
    // R3's label colour (link drawn from R2's side)
    const labels = $('#topo').querySelectorAll('.t-ip'); if (labels[3]) labels[3].classList.toggle('bad', !ok3);
  }

  /* ───────── test with the simulator engine ───────── */
  const PRED = [['up', 'Up, classical'], ['pqc', 'Up with ML-KEM'], ['retry', 'Up after a retry'], ['down', 'Down'], ['half', 'Half-open']];
  let prediction = null, lastRun = null;
  function renderPredict() {
    $('#predict').innerHTML = '<legend>Predict first</legend>' + PRED.map(([v, l]) => `<label for="pr-${v}"><input type="radio" name="pred" id="pr-${v}" value="${v}"${prediction === v ? ' checked' : ''}> ${l}</label>`).join('');
  }
  function simulate() {
    const { Lab } = window.PqcLab;
    let t = Date.UTC(2026, 9, 9, 9, 0, 0);
    const topo = {
      devices: {
        r1: { hostname: 'R1', role: 'Site A', model: 'C8235-G2', startMode: 'priv', interfaces: { [cfg.r1.wan.ifname]: {} } },
        r2: { hostname: 'R2', role: 'WAN', model: 'C8235-G2', startMode: 'priv', interfaces: { 'TwoGigabitEthernet0/0/0': {}, 'TwoGigabitEthernet0/0/1': {} } },
        r3: { hostname: 'R3', role: 'Site B', model: 'C8235-G2', startMode: 'priv', interfaces: { [cfg.r3.wan.ifname]: {} } },
      },
      links: [{ a: ['r1', cfg.r1.wan.ifname], b: ['r2', 'TwoGigabitEthernet0/0/0'] }, { a: ['r2', 'TwoGigabitEthernet0/0/1'], b: ['r3', cfg.r3.wan.ifname] }],
    };
    const lab = new Lab(topo, { now: () => t, disclaimer: false });
    const adv = ms => { for (let x = 0; x < ms; x += 500) { t += 500; lab.tick(); } };
    const logs = { r1: [], r3: [] }, errs = [];
    const exec = (dev, c) => { const r = lab.exec(dev, c); t += 200; lab.tick(); for (const q of lab.drainLogs()) if (logs[q.dev]) logs[q.dev].push(q.text); if (r.lines.some(l => l.cls === 'err')) errs.push(`${dev.toUpperCase()}: ${c} → ${r.lines.filter(l => l.cls === 'err').map(l => l.text.trim()).filter(x => x && x !== '^').join(' ')}`); return r.lines.map(l => l.text).join('\n'); };
    const apply = (dev, text) => { let depth = 0; for (const raw of text.split('\n')) { const x = raw.trim(); if (!x || x === '!') continue; const ind = raw.length - raw.trimStart().length; if (x !== 'configure terminal' && x !== 'end') for (; depth > ind; depth--) exec(dev, 'exit'); exec(dev, x); depth = ind; } };
    apply('r2', `configure terminal\ninterface TwoGigabitEthernet0/0/0\n ip address ${r2.ip1} 255.255.255.0\n no shutdown\ninterface TwoGigabitEthernet0/0/1\n ip address ${r2.ip2} 255.255.255.0\n no shutdown\nend`);
    for (const dev of DEVS) apply(dev, fullConfig(dev, true));
    exec('r1', 'debug crypto ikev2 error'); exec('r3', 'debug crypto ikev2 error');
    adv(2000);
    const seq0 = lab.lastSeq;
    exec('r1', 'clear crypto ikev2 sa');
    const ping = exec('r1', `ping ${cfg.r3.tun.ip || '0.0.0.0'}`);
    adv(1500);
    const first = lab.negLog.find(e => e.seq > seq0) || lab.negLog[lab.negLog.length - 1];
    const ev = { ping, sa1: exec('r1', 'show crypto ikev2 sa'), sa3: exec('r3', 'show crypto ikev2 sa'), enc: exec('r1', 'show crypto ipsec sa | include pkts encaps|pkts decaps') };
    if (first && first.half) { exec(first.resp, `ping ${cfg[first.ini].tun.ip}`); adv(500); }
    const st = lab.pairBetween('r1', 'r3');
    return { first, st, ev, logs, errs, reason: st && st.err };
  }
  function explain(sim) {
    const e = sim.first;
    if (!e) {
      const why = !sim.st ? 'The two tunnel interfaces don\'t point at each other (each tunnel\'s destination must be the other router\'s WAN address, and its source the router\'s own WAN interface), or a block the tunnel needs is missing.' : sim.reason || 'The negotiation never started.';
      return { kind: 'down', title: 'No IKE negotiation took place', why };
    }
    const HN = d => d.toUpperCase();
    if (e.ok && e.half) return { kind: 'half', title: `Half-open: ${HN(e.resp)} is READY, ${HN(e.ini)} has no SA`, why: `${HN(e.ini)} started, ${HN(e.resp)} accepted it and installed its SAs, and only then ${HN(e.ini)} rejected ${HN(e.resp)}'s identity. ${HN(e.resp)} keeps encrypting; ${HN(e.ini)} drops the packets with %CRYPTO-4-RECVD_PKT_INV_SPI. Always check both routers.` };
    if (e.ok && e.keRetry) return { kind: 'retry', title: 'Up, after one INVALID_KE_PAYLOAD retry', why: 'R1\'s first DH group was not one R3 accepts, so R3 asked for another key share. One extra IKE_SA_INIT round trip, then the tunnel came up.' };
    if (e.ok && e.pqc) return { kind: 'pqc', title: `Up with ${e.pqc === 'mlkem1024' ? 'ML-KEM-1024' : 'ML-KEM-768'} (hybrid key exchange)`, why: 'Both proposals share ML-KEM, so the key exchange combines classical DH and ML-KEM. Look for "PQC Key Exchange" in show crypto ikev2 sa detailed.' };
    if (e.ok) return { kind: 'up', title: 'Up, classical', why: e.pqcModes && e.pqcModes.includes('optional') ? 'ML-KEM was optional on one side and missing on the other, so the routers fell back to classical DH without any error.' : 'Every check passed: the algorithms overlap, the keys and identities match, and the transform sets agree.' };
    const map = {
      NO_PROPOSAL_CHOSEN: e.stage === 'child' ? 'The IKE SA was agreed, but the transform sets have nothing in common. The first IPsec SA fails inside IKE_AUTH, and IOS deletes the IKE SA too.' : e.mlkem ? 'The classical algorithms match, but ML-KEM is required on one side without a shared parameter set.' : 'Encryption, integrity and DH group each need a value in common. R3 answered NO_PROPOSAL_CHOSEN.',
      AUTHENTICATION_FAILED: 'The algorithms agree, but the pre-shared keys don\'t, so IKE_AUTH fails on both routers.',
      NO_PROFILE: 'R3 found no IKEv2 profile that accepts R1\'s identity (match identity remote address), so it refused IKE_AUTH.',
      PEER_UNREACHABLE: 'The IKE packets never reach the peer: check the WAN addresses and static routes.',
    };
    return { kind: 'down', title: `Down: ${e.code}${e.stage === 'child' ? ' (IPsec SA)' : ''}`, why: map[e.code] || e.reason || '' };
  }
  function runTest() {
    const btn = $('#run'); btn.disabled = true; btn.textContent = '⏳ Negotiating…';
    setTimeout(() => {
      let html;
      try {
        const sim = simulate(), r = explain(sim); lastRun = r;
        const verdict = prediction ? `<div class="verdict ${prediction === r.kind ? 'ok' : 'no'}">${prediction === r.kind ? '✓' : '✕'} You predicted “${esc(PRED.find(p => p[0] === prediction)[1])}”</div>` : '';
        const errLines = d => sim.logs[d].filter(x => /IKEv2-ERROR|CRYPTO-4/.test(x)).map(x => x.replace(/^\*\w{3}\s+\d+ \d{4} [\d:.]+: /, '')).slice(0, 8);
        const dbg = DEVS.map(d => `<figure><figcaption>${H[d]}: debug crypto ikev2 error</figcaption><pre>${esc(errLines(d).join('\n') || '(no error lines)')}</pre></figure>`).join('');
        html = `<div class="out ${r.kind}"><h3>${esc(r.title)}</h3>${verdict}<p>${esc(r.why)}</p>${sim.errs.length ? `<p class="note">IOS rejected some lines: ${esc(sim.errs.slice(0, 3).join(' · '))}</p>` : ''}</div>
          <div class="evidence">
            <figure><figcaption>R1# ping ${esc(cfg.r3.tun.ip)}</figcaption><pre>${esc(sim.ev.ping)}</pre></figure>
            <figure><figcaption>R1# show crypto ikev2 sa</figcaption><pre>${esc(sim.ev.sa1 || '(empty: no IKE SA)')}</pre></figure>
            <figure><figcaption>R3# show crypto ikev2 sa</figcaption><pre>${esc(sim.ev.sa3 || '(empty: no IKE SA)')}</pre></figure>
            <figure><figcaption>R1# show crypto ipsec sa | include pkts</figcaption><pre>${esc(sim.ev.enc)}</pre></figure>
            ${dbg}
          </div>`;
      } catch (err) { html = `<div class="out down"><h3>The simulator could not run this configuration</h3><p>${esc(err.message)}</p></div>`; lastRun = null; }
      $('#result').innerHTML = html; btn.disabled = false; btn.textContent = '▶ Run negotiation'; refresh();
    }, 30);
  }

  /* ───────── events ───────── */
  const flashBlock = (dev, key) => { const el = $(`#blk-${dev}-${key}`); if (!el) return; el.classList.add('flash'); setTimeout(() => el.classList.remove('flash'), 900); };
  const changed = () => { if (lastRun) { lastRun = null; $('#result').innerHTML = ''; } refresh(); };
  document.addEventListener('input', e => {
    const t = e.target;
    if (t.dataset.r2) { r2[t.dataset.r2] = t.value.trim(); t.classList.toggle('bad', !isIp(r2[t.dataset.r2])); return changed(); }
    if (!t.dataset.dev || t.type === 'checkbox' || t.tagName === 'SELECT') return;
    let v = t.value.trim(); if (t.dataset.f === 'name' || t.dataset.ref) v = v.replace(/\s+/g, '-');
    cfg[t.dataset.dev][t.dataset.b][t.dataset.f] = v; changed();
  });
  document.addEventListener('change', e => {
    const t = e.target;
    if (t.id === 'start') return load(t.value);
    if (t.name === 'pred') { prediction = t.value; return; }
    if (!t.dataset.dev) return;
    const c = cfg[t.dataset.dev][t.dataset.b];
    if (t.type === 'checkbox') c[t.dataset.f] = t.checked; else if (t.tagName === 'SELECT') c[t.dataset.f] = t.value; else return;
    if (t.dataset.f === 'pqc') rerenderBlock(t.dataset.dev, t.dataset.b);
    changed();
  });
  document.addEventListener('click', e => {
    const chip = e.target.closest('.chip');
    if (chip) { const { dev, b, f, v } = chip.dataset, list = cfg[dev][b][f], i = list.indexOf(v); if (i >= 0) list.splice(i, 1); else list.push(v); rerenderBlock(dev, b); return changed(); }
    const eye = e.target.closest('.eye');
    if (eye) { const k = eye.dataset.eye; if (eyes.has(k)) eyes.delete(k); else eyes.add(k); const [dev, key] = k.split(':'); eye.setAttribute('aria-pressed', eyes.has(k)); $(`#blk-${dev}-${key}-ios`).hidden = !eyes.has(k); return refresh(); }
    const fix = e.target.closest('.fix');
    if (fix) { const [dev, key, f] = fix.dataset.fix.split(':'), target = cfg[dev][BY[key].fields.find(x => x.f === f).ref].name; cfg[dev][key][f] = target; $(`#${fieldId(dev, key, f)}`).value = target; return changed(); }
    const ch = e.target.closest('.chunk');
    if (ch) { if (ch.dataset.chunk === 'test') { $('#test').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' }); return; } focus = ch.dataset.chunk || null; renderChunks(); const first = BLOCKS.find(b => b.chunk === focus); if (first) $(`#row-${first.key}`).scrollIntoView({ block: 'start', behavior: 'smooth' }); return; }
    const fb = e.target.closest('[data-full]');
    if (fb) { const dev = fb.dataset.full; $('#full-h').textContent = `${H[dev]} — full configuration`; $('#full-pre').textContent = fullConfig(dev); $('#copy').textContent = 'Copy'; $('#full').showModal(); return; }
    if (e.target.id === 'full-x') return $('#full').close();
    if (e.target.id === 'copy') { const txt = $('#full-pre').textContent; const done = () => { $('#copy').textContent = 'Copied'; }; try { navigator.clipboard.writeText(txt).then(done, () => { selectPre(); }); } catch (err) { selectPre(); } return; }
    if (e.target.id === 'run') return runTest();
  });
  const selectPre = () => { const r = document.createRange(); r.selectNodeContents($('#full-pre')); const s = getSelection(); s.removeAllRanges(); s.addRange(r); $('#copy').textContent = 'Press ⌘C / Ctrl+C'; };
  // hovering a reference highlights the block it points to: names are how blocks connect
  document.addEventListener('focusin', e => { const t = e.target; if (t.dataset && t.dataset.ref) flashBlock(t.dataset.dev, t.dataset.ref); });
  document.addEventListener('mouseover', e => { const t = e.target.closest('[data-ref]'); if (t && !t.dataset.hovered) { t.dataset.hovered = '1'; flashBlock(t.dataset.dev, t.dataset.ref); t.addEventListener('mouseleave', () => { delete t.dataset.hovered; }, { once: true }); } });

  load('example');
  window.__blocks = { get cfg() { return cfg; }, load, analyze, fullConfig, simulate, explain };
})();
