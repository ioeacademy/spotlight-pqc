/* ==========================================================================
   ios-pqc-engine.js — multi-router Cisco IOS XE simulator for PQC IPsec labs
   --------------------------------------------------------------------------
   - Any number of routers, wired back to back: routed ports (default) or
     access switchports + SVIs
   - Per-tunnel IKEv2 negotiation computed from each router's live config:
     proposals (incl. `pqc mlkem768 [mlkem1024 …] [optional]`), RFC 8784 PPK,
     IKEv2 fragmentation, identity matching, PSK (keyring or inline),
     transform sets, and IPsec PFS (`set pfs` — DH/ML-KEM on CREATE_CHILD_SA)
   Command syntax follows the Cisco IOS XE "Post-Quantum Cryptography on
   Cisco 8000 Series Secure Routers for IKEv2 Sessions" configuration guide.
   - Hop-by-hop forwarding (connected + static routes), so a transit router
     can sit between the crypto endpoints
   - IOS-style CLI: modes, abbreviations, `?` help, Tab completion,
     `no` forms, `do`, `| include/exclude/begin/section/count`
   No DOM access — works in the browser (window.PqcLab) and in Node.
   ========================================================================== */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.PqcLab = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const NEG_DELAY_MS = 1500;   // time for a (re)negotiation to complete on its own
  const RETRY_MS = 5000;       // retry interval after a failed negotiation
  const IOS_VERSION = '26.2';

  /* ───────────────────────── IP helpers ───────────────────────── */
  const isIp = s => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) && s.split('.').every(o => +o <= 255);
  const ipInt = s => s.split('.').reduce((a, o) => a * 256 + Number(o), 0);
  const intIp = n => [24, 16, 8, 0].map(b => Math.floor(n / 2 ** b) % 256).join('.');
  const maskLen = m => { const n = ipInt(m); let c = 0; for (let i = 31; i >= 0; i--) { if (Math.floor(n / 2 ** i) % 2) c++; else break; } return c; };
  const lenMask = l => intIp(l === 0 ? 0 : 2 ** 32 - 2 ** (32 - l));
  const isMask = m => isIp(m) && lenMask(maskLen(m)) === m;
  const netOf = (ip, mask) => intIp((ipInt(ip) & ipInt(mask)) >>> 0);
  const inNet = (ip, net, mask) => netOf(ip, mask) === netOf(net, mask);
  const hex = n => Array.from({ length: n }, () => '0123456789ABCDEF'[Math.floor(Math.random() * 16)]).join('');

  /* ───────────────────────── Interfaces ───────────────────────── */
  const IF_TYPES = [
    { name: 'Loopback', short: 'Lo' },
    { name: 'Tunnel', short: 'Tu' },
    { name: 'GigabitEthernet', short: 'Gi' },
    { name: 'TwoGigabitEthernet', short: 'Tw' },
    { name: 'Vlan', short: 'Vl' },
  ];
  function canonIf(s) {
    const m = /^([a-zA-Z-]+)\s*(\d+(?:\/\d+)*)$/.exec(String(s || '').trim());
    if (!m) return null;
    const t = m[1].toLowerCase();
    const exact = IF_TYPES.find(x => x.name.toLowerCase() === t);
    const c = exact ? [exact] : IF_TYPES.filter(x => x.name.toLowerCase().startsWith(t));
    return c.length === 1 ? c[0].name + m[2] : null;
  }
  const ifShort = n => { const t = IF_TYPES.find(x => n.startsWith(x.name)); return t ? t.short + n.slice(t.name.length) : n; };
  const ifKind = n => n.startsWith('Tunnel') ? 'tunnel' : n.startsWith('Vlan') ? 'svi' : n.startsWith('Loopback') ? 'loopback' : 'phys';
  function ifSort(a, b) {
    const ta = IF_TYPES.findIndex(x => a.startsWith(x.name)), tb = IF_TYPES.findIndex(x => b.startsWith(x.name));
    if (ta !== tb) return ta - tb;
    const na = a.replace(/^\D+/, '').split('/').map(Number), nb = b.replace(/^\D+/, '').split('/').map(Number);
    for (let i = 0; i < Math.max(na.length, nb.length); i++) if ((na[i] || 0) !== (nb[i] || 0)) return (na[i] || 0) - (nb[i] || 0);
    return 0;
  }

  /* ───────────────────────── Labels ───────────────────────── */
  const ENC_LABEL = { 'aes-cbc-128': 'AES-CBC, keysize: 128', 'aes-cbc-192': 'AES-CBC, keysize: 192', 'aes-cbc-256': 'AES-CBC, keysize: 256', 'aes-gcm-128': 'AES-GCM, keysize: 128', 'aes-gcm-256': 'AES-GCM, keysize: 256' };
  const PQC_LABEL = { mlkem512: 'ML-KEM-512', mlkem768: 'ML-KEM-768', mlkem1024: 'ML-KEM-1024' };
  const MLKEM_SIZES = { mlkem512: [800, 768], mlkem768: [1184, 1088], mlkem1024: [1568, 1568] };
  const DH_LABEL = { 14: 'MODP-2048', 15: 'MODP-3072', 16: 'MODP-4096', 19: 'ECDH P-256', 20: 'ECDH P-384', 21: 'ECDH P-521', 24: 'MODP-2048/256' };
  // ESP transform characteristics as printed by IOS XE
  const espInfo = esp => /gcm/.test(esp)
    ? { encr: 'AES-GCM', key: (esp.match(/(\d+)/) || [, '256'])[1], hmac: 'None', mtu: 1446, tmtu: 9946, iv: 8 }
    : { encr: 'AES-CBC', key: (esp.match(/esp-aes (\d+)/) || [, '128'])[1], hmac: ((esp.match(/esp-(sha\d*)-hmac/) || [, 'sha'])[1]).toUpperCase().replace(/^SHA$/, 'SHA1'), mtu: 1438, tmtu: 9938, iv: 16 };
  // Shown in `show version` and in the UI: this is a learning aid, not a validation tool
  const DISCLAIMER = [
    '*** Spotlight PQC: EDUCATIONAL SIMULATOR, not a real Cisco device ***',
    'Built to practise IOS XE commands and learn post-quantum VPN concepts and',
    'configuration steps. Output is modelled on IOS XE and may differ from real',
    'platforms and releases. Do not use it to validate, test or certify',
    'configurations for production networks.',
    'Provided "as is", without warranty or support of any kind. Not affiliated',
    'with or endorsed by Cisco Systems, Inc. Use at your own risk.',
  ];
  const spiNum = s => parseInt(String(s).replace(/^0x/i, ''), 16) >>> 0;
  const spiLong = s => { const v = spiNum(s); return `0x${v.toString(16).toUpperCase()}(${v})`; };
  const spiShort = s => `0x${spiNum(s).toString(16).toUpperCase()}`;
  const hms = sec => [sec / 3600, sec / 60 % 60, sec % 60].map(n => String(Math.floor(n)).padStart(2, '0')).join(':');
  const EXCH = ['IKE_SA_INIT', 'IKE_INTERMEDIATE', 'IKE_AUTH', 'CREATE_CHILD_SA', 'CREATE_CHILD_SA_IKE_REKEY', 'INFORMATIONAL'];
  const DEFAULT_PROPOSAL = { enc: ['aes-cbc-256'], integ: ['sha512', 'sha384'], group: [19, 14, 21], prf: null, pqc: null };
  const DH_SHOW = { 14: 'DH_GROUP_2048_MODP/Group 14', 15: 'DH_GROUP_3072_MODP/Group 15', 16: 'DH_GROUP_4096_MODP/Group 16', 19: 'DH_GROUP_256_ECP/Group 19', 20: 'DH_GROUP_384_ECP/Group 20', 21: 'DH_GROUP_521_ECP/Group 21', 24: 'DH_GROUP_2048_256_MODP/Group 24' };
  const DH_KE_BYTES = { 14: 256, 15: 384, 16: 512, 19: 64, 20: 96, 21: 132, 24: 256 };

  /* ───────────────────────── Help text ───────────────────────── */
  const DESC = {
    'enable': 'Turn on privileged commands', 'disable': 'Turn off privileged commands', 'exit': 'Exit from the EXEC', 'logout': 'Exit from the EXEC',
    'ping': 'Send echo messages', 'traceroute': 'Trace route to destination', 'show': 'Show running system information',
    'configure': 'Enter configuration mode', 'configure terminal': 'Configure from the terminal', 'clear': 'Reset functions',
    'clear crypto': 'Encryption module', 'crypto ikev2': 'Configure IKEv2 Options', 'crypto ipsec': 'Configure IPSEC policy',
    'ikev2 sa': 'Clear IKEv2 SAs', 'sa fast': 'Clear SAs without waiting for peer acknowledgement', 'crypto session': 'Clear crypto sessions (tunnels)',
    'write': 'Write running configuration to memory, network, or terminal', 'write memory': 'Write to NV memory', 'copy': 'Copy from one file to another',
    'copy running-config': 'Copy from current system configuration', 'running-config startup-config': 'Copy to startup configuration',
    'debug': 'Debugging functions (see also \'undebug\')', 'debug crypto': 'Cryptographic subsystem', 'crypto ikev2': 'Configure IKEv2 Options',
    'undebug': 'Disable debugging functions (see also \'debug\')', 'all': 'Enable all debugging', 'terminal': 'Set terminal line parameters', 'length': 'Set number of lines on a screen',
    'show running-config': 'Current operating configuration', 'show version': 'System hardware and software status', 'show clock': 'Display the system clock',
    'show history': 'Display the session command history', 'show logging': 'Show the contents of logging buffers', 'show ip': 'IP information',
    'ip interface': 'IP interface status and configuration', 'interface brief': 'Brief summary of IP status and configuration', 'ip route': 'IP routing table',
    'show interfaces': 'Interface status and configuration', 'show crypto': 'Encryption module', 'ikev2 sa': 'Shows ikev2 SAs', 'sa detailed': 'show detailed ikev2 SA information',
    'ikev2 stats': 'Shows IKEv2 statistics', 'ikev2 proposal': 'Show IKEv2 proposals', 'ikev2 policy': 'Show IKEv2 policies', 'ikev2 profile': 'Shows ikev2 profiles',
    'ipsec sa': 'IPSEC SA table', 'ipsec transform-set': 'Crypto transform sets', 'crypto session': 'Show crypto sessions (tunnels)', 'session detail': 'Show detailed crypto session information',
    'running-config interface': 'Show interface configuration', 'ping source': 'specify source address or name', 'repeat': 'specify repeat count',
    'hostname': 'Set system\'s network name', 'interface': 'Select an interface to configure', 'ip': 'Global IP configuration subcommands',
    'crypto': 'Encryption module', 'end': 'Exit from configure mode', 'do': 'To run exec commands in config mode', 'no': 'Negate a command or set its defaults',
    'ip route': 'Establish static routes', 'ikev2 proposal': 'Define IKEv2 proposals', 'ikev2 policy': 'Define IKEV2 policies', 'ikev2 keyring': 'Define IKEv2 keyrings',
    'ikev2 profile': 'Define IKEv2 profiles', 'ikev2 fragmentation': 'Enable fragmentation of IKEv2 packets', 'fragmentation mtu': 'Specify the fragmentation MTU',
    'ipsec transform-set': 'Define transform and settings', 'ipsec profile': 'Configure an ipsec policy profile',
    'esp-gcm': 'ESP transform using GCM cipher', 'esp-aes': 'ESP transform using AES cipher', 'esp-sha-hmac': 'ESP transform using HMAC-SHA1 auth', 'esp-sha256-hmac': 'ESP transform using HMAC-SHA256 auth',
    'esp-sha384-hmac': 'ESP transform using HMAC-SHA384 auth', 'esp-sha512-hmac': 'ESP transform using HMAC-SHA512 auth',
    '128': '128 bit keys.', '192': '192 bit keys.', '256': '256 bit keys.',
    'ip address': 'Set the IP address of an interface', 'shutdown': 'Shutdown the selected interface', 'description': 'Interface specific description',
    'tunnel': 'protocol-over-protocol tunneling', 'tunnel source': 'source of tunnel packets', 'tunnel destination': 'destination of tunnel', 'tunnel mode': 'tunnel encapsulation method',
    'mode ipsec': 'IPSec tunnel encapsulation', 'ipsec ipv4': 'over IPv4', 'mode gre': 'generic route encapsulation protocol', 'gre ip': 'over IP',
    'tunnel protection': 'Enable tunnel protection', 'protection ipsec': 'Use ipsec for tunnel protection', 'ipsec profile': 'Determine the ipsec policy profile to use.',
    'switchport': 'Set switching mode characteristics', 'switchport access': 'Set access mode characteristics of the interface', 'access vlan': 'Set VLAN when interface is in access mode',
    'switchport mode': 'Set trunking mode of the interface', 'mode access': 'Set trunking mode to ACCESS unconditionally',
    'encryption': 'Set encryption algorithm(s)', 'integrity': 'Set integrity hash algorithm(s)', 'group': 'Set the Diffie-Hellman group(s)', 'prf': 'Set pseudo-random function(s)',
    'pqc': 'Set Post-Quantum Cryptography key exchange', 'mlkem512': 'ML-KEM-512 (FIPS 203, NIST level 1)', 'mlkem768': 'ML-KEM-768 (FIPS 203, NIST level 3)', 'mlkem1024': 'ML-KEM-1024 (FIPS 203, NIST level 5)',
    'optional': 'ML-KEM is proposed but not mandatory (fallback to classical allowed)',
    'aes-cbc-128': 'AES-CBC-128', 'aes-cbc-192': 'AES-CBC-192', 'aes-cbc-256': 'AES-CBC-256', 'aes-gcm-128': 'Combined-mode, 128 bit key, 16 byte ICV', 'aes-gcm-256': 'Combined-mode, 256 bit key, 16 byte ICV',
    'sha1': 'SHA-1', 'sha256': 'SHA-256', 'sha384': 'SHA-384', 'sha512': 'SHA-512',
    '14': 'DH 2048 MODP', '15': 'DH 3072 MODP', '16': 'DH 4096 MODP', '19': 'DH 256 ECP', '20': 'DH 384 ECP', '21': 'DH 521 ECP', '24': 'DH 2048 (256 subgroup) MODP',
    'proposal': 'Specify Proposal', 'match': 'Match values of local fields', 'match address': 'Local address', 'address local': 'Local address',
    'peer': 'Configure a Peer and associated keys', 'address': 'Address of the peer', 'pre-shared-key': 'pre share key for the peer',
    'ppk': 'Postquantum Preshared Key (RFC 8784)', 'manual': 'Manually configured PPK', 'id': 'PPK identity', 'key': 'PPK value', 'hex': 'Key in hexadecimal', 'ppk required': 'Tunnel must not come up without PPK',
    'identity': 'Match on peer IKE identity', 'identity remote': 'Remote identity', 'remote address': 'IP Address(es)', 'authentication': 'Set authentication method',
    'local': 'Local authentication method', 'remote': 'Remote authentication method', 'pre-share': 'Pre-Shared Key', 'keyring': 'Keyring',
    'keyring local': 'Keyring for local authentication', 'keyring ppk': 'Keyring holding Postquantum Preshared Keys', 'lifetime': 'Set lifetime for ikev2 SA',
    'mode': 'encapsulation mode (transport/tunnel)', 'mode tunnel': 'tunnel (datagram encapsulation) mode', 'mode transport': 'transport (payload encapsulation) mode',
    'set': 'Specify a parameter for the profile', 'set transform-set': 'Specify list of transform sets in priority order', 'set ikev2-profile': 'Specify ikev2 Profile',
    'set pfs': 'Specify pfs settings', 'source': 'specify source address or name',
    'group14': 'D-H Group14 (2048-bit modulus)', 'group15': 'D-H Group15 (3072-bit modulus)', 'group16': 'D-H Group16 (4096-bit modulus)',
    'group19': 'D-H Group19 (256-bit order ECP)', 'group20': 'D-H Group20 (384-bit order ECP)', 'group21': 'D-H Group21 (521-bit order ECP)', 'group24': 'D-H Group24 (2048-bit modulus & 256-bit subgroup)',
    'pfs pqc': 'Post-Quantum key exchange for PFS', 'pre-share key': 'Inline pre-shared key', 'crypto sa': 'Clear all IPSec security associations', 'sa detail': 'Show detailed IPSec SA information',
    // context-specific (first keyword of the command : previous keyword + keyword)
    'show:ikev2 proposal': 'Show IKEv2 proposals', 'show:ikev2 policy': 'Show IKEv2 policies', 'show:ikev2 profile': 'Shows ikev2 profiles',
    'show:ikev2 sa': 'Shows ikev2 SAs', 'show:crypto session': 'Show crypto sessions (tunnels)', 'show:crypto ikev2': 'Shows ikev2 info',
    'show:crypto ipsec': 'Show IPSEC policy', 'clear:ikev2 sa': 'Clear IKEv2 SAs', 'clear:crypto session': 'Clear crypto sessions (tunnels)',
    'clear:crypto ikev2': 'Clear IKEv2 SAs and statistics', 'debug:crypto ikev2': 'IKEv2 debug messages', 'show:ip route': 'IP routing table',
  };
  const ARG_DESC = { WORD: 'WORD', IP: 'A.B.C.D', IFACE: 'Interface', LINE: 'LINE', RANGE: '' };

  /* ───────────────────────── Pattern parser ───────────────────────── */
  // 'crypto ikev2 proposal WORD'  ·  '(a|b|c)' keyword set  ·  A.B.C.D  ·  IFACE  ·  LINE  ·  <1-100>
  function parsePattern(str) {
    return str.trim().split(/\s+/).map(t => {
      if (t === 'WORD') return { arg: 'WORD' };
      if (t === 'A.B.C.D') return { arg: 'IP' };
      if (t === 'IFACE') return { arg: 'IFACE' };
      if (t === 'LINE') return { arg: 'LINE' };
      let m = /^<(\d+)-(\d+)>$/.exec(t);
      if (m) return { arg: 'RANGE', lo: +m[1], hi: +m[2] };
      m = /^\((.+)\)$/.exec(t);
      if (m) return { kw: m[1].split('|') };
      return { kw: [t] };
    });
  }
  function argAccepts(spec, tok) {
    switch (spec.arg) {
      case 'WORD': case 'LINE': return true;
      case 'IP': return isIp(tok);
      case 'IFACE': return !!canonIf(tok);
      case 'RANGE': return /^\d+$/.test(tok) && +tok >= spec.lo && +tok <= spec.hi;
    }
    return false;
  }
  function tokenize(raw) {
    const toks = [];
    const re = /\S+/g; let m;
    while ((m = re.exec(raw))) toks.push({ t: m[0], pos: m.index });
    // merge "Tunnel 0" / "vlan 12" into one interface token
    for (let i = 0; i < toks.length - 1; i++) {
      const a = toks[i].t, b = toks[i + 1].t;
      if (/^[a-zA-Z-]{2,}$/.test(a) && /^\d+(\/\d+)*$/.test(b) && canonIf(a + b) &&
          !['group', 'repeat', 'length', 'mtu', 'lifetime', 'vlan', 'id', 'key'].includes(a.toLowerCase()) &&
          i > 0 && ['interface', 'source', 'int', 'interfaces'].some(k => k.startsWith(toks[i - 1].t.toLowerCase()) && toks[i - 1].t.length >= 2)) {
        toks.splice(i, 2, { t: a + b, pos: toks[i].pos });
      }
    }
    return toks;
  }
  // Core matcher. Returns {cands, err, errIdx}
  function matchCmds(cmds, toks) {
    let cands = cmds.map(c => ({ c, vals: [], line: false }));
    for (let i = 0; i < toks.length; i++) {
      const tok = toks[i].t, tl = tok.toLowerCase();
      const lineC = cands.filter(x => x.line);
      const active = cands.filter(x => !x.line && i < x.c.tokens.length);
      const kwSet = new Set();
      for (const x of active) { const s = x.c.tokens[i]; if (s.kw) for (const k of s.kw) if (k.startsWith(tl)) kwSet.add(k); }
      let next = [];
      if (kwSet.size) {
        let chosen = kwSet.has(tl) ? tl : (kwSet.size === 1 ? [...kwSet][0] : null);
        if (!chosen) return { cands: [], err: 'ambiguous', errIdx: i };
        for (const x of active) { const s = x.c.tokens[i]; if (s.kw && s.kw.includes(chosen)) next.push({ ...x, vals: [...x.vals, chosen] }); }
      } else {
        for (const x of active) {
          const s = x.c.tokens[i];
          if (s.arg && argAccepts(s, tok)) {
            const v = s.arg === 'IFACE' ? canonIf(tok) : tok;
            next.push({ ...x, vals: [...x.vals, v], line: s.arg === 'LINE' });
          }
        }
      }
      for (const x of lineC) next.push({ ...x, vals: [...x.vals.slice(0, -1), x.vals[x.vals.length - 1] + ' ' + tok] });
      if (!next.length) return { cands: [], err: 'invalid', errIdx: i };
      cands = next;
    }
    return { cands };
  }
  const isComplete = x => x.line || x.vals.length === x.c.tokens.length;

  function helpFor(cmds, raw) {
    const endsSpace = /\s$/.test(raw) || raw === '';
    const toks = tokenize(raw);
    const prefix = endsSpace ? toks : toks.slice(0, -1);
    const partial = endsSpace ? '' : toks[toks.length - 1].t.toLowerCase();
    const r = matchCmds(cmds, prefix);
    if (r.err) return { err: r.err, errIdx: r.errIdx, toks: prefix };
    const n = prefix.length;
    const prevKw = n > 0 ? prefix[n - 1].t.toLowerCase() : '';
    const prevFull = n > 0 ? (r.cands[0] && r.cands[0].vals[n - 1]) : '';
    const out = new Map(); let cr = false;
    for (const x of r.cands) {
      if (x.line) { if (endsSpace) { out.set('LINE', 'LINE'); cr = true; } continue; }
      if (n === x.c.tokens.length) { if (endsSpace) cr = true; continue; }
      const s = x.c.tokens[n];
      if (s.kw) {
        const first = n > 0 ? x.vals[0] : '';
        for (const k of s.kw) if (k.startsWith(partial)) out.set(k, DESC[`${first}:${prevFull} ${k}`] || DESC[`${prevFull} ${k}`] || DESC[`${prevKw} ${k}`] || DESC[k] || '');
      } else if (endsSpace) {
        if (s.arg === 'RANGE') out.set(`<${s.lo}-${s.hi}>`, (x.c.argHelp && x.c.argHelp[n]) || '');
        else out.set(ARG_DESC[s.arg] || s.arg, (x.c.argHelp && x.c.argHelp[n]) || (s.arg === 'IFACE' ? 'Interface name' : ''));
      }
    }
    const entries = [...out.entries()].sort((a, b) => (/^[A-Z<]/.test(a[0]) ? 1 : 0) - (/^[A-Z<]/.test(b[0]) ? 1 : 0) || a[0].localeCompare(b[0]));
    if (cr) entries.push(['<cr>', '<cr>']);
    return { entries, partial: !endsSpace };
  }

  /* ───────────────────────── Command tables ───────────────────────── */
  const C = (p, run, opts = {}) => ({ p, tokens: parsePattern(p), run, ...opts });

  /* ───────────────────────── Lab ───────────────────────── */
  class Lab {
    constructor(topology, opts = {}) {
      this.now = opts.now || (() => Date.now());
      this.disclaimer = opts.disclaimer !== false;
      this.topo = topology;
      this.devs = {};
      this.order = Object.keys(topology.devices);
      this.links = topology.links.map(l => ({ a: l.a, b: l.b, label: l.label || '', speed: l.speed || '' }));
      this.pairState = new Map();
      this.logQueue = [];
      this.cmdLog = [];
      this.seq = 0;
      this.ceCounter = 1000;
      this.sessionCounter = 0;
      this.changeListeners = [];
      for (const k of this.order) this.devs[k] = this._makeDevice(k, topology.devices[k]);
      this._buildCommands();
    }

    /* ---------- device model ---------- */
    _makeDevice(key, def) {
      const d = {
        key, hostname: def.hostname, role: def.role || '', model: def.model || 'C8235-G2', serial: def.serial || 'FGL0000SIM',
        mode: def.startMode || 'exec', ctx: {}, ifaces: {}, routes: [], history: [], logBuf: [],
        crypto: { fragMtu: null, proposals: {}, policies: {}, keyrings: {}, profiles: {}, tsets: {}, ipsecProfiles: {},
          // IKEv2 smart defaults (Cisco "Configuring IKEv2": default proposal/policy/IPsec profile/transform set)
          defaults: { proposal: true, policy: true, ipsecProfile: true, tset: true } },
        debug: { ikev2: false }, arp: new Set(), bootAt: this.now() - (def.uptimeMin || 0) * 60000, lastChange: this.now(), stats: { inReq: 0, outReq: 0, inRej: 0, outRej: 0 },
        exch: {}, pqcSupport: def.pqcSupport !== false, version: def.version || '26.02.01',
      };
      for (const [n, cfg] of Object.entries(def.interfaces)) {
        d.ifaces[n] = { name: n, kind: ifKind(n), shutdown: !!cfg.shutdown, ip: cfg.ip || '', mask: cfg.mask || '', desc: cfg.desc || '',
          vlan: cfg.vlan || null, swMode: cfg.vlan ? 'access' : null, tunnel: ifKind(n) === 'tunnel' ? { source: '', dest: '', mode: 'gre ip', protection: '' } : null,
          boot: true, createdAt: this.now(), cnt: { inP: 0, outP: 0, inB: 0, outB: 0, last: null } };
      }
      for (const r of def.routes || []) d.routes.push({ ...r });
      return d;
    }
    dev(k) { return this.devs[k]; }

    /* ---------- events ---------- */
    _ts() {
      const d = new Date(this.now());
      const mon = d.toLocaleString('en-US', { month: 'short' });
      const p = (n, w = 2) => String(n).padStart(w, '0');
      return `*${mon} ${String(d.getDate()).padStart(2, ' ')} ${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
    }
    _log(devKey, msg, cls = 'log') {
      const line = `${this._ts()}: ${msg}`;
      const d = this.devs[devKey];
      d.logBuf.push(line); if (d.logBuf.length > 200) d.logBuf.shift();
      this.logQueue.push({ dev: devKey, text: line, cls });
    }
    _debug(devKey, msg) { if (this.devs[devKey].debug.ikev2) this.logQueue.push({ dev: devKey, text: `${this._ts()}: ${msg}`, cls: 'debug' }); }
    drainLogs() { const q = this.logQueue; this.logQueue = []; return q; }

    /* ---------- L2 / interface state ---------- */
    _peerPort(devKey, port) {
      for (const l of this.links) {
        if (l.a[0] === devKey && l.a[1] === port) return l.b;
        if (l.b[0] === devKey && l.b[1] === port) return l.a;
      }
      return null;
    }
    portUp(devKey, port) {
      const p = this.devs[devKey].ifaces[port]; if (!p || p.shutdown) return false;
      const peer = this._peerPort(devKey, port); if (!peer) return false;
      const pp = this.devs[peer[0]].ifaces[peer[1]]; return !!pp && !pp.shutdown;
    }
    lineUp(devKey, name) {
      const d = this.devs[devKey], i = d.ifaces[name]; if (!i || i.shutdown) return false;
      switch (i.kind) {
        case 'phys': return this.portUp(devKey, name);
        case 'svi': { const v = +name.slice(4); return Object.values(d.ifaces).some(p => p.kind === 'phys' && p.vlan === v && this.portUp(devKey, p.name)); }
        case 'loopback': return true;
        case 'tunnel': {
          if (i.tunnel.mode === 'ipsec ipv4') { const st = this._pairOf(devKey, name); return !!(st && st.state === 'up' && !st.sa.child.down); }
          return !!(this._srcIp(d, i) && i.tunnel.dest);
        }
      }
      return false;
    }
    _srcIp(d, ifc) {
      const s = ifc.tunnel && ifc.tunnel.source; if (!s) return '';
      if (isIp(s)) return s;
      const src = d.ifaces[s]; return src && src.ip && this.lineUp(d.key, s) ? src.ip : '';
    }

    /* ---------- routing ---------- */
    routes(devKey, opts = {}) {
      const d = this.devs[devKey]; const out = [];
      for (const i of Object.values(d.ifaces)) {
        if (!i.ip) continue;
        if (opts.noTunnels && i.kind === 'tunnel') continue;
        if (!this.lineUp(devKey, i.name)) continue;
        const len = maskLen(i.mask);
        out.push({ type: 'C', net: netOf(i.ip, i.mask), len, iface: i.name });
        out.push({ type: 'L', net: i.ip, len: 32, iface: i.name });
      }
      const conn = out.slice();
      for (const r of d.routes) {
        if (r.iface) {
          // `ip route NET MASK <interface>`: installed while the interface is up (directly connected static)
          if (opts.noTunnels && ifKind(r.iface) === 'tunnel') continue;
          if (d.ifaces[r.iface] && this.lineUp(devKey, r.iface)) out.push({ type: 'S', net: r.net, len: maskLen(r.mask), nh: null, iface: r.iface });
          continue;
        }
        const via = conn.filter(c => c.type === 'C' && inNet(r.nh, c.net, lenMask(c.len))).sort((a, b) => b.len - a.len)[0];
        if (via) out.push({ type: 'S', net: r.net, len: maskLen(r.mask), nh: r.nh, iface: via.iface });
      }
      return out;
    }
    lookup(devKey, ip, opts) {
      const rs = this.routes(devKey, opts).filter(r => inNet(ip, r.net, lenMask(r.len)));
      const rank = { L: 0, C: 1, S: 2 };
      rs.sort((a, b) => b.len - a.len || rank[a.type] - rank[b.type]);
      return rs[0] || null;
    }
    owns(devKey, ip, opts = {}) {
      return Object.values(this.devs[devKey].ifaces).some(i => i.ip === ip && !(opts.noTunnels && i.kind === 'tunnel') && this.lineUp(devKey, i.name));
    }
    _neighbor(devKey, egress, nh, opts) {
      const d = this.devs[devKey], e = d.ifaces[egress];
      if (e.kind === 'phys' && !e.vlan) {
        if (!this.portUp(devKey, egress)) return null;
        const peer = this._peerPort(devKey, egress); const pi = this.devs[peer[0]].ifaces[peer[1]];
        if (pi && !pi.vlan && pi.ip === nh) return { dev: peer[0], ingress: peer[1], via: 'link', port: egress };
        return null;
      }
      if (e.kind === 'svi') {
        const v = +egress.slice(4);
        for (const p of Object.values(d.ifaces)) {
          if (p.kind !== 'phys' || p.vlan !== v || !this.portUp(devKey, p.name)) continue;
          const peer = this._peerPort(devKey, p.name); const pd = this.devs[peer[0]]; const vb = pd.ifaces[peer[1]].vlan;
          const svi = pd.ifaces['Vlan' + vb];
          if (svi && svi.ip === nh && this.lineUp(peer[0], svi.name)) return { dev: peer[0], ingress: svi.name, via: 'link', port: p.name };
        }
        return null;
      }
      if (e.kind === 'tunnel' && !opts.noTunnels) {
        const st = this._pairOf(devKey, egress); if (!st || st.state !== 'up' || st.sa.child.down) return null;
        const other = st.pair.a.dev === devKey ? st.pair.b : st.pair.a;
        const oi = this.devs[other.dev].ifaces[other.if];
        if (!oi) return null;   // point-to-point VTI: any next hop routed into it lands on the peer
        // underlay must still carry the ESP packets
        const s = this._srcIp(d, e);
        if (!this.forward(devKey, e.tunnel.dest, { noTunnels: true }).ok || !this.forward(other.dev, s, { noTunnels: true }).ok) return null;
        return { dev: other.dev, ingress: other.if, via: 'tunnel', key: st.key };
      }
      return null;
    }
    forward(fromKey, dst, opts = {}) {
      let cur = fromKey; const hops = [];
      for (let ttl = 0; ttl < 16; ttl++) {
        if (this.owns(cur, dst, opts)) return { ok: true, hops, end: cur };
        const r = this.lookup(cur, dst, opts);
        if (!r) return { ok: false, hops, at: cur, reason: 'noroute' };
        if (r.type === 'L') return { ok: false, hops, at: cur, reason: 'down' };
        const nh = r.type === 'C' || !r.nh ? dst : r.nh;
        let nb = this._neighbor(cur, r.iface, nh, opts);
        if (!nb && (r.type === 'C' || !r.nh)) {
          // destination is on a connected subnet but owned by a different host: find who owns it
          nb = this._neighbor(cur, r.iface, dst, opts);
        }
        if (!nb) return { ok: false, hops, at: cur, reason: 'nonb' };
        hops.push({ from: cur, to: nb.dev, egress: r.iface, ingress: nb.ingress, via: nb.via, key: nb.key, nh });
        cur = nb.dev;
      }
      return { ok: false, hops, at: cur, reason: 'ttl' };
    }

    /* ---------- IKEv2 / IPsec ---------- */
    _computePairs() {
      const pairs = new Map();
      for (const ak of this.order) {
        const A = this.devs[ak];
        for (const T of Object.values(A.ifaces)) {
          if (T.kind !== 'tunnel' || T.shutdown || T.tunnel.mode !== 'ipsec ipv4' || !T.tunnel.protection || !T.tunnel.dest) continue;
          const sA = this._srcIp(A, T); if (!sA) continue;
          for (const bk of this.order) {
            if (bk === ak) continue;
            const B = this.devs[bk];
            for (const U of Object.values(B.ifaces)) {
              if (U.kind !== 'tunnel' || U.shutdown || U.tunnel.mode !== 'ipsec ipv4' || !U.tunnel.protection) continue;
              if (U.tunnel.dest !== sA || this._srcIp(B, U) !== T.tunnel.dest) continue;
              const [x, y] = this.order.indexOf(ak) < this.order.indexOf(bk) ? [{ dev: ak, if: T.name }, { dev: bk, if: U.name }] : [{ dev: bk, if: U.name }, { dev: ak, if: T.name }];
              const key = `${x.dev}:${x.if}|${y.dev}:${y.if}`;
              if (!pairs.has(key)) pairs.set(key, { a: x, b: y });
            }
          }
        }
      }
      return pairs;
    }
    _pairOf(devKey, ifName) {
      for (const [key, st] of this.pairState) {
        if ((st.pair.a.dev === devKey && st.pair.a.if === ifName) || (st.pair.b.dev === devKey && st.pair.b.if === ifName)) return st;
      }
      return null;
    }
    _policyProposals(d) {
      const out = [];
      // user-defined policies first; the default policy (proposal "default") only when none is complete
      const userOk = Object.values(d.crypto.policies).some(pol => pol.proposals.some(n => { const p = d.crypto.proposals[n]; return p && p.enc.length && p.group.length; }));
      if (!userOk && d.crypto.defaults.policy && d.crypto.defaults.proposal) return [{ name: 'default', ...DEFAULT_PROPOSAL }];
      for (const pol of Object.values(d.crypto.policies)) for (const pn of pol.proposals) {
        const p = d.crypto.proposals[pn];
        if (p && p.enc.length && (p.integ.length || p.enc.every(e => e.includes('gcm'))) && p.group.length && !out.some(o => o.name === pn)) out.push({ name: pn, ...p });
      }
      return out;
    }
    _matchProposal(pa, pb) {
      const enc = pa.enc.find(e => pb.enc.includes(e)); if (!enc) return null;
      const aead = enc.includes('gcm');
      const integ = aead ? null : pa.integ.find(e => pb.integ.includes(e)); if (!aead && !integ) return null;
      const group = pa.group.find(g => pb.group.includes(g)); if (group == null) return null;
      // `pqc mlkem768 [mlkem1024 …] [optional]` — without `optional` ML-KEM is mandatory
      const ka = pa.pqc, kb = pb.pqc; let pqc = null;
      if (ka && kb) pqc = ka.algs.find(x => kb.algs.includes(x)) || null;
      if (!pqc && ((ka && ka.mode === 'required') || (kb && kb.mode === 'required'))) return null;
      const prf = (pa.prf && pb.prf && pa.prf === pb.prf) ? pa.prf : (integ || 'sha512');
      return { enc, integ, prf, group, pqc };
    }
    _keyringPeer(d, kName, ip) {
      const kr = d.crypto.keyrings[kName]; if (!kr) return null;
      return Object.entries(kr.peers).map(([n, p]) => ({ name: n, ...p }))
        .find(p => p.address && inNet(ip, p.address, p.mask || '255.255.255.255')) || null;
    }
    _profileMatches(prof, ip) { return prof.matchRemote.some(m => inNet(ip, m.ip, m.mask || '255.255.255.255')); }

    _negotiate(pair) {
      const A = this.devs[pair.a.dev], B = this.devs[pair.b.dev];
      const TA = A.ifaces[pair.a.if], TB = B.ifaces[pair.b.if];
      const ipA = this._srcIp(A, TA), ipB = this._srcIp(B, TB);
      const trace = [];
      const fail = (code, reason, side) => ({ ok: false, code, reason, side, trace, ipA, ipB });
      trace.push(`IKE_SA_INIT request ${ipA} → ${ipB}`);
      if (!this.forward(A.key, ipB, { noTunnels: true }).ok) return fail('PEER_UNREACHABLE', `${A.hostname} has no route to the tunnel destination ${ipB}. Check the underlay (ip route) — IKE packets never reach the peer.`, 'a');
      if (!this.forward(B.key, ipA, { noTunnels: true }).ok) return fail('PEER_UNREACHABLE', `${B.hostname} cannot route back to ${ipA}. Check the underlay (ip route) on ${B.hostname}.`, 'b');
      const side = [[A, TA, ipB, 'a'], [B, TB, ipA, 'b']].map(([D, T, peerIp, s]) => {
        const ips = D.crypto.ipsecProfiles[T.tunnel.protection];
        if (!ips) return { err: fail('CONFIG', `${D.hostname}: IPsec profile "${T.tunnel.protection}" referenced by ${T.name} does not exist.`, s) };
        // `set transform-set A B C` — list in priority order
        const tsl = (ips.tsList && ips.tsList.length ? ips.tsList : [ips.ts]).filter(n => n && D.crypto.tsets[n]).map(n => ({ name: n, ...D.crypto.tsets[n] }));
        if (!tsl.length) return { err: fail('CONFIG', `${D.hostname}: IPsec profile "${T.tunnel.protection}" has no valid transform-set.`, s) };
        const ts = tsl[0];
        const prof = D.crypto.profiles[ips.ikev2Profile];
        if (!ips.ikev2Profile || !prof) return { err: fail('CONFIG', `${D.hostname}: IPsec profile "${T.tunnel.protection}" has no valid ikev2-profile.`, s) };
        return { D, T, ips, ts, tsl, prof, peerIp, s };
      });
      for (const x of side) if (x.err) return x.err;
      const [sa, sb] = side;
      // proposals
      const propsA = this._policyProposals(A), propsB = this._policyProposals(B);
      if (!propsA.length) return fail('NO_POLICY', `${A.hostname} has no IKEv2 policy pointing to a complete proposal (encryption + integrity + group).`, 'a');
      if (!propsB.length) return fail('NO_POLICY', `${B.hostname} has no IKEv2 policy pointing to a complete proposal (encryption + integrity + group).`, 'b');
      let chosen = null;
      for (const pa of propsA) { for (const pb of propsB) { const m = this._matchProposal(pa, pb); if (m) { chosen = { ...m, propA: pa.name, propB: pb.name, pqcModeA: pa.pqc && pa.pqc.mode, pqcModeB: pb.pqc && pb.pqc.mode }; break; } } if (chosen) break; }
      if (!chosen) {
        const reqA = propsA.some(p => p.pqc && p.pqc.mode === 'required'), reqB = propsB.some(p => p.pqc && p.pqc.mode === 'required');
        const why = (reqA || reqB) ? ` ${reqA ? A.hostname : B.hostname} requires ML-KEM but ${reqA ? B.hostname : A.hostname} does not offer it.` : ' Encryption, integrity and DH group must overlap.';
        return fail('NO_PROPOSAL_CHOSEN', `No matching IKEv2 proposal between ${A.hostname} and ${B.hostname}.${why}`, 'b');
      }
      trace.push(`IKE_SA_INIT response: proposal ${chosen.propB} selected (${chosen.enc}/${chosen.integ || 'AEAD'}/DH ${chosen.group}${chosen.pqc ? ' + ' + PQC_LABEL[chosen.pqc] : ''})`);
      if (chosen.pqc) {
        const fr = A.crypto.fragMtu && B.crypto.fragMtu;
        trace.push(`IKE_INTERMEDIATE: ${PQC_LABEL[chosen.pqc]} encapsulation key ${MLKEM_SIZES[chosen.pqc][0]} B → ciphertext ${MLKEM_SIZES[chosen.pqc][1]} B (${fr ? `IKEv2 fragmentation, MTU ${Math.min(A.crypto.fragMtu, B.crypto.fragMtu) - 28}` : 'no IKEv2 fragmentation — large messages rely on IP fragmentation'})`);
      }
      // identities / profiles
      if (!this._profileMatches(sb.prof, ipA)) return fail('NO_PROFILE', `${B.hostname}: IKEv2 profile "${sb.ips.ikev2Profile}" has no "match identity remote address ${ipA}" — the initiator's identity is not accepted.`, 'b');
      if (!this._profileMatches(sa.prof, ipB)) return fail('NO_PROFILE', `${A.hostname}: IKEv2 profile "${sa.ips.ikev2Profile}" has no "match identity remote address ${ipB}".`, 'a');
      // authentication (PSK)
      // keys: inline `authentication local|remote pre-share key X` wins over the keyring
      const keys = {};
      for (const x of side) {
        if (x.prof.authLocal !== 'pre-share' || x.prof.authRemote !== 'pre-share') return fail('AUTH_CONFIG', `${x.D.hostname}: IKEv2 profile "${x.ips.ikev2Profile}" needs "authentication local pre-share" and "authentication remote pre-share".`, x.s);
        const pk = x.prof.keyringLocal ? this._keyringPeer(x.D, x.prof.keyringLocal, x.peerIp) : null;
        // keyring peer: `pre-shared-key X` (both directions) or asymmetric `pre-shared-key local X` / `remote Y`
        const kLocal = x.prof.authLocalKey || (pk && (pk.pskLocal || pk.psk)), kRemote = x.prof.authRemoteKey || (pk && (pk.pskRemote || pk.psk));
        if (!kLocal || !kRemote) {
          if (!x.prof.keyringLocal || !x.D.crypto.keyrings[x.prof.keyringLocal]) return fail('AUTH_CONFIG', `${x.D.hostname}: IKEv2 profile "${x.ips.ikev2Profile}" has neither a valid "keyring local" nor inline "pre-share key" values.`, x.s);
          return fail('AUTHENTICATION_FAILED', `${x.D.hostname}: keyring "${x.prof.keyringLocal}" has no peer with address ${x.peerIp} and a pre-shared-key.`, x.s);
        }
        keys[x.s] = { local: kLocal, remote: kRemote };
      }
      if (keys.a.local !== keys.b.remote || keys.b.local !== keys.a.remote) return fail('AUTHENTICATION_FAILED', `Pre-shared keys differ between ${A.hostname} and ${B.hostname} — IKE_AUTH fails.`, 'b');
      // PPK (RFC 8784)
      const ppkA = sa.prof.keyringPpk ? (this._keyringPeer(A, sa.prof.keyringPpk, ipB) || {}).ppk : null;
      const ppkB = sb.prof.keyringPpk ? (this._keyringPeer(B, sb.prof.keyringPpk, ipA) || {}).ppk : null;
      let ppk = null;
      if (ppkA && ppkB && ppkA.id === ppkB.id) {
        if (ppkA.key !== ppkB.key) return fail('AUTHENTICATION_FAILED', `PPK "${ppkA.id}" has a different key on ${A.hostname} and ${B.hostname}; the AUTH payloads do not verify.`, 'b');
        ppk = ppkA.id;
      } else if ((ppkA && ppkA.required) || (ppkB && ppkB.required)) {
        const who = ppkA && ppkA.required ? A.hostname : B.hostname;
        return fail('PPK_REQUIRED', `${who} requires a PPK but no matching PPK (same id and key, and "keyring ppk" in the IKEv2 profile) exists on both peers.`, ppkA && ppkA.required ? 'a' : 'b');
      }
      trace.push(`IKE_AUTH: PSK authentication OK${ppk ? `, PPK "${ppk}" mixed into SK_d/SK_pi/SK_pr` : ''}`);
      // child SA
      // child SA: first transform set in the initiator's list that the responder also has
      // RFC 7296: a Child SA failure inside IKE_AUTH does not tear down the IKE SA —
      // the classic "phase 1 up, no traffic" situation.
      const tsA = sa.tsl.find(x => sb.tsl.some(y => y.esp === x.esp && y.mode === x.mode));
      const tsB = tsA && sb.tsl.find(y => y.esp === tsA.esp && y.mode === tsA.mode);
      let childErr = null;
      if (!tsA) {
        childErr = `NO_PROPOSAL_CHOSEN for the Child SA: no IPsec transform set in common (${A.hostname}: ${sa.tsl.map(x => x.esp).join(', ')}; ${B.hostname}: ${sb.tsl.map(x => x.esp).join(', ')}). The IKE SA is READY, but no IPsec SA exists, so no traffic passes.`;
        trace.push('CHILD_SA: ✕ NO_PROPOSAL_CHOSEN (transform sets) — IKE SA kept, no IPsec SA');
      } else trace.push(`CHILD_SA: ${tsA.esp} ${tsA.mode} mode (${A.hostname} ${tsA.name} / ${B.hostname} ${tsB.name})`);
      const frag = !!(A.crypto.fragMtu && B.crypto.fragMtu);
      return {
        ok: true, trace, ipA, ipB, childErr,
        params: {
          ...chosen, ppk, frag, fragMtu: frag ? Math.min(A.crypto.fragMtu, B.crypto.fragMtu) : null,
          profA: sa.ips.ikev2Profile, profB: sb.ips.ikev2Profile, ipsecA: sa.T.tunnel.protection, ipsecB: sb.T.tunnel.protection,
          esp: tsA ? tsA.esp : null, tsA: tsA ? tsA.name : null, tsB: tsB ? tsB.name : null, lifetime: Math.min(sa.prof.lifetime || 86400, sb.prof.lifetime || 86400), auth: 'PSK',
        },
      };
    }
    _ex(devKey, row, col, n = 1) { const e = this.devs[devKey].exch; (e[row] = e[row] || [0, 0, 0, 0, 0, 0, 0, 0])[col] += n; }
    // one request/response exchange between initiator and responder
    _exchange(ini, resp, name) { this._ex(ini, name, 0); this._ex(resp, name, 2); this._ex(resp, name, 1); this._ex(ini, name, 3); }
    _freeTunnelId(devKey) {
      const used = new Set(); for (const st of this.pairState.values()) if (st.sa && st.sa.ids[devKey]) used.add(st.sa.ids[devKey]);
      let i = 1; while (used.has(i)) i++; return i;
    }
    _attempt(st) {
      const now = this.now();
      const { a, b } = st.pair;
      this.devs[a.dev].stats.outReq++; this.devs[b.dev].stats.inReq++;
      const r = this._negotiate(st.pair);
      // exchange counters (show crypto ikev2 stats exchange)
      this._exchange(a.dev, b.dev, 'IKE_SA_INIT');
      for (const nt of ['NAT_DETECTION_SOURCE_IP', 'NAT_DETECTION_DESTINATION_IP']) { this._exchange(a.dev, b.dev, nt); }
      if (r.ok || !['PEER_UNREACHABLE', 'NO_POLICY', 'NO_PROPOSAL_CHOSEN', 'CONFIG'].includes(r.code)) {
        if (r.params && r.params.pqc) this._exchange(a.dev, b.dev, 'IKE_INTERMEDIATE');
        this._exchange(a.dev, b.dev, 'IKE_AUTH');
        this._ex(a.dev, 'INITIAL_CONTACT', 0); this._ex(b.dev, 'INITIAL_CONTACT', 2); this._ex(a.dev, 'CFG_REQUEST', 0); this._ex(b.dev, 'CFG_REQUEST', 1);
        if (r.code === 'AUTHENTICATION_FAILED') { this._ex(b.dev, 'AUTHENTICATION_FAILED', 1); this._ex(a.dev, 'AUTHENTICATION_FAILED', 3); }
      }
      if (r.code === 'NO_PROPOSAL_CHOSEN') { this._ex(b.dev, 'NO_PROPOSAL_CHOSEN', 1); this._ex(a.dev, 'NO_PROPOSAL_CHOSEN', 3); }
      for (const line of r.trace) { this._debug(a.dev, 'IKEv2: ' + line); this._debug(b.dev, 'IKEv2: ' + line); }
      st.lastAttempt = { at: now, ...r };
      if (!r.ok) {
        this.devs[a.dev].stats.outRej++; this.devs[b.dev].stats.inRej++;
        if (st.state !== 'fail' || st.err !== r.reason) {
          this._debug(a.dev, `IKEv2: ERROR: ${r.code}: ${r.reason}`); this._debug(b.dev, `IKEv2: ERROR: ${r.code}: ${r.reason}`);
        }
        st.state = 'fail'; st.err = r.reason; st.code = r.code; st.retryAt = now + RETRY_MS;
        return false;
      }
      const ids = { [a.dev]: this._freeTunnelId(a.dev) };
      ids[b.dev] = this._freeTunnelId(b.dev);
      st.sa = {
        ids, initiator: a.dev, ip: { [a.dev]: r.ipA, [b.dev]: r.ipB }, peerIp: { [a.dev]: r.ipB, [b.dev]: r.ipA },
        params: r.params, establishedAt: now, ceId: ++this.ceCounter, sessionId: ++this.sessionCounter, cryptoSessionId: 76 + this.sessionCounter,
        spi: { [a.dev]: hex(16), [b.dev]: hex(16) }, espSpi: { [a.dev]: '0x' + hex(8), [b.dev]: '0x' + hex(8) },
        counters: { [a.dev]: { encaps: 0, decaps: 0 }, [b.dev]: { encaps: 0, decaps: 0 } }, trace: r.trace,
        // first Child SA is created inside IKE_AUTH: no extra key exchange, so no PFS until a rekey
        child: r.childErr ? { pfs: null, rekeys: 0, down: true, err: r.childErr, init: a.dev, retryAt: now + RETRY_MS } : { pfs: null, rekeys: 0, down: false },
      };
      st.state = 'up'; st.err = null; st.code = null;
      // the IKE packets themselves resolved ARP on every underlay hop, in both directions
      for (const [from, to] of [[a.dev, r.ipB], [b.dev, r.ipA]]) for (const h of this.forward(from, to, { noTunnels: true }).hops) if (h.via === 'link') this.devs[h.from].arp.add(`${h.from}>${h.nh}`);
      for (const [me, other] of [[a, b], [b, a]]) {
        const peer = st.sa.peerIp[me.dev];
        this._debug(me.dev, `IKEv2: SA established with ${peer}`);
        this._log(me.dev, `%CRYPTO-5-IKEV2_SESSION_STATUS: Crypto tunnel v2 is UP.  Peer ${peer}:500       Id: ${peer}`);
        this._log(me.dev, `%LINEPROTO-5-UPDOWN: Line protocol on Interface ${me.if}, changed state to up`);
      }
      return true;
    }
    /* ---------- IPsec PFS (CREATE_CHILD_SA) ----------
       Outcome table from the IOS XE PQC configuration guide (Table 1).
       cfg: null | {kind:'inherit'} | {kind:'group', group} | {kind:'grouppqc', group, pqc}            */
    _pfsOf(devKey, ifName) {
      const d = this.devs[devKey]; const t = d.ifaces[ifName]; const ip = t && d.crypto.ipsecProfiles[t.tunnel.protection];
      return ip ? ip.pfs : null;
    }
    _pfsOutcome(I, R, ike) {
      const k = c => c ? c.kind : 'none';
      const inh = () => ({ group: 'group' + ike.group, pqc: ike.pqc || null });
      const bad = why => ({ ok: false, why });
      const t = {
        none:     { none: () => ({ ok: true, pfs: null }), inherit: () => bad('responder has no "set pfs" but the initiator requires PFS'), group: () => ({ ok: true, pfs: { group: I.group, pqc: null } }), grouppqc: () => bad('initiator requires ML-KEM PFS but the responder has no "set pfs"') },
        inherit:  { none: () => ({ ok: true, pfs: inh() }), inherit: () => ({ ok: true, pfs: inh() }), group: () => ({ ok: true, pfs: { group: I.group, pqc: ike.pqc || null } }), grouppqc: () => ({ ok: true, pfs: { group: I.group, pqc: I.pqc } }) },
        group:    { none: () => ({ ok: true, pfs: { group: R.group, pqc: null } }), inherit: () => bad('responder requires a specific DH group ("set pfs ' + (R && R.group) + '") but the initiator only has "set pfs"'), group: () => I.group === R.group ? { ok: true, pfs: { group: I.group, pqc: null } } : bad(`PFS groups differ (${I.group} vs ${R.group})`), grouppqc: () => bad('initiator requires ML-KEM PFS but the responder only sets a DH group') },
        grouppqc: { none: () => ({ ok: true, pfs: { group: R.group, pqc: R.pqc } }), inherit: () => ({ ok: true, pfs: { group: R.group, pqc: R.pqc } }), group: () => ({ ok: true, pfs: { group: R.group, pqc: R.pqc } }), grouppqc: () => ({ ok: true, pfs: { group: R.group, pqc: R.pqc } }) },
      };
      return t[k(R)][k(I)]();
    }
    _rekeyChild(st, initDev) {
      const sa = st.sa; if (!sa) return;
      const me = st.pair.a.dev === initDev ? st.pair.a : st.pair.b, peer = me === st.pair.a ? st.pair.b : st.pair.a;
      const tsOf = (dk, ifn) => { const d = this.devs[dk], t = d.ifaces[ifn], ip = t && d.crypto.ipsecProfiles[t.tunnel.protection]; return ip ? (ip.tsList && ip.tsList.length ? ip.tsList : [ip.ts]).map(n => d.crypto.tsets[n]).filter(Boolean) : []; };
      const tm = tsOf(me.dev, me.if), tp = tsOf(peer.dev, peer.if);
      const common = tm.find(x => tp.some(y => y.esp === x.esp && y.mode === x.mode));
      let r = this._pfsOutcome(this._pfsOf(me.dev, me.if), this._pfsOf(peer.dev, peer.if), sa.params);
      if (!common) r = { ok: false, why: 'no IPsec transform set in common' };
      else sa.params.esp = common.esp;
      sa.child.rekeys++;
      if (!r.ok) {
        sa.child = { ...sa.child, down: true, err: `NO_PROPOSAL_CHOSEN for the Child SA: ${r.why}.${common ? ' Both sides should use compatible PFS settings — "set pfs" on both is recommended.' : ''} The IKE SA stays READY, but no traffic passes.`, init: initDev, retryAt: this.now() + RETRY_MS };
        for (const d of [me.dev, peer.dev]) this._debug(d, `IKEv2: CREATE_CHILD_SA failed: NO_PROPOSAL_CHOSEN (${r.why})`);
        return false;
      }
      sa.child = { pfs: r.pfs, rekeys: sa.child.rekeys, down: false, at: this.now() };
      sa.espSpi = { [me.dev]: '0x' + hex(8), [peer.dev]: '0x' + hex(8) };
      sa.counters = { [me.dev]: { encaps: 0, decaps: 0 }, [peer.dev]: { encaps: 0, decaps: 0 } };
      for (const d of [me.dev, peer.dev]) this._debug(d, `IKEv2: CREATE_CHILD_SA (rekey) done${r.pfs ? `, PFS ${r.pfs.group}${r.pfs.pqc ? ' + ' + PQC_LABEL[r.pfs.pqc] : ''}` : ', no PFS'}`);
      return true;
    }
    clearIpsecSAs(devKey) {
      for (const st of this.pairState.values()) if (st.state === 'up' && (st.pair.a.dev === devKey || st.pair.b.dev === devKey)) this._rekeyChild(st, devKey);
    }
    _teardown(st, why) {
      if (!st.sa) return;
      for (const me of [st.pair.a, st.pair.b]) {
        const peer = st.sa.peerIp[me.dev];
        this._log(me.dev, `%CRYPTO-5-IKEV2_SESSION_STATUS: Crypto tunnel v2 is DOWN. Peer ${peer}:500       Id: ${peer}`);
        if (this.devs[me.dev].ifaces[me.if]) this._log(me.dev, `%LINEPROTO-5-UPDOWN: Line protocol on Interface ${me.if}, changed state to down`);
      }
      // delete notification: INFORMATIONAL exchange started by the side that cleared (or the initiator)
      const by = why && why.by ? why.by : st.pair.a.dev; const other = by === st.pair.a.dev ? st.pair.b.dev : st.pair.a.dev;
      this._exchange(by, other, 'INFORMATIONAL'); this._ex(by, 'DELETE_REASON', 0);
      st.lastSa = st.sa; st.sa = null; st.state = 'neg'; st.since = this.now();
    }
    reconcile(opts = {}) {
      const now = this.now();
      const current = this._computePairs();
      for (const [key, st] of [...this.pairState]) {
        if (!current.has(key)) { this._teardown(st); this.pairState.delete(key); }
      }
      for (const [key, pair] of current) {
        let st = this.pairState.get(key);
        if (!st) { st = { key, pair, state: 'neg', since: now, sa: null }; this.pairState.set(key, st); }
        st.pair = pair;
        if (st.state === 'up') { const c = st.sa.child; if (c.down && now >= c.retryAt) this._rekeyChild(st, c.init); continue; }
        const due = (st.state === 'neg' && now - st.since >= NEG_DELAY_MS) || (st.state === 'fail' && now >= st.retryAt);
        if (due || (opts.force && opts.force(st))) this._attempt(st);
      }
    }
    tick() { this.reconcile(); }
    _configTouched(devKey) {
      this.devs[devKey].lastChange = this.now();
      for (const st of this.pairState.values()) {
        if (st.state === 'fail') st.retryAt = Math.min(st.retryAt, this.now() + NEG_DELAY_MS);
        if (st.sa && st.sa.child.down) st.sa.child.retryAt = Math.min(st.sa.child.retryAt, this.now() + NEG_DELAY_MS);
      }
    }
    clearSAs(devKey) {
      for (const st of this.pairState.values()) {
        if (st.pair.a.dev !== devKey && st.pair.b.dev !== devKey) continue;
        if (st.sa) this._teardown(st, { by: devKey });
        st.state = 'neg'; st.since = this.now();
      }
    }

    /* ---------- public state for UI / validation ---------- */
    tunnels() {
      return [...this.pairState.values()].map(st => ({
        key: st.key, a: st.pair.a, b: st.pair.b, state: st.state, err: st.err, code: st.code,
        params: st.sa ? st.sa.params : null, sa: st.sa, lastAttempt: st.lastAttempt || null,
      }));
    }
    halfTunnels() {
      // tunnel interfaces configured with protection but without a matching peer tunnel
      const paired = new Set(); for (const st of this.pairState.values()) { paired.add(st.pair.a.dev + ':' + st.pair.a.if); paired.add(st.pair.b.dev + ':' + st.pair.b.if); }
      const out = [];
      for (const k of this.order) for (const i of Object.values(this.devs[k].ifaces)) {
        if (i.kind === 'tunnel' && !paired.has(k + ':' + i.name)) out.push({ dev: k, if: i.name, dest: i.tunnel.dest, protected: !!i.tunnel.protection, mode: i.tunnel.mode, shutdown: i.shutdown });
      }
      return out;
    }
    saBetween(x, y) {
      for (const st of this.pairState.values()) {
        const s = [st.pair.a.dev, st.pair.b.dev];
        if (s.includes(x) && s.includes(y) && st.state === 'up') return { ...st.sa, a: st.pair.a, b: st.pair.b, key: st.key };
      }
      return null;
    }
    pairBetween(x, y) {
      for (const st of this.pairState.values()) { const s = [st.pair.a.dev, st.pair.b.dev]; if (s.includes(x) && s.includes(y)) return st; }
      return null;
    }
    reach(fromKey, ip) {
      const r = this.lookup(fromKey, ip); if (!r) return false;
      const src = this.devs[fromKey].ifaces[r.iface].ip;
      const f = this.forward(fromKey, ip); if (!f.ok) return false;
      return this.forward(f.end, src).ok;
    }
    ranSince(seq, devKey, test) {
      return this.cmdLog.some(e => e.seq > seq && (!devKey || e.dev === devKey) && e.ok && (typeof test === 'function' ? test(e) : test.test(e.canon)));
    }
    get lastSeq() { return this.seq; }
    onChange(fn) { this.changeListeners.push(fn); }

    /* ---------- CLI ---------- */
    prompt(devKey) {
      const d = this.devs[devKey];
      const sfx = { exec: '>', priv: '#', config: '(config)#', if: '(config-if)#', proposal: '(config-ikev2-proposal)#', policy: '(config-ikev2-policy)#',
        keyring: '(config-ikev2-keyring)#', peer: '(config-ikev2-keyring-peer)#', profile: '(config-ikev2-profile)#', tset: '(cfg-crypto-trans)#', ipsecprof: '(ipsec-profile)#' }[d.mode];
      return d.hostname + sfx;
    }
    _modeCmds(d, mode) {
      const base = this.cmds[mode] || [];
      if (mode === 'if') { const i = d.ifaces[d.ctx.iface]; return base.filter(c => !c.when || c.when(i)); }
      return base;
    }
    _resolve(d, raw, mode) {
      // returns {match, neg, mode} or {err, errPos}
      const toks = tokenize(raw);
      if (!toks.length) return { empty: true };
      const tryMode = (m) => {
        const cmds = this._modeCmds(d, m);
        let neg = false, ts = toks;
        if (m !== 'exec' && m !== 'priv' && toks[0].t.toLowerCase() === 'no' && toks.length > 1) { neg = true; ts = toks.slice(1); }
        const pool = neg ? cmds.filter(c => c.no) : cmds.filter(c => !c.noOnly);
        const r = matchCmds(pool, ts);
        if (r.err) return { err: r.err, errPos: ts[r.errIdx].pos, errIdx: r.errIdx + (neg ? 1 : 0) };
        const done = r.cands.filter(isComplete);
        if (!done.length) return { err: 'incomplete' };
        return { match: done[0], neg, mode: m, toks: ts };
      };
      let r = tryMode(mode);
      // IOS: a command that does not parse in a sub-mode is retried in the parent / global mode
      if (r.err && mode !== 'exec' && mode !== 'priv' && mode !== 'config') {
        const chain = mode === 'peer' ? ['keyring', 'config'] : ['config'];
        for (const m of chain) { const r2 = tryMode(m); if (!r2.err) { r2.fallback = true; return r2; } }
      }
      return r;
    }
    exec(devKey, rawIn, opts = {}) {
      const d = this.devs[devKey];
      const raw = rawIn.replace(/\s+$/, '');
      const promptBefore = this.prompt(devKey);
      const out = [];
      const pushHist = () => { if (raw.trim() && !opts.noHistory) { d.history.push(raw); if (d.history.length > 50) d.history.shift(); } };
      if (!raw.trim()) { return { lines: [], prompt: this.prompt(devKey) }; }
      pushHist();
      // output filter
      let cmdPart = raw, filter = null;
      const pi = raw.indexOf('|');
      if (pi >= 0) {
        cmdPart = raw.slice(0, pi).trimEnd();
        const fm = /^\|\s*(\S+)\s*(.*)$/.exec(raw.slice(pi));
        const fk = fm && ['include', 'exclude', 'begin', 'section', 'count'].filter(k => k.startsWith(fm[1].toLowerCase()));
        if (!fm || !fk || fk.length !== 1 || (fk[0] !== 'count' && !fm[2])) {
          out.push(...this._caret(promptBefore, pi + 1), { text: '% Invalid input detected at \'^\' marker.', cls: 'err' });
          this._record(devKey, raw, raw, false); return { lines: out, prompt: this.prompt(devKey) };
        }
        filter = { kind: fk[0], arg: fm[2] };
      }
      const r = this._resolve(d, cmdPart, d.mode);
      if (r.err) {
        if (r.err === 'incomplete') out.push({ text: '% Incomplete command.', cls: 'err' }, { text: '' });
        else if (r.err === 'ambiguous') out.push({ text: `% Ambiguous command:  "${cmdPart}"`, cls: 'err' });
        else out.push(...this._caret(promptBefore, r.errPos), { text: '% Invalid input detected at \'^\' marker.', cls: 'err' }, { text: '' });
        this._record(devKey, raw, raw, false);
        return { lines: out, prompt: this.prompt(devKey) };
      }
      if (r.fallback) { d.mode = r.mode; d.ctx = {}; }
      const canon = (r.neg ? 'no ' : '') + r.match.vals.join(' ');
      const meta = {};
      let res;
      try { res = r.match.c.run.call(this, d, r.match.vals, r.neg, meta) || []; }
      catch (e) { res = [{ text: '% Simulator error: ' + e.message, cls: 'err' }]; }
      let lines = res.map(l => typeof l === 'string' ? { text: l } : l);
      if (filter) lines = this._applyFilter(lines, filter);
      out.push(...lines);
      if (d.mode !== 'exec' && d.mode !== 'priv' && r.match.c.cfg !== false && r.mode !== 'exec' && r.mode !== 'priv') this._configTouched(devKey);
      this.reconcile();
      this._record(devKey, raw, canon, !lines.some(l => l.cls === 'err'), meta);
      for (const fn of this.changeListeners) try { fn(devKey); } catch (e) {}
      return { lines: out, prompt: this.prompt(devKey), meta };
    }
    _record(dev, raw, canon, ok, meta = {}) { this.cmdLog.push({ seq: ++this.seq, dev, raw, canon, ok, meta, at: this.now() }); }
    _caret(prompt, pos) { return [{ text: ' '.repeat(prompt.length + pos) + '^', cls: 'err' }]; }
    _applyFilter(lines, f) {
      let re; try { re = new RegExp(f.arg); } catch (e) { re = { test: s => s.includes(f.arg) }; }
      switch (f.kind) {
        case 'include': return lines.filter(l => re.test(l.text));
        case 'exclude': return lines.filter(l => !re.test(l.text));
        case 'begin': { const i = lines.findIndex(l => re.test(l.text)); return i < 0 ? [] : lines.slice(i); }
        case 'count': return [{ text: `Number of lines which match regexp = ${f.arg ? lines.filter(l => re.test(l.text)).length : lines.length}` }];
        case 'section': {
          const out = []; let inSec = false;
          for (const l of lines) {
            const top = !/^\s/.test(l.text);
            if (top) inSec = re.test(l.text) && l.text !== '!';
            if (inSec && l.text !== '!') out.push(l);
          }
          return out;
        }
      }
      return lines;
    }
    help(devKey, raw) {
      const d = this.devs[devKey];
      let mode = d.mode; let text = raw;
      if (raw.includes('|')) return [{ text: '  begin    Begin with the line that matches' }, { text: '  count    Count number of lines which match regexp' }, { text: '  exclude  Exclude lines that match' }, { text: '  include  Include lines that match' }, { text: '  section  Filter a section of output' }];
      let neg = false;
      if (mode !== 'exec' && mode !== 'priv' && /^\s*no\s+/i.test(text)) { neg = true; text = text.replace(/^\s*no\s+/i, ''); }
      const cmds = this._modeCmds(d, mode);
      let pool = neg ? cmds.filter(c => c.no) : cmds.filter(c => !c.noOnly);
      if (mode !== 'exec' && mode !== 'priv' && !neg && !text.trim()) pool = pool.concat([C('no', () => [], {})]);
      let h = helpFor(pool, text);
      if (h.err && mode !== 'exec' && mode !== 'priv' && mode !== 'config') {
        const g = this._modeCmds(d, 'config'); const h2 = helpFor(neg ? g.filter(c => c.no) : g.filter(c => !c.noOnly), text);
        if (!h2.err) h = h2;
      }
      if (h.err) {
        if (h.err === 'ambiguous') return [{ text: `% Ambiguous command:  "${raw}"`, cls: 'err' }];
        const pos = (h.toks[h.errIdx] || { pos: 0 }).pos + (neg ? raw.length - text.length : 0);
        return [...this._caret(this.prompt(devKey), pos), { text: '% Invalid input detected at \'^\' marker.', cls: 'err' }];
      }
      if (!h.entries.length) return [{ text: '% Unrecognized command', cls: 'err' }];
      if (h.partial) return [{ text: h.entries.map(e => e[0]).join('  ') }];
      const w = Math.max(...h.entries.map(e => e[0].length)) + 2;
      return h.entries.map(([k, v]) => ({ text: '  ' + k.padEnd(w) + v }));
    }
    complete(devKey, raw) {
      const d = this.devs[devKey];
      if (/\s$/.test(raw) || !raw.trim()) return raw;
      let text = raw, neg = '';
      if (d.mode !== 'exec' && d.mode !== 'priv' && /^\s*no\s+/i.test(text)) { neg = text.match(/^\s*no\s+/i)[0]; text = text.slice(neg.length); }
      const cmds = this._modeCmds(d, d.mode);
      const pool = neg ? cmds.filter(c => c.no) : cmds.filter(c => !c.noOnly);
      let h = helpFor(pool, text);
      if ((h.err || !h.entries.length) && !['exec', 'priv', 'config'].includes(d.mode)) {
        const g = this._modeCmds(d, 'config'); h = helpFor(neg ? g.filter(c => c.no) : g.filter(c => !c.noOnly), text);
      }
      if (h.err || !h.entries) return raw;
      const kws = h.entries.map(e => e[0]).filter(k => !/^[A-Z<]/.test(k));
      if (kws.length !== 1) return raw;
      const lastTok = text.match(/(\S+)$/)[1];
      return neg + text.slice(0, text.length - lastTok.length) + kws[0] + ' ';
    }
    history(devKey) { return this.devs[devKey].history; }

    /* ---------- show helpers ---------- */
    _upSAs(devKey) {
      return [...this.pairState.values()].filter(st => (st.pair.a.dev === devKey || st.pair.b.dev === devKey))
        .map(st => ({ st, me: st.pair.a.dev === devKey ? st.pair.a : st.pair.b }))
        .sort((x, y) => ((x.st.sa && x.st.sa.ids[devKey]) || 99) - ((y.st.sa && y.st.sa.ids[devKey]) || 99));
    }
    _saLines(devKey, st, me, detailed) {
      const d = this.devs[devKey], t = d.ifaces[me.if], out = [];
      if (!st.sa) {
        const local = this._srcIp(d, t), remote = t.tunnel.dest;
        out.push(`${String(this._freeTunnelId(devKey)).padEnd(10)}${(local + '/500').padEnd(22)}${(remote + '/500').padEnd(22)}${'none/none'.padEnd(21)}IN-NEG`);
        out.push('      Encr: Unknown - 0, PRF: Unknown - 0, Hash: None, DH Grp:0, Auth sign: Unknown - 0, Auth verify: Unknown - 0');
        out.push('      Life/Active Time: 86400/0 sec');
        return out;
      }
      const sa = st.sa, p = sa.params, init = sa.initiator === devKey;
      const age = Math.max(1, Math.floor((this.now() - sa.establishedAt) / 1000));
      const peer = init ? st.pair.b.dev : st.pair.a.dev;
      out.push(`${String(sa.ids[devKey]).padEnd(10)}${(sa.ip[devKey] + '/500').padEnd(22)}${(sa.peerIp[devKey] + '/500').padEnd(22)}${'none/none'.padEnd(21)}READY`);
      out.push(`      Encr: ${ENC_LABEL[p.enc]}, PRF: ${p.prf.toUpperCase()}, Hash: ${p.integ ? p.integ.toUpperCase() : 'None'}, DH Grp:${p.group}, Auth sign: PSK, Auth verify: PSK${p.ppk ? ', QR' : ''}`);
      if (p.pqc) out.push(`      PQC Key Exchange: ${PQC_LABEL[p.pqc]}`);
      out.push(`      Life/Active Time: ${p.lifetime}/${age} sec`);
      out.push(`      CE id: ${sa.ceId}, Session-id: ${sa.sessionId}`);
      out.push(`      Local spi: ${sa.spi[devKey]}       Remote spi: ${sa.spi[peer]}`);
      if (!detailed) return out;
      // INIT=0, [INTERMEDIATE=1,] AUTH -> next id 2, or 3 with the ML-KEM IKE_INTERMEDIATE exchange (G3)
      const ids = p.pqc ? 3 : 2;
      out.push('      Status Description: Negotiation done', `      Local id: ${sa.ip[devKey]}`, `      Remote id: ${sa.peerIp[devKey]}`);
      out.push(`      Local req msg id:  ${init ? ids : 0}              Remote req msg id:  ${init ? 0 : ids}`);
      out.push(`      Local next msg id: ${init ? ids : 0}              Remote next msg id: ${init ? 0 : ids}`);
      out.push(`      Local req queued:  ${init ? ids : 0}              Remote req queued:  ${init ? 0 : ids}`);
      out.push('      Local window:      20             Remote window:      20', '      DPD configured for 0 seconds, retry 0');
      out.push(p.frag ? '      IETF Std Fragmentation  enabled.' : '      Fragmentation not  configured.');
      if (p.ppk) out.push('      Quantum-safe Encryption using Manual PPK');
      if (p.pqc) out.push(`      Quantum-safe Encryption using PQC: ${PQC_LABEL[p.pqc]}`);
      out.push('      Dynamic Route Update: enabled');
      if (p.frag) out.push(`      IETF Std Fragmentation MTU in use: ${p.fragMtu - 28} bytes.`);
      out.push('      Extended Authentication not configured.', '      NAT-T is not detected', '      Cisco Trust Security SGT is disabled',
        `      Initiator of SA : ${init ? 'Yes' : 'No'}`, '      PEER TYPE: IOS-XE');
      return out;
    }
    _saRows(devKey) { return this._upSAs(devKey).filter(x => x.st.sa || x.st.state === 'neg' || x.st.state === 'fail'); }
    _showIkev2Sa(devKey, detailed) {
      const rows = this._saRows(devKey);
      if (!rows.length) return [];
      const out = [' IPv4 Crypto IKEv2  SA', '', 'Tunnel-id Local                 Remote                fvrf/ivrf            Status'];
      rows.forEach(({ st, me }, i) => { if (i) out.push(''); out.push(...this._saLines(devKey, st, me, detailed)); });
      out.push('', ' IPv6 Crypto IKEv2  SA', '');
      return out;
    }
    _showIkev2Session(devKey, detailed) {
      const rows = this._saRows(devKey).filter(x => x.st.sa);
      if (!rows.length) return [];
      const out = [' IPv4 Crypto IKEv2 Session', ''];
      rows.forEach(({ st, me }, i) => {
        const sa = st.sa, peer = sa.initiator === devKey ? st.pair.b.dev : st.pair.a.dev, child = !sa.child.down;
        if (i) out.push('');
        out.push(`Session-id:${sa.sessionId}, Status:UP-ACTIVE, IKE count:1, CHILD count:${child ? 1 : 0}`, '',
          'Tunnel-id Local                 Remote                fvrf/ivrf            Status', ...this._saLines(devKey, st, me, detailed));
        if (child) {
          const e = espInfo(sa.params.esp);
          out.push('Child sa:', '          local selector       ->      remote_selector', '          0.0.0.0/0 - 255.255.255.255/65535    ->    0.0.0.0/0 - 255.255.255.255/65535',
            `          ESP spi in/out: ${spiShort(sa.espSpi[devKey])}/${spiShort(sa.espSpi[peer])}`);
          if (detailed) out.push('          AH spi in/out: 0x0/0x0', '          CPI in/out: 0x0/0x0', `          Encr: ${e.encr}, keysize: ${e.key}, esp_hmac: ${e.hmac}`, '          ah_hmac: None, comp: IPCOMP_NONE, mode tunnel');
        }
      });
      out.push('', ' IPv6 Crypto IKEv2 Session', '');
      return out;
    }
    _showIkev2Stats(devKey) {
      const d = this.devs[devKey]; const rows = this._upSAs(devKey).filter(x => x.st.sa);
      const outg = rows.filter(x => x.st.sa.initiator === devKey).length, inc = rows.length - outg;
      const negIn = this._upSAs(devKey).filter(x => !x.st.sa && x.st.pair.b.dev === devKey).length, negOut = this._upSAs(devKey).filter(x => !x.st.sa && x.st.pair.a.dev === devKey).length;
      const qr = rows.filter(x => x.st.sa.params.ppk || x.st.sa.params.pqc).length, ppk = rows.filter(x => x.st.sa.params.ppk).length;
      const pad = (v, n) => String(v).padEnd(n);
      return [
        '--------------------------------------------------------------------------------',
        '                          Crypto IKEv2 SA Statistics',
        '--------------------------------------------------------------------------------',
        'System Resource Limit:   0        Max IKEv2 SAs: 0        Max in nego(in/out): 40/60',
        `Total incoming IKEv2 SA Count:    ${pad(inc, 9)}active:        ${pad(inc, 9)}negotiating: ${negIn}`,
        `Total outgoing IKEv2 SA Count:    ${pad(outg, 9)}active:        ${pad(outg, 9)}negotiating: ${negOut}`,
        `Incoming IKEv2 Requests: ${pad(d.stats.inReq, 9)}accepted:      ${pad(d.stats.inReq - d.stats.inRej, 9)}rejected:    ${d.stats.inRej}`,
        `Outgoing IKEv2 Requests: ${pad(d.stats.outReq, 9)}accepted:      ${pad(d.stats.outReq - d.stats.outRej, 9)}rejected:    ${d.stats.outRej}`,
        'Rejected IKEv2 Requests: 0        rsrc low:      0        SA limit:    0',
        'IKEv2 packets dropped at dispatch: 0',
        'Incoming Requests dropped as LOW Q limit reached : 0',
        'Incoming IKEV2 Cookie Challenged Requests: 0',
        '    accepted: 0        rejected: 0        rejected no cookie: 0',
        'Total Deleted sessions of Cert Revoked Peers: 0',
        'Total init sa request rejected due to queue limit : 0',
        'SA Strength Enforcement Rejects - incoming:        0 outgoing:        0',
        `Sessions with Quantum Resistance: ${pad(qr, 9)}Manual: ${pad(ppk, 9)}Dynamic: 0`,
        'PPK Identity Mismatch: 0',
        'PPK Retrieve Failure    -    ALL:      0        With PPK Required:    0',
        'PPK Authentication Failure - ALL:      0        With PPK Required:    0',
      ];
    }
    _showIkev2StatsExchange(devKey) {
      const e = this.devs[devKey].exch, dash = '-'.repeat(118);
      const row = (n, v) => n.slice(0, 30).padEnd(30) + v.map(x => String(x).padStart(11)).join('');
      const sect = (title, names) => { const r = names.filter(n => e[n] && e[n].some(Boolean)); return r.length ? ['', title, '', ...r.map(n => row(n, e[n]))] : []; };
      const cfg = e.CFG_REQUEST && e.CFG_REQUEST.some(Boolean);
      return [dash, 'EXCHANGE/NOTIFY                   TX(REQ)    TX(RES)    RX(REQ)    RX(RES)   RTX(REQ)   RTX(RES)   RRX(REQ)   RRX(RES)',
        ...sect('EXCHANGES', EXCH),
        ...sect('ERROR NOTIFY', ['NO_PROPOSAL_CHOSEN', 'AUTHENTICATION_FAILED']),
        ...sect('OTHER NOTIFY', ['INITIAL_CONTACT', 'SET_WINDOW_SIZE', 'NAT_DETECTION_SOURCE_IP', 'NAT_DETECTION_DESTINATION_IP', 'HTTP_CERT_LOOKUP_SUPPORTED', 'DELETE_REASON', 'USE_PPK', 'PPK_IDENTITY', 'SIGNATURE_HASH_ALGORITHMS_NOTI']),
        ...(cfg ? ['', '', 'CONFIG PAYLOAD TYPE                    TX         RX        RTX        RRX', '', row('CFG_REQUEST', e.CFG_REQUEST.slice(0, 4))] : []),
        '', '', 'OTHER COUNTERS                         TX        RTX', '', row('NO_NAT', [(e.IKE_SA_INIT || [0])[0] + (e.IKE_AUTH || [0])[0], 0]), dash];
    }
    _showIpsecSa(devKey, detail) {
      const d = this.devs[devKey]; const out = [];
      for (const t of Object.values(d.ifaces).filter(i => i.kind === 'tunnel' && i.tunnel.protection).sort((a, b) => ifSort(a.name, b.name))) {
        const st = this._pairOf(devKey, t.name); const sa = st && st.sa && !st.sa.child.down ? st.sa : null;
        const c = sa ? sa.counters[devKey] : { encaps: 0, decaps: 0 };
        const local = this._srcIp(d, t) || '0.0.0.0', init = sa && sa.initiator === devKey;
        const peer = sa && (devKey === st.pair.a.dev ? st.pair.b.dev : st.pair.a.dev);
        const e = espInfo(sa ? sa.params.esp : 'esp-gcm 256'), pfs = sa && sa.child.pfs;
        const left = sa ? Math.max(0, 3600 - Math.floor((this.now() - (sa.child.at || sa.establishedAt)) / 1000)) : 0;
        if (out.length) out.push('');
        out.push(`interface: ${t.name}`, `    Crypto map tag: ${t.name}-head-0, local addr ${local}`, '', '   protected vrf: (none)',
          '   local  ident (addr/mask/prot/port): (0.0.0.0/0.0.0.0/0/0)', '   remote ident (addr/mask/prot/port): (0.0.0.0/0.0.0.0/0/0)',
          `   current_peer ${t.tunnel.dest || '0.0.0.0'} port 500`, '     PERMIT, flags={origin_is_acl,}',
          `    #pkts encaps: ${c.encaps}, #pkts encrypt: ${c.encaps}, #pkts digest: ${c.encaps}`,
          `    #pkts decaps: ${c.decaps}, #pkts decrypt: ${c.decaps}, #pkts verify: ${c.decaps}`,
          '    #pkts compressed: 0, #pkts decompressed: 0', '    #pkts not compressed: 0, #pkts compr. failed: 0', '    #pkts not decompressed: 0, #pkts decompress failed: 0');
        if (detail) out.push('    #pkts no sa (send) 0, #pkts invalid sa (rcv) 0', '    #pkts encaps failed (send) 0, #pkts decaps failed (rcv) 0', '    #pkts invalid prot (recv) 0, #pkts verify failed: 0',
          '    #pkts invalid identity (recv) 0, #pkts invalid len (rcv) 0', '    #pkts replay rollover (send): 0, #pkts replay rollover (rcv) 0', '    ##pkts replay failed (rcv): 0',
          '    #pkts tagged (send): 0, #pkts untagged (rcv): 0', '    #pkts not tagged (send): 0, #pkts not untagged (rcv): 0', '    #pkts internal err (send): 0, #pkts internal err (recv) 0');
        else out.push('    #send errors 0, #recv errors 0');
        out.push('', `     local crypto endpt.: ${local}, remote crypto endpt.: ${t.tunnel.dest || '0.0.0.0'}`,
          `     plaintext mtu ${e.mtu}, path mtu 1500, ip mtu 1500, ip mtu idb ${t.tunnel.source || 'none'}`,
          `     current outbound spi: ${sa ? spiLong(sa.espSpi[peer]) : '0x0(0)'}`,
          pfs ? `     PFS (Y/N): Y, DH group: ${pfs.group}${pfs.pqc ? `, PQC Key Exchange: ${PQC_LABEL[pfs.pqc]}` : ''}` : '     PFS (Y/N): N, DH group: none', '');
        const espBlock = (spi, conn) => [`      spi: ${spiLong(spi)}`, `        transform: ${sa.params.esp} ,`, '        in use settings ={Tunnel, }',
          `        conn id: ${conn}, flow_id: CSR:${conn - 2000}, sibling_flags FFFFFFFF8000${init ? '4' : '0'}048, crypto map: ${t.name}-head-0, initiator : ${init ? 'True' : 'False'}`,
          `        sa timing: remaining key lifetime (sec): ${left}`, '        Kilobyte Volume Rekey has been disabled', `        IV size: ${e.iv} bytes`, '        replay detection support: Y', '        Status: ACTIVE(ACTIVE)'];
        const base = 2020 + 2 * (sa ? Math.max(0, sa.sessionId - 1) : 0);   // inbound/outbound conn ids, e.g. 2022/2021
        out.push('     inbound esp sas:', ...(sa ? espBlock(sa.espSpi[devKey], init ? base + 2 : base + 1) : []), '', '     inbound ah sas:', '', '     inbound pcp sas:', '',
          '     outbound esp sas:', ...(sa ? espBlock(sa.espSpi[peer], init ? base + 1 : base + 2) : []), '', '     outbound ah sas:', '', '     outbound pcp sas:');
      }
      return out.length ? out : ['No IPSec SA found.'];
    }
    _showCryptoSession(devKey, detail) {
      const d = this.devs[devKey];
      const tuns = Object.values(d.ifaces).filter(i => i.kind === 'tunnel' && i.tunnel.protection).sort((a, b) => ifSort(a.name, b.name));
      if (!tuns.length) return [];
      const out = ['Crypto session current status', ''];
      if (detail) out.push('Code: C - IKE Configuration mode, D - Dead Peer Detection', 'K - Keepalives, N - NAT-traversal, T - cTCP encapsulation', 'X - IKE Extended Authentication, F - IKE Fragmentation',
        'R - IKE Auto Reconnect, U - IKE Dynamic Route Update', 'S - SIP VPN, E - Stronger IKE Encryption Enforced', 'Q - Quantum-safe Encryption', '');
      tuns.forEach((t, k) => {
        const st = this._pairOf(devKey, t.name); const sa = st && st.sa; const child = sa && !sa.child.down;
        const prof = (d.crypto.ipsecProfiles[t.tunnel.protection] || {}).ikev2Profile || '';
        const age = sa ? Math.floor((this.now() - sa.establishedAt) / 1000) : 0;
        if (k) out.push('');
        out.push(`Interface: ${t.name}`);
        if (prof) out.push(`Profile: ${prof}`);
        if (sa && detail) out.push(`Uptime: ${hms(age)}`);
        out.push(`Session status: ${sa ? 'UP-ACTIVE' : 'DOWN-NEGOTIATING'}`);
        out.push(`Peer: ${t.tunnel.dest} port 500${detail ? ' fvrf: (none) ivrf: (none)' : ''}`);
        if (detail && sa) out.push(`      Phase1_id: ${t.tunnel.dest}`, '      Desc: (none)');
        if (!sa) { out.push('  IKEv2 SA: none'); return; }
        const p = sa.params, caps = (p.frag ? 'F' : '') + 'U' + (p.pqc || p.ppk ? 'Q' : '');
        out.push(`  Session ID: ${sa.cryptoSessionId}`, `  IKEv2 SA: local ${sa.ip[devKey]}/500 remote ${sa.peerIp[devKey]}/500 Active`);
        if (detail) out.push(`          Capabilities:${caps} connid:${sa.ids[devKey]} lifetime:${hms(Math.max(0, p.lifetime - age))}`);
        out.push('  IPSEC FLOW: permit ip   0.0.0.0/0.0.0.0 0.0.0.0/0.0.0.0', `        Active SAs: ${child ? 2 : 0}, origin: crypto map`);
        if (detail && child) {
          const left = Math.max(0, 3600 - Math.floor((this.now() - (sa.child.at || sa.establishedAt)) / 1000));
          out.push(`        Inbound:  #pkts dec'ed ${sa.counters[devKey].decaps} drop 0 life (KB/Sec) KB Vol Rekey Disabled/${left}`,
            `        Outbound: #pkts enc'ed ${sa.counters[devKey].encaps} drop 0 life (KB/Sec) KB Vol Rekey Disabled/${left}`);
        }
      });
      return out;
    }
    _showIpIntBrief(devKey) {
      const d = this.devs[devKey];
      const out = ['Interface              IP-Address      OK? Method Status                Protocol'];
      // IOS lists interfaces by name (type, then number)
      const byName = (a, b) => { const ta = a.replace(/[\d/.]+$/, ''), tb = b.replace(/[\d/.]+$/, ''); return ta !== tb ? (ta < tb ? -1 : 1) : ifSort(a, b); };
      for (const i of Object.values(d.ifaces).sort((a, b) => byName(a.name, b.name))) {
        const st = i.shutdown ? 'administratively down' : (i.kind === 'phys' ? (this.portUp(devKey, i.name) ? 'up' : 'down') : i.kind === 'svi' ? (this.lineUp(devKey, i.name) ? 'up' : 'down') : 'up');
        const proto = this.lineUp(devKey, i.name) ? 'up' : 'down';
        const method = i.ip ? 'manual' : i.boot ? 'NVRAM' : 'unset';
        out.push(`${i.name.padEnd(22)} ${(i.ip || 'unassigned').padEnd(16)}YES ${method.padEnd(7)}${st.padEnd(22)}${proto}`);
      }
      return out;
    }
    _showIpRoute(devKey) {
      const rs = this.routes(devKey);
      const out = ['Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP',
        '       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area ',
        '       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2',
        '       E1 - OSPF external type 1, E2 - OSPF external type 2, m - OMP',
        '       n - NAT, Ni - NAT inside, No - NAT outside, Nd - NAT DIA',
        '       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2',
        '       ia - IS-IS inter area, * - candidate default, U - per-user static route',
        '       H - NHRP, G - NHRP registered, g - NHRP registration summary',
        '       o - ODR, P - periodic downloaded static route, l - LISP',
        '       a - application route',
        '       + - replicated route, % - next hop override, p - overrides from PfR',
        '       & - replicated local route overrides by connected', ''];
      const def = rs.find(r => r.type === 'S' && r.len === 0);
      out.push(def ? (def.nh ? `Gateway of last resort is ${def.nh} to network 0.0.0.0` : `Gateway of last resort is 0.0.0.0 to network 0.0.0.0`) : 'Gateway of last resort is not set', '');
      if (def) out.push(def.nh ? `S*    0.0.0.0/0 [1/0] via ${def.nh}` : `S*    0.0.0.0/0 is directly connected, ${def.iface}`);
      const classful = ip => { const f = +ip.split('.')[0]; return f < 128 ? [ip.split('.')[0] + '.0.0.0', 8] : f < 192 ? [ip.split('.').slice(0, 2).join('.') + '.0.0', 16] : [ip.split('.').slice(0, 3).join('.') + '.0', 24]; };
      const groups = new Map();
      for (const r of rs) { if (r.len === 0) continue; const [cn, cl] = classful(r.net); const k = cn + '/' + cl; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(r); }
      for (const [k, list] of [...groups].sort((a, b) => ipInt(a[0].split('/')[0]) - ipInt(b[0].split('/')[0]))) {
        list.sort((a, b) => ipInt(a.net) - ipInt(b.net) || a.len - b.len);
        const masks = new Set(list.map(r => r.len));
        out.push(`      ${k} is ${masks.size > 1 ? 'variably subnetted' : 'subnetted'}, ${list.length} subnets${masks.size > 1 ? `, ${masks.size} masks` : ''}`);
        for (const r of list) {
          if (r.type === 'S') out.push(r.nh ? `S        ${r.net}/${r.len} [1/0] via ${r.nh}` : `S        ${r.net}/${r.len} is directly connected, ${r.iface}`);
          else out.push(`${r.type}        ${r.net}/${r.len} is directly connected, ${r.iface}`);
        }
      }
      return out;
    }
    _showInterface(devKey, name) {
      const d = this.devs[devKey]; const i = d.ifaces[name];
      if (!i) return [{ text: '                    ^', cls: 'err' }, { text: '% Invalid input detected at \'^\' marker.', cls: 'err' }];
      const adm = i.shutdown ? 'administratively down' : (this.lineUp(devKey, name) || i.kind !== 'phys' ? 'up' : 'down');
      const out = [`${name} is ${adm}, line protocol is ${this.lineUp(devKey, name) ? 'up' : 'down'}`];
      if (i.kind === 'tunnel') {
        const st = this._pairOf(devKey, name), sa = st && st.sa, e = espInfo(sa ? sa.params.esp : 'esp-gcm 256');
        const s0 = this._srcIp(d, i), ipsec = i.tunnel.mode === 'ipsec ipv4', cnt = i.cnt || { inP: 0, outP: 0, inB: 0, outB: 0, last: null };
        const recent = cnt.last && this.now() - cnt.last < 300000;
        const fmtDate = ms => { const x = new Date(ms); return `${x.toLocaleString('en-US', { month: 'short' })} ${x.getDate()} ${x.getFullYear()} ${x.toTimeString().slice(0, 8)}`; };
        out.push('  Hardware is Tunnel');
        if (i.desc) out.push(`  Description: ${i.desc}`);
        if (i.ip) out.push(`  Internet address is ${i.ip}/${maskLen(i.mask)}`);
        out.push(`  MTU ${ipsec ? e.tmtu : 9976} bytes, BW 100 Kbit/sec, DLY 50000 usec,`, `     reliability 255/255, txload ${recent ? 2 : 1}/255, rxload ${recent ? 2 : 1}/255`,
          '  Encapsulation TUNNEL, loopback not set', '  Keepalive not set', `  Tunnel linestate evaluation ${this.lineUp(devKey, name) ? 'up' : 'down'}`,
          `  Tunnel source ${s0 || 'UNKNOWN'}${i.tunnel.source && !isIp(i.tunnel.source) ? ` (${i.tunnel.source})` : ''}, destination ${i.tunnel.dest || 'UNKNOWN'}`);
        if (i.tunnel.source && !isIp(i.tunnel.source)) out.push('   Tunnel Subblocks:', '      src-track:', `         ${name} source tracking subblock associated with ${i.tunnel.source}`,
          `          Set of tunnels with source ${i.tunnel.source}, 1 member (includes iterators), on interface <OK>`);
        out.push(`  Tunnel protocol/transport ${ipsec ? 'IPSEC/IP' : 'GRE/IP'}`, '  Tunnel TTL 255', `  Tunnel transport MTU ${ipsec ? e.mtu : 1476} bytes`,
          '  Tunnel transmit bandwidth 8000 (kbps)', '  Tunnel receive bandwidth 8000 (kbps)');
        if (i.tunnel.protection) out.push(`  Tunnel protection via IPSec (profile "${i.tunnel.protection}")`);
        out.push('  Tunnel state info:', `    State change to up   : ${sa ? fmtDate(sa.establishedAt) : 'never'}`, `    State change to down : ${fmtDate(i.createdAt)}`, '    Last state info      : down - interface not up');
        const since = ms => ms == null ? 'never' : hms(Math.floor((this.now() - ms) / 1000));
        out.push(`  Last input ${since(cnt.last)}, output ${since(cnt.last)}, output hang never`, `  Last clearing of "show interface" counters ${since(i.createdAt)}`,
          '  Input queue: 0/375/0/0 (size/max/drops/flushes); Total output drops: 0', '  Queueing strategy: fifo', '  Output queue: 0/0 (size/max)',
          `  5 minute input rate ${recent ? 1000 : 0} bits/sec, ${recent ? 1 : 0} packets/sec`, `  5 minute output rate ${recent ? 1000 : 0} bits/sec, ${recent ? 1 : 0} packets/sec`,
          `     ${cnt.inP} packets input, ${cnt.inB} bytes, 0 no buffer`, '     Received 0 broadcasts (0 IP multicasts)', '     0 runts, 0 giants, 0 throttles',
          '     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored, 0 abort', `     ${cnt.outP} packets output, ${cnt.outB} bytes, 0 underruns`,
          '     Output 0 broadcasts (0 IP multicasts)', '     0 output errors, 0 collisions, 0 interface resets', '     0 unknown protocol drops', '     0 output buffer failures, 0 output buffers swapped out');
      } else {
        out.push(`  Hardware is ${i.kind === 'svi' ? 'Ethernet SVI' : i.kind === 'loopback' ? 'Loopback' : i.vlan ? 'Integrated switch port' : '2.5GE MultiGig'}, address is 70b3.17ab.${(this.order.indexOf(devKey) + 1) * 11}0${Object.keys(d.ifaces).indexOf(name)}`);
        if (i.ip) out.push(`  Internet address is ${i.ip}/${maskLen(i.mask)}`);
        out.push(`  MTU 1500 bytes, BW ${i.kind === 'phys' ? '2500000' : '1000000'} Kbit/sec, DLY 10 usec, `);
        if (i.kind === 'phys') out.push(`  Full-duplex, 2500Mb/s, media type is RJ45`, ...(i.vlan ? [`  Switchport access VLAN ${i.vlan}`] : []));
      }
      return out;
    }
    _runningConfig(devKey, onlyIf) {
      const d = this.devs[devKey]; const c = d.crypto; const L = [];
      const ifBlock = (i) => {
        const b = [`interface ${i.name}`];
        if (i.desc) b.push(` description ${i.desc}`);
        if (i.kind === 'phys' && i.vlan) b.push(` switchport access vlan ${i.vlan}`, ' switchport mode access');
        if (i.ip) b.push(` ip address ${i.ip} ${i.mask}`); else if (i.kind !== 'phys' || !i.vlan) b.push(' no ip address');
        if (i.shutdown) b.push(' shutdown');
        if (i.kind === 'phys' && !i.vlan) b.push(' negotiation auto');
        if (i.kind === 'tunnel') {
          if (i.tunnel.source) b.push(` tunnel source ${i.tunnel.source}`);
          if (i.tunnel.mode !== 'gre ip') b.push(` tunnel mode ${i.tunnel.mode}`);
          if (i.tunnel.dest) b.push(` tunnel destination ${i.tunnel.dest}`);
          if (i.tunnel.protection) b.push(` tunnel protection ipsec profile ${i.tunnel.protection}`);
        }
        b.push('!');
        return b;
      };
      if (onlyIf) {
        const i = d.ifaces[onlyIf]; if (!i) return [{ text: '% Interface not found', cls: 'err' }];
        const b = ifBlock(i).slice(0, -1);   // drop the trailing '!'
        const body = ['!', ...b, 'end'];
        return ['Building configuration...', '', `Current configuration : ${body.join('\n').length + 2} bytes`, ...body];
      }
      L.push('!', `! Last configuration change at ${new Date(d.lastChange).toTimeString().slice(0, 8)} UTC ${new Date(d.lastChange).toDateString()} by console`, '!',
        `version ${IOS_VERSION}`, 'service timestamps debug datetime msec', 'service timestamps log datetime msec', 'platform qfp utilization monitor load 80', '!',
        `hostname ${d.hostname}`, '!', 'boot-start-marker', 'boot-end-marker', '!', 'no aaa new-model', '!', `license udi pid ${d.model} sn ${d.serial}`, 'license boot level advantage', '!');
      for (const [n, p] of Object.entries(c.proposals)) {
        L.push(`crypto ikev2 proposal ${n} `);
        if (p.pqc) L.push(` pqc ${p.pqc.algs.join(' ')}${p.pqc.mode === 'optional' ? ' optional' : ''}`);
        if (p.enc.length) L.push(` encryption ${p.enc.join(' ')}`);
        if (p.integ.length) L.push(` integrity ${p.integ.join(' ')}`);
        if (p.prf) L.push(` prf ${p.prf}`);
        if (p.group.length) L.push(` group ${p.group.join(' ')}`);
        L.push('!');
      }
      for (const [n, p] of Object.entries(c.policies)) { L.push(`crypto ikev2 policy ${n} `); for (const x of p.proposals) L.push(` proposal ${x}`); L.push('!'); }
      for (const [n, k] of Object.entries(c.keyrings)) {
        L.push(`crypto ikev2 keyring ${n}`);
        for (const [pn, p] of Object.entries(k.peers)) {
          L.push(` peer ${pn}`);
          if (p.address) L.push(`  address ${p.address}${p.mask ? ' ' + p.mask : ''}`);
          if (p.psk) L.push(`  pre-shared-key ${p.psk}`);
          if (p.pskLocal) L.push(`  pre-shared-key local ${p.pskLocal}`);
          if (p.pskRemote) L.push(`  pre-shared-key remote ${p.pskRemote}`);
          if (p.ppk) L.push(`  ppk manual id ${p.ppk.id} key ${p.ppk.hex ? 'hex ' : ''}${p.ppk.key}${p.ppk.required ? ' required' : ''}`);
          L.push(' !');
        }
        L.push('!');
      }
      L.push('!');
      for (const [n, p] of Object.entries(c.profiles)) {
        L.push(`crypto ikev2 profile ${n}`);
        for (const m of p.matchRemote) L.push(` match identity remote address ${m.ip} ${m.mask || '255.255.255.255'} `);
        if (p.authRemote) L.push(` authentication remote ${p.authRemote}${p.authRemoteKey ? ' key ' + p.authRemoteKey : ''}`);
        if (p.authLocal) L.push(` authentication local ${p.authLocal}${p.authLocalKey ? ' key ' + p.authLocalKey : ''}`);
        if (p.keyringLocal) L.push(` keyring local ${p.keyringLocal}`);
        if (p.keyringPpk) L.push(` keyring ppk ${p.keyringPpk}`);
        if (p.lifetime) L.push(` lifetime ${p.lifetime}`);
        L.push('!');
      }
      if (c.fragMtu) L.push(`crypto ikev2 fragmentation mtu ${c.fragMtu}`, '!');
      L.push('!');
      for (const [n, t] of Object.entries(c.tsets)) { L.push(`crypto ipsec transform-set ${n} ${t.esp} `, ` mode ${t.mode}`, '!'); }
      for (const [n, p] of Object.entries(c.ipsecProfiles)) {
        L.push(`crypto ipsec profile ${n}`);
        if (p.ts) L.push(` set transform-set ${(p.tsList && p.tsList.length ? p.tsList : [p.ts]).join(' ')} `);
        if (p.pfs) L.push(` set pfs${p.pfs.group ? ' ' + p.pfs.group : ''}${p.pfs.pqc ? ' pqc ' + p.pfs.pqc : ''}`);
        if (p.ikev2Profile) L.push(` set ikev2-profile ${p.ikev2Profile}`);
        L.push('!');
      }
      L.push('!');
      for (const i of Object.values(d.ifaces).sort((a, b) => ifSort(a.name, b.name))) L.push(...ifBlock(i));
      L.push('ip forward-protocol nd', 'no ip http server', 'no ip http secure-server');
      for (const r of d.routes) L.push(`ip route ${r.net} ${r.mask} ${r.iface || r.nh}`);
      L.push('!', '!', 'control-plane', '!', 'line con 0', ' stopbits 1', 'line vty 0 4', ' login', ' transport input ssh', '!', 'end', '');
      const body = L.join('\n');
      return ['Building configuration...', '', `Current configuration : ${body.length} bytes`, ...L];
    }

    /* IOS prints these when you enter a crypto object that is still incomplete */
    _incompleteMsg(d, coll, o) {
      if (coll === 'proposals' && !(o.enc.length && o.group.length && (o.integ.length || (o.enc.every(e => e.includes('gcm')) && o.prf))))
        return ['IKEv2 proposal MUST either have a set of an encryption algorithm other than aes-gcm, an integrity algorithm and a DH group configured or', ' encryption algorithm aes-gcm, a prf algorithm and a DH group configured'];
      if (coll === 'policies' && !o.proposals.some(n => { const p = d.crypto.proposals[n]; return p && p.enc.length && p.group.length; }))
        return ['IKEv2 policy MUST have atleast one complete proposal attached'];
      if (coll === 'profiles' && !(o.authLocal && o.authRemote && o.matchRemote.length))
        return ['IKEv2 profile MUST have:', '   1. A local and a remote authentication method.', '   2. A match identity or a match certificate or match any statement.'];
      return [];
    }

    /* ---------- ping / traceroute ---------- */
    _ping(devKey, dst, opts) {
      const d = this.devs[devKey]; const count = opts.repeat || 5;
      const out = ['Type escape sequence to abort.', `Sending ${count}, 100-byte ICMP Echos to ${dst}, timeout is 2 seconds:`];
      let srcIp = '';
      if (opts.source) {
        if (isIp(opts.source)) { if (!Object.values(d.ifaces).some(i => i.ip === opts.source)) return [{ text: `% Invalid source address- IP address not on any of our up interfaces`, cls: 'err' }]; srcIp = opts.source; }
        else { const i = d.ifaces[opts.source]; if (!i || !i.ip) return [{ text: `% Invalid source interface - IP not enabled or interface is down`, cls: 'err' }]; srcIp = i.ip; }
        out.push(`Packet sent with a source address of ${srcIp} `);
      }
      // traffic triggers any pending IKE negotiation immediately
      const before = new Set([...this.pairState.values()].filter(s => s.state === 'up').map(s => s.key));
      this.reconcile({ force: st => st.state === 'neg' || st.state === 'fail' });
      const fresh = [...this.pairState.values()].filter(s => s.state === 'up' && !before.has(s.key));
      const r = this.lookup(devKey, dst);
      if (!srcIp && r) srcIp = d.ifaces[r.iface].ip;
      const fwd = r ? this.forward(devKey, dst) : { ok: false, hops: [] };
      const back = fwd.ok ? this.forward(fwd.end, srcIp) : { ok: false };
      const ok = fwd.ok && back.ok && (!opts.source || this.owns(devKey, srcIp));
      let lost = 0;
      if (ok) {
        const used = new Set(fwd.hops.filter(h => h.via === 'tunnel').map(h => h.key));
        for (const st of fresh) if (used.has(st.key) && st.sa.params.pqc) lost = Math.max(lost, 4);
        for (const h of fwd.hops.filter(h => h.via === 'link')) { const k = `${h.from}>${h.nh}`; if (!this.devs[h.from].arp.has(k)) { this.devs[h.from].arp.add(k); lost = Math.max(lost, 1); } }
        lost = Math.min(lost, count - 1);
      }
      const succ = ok ? count - lost : 0;
      const marks = ok ? '.'.repeat(lost) + '!'.repeat(succ) : '.'.repeat(count);
      out.push(marks.replace(/(.{70})/g, '$1\n'));
      if (succ) {
        const tun = fwd.hops.some(h => h.via === 'tunnel'); const hopsN = fwd.hops.length;
        const mn = 1, avg = hopsN > 1 || tun ? 2 : 1, mx = tun ? 4 : hopsN > 1 ? 3 : 1;
        out.push(`Success rate is ${Math.round(succ / count * 100)} percent (${succ}/${count}), round-trip min/avg/max = ${mn}/${avg}/${mx} ms`);
        for (const [h, dir] of [...fwd.hops.map(h => [h, 'out']), ...back.hops.map(h => [h, 'back'])]) {
          if (h.via !== 'tunnel') continue;
          const st = this.pairState.get(h.key); if (!st || !st.sa) continue;
          st.sa.counters[h.from].encaps += succ; st.sa.counters[h.to].decaps += succ;
          const ti = this.devs[h.from].ifaces[h.egress], tj = this.devs[h.to].ifaces[h.ingress];
          if (ti && ti.cnt) { ti.cnt.outP += succ; ti.cnt.outB += succ * 100; ti.cnt.last = this.now(); }
          if (tj && tj.cnt) { tj.cnt.inP += succ; tj.cnt.inB += succ * 100; tj.cnt.last = this.now(); }
        }
      } else out.push(`Success rate is 0 percent (0/${count})`);
      return { lines: out, ok, succ, count, path: ok ? { fwd: fwd.hops, back: back.hops } : { fwd: fwd.hops, back: [] }, srcIp, lost };
    }
    _traceroute(devKey, dst) {
      const out = ['Type escape sequence to abort.', `Tracing the route to ${dst}`, 'VRF info: (vrf in name/id, vrf out name/id)'];
      const f = this.forward(devKey, dst);
      f.hops.forEach((h, i) => {
        const last = f.ok && i === f.hops.length - 1;
        const ip = last ? dst : this.devs[h.to].ifaces[h.ingress].ip;
        out.push(`  ${i + 1} ${ip} ${i + 1} msec ${i + 1} msec ${i + 2} msec`);
      });
      if (!f.ok) for (let i = f.hops.length; i < f.hops.length + 3; i++) out.push(`  ${i + 1}  *  *  * `);
      return { lines: out, path: f };
    }

    /* ---------- command tables ---------- */
    _buildCommands() {
      const lab = this;
      const err = t => ({ text: t, cls: 'err' });
      const toPriv = d => { d.mode = 'priv'; d.ctx = {}; lab._log(d.key, '%SYS-5-CONFIG_I: Configured from console by console'); return []; };
      const goUp = d => {
        if (d.mode === 'peer') { d.mode = 'keyring'; d.ctx = { keyring: d.ctx.keyring }; }
        else if (d.mode === 'config') { d.mode = 'priv'; d.ctx = {}; lab._log(d.key, '%SYS-5-CONFIG_I: Configured from console by console'); }
        else { d.mode = 'config'; d.ctx = {}; }
        return [];
      };
      const SHOW = [
        C('show running-config', d => lab._runningConfig(d.key)),
        C('show running-config interface IFACE', (d, v) => lab._runningConfig(d.key, v[3])),
        C('show version', d => {
          const up = Math.floor((lab.now() - d.bootAt) / 60000), h = Math.floor(up / 60), m = up % 60;
          const upt = (h ? `${h} hour${h === 1 ? '' : 's'}, ` : '') + `${m} minute${m === 1 ? '' : 's'}`;
          const v = /C8000V/.test(d.model);
          return [`Cisco IOS XE Software, Version ${d.version}`, `Cisco IOS Software [Spotlight-PQC lab], ${v ? 'Virtual XE' : d.model} Software, Version ${d.version}`, 'Technical Support: http://www.cisco.com/techsupport', '',
            ...(lab.disclaimer ? [...DISCLAIMER, ''] : []),
            'ROM: IOS-XE ROMMON', '', `${d.hostname} uptime is ${upt}`, 'System image file is "bootflash:packages.conf"', '',
            v ? 'cisco C8000V (VXE) processor (revision VXE) with 1628922K/3075K bytes of memory.' : `cisco ${d.model} (1RU) processor with 3762145K/6147K bytes of memory.`,
            `Processor board ID ${d.serial}`, '', 'Configuration register is 0x2102', ''];
        }),
        C('show crypto pqc-support', d => [`Supports PQC: ${d.pqcSupport ? 'Yes' : 'No'}`]),
        C('show clock', () => { const t = new Date(lab.now()); return [`*${t.toTimeString().slice(0, 8)}.${String(t.getMilliseconds()).padStart(3, '0')} UTC ${t.toDateString()}`]; }),
        C('show history', d => d.history.slice(-20).map(h => '  ' + h)),
        C('show logging', d => ['Syslog logging: enabled (0 messages dropped, 0 flushes, 0 overruns)', '    Console logging: level debugging', '', `Log Buffer (8192 bytes):`, ...d.logBuf]),
        C('show ip interface brief', d => lab._showIpIntBrief(d.key)),
        C('show ip route', d => lab._showIpRoute(d.key)),
        C('show ip route A.B.C.D', (d, v) => {
          const r = lab.lookup(d.key, v[3]);
          if (!r) return ['% Network not in table'];
          const net = `${r.net}/${r.len}`;
          if (r.type === 'S') return [`Routing entry for ${net}`, `  Known via "static", distance 1, metric 0${r.nh ? '' : ' (connected)'}`, '  Routing Descriptor Blocks:', r.nh ? `  * ${r.nh}` : `  * directly connected, via ${r.iface}`, '      Route metric is 0, traffic share count is 1'];
          return [`Routing entry for ${net}`, `  Known via "connected", distance 0, metric 0 (connected, via interface)`, '  Routing Descriptor Blocks:', `  * directly connected, via ${r.iface}`, '      Route metric is 0, traffic share count is 1'];
        }),
        C('show interfaces IFACE', (d, v) => lab._showInterface(d.key, v[2])),
        C('show crypto ikev2 sa', d => lab._showIkev2Sa(d.key, false)),
        C('show crypto ikev2 sa detailed', d => lab._showIkev2Sa(d.key, true)),
        C('show crypto ikev2 stats', d => lab._showIkev2Stats(d.key)),
        C('show crypto ikev2 stats exchange', d => lab._showIkev2StatsExchange(d.key)),
        C('show crypto ikev2 session', d => lab._showIkev2Session(d.key, false)),
        C('show crypto ikev2 session detailed', d => lab._showIkev2Session(d.key, true)),
        C('show crypto ikev2 proposal', d => {
          const blk = (n, p) => [` IKEv2 proposal: ${n}`, `     Encryption : ${p.enc.map(e => e.toUpperCase()).join(' ')}`, `     Integrity  : ${p.integ.map(e => e.toUpperCase()).join(' ')}`,
            `     PRF        : ${(p.prf ? [p.prf] : p.integ).map(e => e.toUpperCase()).join(' ')}`, `     DH Group   : ${p.group.map(g => DH_SHOW[g] || 'Group ' + g).join(' ')}`,
            `     PQC Key Exchange: ${p.pqc ? p.pqc.algs.map(a => PQC_LABEL[a]).join(' ') : 'none'}`];
          return [...Object.entries(d.crypto.proposals).flatMap(([n, p]) => blk(n, p)), ...(d.crypto.defaults.proposal ? blk('default', DEFAULT_PROPOSAL) : [])];
        }),
        C('show crypto ikev2 policy', d => {
          const blk = (n, fvrf, props) => [` IKEv2 policy : ${n}`, `      Match fvrf ${n === 'default' ? ':' : ' :'} ${fvrf}`, '      Match address local : any', '      Match application type : any', ...props.map(x => `      Proposal    : ${x}`)];
          const user = Object.entries(d.crypto.policies).map(([n, p]) => blk(n, 'global', p.proposals));
          if (d.crypto.defaults.policy) user.push(blk('default', 'any', ['default']));
          return user.flatMap((b, i) => i ? ['', ...b] : b);
        }),
        C('show crypto ikev2 profile', d => Object.entries(d.crypto.profiles).flatMap(([n, p], k) => [...(k ? [''] : []), `IKEv2 profile: ${n}`, ' Shutdown : No', ` Ref Count: ${1 + Object.values(d.crypto.ipsecProfiles).filter(x => x.ikev2Profile === n).length * 2 + Object.values(d.ifaces).filter(x => x.tunnel && x.tunnel.protection && (d.crypto.ipsecProfiles[x.tunnel.protection] || {}).ikev2Profile === n).length * 2}`,
          ' Match criteria:', '  Fvrf: global', '  Local address/interface: none', '  Identities:', ...p.matchRemote.map(m => `   address ${m.ip} ${m.mask || '255.255.255.255'}`),
          '  Certificate maps: none', '  Application type: none', ' Local identity: none', ' Remote identity: none', ` Local authentication method: ${p.authLocal || 'none'}`,
          ` Remote authentication method(s): ${p.authRemote || 'none'}`, ' EAP options: none', ` Keyring: ${p.keyringLocal || 'none'}`, ...(p.keyringPpk ? [` PPK keyring: ${p.keyringPpk}`] : []), ' Trustpoint(s): none',
          ` Lifetime: ${p.lifetime || 86400} seconds`, ' DPD: disabled', ' NAT-keepalive: disabled', ' Ivrf: none', ' Virtual-template: none', ' mode auto: none',
          ' AAA AnyConnect EAP authentication mlist: none', ' AAA EAP authentication mlist: none', ' AAA authentication mlist: none', ' AAA Accounting: none', ' AAA group authorization: none', ' AAA user authorization: none'])),
        C('show crypto ipsec sa', d => lab._showIpsecSa(d.key, false)),
        C('show crypto ipsec sa detail', d => lab._showIpsecSa(d.key, true)),
        C('show crypto ipsec transform-set', d => {
          const all = [...(d.crypto.defaults.tset ? [['default', { esp: 'esp-aes esp-sha-hmac', mode: 'transport' }]] : []), ...Object.entries(d.crypto.tsets)];
          return all.flatMap(([n, t], i) => [...(i ? [''] : []), `Transform set ${n}: { ${t.esp}  }`, `   will negotiate = { ${t.mode === 'tunnel' ? 'Tunnel' : 'Transport'},  },`]);
        }),
        C('show crypto ipsec profile', d => {
          const blk = (n, p, ts) => [`IPSEC profile ${n}`, ...(p.ikev2Profile ? [`\tIKEv2 Profile: ${p.ikev2Profile}`] : []), '\tKilobyte Volume Rekey has been disabled.', '\tSecurity association lifetime:3600 seconds', '\tDualstack (Y/N): N', '',
            '\tResponder-Only (Y/N): N', `\tPFS (Y/N): ${p.pfs ? 'Y' : 'N'}`, ...(p.pfs ? [p.pfs.kind === 'inherit' ? '\t\tInherit (Y/N): Y' : `\t\tDH group:  ${p.pfs.group}`] : []), '\tMixed-mode : Disabled', '\tTransform sets={', ...ts.map(([tn, t]) => `\t\t${tn}:  { ${t.esp}  } ,`), '\t}'];
          const out = Object.entries(d.crypto.ipsecProfiles).map(([n, p]) => blk(n, p, (p.tsList && p.tsList.length ? p.tsList : [p.ts]).filter(x => d.crypto.tsets[x]).map(x => [x, d.crypto.tsets[x]])));
          if (d.crypto.defaults.ipsecProfile) out.push(blk('default', {}, [['default', { esp: 'esp-aes esp-sha-hmac' }]]));
          return out.flatMap((b, i) => i ? ['', ...b] : b);
        }),
        C('show crypto session', d => lab._showCryptoSession(d.key, false)),
        C('show crypto session detail', d => lab._showCryptoSession(d.key, true)),
      ].map(c => ({ ...c, cfg: false }));
      const SHOW_EXEC = SHOW.filter(c => /^show (version|clock|history|ip|interfaces)/.test(c.p));
      const pingRun = (d, v, neg, meta) => {
        const opts = {};
        for (let i = 2; i < v.length; i += 2) { if (v[i] === 'source') opts.source = v[i + 1]; if (v[i] === 'repeat') opts.repeat = +v[i + 1]; }
        const r = lab._ping(d.key, v[1], opts);
        if (Array.isArray(r)) return r;
        Object.assign(meta, { kind: 'ping', dst: v[1], ok: r.ok, succ: r.succ, count: r.count, path: r.path, lost: r.lost, src: r.srcIp });
        return r.lines;
      };
      const PING = [
        C('ping A.B.C.D', pingRun), C('ping A.B.C.D source IFACE', pingRun), C('ping A.B.C.D source A.B.C.D', pingRun),
        C('ping A.B.C.D repeat <1-1000>', pingRun), C('ping A.B.C.D repeat <1-1000> source IFACE', pingRun), C('ping A.B.C.D source IFACE repeat <1-1000>', pingRun),
        C('traceroute A.B.C.D', (d, v, n, meta) => { const r = lab._traceroute(d.key, v[1]); Object.assign(meta, { kind: 'trace', dst: v[1], ok: r.path.ok, path: r.path }); return r.lines; }),
      ].map(c => ({ ...c, cfg: false }));
      const misc = [C('terminal length <0-512>', () => []), C('exit', () => []), C('logout', () => [])].map(c => ({ ...c, cfg: false }));

      const EXEC = [C('enable', d => { d.mode = 'priv'; return []; }), ...PING, ...SHOW_EXEC, ...misc];
      const PRIV = [
        C('enable', () => []),
        C('disable', d => { d.mode = 'exec'; return []; }),
        C('configure terminal', d => { d.mode = 'config'; d.ctx = {}; return ['Enter configuration commands, one per line.  End with CNTL/Z.']; }),
        C('clear crypto ikev2 sa', d => { lab.clearSAs(d.key); return []; }),
        C('clear crypto ikev2 sa fast', d => { lab.clearSAs(d.key); return []; }),
        C('clear crypto session', d => { lab.clearSAs(d.key); return []; }),
        // resets the SA statistics; per-exchange counters keep running from boot (observed on IOS XE 26.02)
        C('clear crypto ikev2 stats', d => { d.stats = { inReq: 0, outReq: 0, inRej: 0, outRej: 0 }; return ['Cleared crypto ikev2 statistics']; }),
        C('clear crypto sa', d => { lab.clearIpsecSAs(d.key); return []; }),
        C('write memory', () => ['Building configuration...', '[OK]']), C('write', () => ['Building configuration...', '[OK]']),
        C('copy running-config startup-config', () => ['Destination filename [startup-config]? ', 'Building configuration...', '[OK]']),
        C('debug crypto ikev2', d => { d.debug.ikev2 = true; return ['IKEv2 default debugging is on']; }),
        C('undebug all', d => { d.debug.ikev2 = false; return ['All possible debugging has been turned off']; }),
        C('no debug all', d => { d.debug.ikev2 = false; return ['All possible debugging has been turned off']; }),
        ...PING, ...SHOW, ...misc,
      ].map(c => ({ ...c, cfg: false }));

      const ifEnter = (d, name) => {
        if (!d.ifaces[name]) {
          const k = ifKind(name);
          if (k === 'phys') return [err('                   ^'), err('% Invalid input detected at \'^\' marker.')];
          d.ifaces[name] = { name, kind: k, shutdown: false, ip: '', mask: '', desc: '', vlan: null, swMode: null, tunnel: k === 'tunnel' ? { source: '', dest: '', mode: 'gre ip', protection: '' } : null,
            boot: false, createdAt: lab.now(), cnt: { inP: 0, outP: 0, inB: 0, outB: 0, last: null } };
          if (k === 'tunnel' || k === 'loopback') lab._log(d.key, `%LINEPROTO-5-UPDOWN: Line protocol on Interface ${name}, changed state to ${k === 'loopback' ? 'up' : 'down'}`);
        }
        d.mode = 'if'; d.ctx = { iface: name }; return [];
      };
      const cp = (d) => d.crypto;
      const newProposal = () => ({ enc: [], integ: [], group: [], prf: null, pqc: null });
      const DEF_KEY = { proposals: 'proposal', policies: 'policy', ipsecProfiles: 'ipsecProfile' };
      const subEnter = (mode, coll, mk, ctxKey) => (d, v, neg) => {
        const name = v[3]; const store = cp(d)[coll];
        if (name === 'default' && DEF_KEY[coll] && !store[name]) { if (neg) { cp(d).defaults[DEF_KEY[coll]] = false; return []; } cp(d).defaults[DEF_KEY[coll]] = true; }
        if (neg) {
          if (!store[name]) return [err(`% ${ctxKey} ${name} not found`)];
          if (coll === 'ipsecProfiles' && Object.values(d.ifaces).some(i => i.tunnel && i.tunnel.protection === name)) return [err(`% Profile ${name} is in use by tunnel interface(s); remove "tunnel protection" first`)];
          delete store[name]; return [];
        }
        if (!store[name]) store[name] = mk();
        d.mode = mode; d.ctx = { [ctxKey]: name };
        return lab._incompleteMsg(d, coll, store[name]);
      };
      const tsRun = (d, v, neg) => {
        const name = v[3];
        if (neg) { if (Object.values(cp(d).ipsecProfiles).some(p => p.ts === name)) { /* allowed, profile becomes incomplete */ } delete cp(d).tsets[name]; return []; }
        const esp = v.slice(4).join(' ');
        cp(d).tsets[name] = { esp, mode: (cp(d).tsets[name] || {}).mode || 'tunnel' };
        d.mode = 'tset'; d.ctx = { tset: name }; return [];
      };
      const CONFIG = [
        C('hostname WORD', (d, v) => { d.hostname = v[1]; return []; }),
        C('interface IFACE', (d, v, neg) => {
          if (!neg) return ifEnter(d, v[1]);
          const i = d.ifaces[v[1]]; if (!i) return [err('% Interface not found')];
          if (i.kind === 'phys' || i.kind === 'svi') return [err('% Removal of physical interfaces is not permitted')];
          delete d.ifaces[v[1]]; return [];
        }, { no: true }),
        C('ip route A.B.C.D A.B.C.D IFACE', (d, v, neg) => {
          const [net, mask, ifn] = [v[2], v[3], v[4]];
          if (!isMask(mask) || netOf(net, mask) !== net) return [err('%Inconsistent address and mask')];
          const i = d.routes.findIndex(r => r.net === net && r.mask === mask && r.iface === ifn);
          if (neg) { if (i >= 0) d.routes.splice(i, 1); else return [err('%No matching route to delete')]; }
          else if (i < 0) d.routes.push({ net, mask, iface: ifn });
          return [];
        }, { no: true, argHelp: { 4: 'Interface' } }),
        C('ip route A.B.C.D A.B.C.D A.B.C.D', (d, v, neg) => {
          const [net, mask, nh] = [v[2], v[3], v[4]];
          if (!isMask(mask)) return [err('%Inconsistent address and mask')];
          if (netOf(net, mask) !== net) return [err('%Inconsistent address and mask')];
          const i = d.routes.findIndex(r => r.net === net && r.mask === mask && r.nh === nh);
          if (neg) { if (i >= 0) d.routes.splice(i, 1); else return [err('%No matching route to delete')]; }
          else if (i < 0) d.routes.push({ net, mask, nh });
          return [];
        }, { no: true, argHelp: { 2: 'Destination prefix', 3: 'Destination prefix mask', 4: 'Forwarding router\'s address' } }),
        C('ip domain lookup', () => [], { no: true }),
        C('crypto ikev2 proposal WORD', subEnter('proposal', 'proposals', newProposal, 'proposal'), { no: true, argHelp: { 3: 'Proposal name' } }),
        C('crypto ikev2 policy WORD', subEnter('policy', 'policies', () => ({ proposals: [] }), 'policy'), { no: true, argHelp: { 3: 'Policy name' } }),
        C('crypto ikev2 keyring WORD', subEnter('keyring', 'keyrings', () => ({ peers: {} }), 'keyring'), { no: true, argHelp: { 3: 'Name of the key ring' } }),
        C('crypto ikev2 profile WORD', subEnter('profile', 'profiles', () => ({ matchRemote: [], authLocal: '', authRemote: '', authLocalKey: '', authRemoteKey: '', keyringLocal: '', keyringPpk: '', lifetime: null }), 'profile'), { no: true, argHelp: { 3: 'Profile name' } }),
        C('crypto ikev2 fragmentation', (d, v, neg) => { cp(d).fragMtu = neg ? null : 576; return []; }, { no: true }),
        C('crypto ikev2 fragmentation mtu <68-1500>', (d, v, neg) => { cp(d).fragMtu = neg ? null : +v[4]; return []; }, { no: true, argHelp: { 4: 'MTU in bytes (IKE packet size including IP/UDP headers)' } }),
        C('crypto ipsec transform-set WORD', tsRun, { no: true, noOnly: true }),
        C('crypto ipsec transform-set WORD esp-gcm', tsRun, { no: true, argHelp: { 3: 'Transform set tag' } }),
        C('crypto ipsec transform-set WORD esp-gcm (128|192|256)', tsRun, { no: true }),
        C('crypto ipsec transform-set WORD esp-aes (esp-sha-hmac|esp-sha256-hmac|esp-sha384-hmac|esp-sha512-hmac)', tsRun, { no: true }),
        C('crypto ipsec transform-set WORD esp-aes (128|192|256) (esp-sha-hmac|esp-sha256-hmac|esp-sha384-hmac|esp-sha512-hmac)', tsRun, { no: true }),
        C('crypto ipsec profile WORD', subEnter('ipsecprof', 'ipsecProfiles', () => ({ ts: '', ikev2Profile: '', pfs: null }), 'ipsec profile'), { no: true, argHelp: { 3: 'Profile name' } }),
        C('end', toPriv, { cfg: false }), C('exit', goUp, { cfg: false }),
        C('do LINE', (d, v) => {
          const saved = d.mode, ctx = d.ctx; d.mode = 'priv';
          const r = lab._resolve(d, v.slice(1).join(' '), 'priv');
          let res;
          if (r.err) res = [err(r.err === 'incomplete' ? '% Incomplete command.' : '% Invalid input detected at \'^\' marker.')];
          else { const meta = {}; res = r.match.c.run.call(lab, d, r.match.vals, false, meta) || []; }
          d.mode = saved; d.ctx = ctx; return res;
        }, { cfg: false }),
      ];
      const sub = (fn) => (d, v, neg, meta) => fn(d, v, neg, meta);
      const ifc = d => d.ifaces[d.ctx.iface];
      const IFACE = [
        C('ip address A.B.C.D A.B.C.D', sub((d, v, neg) => {
          const i = ifc(d);
          if (i.kind === 'phys' && i.vlan) return [err('% IP addresses may not be configured on L2 links.')];
          if (neg) { i.ip = ''; i.mask = ''; return []; }
          if (!isMask(v[3])) return [err(`Bad mask /${v[3]} for address ${v[2]}`)];
          for (const o of Object.values(d.ifaces)) if (o !== i && o.ip && (inNet(v[2], o.ip, o.mask) || inNet(o.ip, v[2], v[3]))) return [err(`% ${netOf(v[2], v[3])} overlaps with ${o.name}`)];
          i.ip = v[2]; i.mask = v[3]; return [];
        }), { no: true, argHelp: { 2: 'IP address', 3: 'IP subnet mask' } }),
        C('ip address', sub((d) => { const i = ifc(d); i.ip = ''; i.mask = ''; return []; }), { no: true, noOnly: true }),
        C('shutdown', sub((d, v, neg) => {
          const i = ifc(d); const before = lab.lineUp(d.key, i.name); i.shutdown = !neg;
          if (!neg && before !== false) lab._log(d.key, `%LINK-5-CHANGED: Interface ${i.name}, changed state to administratively down`);
          if (neg && i.kind !== 'tunnel') lab._log(d.key, `%LINK-3-UPDOWN: Interface ${i.name}, changed state to up`);
          return [];
        }), { no: true }),
        C('description LINE', sub((d, v, neg) => { ifc(d).desc = neg ? '' : v.slice(1).join(' '); return []; }), { no: true }),
        C('description', sub((d) => { ifc(d).desc = ''; return []; }), { no: true, noOnly: true }),
        C('switchport access vlan <1-4094>', sub((d, v, neg) => { ifc(d).vlan = neg ? 1 : +v[3]; return []; }), { no: true, when: i => i.kind === 'phys' }),
        C('switchport mode access', sub(() => []), { no: true, when: i => i.kind === 'phys' }),
        C('tunnel source IFACE', sub((d, v, neg) => { ifc(d).tunnel.source = neg ? '' : v[2]; return []; }), { no: true, when: i => i.kind === 'tunnel' }),
        C('tunnel source A.B.C.D', sub((d, v, neg) => { ifc(d).tunnel.source = neg ? '' : v[2]; return []; }), { no: true, when: i => i.kind === 'tunnel' }),
        C('tunnel source', sub((d) => { ifc(d).tunnel.source = ''; return []; }), { no: true, noOnly: true, when: i => i.kind === 'tunnel' }),
        C('tunnel destination A.B.C.D', sub((d, v, neg) => { ifc(d).tunnel.dest = neg ? '' : v[2]; return []; }), { no: true, when: i => i.kind === 'tunnel' }),
        C('tunnel destination', sub((d) => { ifc(d).tunnel.dest = ''; return []; }), { no: true, noOnly: true, when: i => i.kind === 'tunnel' }),
        C('tunnel mode ipsec ipv4', sub((d, v, neg) => { ifc(d).tunnel.mode = neg ? 'gre ip' : 'ipsec ipv4'; return []; }), { no: true, when: i => i.kind === 'tunnel' }),
        C('tunnel mode gre ip', sub((d) => { ifc(d).tunnel.mode = 'gre ip'; return []; }), { no: true, when: i => i.kind === 'tunnel' }),
        C('tunnel protection ipsec profile WORD', sub((d, v, neg) => {
          const t = ifc(d).tunnel;
          if (neg) { t.protection = ''; return []; }
          if (!cp(d).ipsecProfiles[v[4]]) return [err(`% IPSec profile ${v[4]} does not exist`)];
          t.protection = v[4]; return [];
        }), { no: true, when: i => i.kind === 'tunnel', argHelp: { 4: 'IPSec profile name' } }),
        C('tunnel protection ipsec profile', sub((d) => { ifc(d).tunnel.protection = ''; return []; }), { no: true, noOnly: true, when: i => i.kind === 'tunnel' }),
        C('interface IFACE', (d, v) => ifEnter(d, v[1])),
        C('end', toPriv, { cfg: false }), C('exit', goUp, { cfg: false }),
      ];
      const prop = d => cp(d).proposals[d.ctx.proposal];
      const listCmd = (kw, field, opts, conv = x => x) => [1, 2, 3].map(n => C(`${kw} ${Array(n).fill(`(${opts})`).join(' ')}`, (d, v, neg) => {
        const p = prop(d); const vals = v.slice(1).map(conv);
        if (neg) p[field] = p[field].filter(x => !vals.includes(x)); else for (const x of vals) if (!p[field].includes(x)) p[field].push(x);
        return [];
      }, { no: true }));
      const PROPOSAL = [
        ...listCmd('encryption', 'enc', 'aes-cbc-128|aes-cbc-192|aes-cbc-256|aes-gcm-128|aes-gcm-256'),
        ...listCmd('integrity', 'integ', 'sha1|sha256|sha384|sha512'),
        ...listCmd('group', 'group', '14|15|16|19|20|21|24', Number),
        C('prf (sha1|sha256|sha384|sha512)', (d, v, neg) => { prop(d).prf = neg ? null : v[1]; return []; }, { no: true }),
        // guide: `pqc mlkem768 mlkem1024 optional` — 1..3 ML-KEM algorithms, `optional` allows classical fallback
        ...[1, 2, 3].flatMap(n => [false, true].map(opt => C(`pqc ${Array(n).fill('(mlkem512|mlkem768|mlkem1024)').join(' ')}${opt ? ' optional' : ''}`, (d, v, neg) => {
          const algs = [...new Set(v.slice(1, 1 + n))];
          prop(d).pqc = neg ? null : { algs, mode: opt ? 'optional' : 'required' }; return [];
        }, { no: true }))),
        C('pqc', (d) => { prop(d).pqc = null; return []; }, { no: true, noOnly: true }),
        C('end', toPriv, { cfg: false }), C('exit', goUp, { cfg: false }),
      ];
      const POLICY = [
        C('proposal WORD', (d, v, neg) => {
          const p = cp(d).policies[d.ctx.policy];
          if (neg) { p.proposals = p.proposals.filter(x => x !== v[1]); return []; }
          if (!cp(d).proposals[v[1]]) return [err(`% IKEv2 proposal ${v[1]} does not exist. Please configure the proposal first.`)];
          if (!p.proposals.includes(v[1])) p.proposals.push(v[1]); return [];
        }, { no: true, argHelp: { 1: 'Specify Proposal' } }),
        C('match address local A.B.C.D', () => [], { no: true }), C('match fvrf any', () => [], { no: true }),
        C('end', toPriv, { cfg: false }), C('exit', goUp, { cfg: false }),
      ];
      const KEYRING = [
        C('peer WORD', (d, v, neg) => {
          const kr = cp(d).keyrings[d.ctx.keyring];
          if (neg) { delete kr.peers[v[1]]; return []; }
          if (!kr.peers[v[1]]) kr.peers[v[1]] = { address: '', mask: '', psk: '', ppk: null };
          d.mode = 'peer'; d.ctx = { keyring: d.ctx.keyring, peer: v[1] }; return [];
        }, { no: true, argHelp: { 1: 'Name of peer' } }),
        C('end', toPriv, { cfg: false }), C('exit', goUp, { cfg: false }),
      ];
      const peer = d => cp(d).keyrings[d.ctx.keyring].peers[d.ctx.peer];
      const ppkSet = (d, v, neg) => {
        const p = peer(d);
        if (neg) { p.ppk = null; return []; }
        const hexIdx = v.indexOf('hex'); const keyIdx = hexIdx >= 0 ? hexIdx + 1 : 5;
        const key = v[keyIdx];
        if (hexIdx >= 0 && !/^[0-9a-fA-F]+$/.test(key)) return [err('% Invalid hex key')];
        p.ppk = { id: v[3], key, hex: hexIdx >= 0, required: v.includes('required') };
        return [];
      };
      const PEER = [
        C('address A.B.C.D', (d, v, neg) => { const p = peer(d); if (neg) { p.address = ''; p.mask = ''; } else { p.address = v[1]; p.mask = ''; } return []; }, { no: true, argHelp: { 1: 'IPv4 address' } }),
        C('address A.B.C.D A.B.C.D', (d, v, neg) => { const p = peer(d); if (neg) { p.address = ''; p.mask = ''; } else { p.address = v[1]; p.mask = v[2]; } return []; }, { no: true }),
        C('address', d => { peer(d).address = ''; return []; }, { no: true, noOnly: true }),
        C('pre-shared-key WORD', (d, v, neg) => { peer(d).psk = neg ? '' : v[1]; return []; }, { no: true, argHelp: { 1: 'The UNENCRYPTED (cleartext) user password' } }),
        C('pre-shared-key (0|6) WORD', (d, v, neg) => { peer(d).psk = neg ? '' : v[2]; return []; }, { no: true }),
        C('pre-shared-key (local|remote) WORD', (d, v, neg) => { peer(d)[v[1] === 'local' ? 'pskLocal' : 'pskRemote'] = neg ? '' : v[2]; return []; }, { no: true, argHelp: { 2: 'The pre-shared key' } }),
        C('pre-shared-key', d => { peer(d).psk = ''; return []; }, { no: true, noOnly: true }),
        C('ppk manual id WORD key WORD', ppkSet, { no: true, argHelp: { 3: 'PPK identity', 5: 'PPK value' } }),
        C('ppk manual id WORD key WORD required', ppkSet, { no: true }),
        C('ppk manual id WORD key hex WORD', ppkSet, { no: true, argHelp: { 6: 'PPK value in hex' } }),
        C('ppk manual id WORD key hex WORD required', ppkSet, { no: true }),
        C('ppk manual id WORD', ppkSet, { no: true, noOnly: true }),
        C('ppk manual', ppkSet, { no: true, noOnly: true }),
        C('description LINE', () => [], { no: true }),
        C('identity address A.B.C.D', () => [], { no: true }),
        C('end', toPriv, { cfg: false }), C('exit', goUp, { cfg: false }),
      ];
      const prof = d => cp(d).profiles[d.ctx.profile];
      const PROFILE = [
        C('match identity remote address A.B.C.D', (d, v, neg) => { const p = prof(d); p.matchRemote = p.matchRemote.filter(m => m.ip !== v[4]); if (!neg) p.matchRemote.push({ ip: v[4], mask: '255.255.255.255' }); return []; }, { no: true, argHelp: { 4: 'IP address' } }),
        C('match identity remote address A.B.C.D A.B.C.D', (d, v, neg) => { const p = prof(d); p.matchRemote = p.matchRemote.filter(m => m.ip !== v[4]); if (!neg) p.matchRemote.push({ ip: v[4], mask: v[5] }); return []; }, { no: true, argHelp: { 5: 'Mask' } }),
        C('authentication (local|remote) pre-share', (d, v, neg) => { const l = v[1] === 'local'; prof(d)[l ? 'authLocal' : 'authRemote'] = neg ? '' : 'pre-share'; prof(d)[l ? 'authLocalKey' : 'authRemoteKey'] = ''; return []; }, { no: true }),
        C('authentication (local|remote) pre-share key WORD', (d, v, neg) => { const l = v[1] === 'local'; prof(d)[l ? 'authLocal' : 'authRemote'] = neg ? '' : 'pre-share'; prof(d)[l ? 'authLocalKey' : 'authRemoteKey'] = neg ? '' : v[4]; return []; }, { no: true, argHelp: { 4: 'The pre-shared key' } }),
        C('keyring local WORD', (d, v, neg) => { prof(d).keyringLocal = neg ? '' : v[2]; return []; }, { no: true, argHelp: { 2: 'Name of the keyring' } }),
        C('keyring local', d => { prof(d).keyringLocal = ''; return []; }, { no: true, noOnly: true }),
        C('keyring ppk WORD', (d, v, neg) => { prof(d).keyringPpk = neg ? '' : v[2]; return []; }, { no: true, argHelp: { 2: 'Name of the keyring holding PPKs' } }),
        C('keyring ppk', d => { prof(d).keyringPpk = ''; return []; }, { no: true, noOnly: true }),
        C('lifetime <120-86400>', (d, v, neg) => { prof(d).lifetime = neg ? null : +v[1]; return []; }, { no: true, argHelp: { 1: 'lifetime in seconds' } }),
        C('identity local address A.B.C.D', () => [], { no: true }),
        C('end', toPriv, { cfg: false }), C('exit', goUp, { cfg: false }),
      ];
      const TSET = [
        C('mode (tunnel|transport)', (d, v, neg) => { cp(d).tsets[d.ctx.tset].mode = neg ? 'tunnel' : v[1]; return []; }, { no: true }),
        C('end', toPriv, { cfg: false }), C('exit', goUp, { cfg: false }),
      ];
      const ips = d => cp(d).ipsecProfiles[d.ctx['ipsec profile']];
      const IPSECPROF = [
        ...[1, 2, 3, 4].map(n => C(`set transform-set ${Array(n).fill('WORD').join(' ')}`, (d, v, neg) => {
          if (neg) { ips(d).ts = ''; ips(d).tsList = []; return []; }
          const names = v.slice(2);
          const missing = names.find(x => !cp(d).tsets[x]);
          if (missing) return [err(`ERROR: transform set with tag "${missing}" does not exist.`)];
          ips(d).tsList = [...new Set(names)]; ips(d).ts = names[0]; return [];
        }, { no: true, argHelp: { 2: 'Proposal tag' } })),
        C('set ikev2-profile WORD', (d, v, neg) => {
          if (neg) { ips(d).ikev2Profile = ''; return []; }
          if (!cp(d).profiles[v[2]]) return [err(`% IKEv2 profile ${v[2]} does not exist`)];
          ips(d).ikev2Profile = v[2]; return [];
        }, { no: true, argHelp: { 2: 'ikev2 Profile name' } }),
        C('set pfs', (d, v, neg) => { ips(d).pfs = neg ? null : { kind: 'inherit' }; return []; }, { no: true }),
        C('set pfs (group14|group15|group16|group19|group20|group21|group24)', (d, v, neg) => { ips(d).pfs = neg ? null : { kind: 'group', group: v[2] }; return []; }, { no: true }),
        C('set pfs (group14|group15|group16|group19|group20|group21|group24) pqc (mlkem512|mlkem768|mlkem1024)', (d, v, neg) => { ips(d).pfs = neg ? null : { kind: 'grouppqc', group: v[2], pqc: v[4] }; return []; }, { no: true }),
        C('end', toPriv, { cfg: false }), C('exit', goUp, { cfg: false }),
      ];
      this.cmds = { exec: EXEC, priv: PRIV, config: CONFIG, if: IFACE, proposal: PROPOSAL, policy: POLICY, keyring: KEYRING, peer: PEER, profile: PROFILE, tset: TSET, ipsecprof: IPSECPROF };
    }
  }

  return { Lab, DISCLAIMER, canonIf, ifShort, isIp, PQC_LABEL, DH_LABEL, DH_KE_BYTES, MLKEM_SIZES, ENC_LABEL, NEG_DELAY_MS };
});
