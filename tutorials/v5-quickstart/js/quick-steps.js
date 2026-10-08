/* ==========================================================================
   quick-steps.js — three short tutorials forked from the v3 lab
     ?track=classic   Build a classic IKEv2 VPN (only that)
     ?track=pqc       Build a post-quantum (ML-KEM-768 hybrid) VPN from scratch
     ?track=migrate   Start classic, then take the steps to post-quantum

   Same step shape and engine as v3 (../v3-three-router/js):
     { id, title, part, devices, html, run:[[dev, cmd], ...],
       validate(ctx) -> bool, hints:[{ when(dev, canon, raw, lab), text }] }
   ========================================================================== */
(function (root) {
  const GUIDE_URL = 'https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/security-vpn/m-pqc-ikev2.html';
  const IKEV2_URL = 'https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-cfg-ikev2-flex.html';
  const BLOG_URL = 'https://blogs.cisco.com/developer/post-quantum-key-exchange-on-cisco-routers-ipsec-series-part-9';
  const link = (url, txt) => `<a href="${url}" target="_blank" rel="noopener">${txt}</a>`;
  const PSK = 'C1sco12345psk';

  /* ---------- HTML helpers ---------- */
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const cfg = (dev, lines, note) => `<div class="cfg"><div class="cfg-head"><span class="dev-chip dev-${dev}">${dev.toUpperCase()}</span>${note ? `<span class="cfg-note">${note}</span>` : ''}</div><pre>${esc(lines.join('\n'))}</pre></div>`;
  const out = lines => `<pre class="out">${esc(lines.join('\n'))}</pre>`;
  const callout = (kind, html) => `<div class="callout ${kind}">${html}</div>`;
  const runOf = (dev, lines) => lines.map(c => [dev, c]);
  const shown = lines => lines.slice(1, -1).filter(l => !/^\s*exit$/.test(l));
  const EDU_NOTICE = callout('edu', `<b>🎓 For learning only.</b> This is a simulator to practise IOS XE commands and get familiar with VPN and post-quantum concepts. It is not a real router: output can differ from real platforms, so <b>don't use it to validate configurations</b>. Provided <b>as is</b>, with no warranty and no support. <a href="https://github.com/ioeacademy/spotlight-pqc/blob/main/DISCLAIMER.md" target="_blank" rel="noopener">Full disclaimer</a>.`);
  const LAB_TABLE = `<table class="t mono">
<tr><th></th><th>Role</th><th>WAN interface</th><th>Address</th></tr>
<tr><td>R1</td><td>VPN peer</td><td>Tw0/0/0</td><td>10.0.12.1/24</td></tr>
<tr><td rowspan="2">R2</td><td rowspan="2">Transit ("the WAN")</td><td>Tw0/0/0</td><td>10.0.12.2/24</td></tr>
<tr><td>Tw0/0/1</td><td>10.0.23.1/24</td></tr>
<tr><td>R3</td><td>VPN peer</td><td>Tw0/0/0</td><td>10.0.23.2/24</td></tr>
</table>
<p>The tunnel runs between R1 and R3 and uses the overlay network <code>192.168.100.0/24</code> (R1 = .1, R3 = .2).</p>`;
  const HOW = callout('info', 'Type commands in the console on the right (<kbd>?</kbd> for help, <kbd>Tab</kbd> to complete). Each step checks the <i>real state</i> of the simulated routers. Stuck? <b>Show Me</b> types the commands for you.');

  /* ---------- validation helpers ---------- */
  const sa13 = lab => lab.saBetween('r1', 'r3');
  const pingOk = (ctx, dk, ip) => ctx.lab.ranSince(ctx.since, dk, e => e.meta && e.meta.kind === 'ping' && e.meta.dst === ip && e.meta.succ > 0);
  const ran = (ctx, dk, re) => ctx.lab.ranSince(ctx.since, dk, re);
  const proposalsOf = (lab, dk) => Object.values(lab.dev(dk).crypto.policies).flatMap(p => p.proposals).map(n => lab.dev(dk).crypto.proposals[n]).filter(Boolean);
  // complete chain on `dk`: tunnel → ipsec profile → transform set + ikev2 profile → keyring with the peer's PSK
  function chainTo(lab, dk, peerIp) {
    const c = lab.dev(dk).crypto;
    return Object.values(lab.dev(dk).ifaces).some(t => {
      if (t.kind !== 'tunnel' || t.shutdown || t.tunnel.mode !== 'ipsec ipv4' || t.tunnel.dest !== peerIp || !t.ip) return false;
      const ip = c.ipsecProfiles[t.tunnel.protection]; if (!ip || !c.tsets[ip.ts]) return false;
      const pr = c.profiles[ip.ikev2Profile]; if (!pr || pr.authLocal !== 'pre-share' || pr.authRemote !== 'pre-share' || !pr.matchRemote.some(m => m.ip === peerIp)) return false;
      const kr = c.keyrings[pr.keyringLocal]; return !!kr && Object.values(kr.peers).some(p => p.address === peerIp && p.psk);
    }) && proposalsOf(lab, dk).some(p => p.enc.length && p.group.length);
  }
  // proof of encryption: a ping through the tunnel, then `show crypto ipsec sa` after it, with encaps > 0
  function encryptionProven(ctx, dk, tunIp, peer) {
    const log = ctx.lab.cmdLog.filter(e => e.seq > ctx.since && e.dev === dk && e.ok);
    const p = log.find(e => e.meta && e.meta.kind === 'ping' && e.meta.dst === tunIp && e.meta.succ > 0 && e.meta.path && e.meta.path.fwd.some(h => h.via === 'tunnel'));
    if (!p) return false;
    const sa = ctx.lab.saBetween(dk, peer);
    return log.some(e => e.seq > p.seq && /^show crypto ipsec sa/.test(e.canon)) && !!sa && sa.counters[dk].encaps > 0;
  }

  /* ---------- configuration blocks ---------- */
  const tunnel = (ip, dest) => ['interface Tunnel0', ` ip address ${ip} 255.255.255.0`, ' tunnel source TwoGigabitEthernet0/0/0', ` tunnel destination ${dest}`, ' tunnel mode ipsec ipv4'];
  function vpnConfig({ name, peerName, peer, tunIp, pqc, pfs, frag }) {
    return ['configure terminal',
      ...(frag ? ['crypto ikev2 fragmentation mtu 1400'] : []),
      `crypto ikev2 proposal ${name}-PROPOSAL`, ' encryption aes-cbc-256', ' integrity sha512', ' group 20', ...(pqc ? [` pqc ${pqc}`] : []), ' exit',
      `crypto ikev2 policy ${name}-POLICY`, ` proposal ${name}-PROPOSAL`, ' exit',
      `crypto ikev2 keyring ${name}-KEYRING`, ` peer ${peerName}`, `  address ${peer}`, `  pre-shared-key ${PSK}`, '  exit', ' exit',
      `crypto ikev2 profile ${name}-PROFILE`, ` match identity remote address ${peer} 255.255.255.255`, ' authentication remote pre-share', ' authentication local pre-share', ` keyring local ${name}-KEYRING`, ' exit',
      `crypto ipsec transform-set ${name}-TS esp-gcm 256`, ' mode tunnel', ' exit',
      `crypto ipsec profile ${name}-IPSEC`, ` set transform-set ${name}-TS`, ` set ikev2-profile ${name}-PROFILE`, ...(pfs ? [' set pfs'] : []), ' exit',
      ...tunnel(tunIp, peer), ` tunnel protection ipsec profile ${name}-IPSEC`,
      'end'];
  }
  const R1_CLASSIC = vpnConfig({ name: 'CLASSIC', peerName: 'R3', peer: '10.0.23.2', tunIp: '192.168.100.1' });
  const R3_CLASSIC = vpnConfig({ name: 'CLASSIC', peerName: 'R1', peer: '10.0.12.1', tunIp: '192.168.100.2' });
  const R1_PQC = vpnConfig({ name: 'PQC', peerName: 'R3', peer: '10.0.23.2', tunIp: '192.168.100.1', pqc: 'mlkem768', pfs: true, frag: true });
  const R3_PQC = vpnConfig({ name: 'PQC', peerName: 'R1', peer: '10.0.12.1', tunIp: '192.168.100.2', pqc: 'mlkem768', pfs: true, frag: true });

  const BLOCKS = `<table class="t">
<tr><th>Block</th><th>What it does</th></tr>
<tr><td><code>crypto ikev2 proposal</code></td><td>Algorithms for the IKE SA: encryption, integrity, DH group</td></tr>
<tr><td><code>crypto ikev2 policy</code></td><td>Which proposal(s) to use</td></tr>
<tr><td><code>crypto ikev2 keyring</code></td><td>The peer's address and pre-shared key</td></tr>
<tr><td><code>crypto ikev2 profile</code></td><td>Who the peer is and how both sides authenticate</td></tr>
<tr><td><code>crypto ipsec transform-set</code></td><td>How the data is encrypted (ESP)</td></tr>
<tr><td><code>crypto ipsec profile</code></td><td>Ties the transform set to the IKEv2 profile</td></tr>
<tr><td><code>interface Tunnel0</code></td><td>The tunnel (VTI). Traffic routed into it is encrypted</td></tr>
</table>`;

  /* ═══════════════════════ shared steps ═══════════════════════ */
  const UNDERLAY = {
    id: 'underlay', title: 'Connect R1 and R3 through R2', part: 'base', devices: ['r1', 'r3'],
    html: `
<p>Before any VPN, the two peers must reach each other over the WAN. R1 and R3 are not directly connected: each needs a static route through R2.</p>
${cfg('r1', ['configure terminal', 'ip route 10.0.23.0 255.255.255.0 10.0.12.2', 'end'])}
${cfg('r3', ['configure terminal', 'ip route 10.0.12.0 255.255.255.0 10.0.23.1', 'end'])}
${cfg('r1', ['ping 10.0.23.2'], 'test')}
${callout('tip', 'The first ping may show <code>.!!!!</code>: the first packet is lost while ARP resolves the next hop.')}
<div class="goal">Goal: <code>ping 10.0.23.2</code> from R1 succeeds.</div>`,
    run: [['r1', 'enable'], ...runOf('r1', ['configure terminal', 'ip route 10.0.23.0 255.255.255.0 10.0.12.2', 'end']),
      ['r3', 'enable'], ...runOf('r3', ['configure terminal', 'ip route 10.0.12.0 255.255.255.0 10.0.23.1', 'end']), ['r1', 'ping 10.0.23.2']],
    validate: ctx => ctx.lab.reach('r1', '10.0.23.2') && pingOk(ctx, 'r1', '10.0.23.2'),
    hints: [
      { when: (d, c) => d === 'r1' && /^ip route 10\.0\.23\.0 255\.255\.255\.0 10\.0\.23\.1/.test(c), text: 'From R1 the next hop is R2 on R1\'s own subnet: <code>10.0.12.2</code>.' },
      { when: (d, c, r, lab) => d === 'r1' && /^ping 10\.0\.23\.2/.test(c) && lab.dev('r1').routes.length && !lab.dev('r3').routes.length, text: 'R1 has its route, but R3 also needs a route back. Add it on <b>R3</b>.' },
    ],
  };
  const verifyStep = (id, title, { pqc }) => ({
    id, title, part: 'verify', devices: ['r1'],
    html: `
<p>A ping alone doesn't prove anything: R1 can already reach R3 in the clear. Collect three pieces of evidence:</p>
<h4>1 · The IKE SA is up${pqc ? ' with ML-KEM' : ''}</h4>
${cfg('r1', [pqc ? 'show crypto ikev2 sa detailed' : 'show crypto ikev2 sa'])}
${pqc ? out(['      Encr: AES-CBC, keysize: 256, PRF: SHA512, Hash: SHA512, DH Grp:20, Auth sign: PSK, Auth verify: PSK', '      PQC Key Exchange: ML-KEM-768', '      ...', '      Quantum-safe Encryption using PQC: ML-KEM-768']) : out(['      Encr: AES-CBC, keysize: 256, PRF: SHA512, Hash: SHA512, DH Grp:20, Auth sign: PSK, Auth verify: PSK'])}
<h4>2 · Traffic for the overlay goes into the tunnel</h4>
${cfg('r1', ['show ip route 192.168.100.2'])}
<h4>3 · The encryption counters go up</h4>
${cfg('r1', ['ping 192.168.100.2', 'show crypto ipsec sa | include pkts encaps'])}
<p><code>#pkts encaps</code> above zero proves the pings were encrypted.</p>
<div class="goal">Goal: ping 192.168.100.2, then <code>show crypto ipsec sa</code> shows encrypted packets${pqc ? ', on an SA that uses ML-KEM-768' : ''}.</div>`,
    run: runOf('r1', [pqc ? 'show crypto ikev2 sa detailed' : 'show crypto ikev2 sa', 'show ip route 192.168.100.2', 'ping 192.168.100.2', 'show crypto ipsec sa | include pkts encaps']),
    validate: ctx => encryptionProven(ctx, 'r1', '192.168.100.2', 'r3') && (!pqc || !!(sa13(ctx.lab) && sa13(ctx.lab).params.pqc)),
    hints: [{ when: (d, c, r, lab) => d === 'r1' && /^ping 192\.168\.100\.2/.test(c) && !lab.cmdLog.slice(-1)[0].meta.succ, text: 'The ping failed. Check <code>show crypto ikev2 sa</code>: without a READY SA the tunnel is down. Click the arc in the topology to see why.' }],
  });

  /* ═══════════════════════ Track 1 · Classic ═══════════════════════ */
  const CLASSIC = [
    {
      id: 'c-intro', title: 'Build a classic IKEv2 VPN', part: 'intro', devices: [],
      html: `
${EDU_NOTICE}
<p>In this short lab you build a <b>site-to-site IPsec VPN</b> between R1 and R3 with <b>IKEv2</b> and a tunnel interface. R2 is the WAN in the middle: it only forwards packets.</p>
<p>A Cisco IKEv2 VPN is made of seven blocks. You will configure them in this order:</p>
${BLOCKS}
<h4>The lab</h4>
${LAB_TABLE}
${HOW}`,
      run: [], validate: () => true, hints: [],
    },
    UNDERLAY,
    {
      id: 'c-r1', title: 'Configure the VPN on R1', part: 'base', devices: ['r1'],
      html: `
${cfg('r1', shown(R1_CLASSIC))}
<table class="t">
<tr><td><code>group 20</code></td><td>The Diffie-Hellman group (ECDH P-384). The encryption keys come from this exchange.</td></tr>
<tr><td><code>pre-shared-key</code></td><td>Only <b>authenticates</b> the peer. Both sides must use the same key.</td></tr>
<tr><td><code>esp-gcm 256</code></td><td>Encrypts the traffic inside the tunnel.</td></tr>
<tr><td><code>tunnel destination</code></td><td>R3's WAN address. R2 just forwards the encrypted packets.</td></tr>
</table>
${callout('warn', `<b>Lab-only key.</b> <code>${PSK}</code> is a teaching value. Real pre-shared keys must be long and random.`)}
<div class="goal">Goal: R1 has a complete VPN configuration towards 10.0.23.2.</div>`,
      run: runOf('r1', R1_CLASSIC),
      validate: ctx => chainTo(ctx.lab, 'r1', '10.0.23.2'),
      hints: [
        { when: (d, c) => d === 'r1' && /^tunnel destination 10\.0\.12\.2/.test(c), text: 'The tunnel ends on <b>R3</b> (10.0.23.2), not on R2.' },
        { when: (d, c, r, lab) => d === 'r1' && /^tunnel protection/.test(c) && !Object.keys(lab.dev('r1').crypto.ipsecProfiles).length, text: 'Create the <code>crypto ipsec profile</code> first.' },
      ],
    },
    {
      id: 'c-r3', title: 'Mirror it on R3', part: 'base', devices: ['r3'],
      html: `
<p>R3 is the mirror image: the peer is R1 (10.0.12.1) and the tunnel address is .2.</p>
${cfg('r3', shown(R3_CLASSIC))}
<p>When both sides match, IKEv2 negotiates on its own: watch for <code>%CRYPTO-5-IKEV2_SESSION_STATUS ... UP</code> and the arc on the topology.</p>
${callout('info', 'If the arc stays grey or red, click it: the handshake inspector tells you which setting doesn\'t match.')}
<div class="goal">Goal: an IKEv2 SA between R1 and R3.</div>`,
      run: runOf('r3', R3_CLASSIC),
      validate: ctx => !!sa13(ctx.lab),
      hints: [
        { when: (d, c) => d === 'r3' && /^address 10\.0\.23/.test(c), text: 'On R3 the peer is <b>R1</b>: <code>address 10.0.12.1</code>.' },
        { when: (d, c) => d === 'r3' && /^pre-shared-key /.test(c) && !c.includes(PSK), text: `The key must be identical on both peers: <code>${PSK}</code>.` },
      ],
    },
    verifyStep('c-verify', 'Prove the traffic is encrypted', { pqc: false }),
    {
      id: 'c-wrap', title: 'Done: a classic VPN', part: 'intro', devices: [],
      html: `
<p>You built a classic IKEv2 VPN and proved that traffic is encrypted.</p>
${callout('warn', '<b>This VPN is classical.</b> Its keys come from ECDH group 20, which a future quantum computer could break with Shor\'s algorithm. Traffic recorded today could be decrypted later ("harvest now, decrypt later").')}
<p><b>Next:</b> <a href="?track=migrate">From classic to PQC</a> shows the few lines that make this VPN quantum-safe, or <a href="?track=pqc">Build a PQC VPN</a> starts directly with ML-KEM.</p>
<p class="src">Reference: ${link(IKEV2_URL, 'Configuring IKEv2 (IOS XE)')} · ${link('https://www.rfc-editor.org/rfc/rfc7296', 'RFC 7296')}</p>`,
      run: [], validate: () => true, hints: [],
    },
  ];

  /* ═══════════════════════ Track 2 · PQC ═══════════════════════ */
  const PQC = [
    {
      id: 'p-intro', title: 'Build a post-quantum VPN', part: 'intro', devices: [],
      html: `
${EDU_NOTICE}
<p>In this short lab you build a <b>quantum-safe IKEv2 VPN</b> between R1 and R3 using <b>ML-KEM-768</b> (FIPS 203), supported natively on IOS XE 26.1 and later.</p>
<p>A post-quantum VPN is a normal IKEv2 VPN plus three lines:</p>
<table class="t">
<tr><th>Line</th><th>Why</th></tr>
<tr><td><code>pqc mlkem768</code> (in the proposal)</td><td>Adds an ML-KEM key exchange <b>on top of</b> classical DH (a <i>hybrid</i>, RFC 9370). Both must be broken to recover the keys.</td></tr>
<tr><td><code>crypto ikev2 fragmentation mtu 1400</code></td><td>ML-KEM keys are large (1,184 bytes). IKEv2 fragmentation (RFC 7383) avoids IP fragmentation.</td></tr>
<tr><td><code>set pfs</code> (in the IPsec profile)</td><td>Every rekey of the data SA also runs DH + ML-KEM, so rekeys stay quantum-safe.</td></tr>
</table>
<h4>The lab</h4>
${LAB_TABLE}
${HOW}`,
      run: [], validate: () => true, hints: [],
    },
    UNDERLAY,
    {
      id: 'p-r1', title: 'Configure the PQC VPN on R1', part: 'pqc', devices: ['r1'],
      html: `
${cfg('r1', shown(R1_PQC))}
<table class="t">
<tr><td><code>pqc mlkem768</code></td><td>ML-KEM-768 is <b>required</b>: a peer without it is rejected. Add <code>optional</code> (<code>pqc mlkem768 optional</code>) only when some peers can't do ML-KEM yet.</td></tr>
<tr><td><code>group 20</code></td><td>Still needed: the classical half of the hybrid exchange.</td></tr>
<tr><td><code>fragmentation mtu 1400</code></td><td>Recommended on both peers by the ${link(GUIDE_URL, 'IOS XE PQC guide')}.</td></tr>
<tr><td><code>set pfs</code></td><td>Without a group: inherits DH group 20 <i>and</i> ML-KEM from the IKE SA.</td></tr>
</table>
${callout('warn', `<b>Lab-only key.</b> <code>${PSK}</code> is a teaching value. Real pre-shared keys must be long and random.`)}
<div class="goal">Goal: R1 has a complete VPN configuration towards 10.0.23.2, with ML-KEM in its proposal.</div>`,
      run: runOf('r1', R1_PQC),
      validate: ctx => chainTo(ctx.lab, 'r1', '10.0.23.2') && proposalsOf(ctx.lab, 'r1').some(p => p.pqc),
      hints: [{ when: (d, c) => d === 'r1' && /^pqc mlkem768 required/.test(c), text: 'There is no <code>required</code> keyword: <code>pqc mlkem768</code> on its own is already mandatory.' }],
    },
    {
      id: 'p-r3', title: 'Mirror it on R3', part: 'pqc', devices: ['r3'],
      html: `
<p>Same configuration on R3, with R1 as the peer:</p>
${cfg('r3', shown(R3_PQC))}
<p>Watch the arc: it turns purple when the SA is up with ML-KEM. The first pings may time out (<code>..!!!</code>) while the larger handshake completes.</p>
<div class="goal">Goal: the R1–R3 SA is up with ML-KEM-768.</div>`,
      run: runOf('r3', R3_PQC),
      validate: ctx => !!(sa13(ctx.lab) && sa13(ctx.lab).params.pqc === 'mlkem768'),
      hints: [
        { when: (d, c) => d === 'r3' && /^address 10\.0\.23/.test(c), text: 'On R3 the peer is <b>R1</b>: <code>address 10.0.12.1</code>.' },
        { when: (d, c, r, lab) => d === 'r3' && /^end$/.test(c) && !proposalsOf(lab, 'r3').some(p => p.pqc) && proposalsOf(lab, 'r1').some(p => p.pqc && p.pqc.mode === 'required'), text: 'R1 requires ML-KEM. Without <code>pqc mlkem768</code> on R3 the negotiation fails with NO_PROPOSAL_CHOSEN.' },
      ],
    },
    verifyStep('p-verify', 'Prove it is quantum-safe and encrypted', { pqc: true }),
    {
      id: 'p-rekey', title: 'Check a quantum-safe rekey', part: 'pqc', devices: ['r1'],
      html: `
<p>The data SA is rekeyed regularly. Force a rekey and check that <code>set pfs</code> ran a fresh DH + ML-KEM exchange. The IKE SA stays up:</p>
${cfg('r1', ['clear crypto sa', 'ping 192.168.100.2', 'show crypto ipsec sa detail | include PFS'])}
${out(['     PFS (Y/N): Y, DH group: group20, PQC Key Exchange: ML-KEM-768'])}
${callout('info', '<code>set pfs</code> must be configured on <b>both</b> peers. If it is missing on one side, the first tunnel works but the rekey fails with NO_PROPOSAL_CHOSEN.')}
<div class="goal">Goal: the IPsec SA shows <code>PFS (Y/N): Y</code> with ML-KEM-768.</div>`,
      run: runOf('r1', ['clear crypto sa', 'ping 192.168.100.2', 'show crypto ipsec sa detail | include PFS']),
      validate: ctx => { const sa = sa13(ctx.lab); return !!(sa && !sa.child.down && sa.child.pfs && sa.child.pfs.pqc); },
      hints: [],
    },
    {
      id: 'p-wrap', title: 'Done: a post-quantum VPN', part: 'intro', devices: [],
      html: `
<p>Your VPN's key exchange is now hybrid: ECDH group 20 <b>and</b> ML-KEM-768, for the IKE SA and for every rekey.</p>
<table class="t">
<tr><th>Evidence</th><th>Command</th></tr>
<tr><td><code>PQC Key Exchange: ML-KEM-768</code></td><td><code>show crypto ikev2 sa detailed</code></td></tr>
<tr><td><code>Capabilities:FUQ</code> (Q = quantum-safe)</td><td><code>show crypto session detail</code></td></tr>
<tr><td><code>PFS … PQC Key Exchange: ML-KEM-768</code></td><td><code>show crypto ipsec sa detail</code></td></tr>
</table>
${callout('warn', '<b>Still to do: authentication.</b> The peers still authenticate with a pre-shared key. Quantum-safe certificates (ML-DSA) are the next step.')}
<p><b>Next:</b> <a href="?track=migrate">From classic to PQC</a> shows how to upgrade an existing VPN without an outage.</p>
<p class="src">Reference: ${link(GUIDE_URL, 'Cisco IOS XE — Post-Quantum Cryptography for IKEv2')} · ${link(BLOG_URL, 'IPsec Series Part 9 (Cisco Blogs)')}</p>`,
      run: [], validate: () => true, hints: [],
    },
  ];

  /* ═══════════════════════ Track 3 · Classic → PQC ═══════════════════════ */
  const addPqc = (mode) => ['configure terminal', 'crypto ikev2 proposal CLASSIC-PROPOSAL', `pqc mlkem768${mode === 'optional' ? ' optional' : ''}`, 'end'];
  const MIGRATE = [
    {
      id: 'm-intro', title: 'From classic to post-quantum', part: 'intro', devices: [],
      html: `
${EDU_NOTICE}
<p>Most networks already have classic VPNs. In this lab you first build one, then make it <b>quantum-safe</b> step by step, without ever losing the tunnel for longer than a renegotiation.</p>
<table class="t">
<tr><th>Step</th><th>Change</th><th>Why</th></tr>
<tr><td>1</td><td><code>crypto ikev2 fragmentation mtu 1400</code></td><td>Prepare for large ML-KEM messages</td></tr>
<tr><td>2</td><td><code>pqc mlkem768 optional</code> on R1</td><td>Offer ML-KEM, still accept classic peers</td></tr>
<tr><td>3</td><td><code>pqc mlkem768 optional</code> on R3</td><td>Both sides offer it: the tunnel becomes hybrid</td></tr>
<tr><td>4</td><td><code>set pfs</code></td><td>Rekeys also use ML-KEM</td></tr>
<tr><td>5</td><td><code>pqc mlkem768</code> (no <code>optional</code>)</td><td>Refuse classic-only peers</td></tr>
</table>
<h4>The lab</h4>
${LAB_TABLE}
${HOW}`,
      run: [], validate: () => true, hints: [],
    },
    UNDERLAY,
    {
      id: 'm-classic', title: 'Start from a classic VPN', part: 'base', devices: ['r1', 'r3'],
      html: `
<p>Build the classic VPN on both routers. It's the same configuration as the Classic tutorial:</p>
${cfg('r1', shown(R1_CLASSIC))}
${cfg('r3', shown(R3_CLASSIC), 'mirror: peer R1 (10.0.12.1), tunnel .2')}
<p>Then look at the SA:</p>
${cfg('r1', ['show crypto ikev2 sa'])}
${out(['      Encr: AES-CBC, keysize: 256, PRF: SHA512, Hash: SHA512, DH Grp:20, Auth sign: PSK, Auth verify: PSK'])}
${callout('warn', '<b>The starting point is classical:</b> only ECDH group 20 protects the key exchange. That\'s what we\'re going to fix.')}
<div class="goal">Goal: a classic IKEv2 SA between R1 and R3, checked with <code>show crypto ikev2 sa</code>.</div>`,
      run: [...runOf('r1', R1_CLASSIC), ...runOf('r3', R3_CLASSIC), ['r1', 'ping 192.168.100.2'], ['r1', 'show crypto ikev2 sa']],
      validate: ctx => !!sa13(ctx.lab) && ran(ctx, 'r1', /^show crypto ikev2 sa/),
      hints: [{ when: (d, c) => d === 'r3' && /^address 10\.0\.23/.test(c), text: 'On R3 the peer is <b>R1</b>: <code>address 10.0.12.1</code>.' }],
    },
    {
      id: 'm-frag', title: 'Step 1 · Enable IKEv2 fragmentation', part: 'pqc', devices: ['r1', 'r3'],
      html: `
<p>An ML-KEM-768 public key is 1,184 bytes, and the handshake messages get bigger than a typical path MTU. Enable IKEv2 fragmentation (RFC 7383) on <b>both</b> peers first. It changes nothing for the running tunnel:</p>
${cfg('r1', ['crypto ikev2 fragmentation mtu 1400'])}
${cfg('r3', ['crypto ikev2 fragmentation mtu 1400'])}
<div class="goal">Goal: fragmentation enabled on R1 and R3.</div>`,
      run: [...runOf('r1', ['configure terminal', 'crypto ikev2 fragmentation mtu 1400', 'end']), ...runOf('r3', ['configure terminal', 'crypto ikev2 fragmentation mtu 1400', 'end'])],
      validate: ctx => ['r1', 'r3'].every(k => !!ctx.lab.dev(k).crypto.fragMtu),
      hints: [],
    },
    {
      id: 'm-r1', title: 'Step 2 · Offer ML-KEM on R1 (optional)', part: 'pqc', devices: ['r1'],
      html: `
<p>Add ML-KEM to R1's existing proposal, as <b>optional</b>:</p>
${cfg('r1', ['crypto ikev2 proposal CLASSIC-PROPOSAL', ' pqc mlkem768 optional'])}
<p>Then renegotiate and look at the SA:</p>
${cfg('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show crypto ikev2 sa detailed | include PQC|DH Grp'])}
<p>The tunnel comes back <b>still classical</b>. R1 offers ML-KEM, R3 doesn't yet, and <code>optional</code> lets them fall back to plain DH. That's how you upgrade one site at a time without an outage.</p>
<div class="goal">Goal: R1 offers ML-KEM as optional, and the tunnel is still up.</div>`,
      run: [...runOf('r1', [...addPqc('optional'), 'clear crypto ikev2 sa', 'ping 192.168.100.2', 'show crypto ikev2 sa detailed | include PQC|DH Grp'])],
      validate: ctx => proposalsOf(ctx.lab, 'r1').some(p => p.pqc && p.pqc.mode === 'optional') && !!sa13(ctx.lab),
      hints: [{ when: (d, c) => d === 'r1' && /^pqc mlkem768$/.test(c), text: 'Without <code>optional</code>, R1 would <b>require</b> ML-KEM and reject R3, which doesn\'t support it yet. Use <code>pqc mlkem768 optional</code> during the migration.' }],
    },
    {
      id: 'm-r3', title: 'Step 3 · Offer ML-KEM on R3', part: 'pqc', devices: ['r3', 'r1'],
      html: `
<p>Now upgrade the other side the same way:</p>
${cfg('r3', ['crypto ikev2 proposal CLASSIC-PROPOSAL', ' pqc mlkem768 optional'])}
${cfg('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show crypto ikev2 sa detailed'])}
<p>Both peers offer ML-KEM, so it is used. Look for <code>PQC Key Exchange: ML-KEM-768</code> and <code>Quantum-safe Encryption using PQC</code>. The arc turns purple.</p>
${callout('info', 'An SA never changes by itself: it keeps the algorithms it was negotiated with. That\'s why each step clears the SA (or you could shut and re-enable the tunnel interface).')}
<div class="goal">Goal: the R1–R3 SA uses ML-KEM-768.</div>`,
      run: [...runOf('r3', addPqc('optional')), ...runOf('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show crypto ikev2 sa detailed'])],
      validate: ctx => !!(sa13(ctx.lab) && sa13(ctx.lab).params.pqc),
      hints: [{ when: (d, c, r, lab) => /^show crypto ikev2 sa/.test(c) && ['r1', 'r3'].every(k => proposalsOf(lab, k).some(p => p.pqc)) && sa13(lab) && !sa13(lab).params.pqc, text: 'Both sides offer ML-KEM, but this SA was negotiated before. Run <code>clear crypto ikev2 sa</code>.' }],
    },
    {
      id: 'm-pfs', title: 'Step 4 · Quantum-safe rekeys with set pfs', part: 'pqc', devices: ['r1', 'r3'],
      html: `
<p>ML-KEM now protects the IKE SA. Rekeys of the data SA only get a fresh exchange with <b>Perfect Forward Secrecy</b>. Add it on <b>both</b> peers, then force a rekey:</p>
${cfg('r1', ['crypto ipsec profile CLASSIC-IPSEC', ' set pfs'])}
${cfg('r3', ['crypto ipsec profile CLASSIC-IPSEC', ' set pfs'])}
${cfg('r1', ['clear crypto sa', 'ping 192.168.100.2', 'show crypto ipsec sa detail | include PFS'])}
${out(['     PFS (Y/N): Y, DH group: group20, PQC Key Exchange: ML-KEM-768'])}
<div class="goal">Goal: the IPsec SA shows <code>PFS (Y/N): Y</code> with ML-KEM-768.</div>`,
      run: [...runOf('r1', ['configure terminal', 'crypto ipsec profile CLASSIC-IPSEC', 'set pfs', 'end']), ...runOf('r3', ['configure terminal', 'crypto ipsec profile CLASSIC-IPSEC', 'set pfs', 'end']),
        ...runOf('r1', ['clear crypto sa', 'ping 192.168.100.2', 'show crypto ipsec sa detail | include PFS'])],
      validate: ctx => { const sa = sa13(ctx.lab); return !!(sa && !sa.child.down && sa.child.pfs && sa.child.pfs.pqc); },
      hints: [{ when: (d, c, r, lab) => /^(ping|show crypto ipsec)/.test(c) && sa13(lab) && sa13(lab).child.down, text: 'The rekey failed: <code>set pfs</code> is on one side only. Add it on <b>both</b> IPsec profiles, then <code>clear crypto sa</code> again.' }],
    },
    {
      id: 'm-enforce', title: 'Step 5 · Enforce ML-KEM', part: 'pqc', devices: ['r1', 'r3'],
      html: `
<p>Every peer is upgraded, so classical fallback is no longer needed. Re-enter the line <b>without</b> <code>optional</code> on both routers. There is no <code>required</code> keyword: leaving out <code>optional</code> is what enforces ML-KEM.</p>
${cfg('r1', ['crypto ikev2 proposal CLASSIC-PROPOSAL', ' pqc mlkem768'])}
${cfg('r3', ['crypto ikev2 proposal CLASSIC-PROPOSAL', ' pqc mlkem768'])}
${cfg('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show running-config | section CLASSIC-PROPOSAL'])}
${callout('tip', 'With both sides enforcing ML-KEM, a classic-only peer is now <b>rejected</b> (NO_PROPOSAL_CHOSEN) instead of silently downgrading.')}
<div class="goal">Goal: both proposals require ML-KEM and the tunnel is up with ML-KEM-768.</div>`,
      run: [...runOf('r1', addPqc('required')), ...runOf('r3', addPqc('required')), ...runOf('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show running-config | section CLASSIC-PROPOSAL'])],
      validate: ctx => ['r1', 'r3'].every(k => proposalsOf(ctx.lab, k).some(p => p.pqc && p.pqc.mode === 'required')) && !!(sa13(ctx.lab) && sa13(ctx.lab).params.pqc),
      hints: [{ when: (d, c) => /^pqc mlkem768 required/.test(c), text: 'There is no <code>required</code> keyword. Type <code>pqc mlkem768</code> on its own.' }],
    },
    {
      id: 'm-wrap', title: 'Done: classic → post-quantum', part: 'intro', devices: [],
      html: `
<p>Your classic VPN is now quantum-safe. The whole migration came down to <b>three lines per router</b>:</p>
${cfg('r1', ['crypto ikev2 fragmentation mtu 1400', '!', 'crypto ikev2 proposal CLASSIC-PROPOSAL', ' pqc mlkem768', '!', 'crypto ipsec profile CLASSIC-IPSEC', ' set pfs'], 'added to the classic configuration')}
<table class="t">
<tr><th>Lesson</th><th></th></tr>
<tr><td>Hybrid</td><td>ML-KEM is added <i>on top of</i> DH group 20, not instead of it</td></tr>
<tr><td><code>optional</code></td><td>Lets upgraded and legacy peers coexist during the rollout</td></tr>
<tr><td>Renegotiate</td><td>New settings apply only to new SAs: clear the SA or bounce the tunnel</td></tr>
<tr><td>Enforce</td><td>Drop <code>optional</code> once every peer supports ML-KEM</td></tr>
</table>
${callout('info', 'With many sites, upgrade the <b>hub</b> first with <code>optional</code>, then the spokes, then enforce at the hub. The full <a href="../v3-three-router/">Part 9 lab</a> walks through that hub-and-spoke rollout.')}
<p class="src">Reference: ${link(GUIDE_URL, 'Cisco IOS XE — Post-Quantum Cryptography for IKEv2')} · ${link(BLOG_URL, 'IPsec Series Part 9 (Cisco Blogs)')}</p>`,
      run: [], validate: () => true, hints: [],
    },
  ];

  /* ═══════════════════════ Track 4 · Negotiation lab ═══════════════════════
     Scenarios and expected behaviour: vpn-negotiation-mismatch-teaching dataset (CML IOS XE 26.02).
     C0–C8 were captured on CML; M2 is backed by real C8235-G2 output; M1/M4 are inferred.        */
  const NAMES = { prop: 'VPN-PROP', pol: 'VPN-POL', keys: 'VPN-KEYS', prof: 'VPN-PROF', ts: 'VPN-TS', ipsec: 'VPN-IPSEC' };
  const NEG_BASE = { enc: ['aes-cbc-256'], integ: ['sha512'], group: [20], pqc: 'none', optional: false, ts: 'esp-gcm 256', psk: PSK };
  const BASE = { r1: { ...NEG_BASE, peerId: '10.0.23.2' }, r3: { ...NEG_BASE, peerId: '10.0.12.1' } };
  const SCENARIOS = [
    { id: 'C0', title: 'Baseline: both ends identical', label: 'observed', initiator: 'r1', r1: {}, r3: {} },
    { id: 'C1', title: 'Encryption differs (R3 aes-cbc-128)', label: 'observed', initiator: 'r3', r1: {}, r3: { enc: ['aes-cbc-128'] } },
    { id: 'C2', title: 'Integrity differs (R3 sha256)', label: 'observed', initiator: 'r3', r1: {}, r3: { integ: ['sha256'] } },
    { id: 'C3', title: 'DH group differs (R3 group 21)', label: 'observed', initiator: 'r3', r1: {}, r3: { group: [21] } },
    { id: 'C4', title: 'R3 offers lists, group 21 first: INVALID_KE_PAYLOAD retry', label: 'observed', initiator: 'r3', r1: {}, r3: { enc: ['aes-cbc-128', 'aes-cbc-256'], integ: ['sha256', 'sha512'], group: [21, 20] } },
    { id: 'C5', title: 'Responder lists group 21 20, initiator only 20: no retry', label: 'observed', initiator: 'r3', r1: { group: [21, 20] }, r3: {} },
    { id: 'C6', title: 'ESP transform set differs', label: 'observed', initiator: 'r1', r1: {}, r3: { ts: 'esp-aes 256 esp-sha256-hmac' } },
    { id: 'C7', title: 'Pre-shared key differs', label: 'observed', initiator: 'r3', r1: {}, r3: { psk: 'Wr0ngKey-lab' } },
    { id: 'C8', title: 'R3 expects another peer identity (10.0.12.99): half-open', label: 'observed', initiator: 'r3', r1: {}, r3: { peerId: '10.0.12.99' } },
    { id: 'M1', title: 'ML-KEM required on R1, none on R3', label: 'inferred', initiator: 'r3', r1: { pqc: 'mlkem768' }, r3: {} },
    { id: 'M2', title: 'ML-KEM optional on R1, none on R3: silent fallback', label: 'derived', initiator: 'r3', r1: { pqc: 'mlkem768', optional: true }, r3: {} },
    { id: 'M4', title: 'ML-KEM 768 on R1, 1024 on R3, both required', label: 'inferred', initiator: 'r3', r1: { pqc: 'mlkem768' }, r3: { pqc: 'mlkem1024' } },
  ];
  // IOS commands that turn configuration `from` into `to` (one router); used by the panel and by the tests
  function negCommands(dev, from, to) {
    const L = [], prop = [], peer = dev === 'r1' ? 'R3' : 'R1';
    if (to.enc.join() !== from.enc.join()) prop.push(` encryption ${to.enc.join(' ')}`);
    if (to.integ.join() !== from.integ.join()) prop.push(` integrity ${to.integ.join(' ')}`);
    if (to.group.join() !== from.group.join()) prop.push(` group ${to.group.join(' ')}`);
    if (to.pqc !== from.pqc || to.optional !== from.optional) prop.push(to.pqc === 'none' ? ' no pqc' : ` pqc ${to.pqc}${to.optional ? ' optional' : ''}`);
    if (prop.length) L.push(`crypto ikev2 proposal ${NAMES.prop}`, ...prop);
    if (to.ts !== from.ts) L.push(`crypto ipsec transform-set ${NAMES.ts} ${to.ts}`);
    if (to.psk !== from.psk) L.push(`crypto ikev2 keyring ${NAMES.keys}`, ` peer ${peer}`, `  pre-shared-key ${to.psk}`);
    if (to.peerId !== from.peerId) L.push(`crypto ikev2 profile ${NAMES.prof}`, ` no match identity remote address ${from.peerId} 255.255.255.255`, ` match identity remote address ${to.peerId} 255.255.255.255`);
    return L;
  }
  const NEG = { NAMES, BASE, SCENARIOS, TUN: { r1: '192.168.100.1', r3: '192.168.100.2' }, commands: negCommands,
    apply: (sc, dev) => JSON.parse(JSON.stringify({ ...BASE[dev], ...sc[dev] })) };
  const R1_NEG = [...vpnConfig({ name: 'VPN', peerName: 'R3', peer: '10.0.23.2', tunIp: '192.168.100.1', pfs: true, frag: true }).slice(0, -1), 'end']
    .map(l => l.replace('VPN-POLICY', NAMES.pol).replace('VPN-PROPOSAL', NAMES.prop).replace('VPN-KEYRING', NAMES.keys).replace('VPN-PROFILE', NAMES.prof));
  const R3_NEG = [...vpnConfig({ name: 'VPN', peerName: 'R1', peer: '10.0.12.1', tunIp: '192.168.100.2', pfs: true, frag: true }).slice(0, -1), 'end']
    .map(l => l.replace('VPN-POLICY', NAMES.pol).replace('VPN-PROPOSAL', NAMES.prop).replace('VPN-KEYRING', NAMES.keys).replace('VPN-PROFILE', NAMES.prof));
  // negotiation attempts since the step started
  const negSince = (ctx, test) => ctx.lab.negLog.filter(e => e.seq > ctx.since).some(test);
  const upNow = lab => { const sa = sa13(lab); return !!sa; };
  const PANEL_TIP = callout('info', 'Use the <b>Negotiation parameters</b> panel below: pick a scenario (or change settings yourself), <b>predict</b> the outcome, then <b>Apply & renegotiate</b>. The panel types the IOS commands into the consoles, clears the SA from the router you chose as initiator and pings through the tunnel. You can also type the commands yourself.') + '<div class="neg-slot"></div>';

  const NEGOTIATE = [
    {
      id: 'n-intro', title: 'When the two ends choose differently', part: 'intro', devices: [],
      html: `
${EDU_NOTICE}
<p>Each end of an IKEv2 VPN has its own configuration. In this lab you change <b>one setting at a time</b> on R1 or R3 and watch what the routers do: does the tunnel come up, fail, retry, or end up half-open?</p>
<p>Every experiment reproduces a scenario that was <b>captured on real IOS XE 26.02 routers</b> (Cisco Modeling Labs). The simulator's outcome, error lines and show output were checked against those captures.</p>
<table class="t">
<tr><th>Exchange</th><th>What is agreed</th><th>If it fails</th></tr>
<tr><td>IKE_SA_INIT</td><td>Encryption, integrity/PRF, DH group, ML-KEM</td><td>NO_PROPOSAL_CHOSEN — no SA at all</td></tr>
<tr><td>IKE_AUTH</td><td>Identity, pre-shared key, and the first Child SA (transform set)</td><td>Authentication or Child SA failure</td></tr>
</table>
<p>For each experiment: <b>predict → apply → observe → explain</b>. Predicting first makes the result stick.</p>
<h4>The lab</h4>
${LAB_TABLE}`,
      run: [], validate: () => true, hints: [],
    },
    {
      id: 'n-build', title: 'Build the baseline on both routers', part: 'base', devices: ['r1', 'r3'],
      html: `
<p>Both ends start identical: <code>aes-cbc-256 / sha512 / group 20</code>, the same pre-shared key and the transform set <code>esp-gcm 256</code>. Turn on <code>debug crypto ikev2 error</code> on both routers so the negotiation errors appear in the consoles.</p>
${cfg('r1', ['configure terminal', 'ip route 10.0.23.0 255.255.255.0 10.0.12.2', 'end'])}
${cfg('r3', ['configure terminal', 'ip route 10.0.12.0 255.255.255.0 10.0.23.1', 'end'])}
${cfg('r1', shown(R1_NEG))}
${cfg('r3', shown(R3_NEG))}
${cfg('r1', ['debug crypto ikev2 error', 'ping 192.168.100.2'])}
${cfg('r3', ['debug crypto ikev2 error'])}
${callout('tip', 'The baseline also logs <code>% IKEv2 profile not found</code> and <code>Error constructing config reply</code> on one router. That is harmless config-exchange noise, seen on real routers too: the tunnel is fine. Don\'t chase it.')}
<div class="goal">Goal: the R1–R3 tunnel is up and <code>debug crypto ikev2 error</code> is on, on both routers.</div>`,
      run: [['r1', 'enable'], ...runOf('r1', ['configure terminal', 'ip route 10.0.23.0 255.255.255.0 10.0.12.2', 'end']), ['r3', 'enable'], ...runOf('r3', ['configure terminal', 'ip route 10.0.12.0 255.255.255.0 10.0.23.1', 'end']),
        ...runOf('r1', R1_NEG), ...runOf('r3', R3_NEG), ['r1', 'debug crypto ikev2 error'], ['r3', 'debug crypto ikev2 error'], ['r1', 'ping 192.168.100.2']],
      validate: ctx => upNow(ctx.lab) && ['r1', 'r3'].every(k => ctx.lab.dev(k).debug.err || ctx.lab.dev(k).debug.ikev2),
      hints: [{ when: (d, c) => /^debug crypto ikev2$/.test(c), text: 'Full debugging works too, but it is verbose. <code>debug crypto ikev2 error</code> shows only the lines that matter here.' }],
    },
    {
      id: 'n-one', title: 'One setting differs (C1–C3)', part: 'verify', devices: ['r1', 'r3'], panel: true,
      html: `
<p>Change <b>one</b> IKE algorithm on R3 only: try <b>C1</b> (encryption), <b>C2</b> (integrity) or <b>C3</b> (DH group).</p>
${PANEL_TIP}
<p>Then read the consoles. The <b>responder</b> prints what it received and what it expected:</p>
${out(["IKEv2-ERROR:(SESSION ID = 89,SA ID = 1):Received Policies: : Failed to find a matching policyProposal 1:  ENCRYPTION: AES-CBC-128 PRF: SHA512 INTEGRITY: SHA512 DH GROUP: DH_GROUP_384_ECP/Group 20", "IKEv2-ERROR:(SESSION ID = 89,SA ID = 1):Expected Policies: : Failed to find a matching policyProposal 1:  ENCRYPTION: AES-CBC-256 PRF: SHA512 INTEGRITY: SHA512 DH GROUP: DH_GROUP_384_ECP/Group 20"])}
<p>The initiator only gets <code>: Received no proposal chosen notify</code>. Compare the two policy lines to see <i>which</i> algorithm differs.</p>
<p><b>Question:</b> on which router do you find the useful line, and why there?</p>
<div class="goal">Goal: cause a NO_PROPOSAL_CHOSEN, then go back to the <b>↺ baseline</b> so the tunnel is up again.</div>`,
      run: [], validate: ctx => negSince(ctx, e => e.code === 'NO_PROPOSAL_CHOSEN' && e.stage === 'init' && !e.mlkem) && upNow(ctx.lab), hints: [],
    },
    {
      id: 'n-lists', title: 'Lists, and the DH retry (C4, C5)', part: 'verify', devices: ['r1', 'r3'], panel: true,
      html: `
<p>A proposal can list several values. The responder picks from the <b>overlap</b>, so lists make a proposal tolerant.</p>
<p>There is a catch for DH: the initiator must already send its key share (KE payload) in IKE_SA_INIT, so it <i>guesses</i> — it uses the <b>first</b> group in its list. If the responder picks another group, it answers <code>INVALID_KE_PAYLOAD</code> and the initiator retries. One extra round trip, no failure.</p>
<ul><li><b>C4</b>: R3 initiates with <code>group 21 20</code>; R1 only has 20 → retry.</li>
<li><b>C5</b>: R1 (the responder) lists <code>21 20</code>, R3 only 20 → <b>no</b> retry. Only the initiator's first group matters.</li></ul>
${PANEL_TIP}
<p>Check <code>show crypto ikev2 stats exchange</code> before and after: the retry costs one extra IKE_SA_INIT.</p>
<div class="goal">Goal: bring the tunnel up after an INVALID_KE_PAYLOAD retry.</div>`,
      run: [], validate: ctx => negSince(ctx, e => e.ok && e.keRetry), hints: [],
    },
    {
      id: 'n-child', title: 'Two SAs: the transform set (C6)', part: 'verify', devices: ['r1', 'r3'], panel: true,
      html: `
<p>The IKE SA and the IPsec (Child) SA are negotiated separately. The first Child SA is negotiated <b>inside IKE_AUTH</b>, with the transform set.</p>
<p>Try <b>C6</b>: R3 uses <code>esp-aes 256 esp-sha256-hmac</code> instead of <code>esp-gcm 256</code>. The IKE proposal still matches…</p>
${PANEL_TIP}
${callout('info', 'On IOS XE, when that first Child SA fails, the router deletes the IKE SA too: <code>show crypto ikev2 sa</code> is empty and <code>show crypto session</code> is DOWN on both ends. Look for <code>Received Policies: … ESP: Proposal 1:</code> on the responder.')}
<div class="goal">Goal: cause the transform-set failure, then restore the baseline.</div>`,
      run: [], validate: ctx => negSince(ctx, e => e.stage === 'child') && upNow(ctx.lab), hints: [],
    },
    {
      id: 'n-auth', title: 'Authentication and identity (C7, C8)', part: 'verify', devices: ['r1', 'r3'], panel: true,
      html: `
<p>Authentication comes <b>after</b> the algorithms are agreed, in IKE_AUTH.</p>
<ul><li><b>C7</b>: different pre-shared keys → <code>Failed to authenticate the IKE SA</code> on both routers.</li>
<li><b>C8</b>: R3's profile expects R1 at <code>10.0.12.99</code>. With R3 initiating, R1 accepts R3 and installs its SAs; R3 only then rejects R1's identity. Result: a <b>half-open</b> tunnel. R1 shows READY and keeps encrypting; R3 has no SA and drops the packets with <code>%CRYPTO-4-RECVD_PKT_INV_SPI</code>.</li></ul>
${PANEL_TIP}
${callout('tip', 'Run C8 a second time with <b>R1</b> initiating. What changes, and why? (Hint: the responder checks the identity <i>before</i> it answers.) Always check <b>both</b> peers.')}
<div class="goal">Goal: see an authentication failure and a half-open tunnel.</div>`,
      run: [], validate: ctx => negSince(ctx, e => e.code === 'AUTHENTICATION_FAILED') && negSince(ctx, e => e.ok && e.half), hints: [],
    },
    {
      id: 'n-pqc', title: 'ML-KEM is one more transform (M2, M1, M4)', part: 'pqc', devices: ['r1', 'r3'], panel: true,
      html: `
<p>ML-KEM sits in the IKE proposal like the other algorithms:</p>
<ul><li><b>M2</b>: <code>pqc mlkem768 optional</code> on R1, nothing on R3 → the tunnel comes up <b>classical, silently</b>. No error; the only evidence is a missing <code>PQC Key Exchange:</code> line.</li>
<li><b>M1</b>: <code>pqc mlkem768</code> (required) on R1, nothing on R3 → fails like any proposal mismatch.</li>
<li><b>M4</b>: R1 <code>mlkem768</code>, R3 <code>mlkem1024</code>, both required → no common parameter set, fails.</li></ul>
${PANEL_TIP}
${callout('info', 'M2 matches real C8235-G2 output (Gomez, Exercise 4). M1 and M4 are the <i>expected</i> behaviour of an ML-KEM-capable router; the CML virtual routers used for the other captures ignore <code>pqc</code>.')}
<div class="goal">Goal: see the silent classical fallback (M2) and a required-ML-KEM failure (M1 or M4).</div>`,
      run: [], validate: ctx => negSince(ctx, e => e.ok && !e.pqc && e.pqcModes.includes('optional')) && negSince(ctx, e => e.code === 'NO_PROPOSAL_CHOSEN' && e.mlkem), hints: [],
    },
    {
      id: 'n-wrap', title: 'The rules you found', part: 'intro', devices: [], panel: true,
      html: `
<table class="t">
<tr><th>#</th><th>Rule</th><th>Seen in</th></tr>
<tr><td>1</td><td>IKE_SA_INIT negotiates the algorithms. Encryption, integrity/PRF and DH group each need a common value, or NO_PROPOSAL_CHOSEN.</td><td>C1–C3</td></tr>
<tr><td>2</td><td>The responder picks from the overlap: lists make a proposal tolerant.</td><td>C4</td></tr>
<tr><td>3</td><td>A wrong DH guess costs one INVALID_KE_PAYLOAD retry, not a failure. Only the initiator's first group matters.</td><td>C4, C5</td></tr>
<tr><td>4</td><td>The IKE SA and the IPsec SA are negotiated separately; a Child SA failure in IKE_AUTH deletes the IKE SA too.</td><td>C6</td></tr>
<tr><td>5</td><td>Authentication and identity are checked after algorithm agreement, in IKE_AUTH.</td><td>C7, C8</td></tr>
<tr><td>6</td><td>One end can believe the tunnel is up. Always check both peers.</td><td>C8</td></tr>
<tr><td>7</td><td>ML-KEM is one more transform. Required behaves like any mismatch; optional falls back silently.</td><td>M1, M2, M4</td></tr>
<tr><td>8</td><td>Not every error matters: config-exchange noise appears on a healthy tunnel.</td><td>C0</td></tr>
</table>
<p>Keep experimenting with the panel: combine changes, swap the initiator, and predict before you apply.</p>
<div class="neg-slot"></div>
<p class="src">Diagnostic toolbox: <code>show crypto ikev2 proposal</code>, <code>show crypto ikev2 sa [detailed]</code>, <code>show crypto session</code>, <code>show crypto ipsec sa</code>, <code>show crypto ikev2 stats exchange</code>, <code>debug crypto ikev2 error</code>, <code>clear crypto ikev2 sa</code>.</p>`,
      run: [], validate: () => true, hints: [],
    },
  ];

  const ALL = [...CLASSIC, ...PQC, ...MIGRATE, ...NEGOTIATE];
  const BY_ID = Object.fromEntries(ALL.map(x => [x.id, x]));
  const TRACKS = {
    classic: { title: 'Quick lab · Classic IKEv2 VPN', badge: 'Classic', kicker: 'Short lab — classic site-to-site VPN', finish: 'Lab complete — classic IKEv2 VPN built and proven', steps: CLASSIC.map(x => x.id) },
    pqc: { title: 'Quick lab · Post-Quantum VPN (ML-KEM)', badge: 'PQC', kicker: 'Short lab — ML-KEM-768 hybrid VPN', finish: 'Lab complete — post-quantum VPN with ML-KEM-768', steps: PQC.map(x => x.id) },
    negotiate: { title: 'Quick lab · Negotiation experiments', badge: 'Negotiation', kicker: 'What happens when the two ends differ', finish: 'Lab complete — you derived the negotiation rules', steps: NEGOTIATE.map(x => x.id) },
    migrate: { title: 'Quick lab · From Classic to PQC', badge: 'Classic → PQC', kicker: 'Short lab — upgrade a classic VPN to ML-KEM', finish: 'Lab complete — classic VPN migrated to ML-KEM-768', steps: MIGRATE.map(x => x.id) },
  };
  const api = { STEPS: ALL, TRACKS, BY_ID, DEFAULT_TRACK: 'classic', GUIDE_URL, BLOG_URL, NEG };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.TUTORIAL = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
