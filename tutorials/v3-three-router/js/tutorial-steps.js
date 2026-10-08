/* ==========================================================================
   tutorial-steps.js — "Post-Quantum Key Exchange on Cisco Routers"
   Hands-on reproduction of IPsec Series Part 9 (Julio Gomez, Cisco Blogs,
   1 Sep 2026) on three simulated C8235-G2 routers.

   Step shape:
     { id, title, part, devices, html, run:[[dev, cmd], ...],
       validate(ctx) -> bool, hints:[{ when(dev, canon, raw), text }] }
   ctx = { lab, since }  (since = lab.seq when the step became active)
   ========================================================================== */
(function (root) {
  const BLOG_URL = 'https://blogs.cisco.com/developer/post-quantum-key-exchange-on-cisco-routers-ipsec-series-part-9';
  const GUIDE_URL = 'https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/security-vpn/m-pqc-ikev2.html';
  const guide = (txt = 'IOS XE PQC configuration guide') => `<a href="${GUIDE_URL}" target="_blank" rel="noopener">${txt}</a>`;
  const PSK = 'C1sco12345psk';
  const PPK_HEX = '48656C6C6F506F737451756172746E756D';

  /* ---------- tiny HTML helpers ---------- */
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const cfg = (dev, lines, note) => `<div class="cfg"><div class="cfg-head"><span class="dev-chip dev-${dev}">${dev.toUpperCase()}</span>${note ? `<span class="cfg-note">${note}</span>` : ''}</div><pre>${esc(lines.join('\n'))}</pre></div>`;
  const out = (lines) => `<pre class="out">${esc(lines.join('\n'))}</pre>`;
  const callout = (kind, html) => `<div class="callout ${kind}">${html}</div>`;
  const EDU_NOTICE = callout('edu', `<b>🎓 For learning only.</b> This is a simulator to practise IOS XE commands and get familiar with post-quantum VPN concepts and configuration steps. It is not a real router: output can differ from real platforms and software releases, so <b>don't use it to validate configurations</b> for a real network. It is provided <b>as is</b>, with no warranty and no support. Always check the official Cisco documentation and test on real equipment before deploying. <a href="https://github.com/ioeacademy/spotlight-pqc/blob/main/DISCLAIMER.md" target="_blank" rel="noopener">Full disclaimer</a>.`);
  const runOf = (dev, lines) => lines.map(c => [dev, c]);

  /* ---------- validation helpers ---------- */
  // Is the IPsec chain on `dk` towards `peerIp` complete? (tunnel → ipsec profile → ts + ikev2 profile → keyring)
  function chainTo(lab, dk, peerIp) {
    const d = lab.dev(dk), c = d.crypto;
    return Object.values(d.ifaces).some(t => {
      if (t.kind !== 'tunnel' || t.shutdown || t.tunnel.mode !== 'ipsec ipv4' || t.tunnel.dest !== peerIp || !t.ip) return false;
      const ip = c.ipsecProfiles[t.tunnel.protection]; if (!ip || !c.tsets[ip.ts]) return false;
      const pr = c.profiles[ip.ikev2Profile]; if (!pr || pr.authLocal !== 'pre-share' || pr.authRemote !== 'pre-share') return false;
      if (!pr.matchRemote.some(m => m.ip === peerIp)) return false;
      if (pr.authLocalKey && pr.authRemoteKey) return true;
      const kr = c.keyrings[pr.keyringLocal]; if (!kr) return false;
      return Object.values(kr.peers).some(p => p.address === peerIp && p.psk);
    });
  }
  const hasPolicy = (lab, dk) => Object.values(lab.dev(dk).crypto.policies).some(p => p.proposals.some(n => { const x = lab.dev(dk).crypto.proposals[n]; return x && x.enc.length && x.group.length; }));
  const pingOk = (ctx, dk, ip) => ctx.lab.ranSince(ctx.since, dk, e => e.meta && e.meta.kind === 'ping' && e.meta.dst === ip && e.meta.succ > 0);
  const ran = (ctx, dk, re) => ctx.lab.ranSince(ctx.since, dk, re);
  // proof of encryption: a successful ping through the tunnel, then `show crypto ipsec sa` AFTER it,
  // with the outbound ESP counter above zero (ping success alone proves nothing: the underlay is reachable in clear)
  function encryptionProven(ctx, dk, tunIp, peer) {
    const log = ctx.lab.cmdLog.filter(e => e.seq > ctx.since && e.dev === dk && e.ok);
    const p = log.find(e => e.meta && e.meta.kind === 'ping' && e.meta.dst === tunIp && e.meta.succ > 0 && e.meta.path && e.meta.path.fwd.some(h => h.via === 'tunnel'));
    if (!p) return false;
    const shown = log.some(e => e.seq > p.seq && /^show crypto ipsec sa/.test(e.canon));
    const sa = ctx.lab.saBetween(dk, peer);
    return shown && !!sa && sa.counters[dk].encaps > 0;
  }
  const proposalsOf = (lab, dk) => Object.values(lab.dev(dk).crypto.policies).flatMap(p => p.proposals).map(n => lab.dev(dk).crypto.proposals[n]).filter(Boolean);

  /* ---------- shared config blocks ---------- */
  const R1_CLASSIC = [
    'configure terminal',
    'crypto ikev2 proposal CLASSICAL-PROPOSAL', ' encryption aes-cbc-256', ' integrity sha512', ' group 20', ' exit',
    'crypto ikev2 policy CLASSICAL-POLICY', ' proposal CLASSICAL-PROPOSAL', ' exit',
    'crypto ikev2 keyring CLASSICAL-KEYRING', ' peer R3', `  address 10.0.23.2`, `  pre-shared-key ${PSK}`, '  exit', ' exit',
    'crypto ikev2 profile CLASSICAL-PROFILE', ' match identity remote address 10.0.23.2 255.255.255.255', ' authentication remote pre-share', ' authentication local pre-share', ' keyring local CLASSICAL-KEYRING', ' exit',
    'crypto ipsec transform-set CLASSICAL-TS esp-gcm 256', ' mode tunnel', ' exit',
    'crypto ipsec profile CLASSICAL-IPSEC', ' set transform-set CLASSICAL-TS', ' set ikev2-profile CLASSICAL-PROFILE', ' exit',
    'interface Tunnel0', ' ip address 192.168.100.1 255.255.255.0', ' tunnel source TwoGigabitEthernet0/0/0', ' tunnel destination 10.0.23.2', ' tunnel mode ipsec ipv4', ' tunnel protection ipsec profile CLASSICAL-IPSEC',
    'end',
  ];
  const R3_CLASSIC = R1_CLASSIC.map(l => l
    .replace(' peer R3', ' peer R1').replace('10.0.23.2', '10.0.12.1').replace('10.0.23.2', '10.0.12.1')
    .replace('192.168.100.1', '192.168.100.2'));

  const CLASSIC_INTRO = {
    id: 'intro-classic', title: 'Classic site-to-site VPN with IKEv2', part: 'intro', devices: [],
    html: `
${EDU_NOTICE}
<p>In this track you build a <b>route-based IPsec VPN</b> between two Cisco IOS XE routers, R1 and R3, using <b>IKEv2</b> and a <b>Virtual Tunnel Interface (VTI)</b>. A third router, R2, sits in between as the "WAN": it only forwards packets.</p>
<p>You will configure these blocks, in the same order the router uses them:</p>
<table class="t">
<tr><th>Object</th><th>What it does</th></tr>
<tr><td><code>crypto ikev2 proposal</code></td><td>Algorithms for the IKE SA: encryption, integrity, DH group</td></tr>
<tr><td><code>crypto ikev2 policy</code></td><td>Which proposals to use. Chosen by local address/VRF at IKE_SA_INIT, before the peer's identity is known</td></tr>
<tr><td><code>crypto ikev2 keyring</code></td><td>The peer's address and pre-shared key</td></tr>
<tr><td><code>crypto ikev2 profile</code></td><td>Who the peer is (<code>match identity</code>) and how both sides authenticate. Used in IKE_AUTH</td></tr>
<tr><td><code>crypto ipsec transform-set</code></td><td>ESP algorithms for the data (the Child SA)</td></tr>
<tr><td><code>crypto ipsec profile</code></td><td>Bundles the transform set and the IKEv2 profile</td></tr>
<tr><td><code>interface Tunnel0</code></td><td>The VTI: <code>tunnel protection</code> attaches the profile. Traffic <i>routed</i> to it gets encrypted</td></tr>
</table>
<h4>The lab</h4>
<table class="t mono">
<tr><th></th><th>Role</th><th>WAN interface</th><th>Address</th></tr>
<tr><td>R1</td><td>VPN peer</td><td>Tw0/0/0</td><td>10.0.12.1/24</td></tr>
<tr><td rowspan="2">R2</td><td rowspan="2">Transit ("WAN")</td><td>Tw0/0/0</td><td>10.0.12.2/24</td></tr>
<tr><td>Tw0/0/1</td><td>10.0.23.1/24</td></tr>
<tr><td>R3</td><td>VPN peer</td><td>Tw0/0/0</td><td>10.0.23.2/24</td></tr>
</table>
${callout('info', '<b>Design rule:</b> the tunnel endpoints (10.0.12.1 ↔ 10.0.23.2) must be reachable over the physical network, <i>outside</i> the tunnel. Only traffic for the overlay (192.168.100.0/24) is routed into Tunnel0. Routing a tunnel\'s own destination through the tunnel creates recursive routing.')}
${callout('info', 'Type IOS commands in the console on the right (<kbd>?</kbd> for help, <kbd>Tab</kbd> to complete). Each step checks the <i>actual state</i> of the simulated network. <b>Show Me</b> types the commands for you.')}
<p class="src">Command syntax follows the Cisco <a href="https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-cfg-ikev2-flex.html" target="_blank" rel="noopener">IOS XE IKEv2 configuration guide</a> and the <a href="https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-ipsec-virt-tunnl-0.html" target="_blank" rel="noopener">IPsec VTI guide</a>. The IOS XE behaviour shown here is simulated.</p>`,
    run: [], validate: () => true, hints: [],
  };
  const CLASSIC_WRAP = {
    id: 'wrap-classic', title: 'What you built, and what is still missing', part: 'intro', devices: [],
    html: `
<p>You built a classic, route-based IKEv2 VPN and <b>proved</b> that traffic is encrypted:</p>
<table class="t">
<tr><th>Evidence</th><th>Command</th></tr>
<tr><td>IKE SA up, algorithms agreed</td><td><code>show crypto ikev2 sa</code> → READY</td></tr>
<tr><td>Traffic routed into the tunnel</td><td><code>show ip route 192.168.100.2</code> → Tunnel0</td></tr>
<tr><td>Packets actually encrypted</td><td><code>show crypto ipsec sa</code> → encaps/decaps increasing</td></tr>
</table>
${callout('warn', '<b>This VPN is classical.</b> Its keys come from ECDH group 20, which a future quantum computer could break with Shor\'s algorithm. Traffic recorded today could be decrypted later ("harvest now, decrypt later").')}
<p><b>Next:</b> the <a href="?track=full">post-quantum track</a> continues from here. It adds a PPK (RFC 8784), then native ML-KEM-768, and ends with a phased hub-and-spoke migration.</p>
<p class="src">References: ${guide('Cisco IOS XE PQC for IKEv2')} · <a href="https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-cfg-ikev2-flex.html" target="_blank" rel="noopener">Configuring IKEv2 (IOS XE 17)</a> · <a href="https://www.rfc-editor.org/rfc/rfc7296" target="_blank" rel="noopener">RFC 7296</a></p>`,
    run: [], validate: () => true, hints: [],
  };

  const STEPS = [
  /* ───────────────────────── 1 ───────────────────────── */
  {
    id: 'intro', title: 'From the lab bench to real routers', part: 'intro', devices: [],
    html: `
${EDU_NOTICE}
<p>Parts 1–8 of the series built quantum-safe IPsec tunnels in containers. Part 9 moves the same ideas onto <b>Cisco 8000 Series Secure Routers</b>, where the question is no longer "does the protocol work?" but "does the platform work?".</p>
<p>In this tutorial you will configure three simulated <b>C8235-G2</b> routers running <b>IOS XE ${'26.2'}</b> and walk the key exchange through every stage that Part 9 covers:</p>
<table class="t">
<tr><th>Stage</th><th>What protects the IKE key exchange</th></tr>
<tr><td><span class="pill classic">Classical</span></td><td>ECDH group 20 (P-384) + pre-shared key. Breakable by Shor's algorithm.</td></tr>
<tr><td><span class="pill ppk">PPK</span></td><td>RFC 8784: an out-of-band secret mixed into the key derivation</td></tr>
<tr><td><span class="pill pqc">ML-KEM</span></td><td>Native ML-KEM-768 hybrid key exchange (FIPS 203, RFC 9370)</td></tr>
<tr><td><span class="pill hub">Migration</span></td><td>Hub-and-spoke, rolled out one site at a time with zero outage</td></tr>
</table>
<h4>The lab</h4>
<p>Three routers connected back to back on their <b>WAN interfaces</b>. The diagram above is live: click a router to open its console. Tunnels appear as arcs once you build them, coloured by how quantum-safe they are.</p>
<table class="t mono">
<tr><th></th><th>Role</th><th>Interface</th><th>Address</th></tr>
<tr><td>R1</td><td>Spoke-1</td><td>Tw0/0/0 (WAN)</td><td>10.0.12.1/24</td></tr>
<tr><td rowspan="2">R2</td><td rowspan="2">Hub / Transit</td><td>Tw0/0/0 (WAN, to R1)</td><td>10.0.12.2/24</td></tr>
<tr><td>Tw0/0/1 (WAN, to R3)</td><td>10.0.23.1/24</td></tr>
<tr><td>R3</td><td>Spoke-2</td><td>Tw0/0/0 (WAN)</td><td>10.0.23.2/24</td></tr>
</table>
${callout('info', `<b>Note on interfaces:</b> the blog's bench plugged the cables into the routers' LAN ports and put the addresses on VLAN interfaces (<code>Vlan12</code>, <code>Vlan23</code>). This lab uses <b>routed WAN interfaces</b> instead, which is the usual design for site-to-site VPNs: the C8235-G2 has 2× 2.5 GE mGig WAN ports (<a href="https://www.cisco.com/c/dam/en/us/products/collateral/routers/secure-routers/8200-series-secure-routers-ds.pdf" target="_blank" rel="noopener">Cisco 8200 datasheet</a>). The IPsec and PQC configuration is identical either way; only <code>tunnel source</code> changes. Interface numbering is illustrative.`)}
${callout('info', `<b>How it works:</b> type IOS commands in the console on the right. You can use <kbd>?</kbd> for help, <kbd>Tab</kbd> to complete, and <kbd>↑</kbd>/<kbd>↓</kbd> for history. Each step checks the <i>actual state</i> of the simulated network, not the exact text you typed. <b>Show Me</b> types the commands for you.`)}
<p class="src">Based on <a href="${BLOG_URL}" target="_blank" rel="noopener">Post-Quantum Key Exchange on Cisco Routers – IPsec Series, Part 9</a> by Julio Gomez (Cisco Blogs, 1 Sep 2026). Command syntax checked against the Cisco ${guide('Security and VPN Configuration Guide — Post-Quantum Cryptography for IKEv2')}. The IOS XE behaviour shown here is simulated.</p>`,
    run: [], validate: () => true, hints: [],
  },

  /* ───────────────────────── 2 ───────────────────────── */
  {
    id: 'underlay', title: 'Make R2 a Layer 3 transit hop', part: 'base', devices: ['r1', 'r3'],
    html: `
<p>In the first half of the lab the IPsec tunnel runs <b>end to end between R1 and R3</b>. R2 sits in the middle and only forwards packets, as a real WAN does when the crypto endpoints are not directly connected.</p>
<p>R2 knows both subnets because they are directly connected to it. The spokes don't: R1 has no route to 10.0.23.0/24, and R3 has no route to 10.0.12.0/24. Try it first:</p>
${cfg('r1', ['ping 10.0.23.2'], 'fails — no route yet')}
<p>Add a static route on each spoke that points at R2:</p>
${cfg('r1', ['configure terminal', 'ip route 10.0.23.0 255.255.255.0 10.0.12.2', 'end'])}
${cfg('r3', ['configure terminal', 'ip route 10.0.12.0 255.255.255.0 10.0.23.1', 'end'])}
<p>Then confirm that R1 reaches R3 and that the path goes through R2:</p>
${cfg('r1', ['ping 10.0.23.2', 'traceroute 10.0.23.2'])}
${callout('tip', 'The first ping may show <code>.!!!!</code>. The first packet is lost while ARP resolves the next hop, exactly as on real IOS.')}
<div class="goal">Goal: a successful <code>ping 10.0.23.2</code> from R1.</div>`,
    run: [['r1', 'enable'], ['r1', 'show ip interface brief'], ['r1', 'ping 10.0.23.2'], ...runOf('r1', ['configure terminal', 'ip route 10.0.23.0 255.255.255.0 10.0.12.2', 'end']),
      ['r3', 'enable'], ...runOf('r3', ['configure terminal', 'ip route 10.0.12.0 255.255.255.0 10.0.23.1', 'end']), ['r1', 'ping 10.0.23.2'], ['r1', 'traceroute 10.0.23.2']],
    validate: ctx => ctx.lab.reach('r1', '10.0.23.2') && pingOk(ctx, 'r1', '10.0.23.2'),
    hints: [
      { when: (d, c) => /^ip route 10\.0\.23\.0 255\.255\.255\.0 10\.0\.23\.1/.test(c) && d === 'r1', text: 'From R1 the next hop must be R2\'s address on <i>R1\'s</i> subnet: <code>10.0.12.2</code>.' },
      { when: (d, c) => /^ip route 10\.0\.12\.0 255\.255\.255\.0 10\.0\.12\.2/.test(c) && d === 'r3', text: 'From R3 the next hop is R2\'s address on the R2–R3 link: <code>10.0.23.1</code>.' },
      { when: (d, c, r, lab) => d === 'r1' && /^ping 10\.0\.23\.2/.test(c) && lab.dev('r1').routes.length && !lab.dev('r3').routes.length, text: 'R1 has its route now, but the reply from R3 also needs a way back. Add the return route on <b>R3</b>.' },
    ],
  },

  /* ───────────────────────── 3 ───────────────────────── */
  {
    id: 'r1-classic', title: 'Classical IKEv2 + VTI on R1', part: 'base', devices: ['r1'],
    html: `
<p>Start with the classical baseline. This is the IKEv2 configuration on R1, exactly as it appears in the blog. It is a route-based VPN on a <b>Virtual Tunnel Interface</b>:</p>
${cfg('r1', R1_CLASSIC.slice(1, -1).filter(l => !/^\s*exit$/.test(l)))}
<table class="t">
<tr><td><code>group 20</code></td><td>ECDH on NIST P-384. The containers used X25519; both are classical elliptic-curve DH, and Shor's algorithm breaks both.</td></tr>
<tr><td><code>pre-shared-key</code></td><td>Used <b>only for authentication</b>: it proves R1 is really talking to R3. The encryption keys come from the DH exchange.</td></tr>
<tr><td><code>esp-gcm 256</code></td><td>Protects the data plane. AES-256 is already considered quantum-resistant; the weak spot is the <i>key exchange</i>.</td></tr>
<tr><td><code>tunnel source TwoGigabitEthernet0/0/0</code></td><td>The tunnel is sourced from the WAN interface. 10.0.23.2 is two hops away, through R2.</td></tr>
</table>
${callout('warn', `<b>Lab-only key.</b> <code>${PSK}</code> is a teaching value, not a recommendation. A pre-shared key must be long and random: RFC 7296 §2.15 warns that human-memorable keys can be guessed offline. In production, use a long randomly generated key or certificates.`)}
${callout('tip', 'In real IOS the indentation is cosmetic. Type <code>exit</code> to leave a sub-mode, or just type the next global command and the parser drops back to global configuration on its own.')}
<div class="goal">Goal: R1 has a complete tunnel → IPsec profile → IKEv2 profile → keyring chain towards 10.0.23.2.</div>`,
    run: runOf('r1', R1_CLASSIC),
    validate: ctx => chainTo(ctx.lab, 'r1', '10.0.23.2') && hasPolicy(ctx.lab, 'r1'),
    hints: [
      { when: (d, c) => d === 'r1' && /^match identity remote address 10\.0\.12/.test(c), text: 'R1 must accept the identity of its <b>peer</b>, R3: <code>10.0.23.2</code>.' },
      { when: (d, c) => d === 'r1' && /^tunnel destination 10\.0\.12\.2/.test(c), text: 'The tunnel ends on <b>R3</b> (10.0.23.2). R2 only forwards the encrypted packets.' },
      { when: (d, c, raw, lab) => d === 'r1' && /^tunnel protection/.test(c) && !Object.keys(lab.dev('r1').crypto.ipsecProfiles).length, text: 'Create the <code>crypto ipsec profile</code> first; the tunnel can only reference a profile that already exists.' },
    ],
  },

  /* ───────────────────────── 4 ───────────────────────── */
  {
    id: 'r3-classic', title: 'Mirror the configuration on R3', part: 'base', devices: ['r3'],
    html: `
<p>R3 mirrors R1, with the peer address and the tunnel IP swapped:</p>
${cfg('r3', R3_CLASSIC.slice(1, -1).filter(l => !/^\s*exit$/.test(l)))}
<p>Once both ends agree, IKEv2 negotiates on its own. Watch the console for <code>%CRYPTO-5-IKEV2_SESSION_STATUS ... UP</code>, and watch the arc that appears over the topology.</p>
${callout('info', 'The pre-shared key, the transform set and the proposal algorithms must match on both sides. If the tunnel stays grey, click the arc to open the <b>handshake inspector</b>: it tells you exactly which check failed.')}
<div class="goal">Goal: an IKEv2 SA between R1 and R3.</div>`,
    run: runOf('r3', R3_CLASSIC),
    validate: ctx => !!ctx.lab.saBetween('r1', 'r3'),
    hints: [
      { when: (d, c) => d === 'r3' && /^address 10\.0\.23/.test(c), text: 'On R3 the peer is <b>R1</b>: <code>address 10.0.12.1</code>.' },
      { when: (d, c) => d === 'r3' && /^tunnel source/.test(c) && !c.includes('TwoGigabitEthernet0/0/0'), text: 'Source the tunnel from R3\'s WAN interface, <code>TwoGigabitEthernet0/0/0</code> (10.0.23.2).' },
      { when: (d, c) => d === 'r3' && /^pre-shared-key /.test(c) && !c.includes(PSK), text: `Pre-shared keys must be identical on both peers. R1 uses <code>${PSK}</code>.` },
    ],
  },

  /* ───────────────────────── 5 ───────────────────────── */
  {
    id: 'baseline', title: 'Prove the traffic is encrypted', part: 'verify', devices: ['r1', 'r2'],
    html: `
<p>A successful ping does <b>not</b> prove that traffic is encrypted. The routers can already reach each other in the clear over the underlay. To prove encryption you need three pieces of evidence.</p>
<h4>1 · The IKE SA is up</h4>
${cfg('r1', ['show crypto ikev2 sa'])}
${out(['      Encr: AES-CBC, keysize: 256, PRF: SHA512, Hash: SHA512, DH Grp:20, Auth sign: PSK, Auth verify: PSK'])}
<p><b>DH Grp:20, Auth sign: PSK</b>: a classical key exchange with pre-shared-key authentication. That's the baseline everything else is measured against.</p>
<h4>2 · The traffic is routed into the tunnel</h4>
${cfg('r1', ['show ip route 192.168.100.2'])}
<p>The route must point at <code>Tunnel0</code>. With a VTI, <i>the routing table decides what gets encrypted</i>: only traffic routed to the tunnel interface is protected.</p>
<h4>3 · The IPsec counters go up</h4>
${cfg('r1', ['show crypto ipsec sa | include pkts encaps', 'ping 192.168.100.2', 'show crypto ipsec sa | include pkts encaps'])}
<p>The <code>#pkts encaps</code> / <code>#pkts encrypt</code> counters must increase by the number of pings. That is proof the packets went through the IPsec SA.</p>
${callout('tip', 'Contrast: <code>ping 10.0.23.2</code> (R3\'s WAN address) also succeeds, but the counters <b>do not move</b>. That traffic follows the underlay route in the clear. It is the tunnel endpoint itself, not traffic routed into the tunnel.')}
<p>Finally, look at the transit router:</p>
${cfg('r2', ['show crypto ikev2 sa'])}
${callout('info', 'R2 has <b>no</b> SA. It only forwards ESP packets between 10.0.12.1 and 10.0.23.2 and cannot read them. Swapping the PSK for certificates would not change the encryption keys, which come from the DH exchange. Part 10 of the series makes that swap.')}
<div class="goal">Goal: on R1, ping 192.168.100.2 through the tunnel, then run <code>show crypto ipsec sa</code> and see the encaps counter above zero.</div>`,
    run: [['r1', 'show crypto ikev2 sa'], ['r1', 'show ip route 192.168.100.2'], ['r1', 'show crypto ipsec sa | include pkts encaps'], ['r1', 'ping 192.168.100.2'], ['r1', 'show crypto ipsec sa | include pkts encaps'],
      ['r1', 'ping 10.0.23.2'], ['r1', 'show crypto ipsec sa | include pkts encaps'], ['r2', 'enable'], ['r2', 'show crypto ikev2 sa']],
    validate: ctx => encryptionProven(ctx, 'r1', '192.168.100.2', 'r3'),
    hints: [
      { when: (d, c) => /^ping 192\.168\.100\.2/.test(c) && d !== 'r1' && d !== 'r3', text: 'Ping from R1 (or R3). R2 is not part of the overlay, so it has no route to 192.168.100.0/24.' },
      { when: (d, c, r, lab) => d === 'r1' && /^ping 192\.168\.100\.2/.test(c) && !lab.cmdLog.slice(-1)[0].meta.succ, text: 'The ping failed. Check <code>show crypto ikev2 sa</code> first: without a READY SA, Tunnel0 is down and there is no route to 192.168.100.0/24.' },
      { when: (d, c) => d === 'r1' && /^ping 10\.0\.23\.2/.test(c), text: 'Now compare the counters: did <code>#pkts encaps</code> change? It shouldn\'t. This ping went over the underlay in the clear.' },
    ],
  },

  /* ───────────────────────── 6 ───────────────────────── */
  {
    id: 'ppk', title: 'Add a Postquantum Preshared Key (RFC 8784)', part: 'ppk', devices: ['r1', 'r3'],
    html: `
<p>A <b>PPK</b> is an extra secret mixed into the IKEv2 key derivation. It <b>never travels on the wire</b>. An attacker who records the handshake today and later breaks the ECDH exchange with a quantum computer still cannot derive the session keys.</p>
<p>The PPK goes inside the existing keyring, on both peers:</p>
${cfg('r1', ['crypto ikev2 keyring CLASSICAL-KEYRING', ' peer R3', `  ppk manual id PPK-R1R3 key hex ${PPK_HEX} required`, '!', 'crypto ikev2 profile CLASSICAL-PROFILE', ' keyring ppk CLASSICAL-KEYRING'])}
${cfg('r3', ['crypto ikev2 keyring CLASSICAL-KEYRING', ' peer R1', `  ppk manual id PPK-R1R3 key hex ${PPK_HEX} required`, '!', 'crypto ikev2 profile CLASSICAL-PROFILE', ' keyring ppk CLASSICAL-KEYRING'])}
<p><code>required</code> means the tunnel will not come up without the PPK. Both sides need the same <b>ID</b> and <b>key</b>.</p>
${callout('warn', 'The running SA does not change by itself; it was negotiated before the PPK existed. Clear it so that IKEv2 renegotiates:')}
${cfg('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show crypto ikev2 sa detailed | include Quantum', 'show crypto ikev2 stats | include Quantum'])}
<p>Underneath, it is the same classical DH exchange, but the derived keys now also depend on a secret that was never transmitted. The catch is operational: every peer pair needs its own secret, provisioned and rotated out of band.</p>
<div class="goal">Goal: the R1–R3 SA reports <code>Quantum-safe Encryption using Manual PPK</code>.</div>`,
    run: [...runOf('r1', ['configure terminal', 'crypto ikev2 keyring CLASSICAL-KEYRING', 'peer R3', `ppk manual id PPK-R1R3 key hex ${PPK_HEX} required`, 'exit', 'exit', 'crypto ikev2 profile CLASSICAL-PROFILE', 'keyring ppk CLASSICAL-KEYRING', 'end']),
      ...runOf('r3', ['configure terminal', 'crypto ikev2 keyring CLASSICAL-KEYRING', 'peer R1', `ppk manual id PPK-R1R3 key hex ${PPK_HEX} required`, 'exit', 'exit', 'crypto ikev2 profile CLASSICAL-PROFILE', 'keyring ppk CLASSICAL-KEYRING', 'end']),
      ...runOf('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show crypto ikev2 sa detailed | include Quantum', 'show crypto ikev2 stats | include Quantum'])],
    validate: ctx => { const sa = ctx.lab.saBetween('r1', 'r3'); return !!(sa && sa.params.ppk); },
    hints: [
      { when: (d, c, r, lab) => /^clear crypto ikev2 sa/.test(c) && (!lab.dev('r1').crypto.profiles['CLASSICAL-PROFILE'] || !lab.dev('r3').crypto.profiles['CLASSICAL-PROFILE'] || !lab.dev('r1').crypto.profiles['CLASSICAL-PROFILE'].keyringPpk || !lab.dev('r3').crypto.profiles['CLASSICAL-PROFILE'].keyringPpk), text: 'The PPK is only used when the IKEv2 profile points at it: <code>keyring ppk CLASSICAL-KEYRING</code> on <b>both</b> routers. With <code>required</code> on one side only, the tunnel will not come back.' },
      { when: (d, c) => /^ppk manual id (?!PPK-R1R3)/.test(c), text: 'Use the same PPK identity on both peers: <code>PPK-R1R3</code>.' },
    ],
  },

  /* ───────────────────────── 7 ───────────────────────── */
  {
    id: 'noppk', title: 'Remove the PPK', part: 'ppk', devices: ['r1', 'r3'],
    html: `
<p>PPK proved the concept: you can protect the key derivation against quantum attacks without changing the DH exchange. It is a <b>transitional</b> tool, though. Once the platform supports ML-KEM natively, you no longer need the out-of-band secret.</p>
<p>Remove it on both R1 and R3. The peer name is <code>R3</code> on R1 and <code>R1</code> on R3:</p>
${cfg('r1', ['crypto ikev2 profile CLASSICAL-PROFILE', ' no keyring ppk CLASSICAL-KEYRING', '!', 'crypto ikev2 keyring CLASSICAL-KEYRING', ' peer R3', '  no ppk manual id PPK-R1R3'])}
${cfg('r3', ['crypto ikev2 profile CLASSICAL-PROFILE', ' no keyring ppk CLASSICAL-KEYRING', '!', 'crypto ikev2 keyring CLASSICAL-KEYRING', ' peer R1', '  no ppk manual id PPK-R1R3'])}
${cfg('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show crypto ikev2 sa'])}
<p>You are back to the baseline: classical DH, classical PSK, no quantum protection. Now for the real thing.</p>
<div class="goal">Goal: the R1–R3 SA is up again <b>without</b> a PPK, and no PPK is configured on either side.</div>`,
    run: [...runOf('r1', ['configure terminal', 'crypto ikev2 profile CLASSICAL-PROFILE', 'no keyring ppk CLASSICAL-KEYRING', 'exit', 'crypto ikev2 keyring CLASSICAL-KEYRING', 'peer R3', 'no ppk manual id PPK-R1R3', 'end']),
      ...runOf('r3', ['configure terminal', 'crypto ikev2 profile CLASSICAL-PROFILE', 'no keyring ppk CLASSICAL-KEYRING', 'exit', 'crypto ikev2 keyring CLASSICAL-KEYRING', 'peer R1', 'no ppk manual id PPK-R1R3', 'end']),
      ...runOf('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show crypto ikev2 sa'])],
    validate: ctx => {
      const sa = ctx.lab.saBetween('r1', 'r3'); if (!sa || sa.params.ppk) return false;
      return ['r1', 'r3'].every(k => Object.values(ctx.lab.dev(k).crypto.profiles).every(p => !p.keyringPpk) && Object.values(ctx.lab.dev(k).crypto.keyrings).every(kr => Object.values(kr.peers).every(p => !p.ppk)));
    },
    hints: [{ when: (d, c, r, lab) => /^clear crypto ikev2 sa/.test(c) && ['r1', 'r3'].some(k => Object.values(lab.dev(k).crypto.keyrings).some(kr => Object.values(kr.peers).some(p => p.ppk && p.ppk.required))), text: 'One router still has a <code>required</code> PPK. Its peer no longer offers it, so the tunnel cannot come up. Remove the PPK on both sides.' }],
  },

  /* ───────────────────────── 8 ───────────────────────── */
  {
    id: 'mlkem', title: 'Native ML-KEM-768 hybrid key exchange', part: 'pqc', devices: ['r1', 'r3'],
    html: `
<p>Since IOS XE 26.1, ML-KEM is supported natively for IKEv2. In the IKEv2 proposal you add the ML-KEM algorithm(s) as an <b>Additional Key Exchange</b>, on top of the classical DH group. You also enable IKEv2 fragmentation:</p>
${cfg('r1', ['crypto ikev2 fragmentation mtu 1400', '!', 'crypto ikev2 proposal CLASSICAL-PROPOSAL', ' pqc mlkem768 optional'])}
${cfg('r3', ['crypto ikev2 fragmentation mtu 1400', '!', 'crypto ikev2 proposal CLASSICAL-PROPOSAL', ' pqc mlkem768 optional'])}
<table class="t">
<tr><td><code>pqc mlkem768 optional</code></td><td>Proposes ML-KEM-768 alongside ECDH group 20, a <b>hybrid</b> exchange. You can list several algorithms in preference order, for example <code>pqc mlkem768 mlkem1024 optional</code>. <b>optional</b> means ML-KEM is proposed but not mandatory: fallback to classical is allowed if the peer does not support it. Without <code>optional</code>, ML-KEM is enforced.</td></tr>
<tr><td><code>fragmentation mtu 1400</code></td><td>The ML-KEM-768 encapsulation key alone is 1,184 bytes, and ML-KEM-1024's is 1,568. The ${guide('configuration guide')} recommends RFC 7383 IKEv2 fragmentation at 1400 bytes, on the hub and on the spokes. It avoids IP-level fragmentation and the packet drops that often come with it.</td></tr>
</table>
${cfg('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show crypto ikev2 sa detailed'])}
${callout('info', 'The first few pings may time out (<code>....!</code>) while the larger handshake completes. Look for <code>PQC Key Exchange: ML-KEM-768</code>, <code>Quantum-safe Encryption using PQC: ML-KEM-768</code> and <code>IETF Std Fragmentation MTU in use: 1372 bytes</code>, which is the 1400-byte MTU minus the IP and UDP headers.')}
${callout('tip', 'Instead of clearing the SA, the guide suggests shutting the tunnel interface and bringing it back up (<code>interface Tunnel0</code> → <code>shutdown</code> → <code>no shutdown</code>) so the new configuration is applied. Both work here.')}
<div class="goal">Goal: the R1–R3 SA uses <code>PQC Key Exchange: ML-KEM-768</code>, with no pre-shared secret distributed out of band.</div>`,
    run: [...runOf('r1', ['configure terminal', 'crypto ikev2 fragmentation mtu 1400', 'crypto ikev2 proposal CLASSICAL-PROPOSAL', 'pqc mlkem768 optional', 'end']),
      ...runOf('r3', ['configure terminal', 'crypto ikev2 fragmentation mtu 1400', 'crypto ikev2 proposal CLASSICAL-PROPOSAL', 'pqc mlkem768 optional', 'end']),
      ...runOf('r1', ['clear crypto ikev2 sa', 'ping 192.168.100.2', 'show crypto ikev2 sa detailed'])],
    validate: ctx => { const sa = ctx.lab.saBetween('r1', 'r3'); return !!(sa && sa.params.pqc === 'mlkem768'); },
    hints: [
      { when: (d, c, r, lab) => /^show crypto ikev2 sa detail/.test(c) && lab.saBetween('r1', 'r3') && lab.saBetween('r1', 'r3').params.pqc && !lab.saBetween('r1', 'r3').params.frag, text: 'ML-KEM is up, but the output says <code>Fragmentation not configured</code>. The guide recommends <code>crypto ikev2 fragmentation mtu 1400</code> on <b>both</b> peers so that large PQC messages don\'t depend on IP fragmentation.' },
      { when: (d, c, r, lab) => /^show crypto ikev2 sa/.test(c) && ['r1', 'r3'].every(k => proposalsOf(lab, k).some(p => p.pqc)) && lab.saBetween('r1', 'r3') && !lab.saBetween('r1', 'r3').params.pqc, text: 'Both proposals now offer ML-KEM, but this SA was negotiated earlier. <code>clear crypto ikev2 sa</code> to renegotiate.' },
    ],
  },

  /* ───────────────────────── 8b ───────────────────────── */
  {
    id: 'pfs', title: 'Quantum-safe rekeys with set pfs', part: 'pqc', devices: ['r1', 'r3'],
    html: `
<p>ML-KEM now protects the <b>IKE SA</b>. The IPsec (Child) SA that carries the traffic is first created inside IKE_AUTH and takes its keys from the IKE SA. Each <b>rekey</b>, however, runs a new CREATE_CHILD_SA exchange, and that rekey only gets a fresh key exchange if <b>Perfect Forward Secrecy</b> is enabled.</p>
<p>This step is not in the blog. It comes from the ${guide('IOS XE PQC configuration guide')}, which recommends <code>set pfs</code> <i>without</i> a group on both peers: between IOS XE devices it inherits the DH group <b>and ML-KEM</b> from the IKEv2 SA.</p>
${cfg('r1', ['crypto ipsec profile CLASSICAL-IPSEC', ' set pfs'])}
${cfg('r3', ['crypto ipsec profile CLASSICAL-IPSEC', ' set pfs'])}
<p>PQC for IPsec only applies after a rekey. Force one by clearing the IPsec SAs; the IKE SA stays up:</p>
${cfg('r1', ['clear crypto sa', 'ping 192.168.100.2', 'show crypto ipsec sa detail | include PFS'])}
${out(['     PFS (Y/N): Y, DH group: group20, PQC Key Exchange: ML-KEM-768'])}
${callout('warn', 'Mismatched PFS settings break <b>rekeys</b>, not the initial tunnel. Try it: <code>no set pfs</code> on R3 only, then <code>clear crypto sa</code> on R1. You get NO_PROPOSAL_CHOSEN and traffic stops until the settings are compatible again. The guide\'s Table 1 lists every combination.')}
<div class="goal">Goal: the R1–R3 IPsec SA shows <code>PFS (Y/N): Y</code> with <code>PQC Key Exchange: ML-KEM-768</code>.</div>`,
    run: [...runOf('r1', ['configure terminal', 'crypto ipsec profile CLASSICAL-IPSEC', 'set pfs', 'end']),
      ...runOf('r3', ['configure terminal', 'crypto ipsec profile CLASSICAL-IPSEC', 'set pfs', 'end']),
      ...runOf('r1', ['clear crypto sa', 'ping 192.168.100.2', 'show crypto ipsec sa detail | include PFS'])],
    validate: ctx => { const sa = ctx.lab.saBetween('r1', 'r3'); return !!(sa && !sa.child.down && sa.child.pfs && sa.child.pfs.pqc); },
    hints: [
      { when: (d, c, r, lab) => /^show crypto ipsec sa/.test(c) && lab.saBetween('r1', 'r3') && !lab.saBetween('r1', 'r3').child.pfs && ['r1', 'r3'].every(k => Object.values(lab.dev(k).crypto.ipsecProfiles).some(p => p.pfs)), text: '<code>set pfs</code> is configured, but this Child SA came from IKE_AUTH, before any rekey. Run <code>clear crypto sa</code> to trigger a CREATE_CHILD_SA.' },
      { when: (d, c, r, lab) => /^(ping|show crypto ipsec)/.test(c) && lab.saBetween('r1', 'r3') && lab.saBetween('r1', 'r3').child.down, text: 'The rekey failed with NO_PROPOSAL_CHOSEN. The PFS settings are incompatible: put <code>set pfs</code> on <b>both</b> IPsec profiles.' },
    ],
  },

  /* ───────────────────────── 9 ───────────────────────── */
  {
    id: 'decom', title: 'Decommission the end-to-end tunnel', part: 'hub', devices: ['r1', 'r3'],
    html: `
<p>Now for the real-world scenario: many sites that <b>cannot all be upgraded at once</b>. The topology changes. <b>R2 becomes a VPN hub</b> that terminates one tunnel to each spoke. It is the same three boxes, with a new role for the one in the middle.</p>
<p>First remove the R1–R3 tunnel and its IKEv2 objects. The transform set and the fragmentation setting stay; you will reuse them.</p>
${cfg('r1', ['no interface Tunnel0', 'no crypto ipsec profile CLASSICAL-IPSEC', 'no crypto ikev2 profile CLASSICAL-PROFILE', 'no crypto ikev2 policy CLASSICAL-POLICY', 'no crypto ikev2 proposal CLASSICAL-PROPOSAL', 'no crypto ikev2 keyring CLASSICAL-KEYRING'])}
${cfg('r3', ['no interface Tunnel0', 'no crypto ipsec profile CLASSICAL-IPSEC', 'no crypto ikev2 profile CLASSICAL-PROFILE', 'no crypto ikev2 policy CLASSICAL-POLICY', 'no crypto ikev2 proposal CLASSICAL-PROPOSAL', 'no crypto ikev2 keyring CLASSICAL-KEYRING'])}
${callout('info', 'Order matters: IOS won\'t delete an IPsec profile that a tunnel interface still uses. Remove the tunnel first.')}
<div class="goal">Goal: no protected tunnel and no IKEv2 policy left on R1 or R3.</div>`,
    run: ['r1', 'r3'].flatMap(k => runOf(k, ['configure terminal', 'no interface Tunnel0', 'no crypto ipsec profile CLASSICAL-IPSEC', 'no crypto ikev2 profile CLASSICAL-PROFILE', 'no crypto ikev2 policy CLASSICAL-POLICY', 'no crypto ikev2 proposal CLASSICAL-PROPOSAL', 'no crypto ikev2 keyring CLASSICAL-KEYRING', 'end'])),
    validate: ctx => ['r1', 'r3'].every(k => !Object.values(ctx.lab.dev(k).ifaces).some(i => i.kind === 'tunnel' && i.tunnel.protection) && !Object.keys(ctx.lab.dev(k).crypto.policies).length),
    hints: [],
  },

  /* ───────────────────────── 10 ───────────────────────── */
  {
    id: 'hub', title: 'Upgrade the hub first (R2)', part: 'hub', devices: ['r2'],
    html: `
<p>The migration starts at the hub. Its proposal includes ML-KEM as <b>optional</b>, so it can talk to both upgraded and legacy spokes. One keyring holds both peers, one IKEv2 profile accepts both identities, and each spoke gets its own tunnel interface:</p>
${cfg('r2', [
  'crypto ikev2 fragmentation mtu 1400', '!',
  'crypto ikev2 proposal HUB-PROPOSAL', ' pqc mlkem768 optional', ' encryption aes-cbc-256', ' integrity sha512', ' group 20', '!',
  'crypto ikev2 policy HUB-POLICY', ' proposal HUB-PROPOSAL', '!',
  'crypto ikev2 keyring HUB-KEYRING', ' peer R1', '  address 10.0.12.1', `  pre-shared-key ${PSK}`, ' peer R3', '  address 10.0.23.2', `  pre-shared-key ${PSK}`, '!',
  'crypto ikev2 profile HUB-PROFILE', ' match identity remote address 10.0.12.1 255.255.255.255', ' match identity remote address 10.0.23.2 255.255.255.255', ' authentication remote pre-share', ' authentication local pre-share', ' keyring local HUB-KEYRING', '!',
  'crypto ipsec transform-set HUB-TS esp-gcm 256', ' mode tunnel', '!',
  'crypto ipsec profile HUB-IPSEC', ' set transform-set HUB-TS', ' set ikev2-profile HUB-PROFILE', ' set pfs', '!',
  'interface Tunnel1', ' description to R1 (Spoke-1)', ' ip address 192.168.12.2 255.255.255.0', ' tunnel source TwoGigabitEthernet0/0/0', ' tunnel destination 10.0.12.1', ' tunnel mode ipsec ipv4', ' tunnel protection ipsec profile HUB-IPSEC', '!',
  'interface Tunnel2', ' description to R3 (Spoke-2)', ' ip address 192.168.23.1 255.255.255.0', ' tunnel source TwoGigabitEthernet0/0/1', ' tunnel destination 10.0.23.2', ' tunnel mode ipsec ipv4', ' tunnel protection ipsec profile HUB-IPSEC'])}
${callout('info', `This follows the ${guide('guide')}'s upgrade workflow: <b>upgrade the hub (responder) before the spokes</b>, using <code>optional</code> so that upgraded spokes negotiate a PQC hybrid while legacy spokes fall back to classical DH. Enable fragmentation and <code>set pfs</code> on the hub and on the spokes.`)}
${callout('info', 'The blog shows only the proposals for this phase. The tunnel addressing (192.168.12.0/24 towards R1, 192.168.23.0/24 towards R3) and the object names are this tutorial\'s choice. R2 never needed fragmentation while it was only a transit hop, so it is added here.')}
<div class="goal">Goal: R2 has complete tunnels towards 10.0.12.1 and 10.0.23.2, with ML-KEM offered as optional.</div>`,
    run: runOf('r2', ['configure terminal', 'crypto ikev2 fragmentation mtu 1400',
      'crypto ikev2 proposal HUB-PROPOSAL', 'pqc mlkem768 optional', 'encryption aes-cbc-256', 'integrity sha512', 'group 20', 'exit',
      'crypto ikev2 policy HUB-POLICY', 'proposal HUB-PROPOSAL', 'exit',
      'crypto ikev2 keyring HUB-KEYRING', 'peer R1', 'address 10.0.12.1', `pre-shared-key ${PSK}`, 'exit', 'peer R3', 'address 10.0.23.2', `pre-shared-key ${PSK}`, 'exit', 'exit',
      'crypto ikev2 profile HUB-PROFILE', 'match identity remote address 10.0.12.1 255.255.255.255', 'match identity remote address 10.0.23.2 255.255.255.255', 'authentication remote pre-share', 'authentication local pre-share', 'keyring local HUB-KEYRING', 'exit',
      'crypto ipsec transform-set HUB-TS esp-gcm 256', 'mode tunnel', 'exit',
      'crypto ipsec profile HUB-IPSEC', 'set transform-set HUB-TS', 'set ikev2-profile HUB-PROFILE', 'set pfs', 'exit',
      'interface Tunnel1', 'description to R1 (Spoke-1)', 'ip address 192.168.12.2 255.255.255.0', 'tunnel source TwoGigabitEthernet0/0/0', 'tunnel destination 10.0.12.1', 'tunnel mode ipsec ipv4', 'tunnel protection ipsec profile HUB-IPSEC', 'exit',
      'interface Tunnel2', 'description to R3 (Spoke-2)', 'ip address 192.168.23.1 255.255.255.0', 'tunnel source TwoGigabitEthernet0/0/1', 'tunnel destination 10.0.23.2', 'tunnel mode ipsec ipv4', 'tunnel protection ipsec profile HUB-IPSEC', 'end']),
    validate: ctx => chainTo(ctx.lab, 'r2', '10.0.12.1') && chainTo(ctx.lab, 'r2', '10.0.23.2') && proposalsOf(ctx.lab, 'r2').some(p => p.pqc && p.pqc.mode === 'optional') && !!ctx.lab.dev('r2').crypto.fragMtu,
    hints: [
      { when: (d, c) => d === 'r2' && /^match identity remote address/.test(c), text: 'The hub\'s single profile needs <b>two</b> <code>match identity</code> lines, one per spoke.' },
      { when: (d, c, r, lab) => d === 'r2' && /^tunnel source/.test(c) && lab.dev('r2').ctx.iface === 'Tunnel2' && c.includes('TwoGigabitEthernet0/0/0'), text: 'Tunnel2 goes to R3, so source it from the WAN interface facing R3: <code>TwoGigabitEthernet0/0/1</code> (10.0.23.1). Tunnel1 uses <code>TwoGigabitEthernet0/0/0</code>.' },
    ],
  },

  /* ───────────────────────── 11 ───────────────────────── */
  {
    id: 'spoke1', title: 'Spoke R1 — already upgraded', part: 'hub', devices: ['r1'],
    html: `
<p>R1 is an upgraded spoke, so its proposal offers ML-KEM too. It reuses the <code>CLASSICAL-TS</code> transform set and the fragmentation setting that are still configured.</p>
${cfg('r1', [
  'crypto ikev2 proposal PQC-PROPOSAL', ' pqc mlkem768 optional', ' encryption aes-cbc-256', ' integrity sha512', ' group 20', '!',
  'crypto ikev2 policy PQC-POLICY', ' proposal PQC-PROPOSAL', '!',
  'crypto ikev2 keyring SPOKE-KEYRING', ' peer R2', '  address 10.0.12.2', `  pre-shared-key ${PSK}`, '!',
  'crypto ikev2 profile SPOKE-PROFILE', ' match identity remote address 10.0.12.2 255.255.255.255', ' authentication remote pre-share', ' authentication local pre-share', ' keyring local SPOKE-KEYRING', '!',
  'crypto ipsec profile SPOKE-IPSEC', ' set transform-set CLASSICAL-TS', ' set ikev2-profile SPOKE-PROFILE', ' set pfs', '!',
  'interface Tunnel1', ' ip address 192.168.12.1 255.255.255.0', ' tunnel source TwoGigabitEthernet0/0/0', ' tunnel destination 10.0.12.2', ' tunnel mode ipsec ipv4', ' tunnel protection ipsec profile SPOKE-IPSEC'])}
<p>Then check the tunnel to the hub:</p>
${cfg('r1', ['ping 192.168.12.2', 'show crypto ikev2 sa'])}
<div class="goal">Goal: the R1–R2 SA comes up with <code>PQC Key Exchange: ML-KEM-768</code>.</div>`,
    run: runOf('r1', ['configure terminal',
      'crypto ikev2 proposal PQC-PROPOSAL', 'pqc mlkem768 optional', 'encryption aes-cbc-256', 'integrity sha512', 'group 20', 'exit',
      'crypto ikev2 policy PQC-POLICY', 'proposal PQC-PROPOSAL', 'exit',
      'crypto ikev2 keyring SPOKE-KEYRING', 'peer R2', 'address 10.0.12.2', `pre-shared-key ${PSK}`, 'exit', 'exit',
      'crypto ikev2 profile SPOKE-PROFILE', 'match identity remote address 10.0.12.2 255.255.255.255', 'authentication remote pre-share', 'authentication local pre-share', 'keyring local SPOKE-KEYRING', 'exit',
      'crypto ipsec profile SPOKE-IPSEC', 'set transform-set CLASSICAL-TS', 'set ikev2-profile SPOKE-PROFILE', 'set pfs', 'exit',
      'interface Tunnel1', 'ip address 192.168.12.1 255.255.255.0', 'tunnel source TwoGigabitEthernet0/0/0', 'tunnel destination 10.0.12.2', 'tunnel mode ipsec ipv4', 'tunnel protection ipsec profile SPOKE-IPSEC', 'end',
      'ping 192.168.12.2', 'show crypto ikev2 sa']),
    validate: ctx => { const sa = ctx.lab.saBetween('r1', 'r2'); return !!(sa && sa.params.pqc); },
    hints: [{ when: (d, c) => d === 'r1' && /^tunnel destination 10\.0\.23/.test(c), text: 'The spoke\'s tunnel now ends on the <b>hub</b>, R2, at <code>10.0.12.2</code>.' }],
  },

  /* ───────────────────────── 12 ───────────────────────── */
  {
    id: 'spoke2', title: 'Spoke R3 — still legacy', part: 'hub', devices: ['r3', 'r2'],
    html: `
<p>R3 has not been upgraded yet. Its proposal has <b>no</b> <code>pqc</code> line:</p>
${cfg('r3', [
  'crypto ikev2 proposal SPOKE-PROPOSAL', ' encryption aes-cbc-256', ' integrity sha512', ' group 20', '!',
  'crypto ikev2 policy SPOKE-POLICY', ' proposal SPOKE-PROPOSAL', '!',
  'crypto ikev2 keyring SPOKE-KEYRING', ' peer R2', '  address 10.0.23.1', `  pre-shared-key ${PSK}`, '!',
  'crypto ikev2 profile SPOKE-PROFILE', ' match identity remote address 10.0.23.1 255.255.255.255', ' authentication remote pre-share', ' authentication local pre-share', ' keyring local SPOKE-KEYRING', '!',
  'crypto ipsec profile SPOKE-IPSEC', ' set transform-set CLASSICAL-TS', ' set ikev2-profile SPOKE-PROFILE', ' set pfs', '!',
  'interface Tunnel2', ' ip address 192.168.23.2 255.255.255.0', ' tunnel source TwoGigabitEthernet0/0/0', ' tunnel destination 10.0.23.1', ' tunnel mode ipsec ipv4', ' tunnel protection ipsec profile SPOKE-IPSEC'])}
<p>Now look at the hub's two tunnels:</p>
${cfg('r2', ['show crypto ikev2 sa'])}
<p>The hub has one SA per spoke. The R2–R1 tunnel shows ML-KEM-768 because both ends support it. The R2–R3 tunnel stays classical: R3 does not offer <code>pqc</code>, so the hub falls back to plain DH group 20. That is <code>optional</code> doing its job: <b>no breakage, graceful fallback</b>.</p>
<div class="goal">Goal: the R2–R3 SA is up and classical while R2–R1 stays on ML-KEM. Check it with <code>show crypto ikev2 sa</code> on R2.</div>`,
    run: [...runOf('r3', ['configure terminal',
      'crypto ikev2 proposal SPOKE-PROPOSAL', 'encryption aes-cbc-256', 'integrity sha512', 'group 20', 'exit',
      'crypto ikev2 policy SPOKE-POLICY', 'proposal SPOKE-PROPOSAL', 'exit',
      'crypto ikev2 keyring SPOKE-KEYRING', 'peer R2', 'address 10.0.23.1', `pre-shared-key ${PSK}`, 'exit', 'exit',
      'crypto ikev2 profile SPOKE-PROFILE', 'match identity remote address 10.0.23.1 255.255.255.255', 'authentication remote pre-share', 'authentication local pre-share', 'keyring local SPOKE-KEYRING', 'exit',
      'crypto ipsec profile SPOKE-IPSEC', 'set transform-set CLASSICAL-TS', 'set ikev2-profile SPOKE-PROFILE', 'set pfs', 'exit',
      'interface Tunnel2', 'ip address 192.168.23.2 255.255.255.0', 'tunnel source TwoGigabitEthernet0/0/0', 'tunnel destination 10.0.23.1', 'tunnel mode ipsec ipv4', 'tunnel protection ipsec profile SPOKE-IPSEC', 'end',
      'ping 192.168.23.1']), ['r2', 'show crypto ikev2 sa']],
    validate: ctx => { const a = ctx.lab.saBetween('r2', 'r3'), b = ctx.lab.saBetween('r1', 'r2'); return !!(a && !a.params.pqc && b && b.params.pqc && ran(ctx, 'r2', /^show crypto ikev2 sa/)); },
    hints: [{ when: (d, c) => d === 'r3' && /^pqc /.test(c), text: 'In this step R3 plays the <b>legacy</b> spoke: leave <code>pqc</code> out of its proposal for now. You will upgrade it in the next step.' }],
  },

  /* ───────────────────────── 13 ───────────────────────── */
  {
    id: 'upgrade-r3', title: 'Upgrade R3 — zero outage', part: 'pqc', devices: ['r3', 'r2'],
    html: `
<p>When R3's turn comes, the upgrade is a single line:</p>
${cfg('r3', ['crypto ikev2 proposal SPOKE-PROPOSAL', ' pqc mlkem768 optional'])}
<p>Renegotiate from the hub and check both tunnels:</p>
${cfg('r2', ['clear crypto ikev2 sa', 'ping 192.168.12.1', 'ping 192.168.23.2', 'show crypto ikev2 sa'])}
<p>Both tunnels are now quantum-safe. R1 was never touched, and its tunnel only renegotiated because you cleared the SAs on the hub.</p>
<div class="goal">Goal: both hub SAs show <code>PQC Key Exchange: ML-KEM-768</code>.</div>`,
    run: [...runOf('r3', ['configure terminal', 'crypto ikev2 proposal SPOKE-PROPOSAL', 'pqc mlkem768 optional', 'end']),
      ...runOf('r2', ['clear crypto ikev2 sa', 'ping 192.168.12.1', 'ping 192.168.23.2', 'show crypto ikev2 sa'])],
    validate: ctx => { const a = ctx.lab.saBetween('r2', 'r3'), b = ctx.lab.saBetween('r1', 'r2'); return !!(a && a.params.pqc && b && b.params.pqc); },
    hints: [{ when: (d, c, r, lab) => d === 'r2' && /^show crypto ikev2 sa/.test(c) && proposalsOf(lab, 'r3').some(p => p.pqc) && lab.saBetween('r2', 'r3') && !lab.saBetween('r2', 'r3').params.pqc, text: 'R3 offers ML-KEM now, but the R2–R3 SA predates the change. Run <code>clear crypto ikev2 sa</code> on R2.' }],
  },

  /* ───────────────────────── 14 ───────────────────────── */
  {
    id: 'enforce', title: 'Enforce PQC at the hub', part: 'pqc', devices: ['r2'],
    html: `
<p>Once every spoke is upgraded, remove the <code>optional</code> keyword on the hub. As the ${guide('configuration guide')} puts it, a device configured for PQC whose peer does not support it fails the session. Classical-only peers are now <b>rejected</b> instead of silently falling back:</p>
${cfg('r2', ['crypto ikev2 proposal HUB-PROPOSAL', ' pqc mlkem768'])}
${cfg('r2', ['clear crypto ikev2 sa', 'ping 192.168.12.1', 'ping 192.168.23.2', 'show crypto ikev2 sa'])}
${callout('tip', 'Prove the enforcement. On R3, run <code>no pqc mlkem768 optional</code> under <code>SPOKE-PROPOSAL</code>, then <code>clear crypto ikev2 sa</code> on R2. The R2–R3 tunnel now fails with NO_PROPOSAL_CHOSEN; click its arc to see why. Restore the line on R3 afterwards.')}
${callout('info', 'The blog calls this "change optional to required". On IOS XE there is no <code>required</code> keyword: re-entering <code>pqc mlkem768</code> without <code>optional</code> is what enforces it. Check with <code>show running-config | section HUB-PROPOSAL</code>.')}
<div class="goal">Goal: the hub's proposal has <code>pqc mlkem768</code> without <code>optional</code>, and both tunnels are up with ML-KEM-768.</div>`,
    run: runOf('r2', ['configure terminal', 'crypto ikev2 proposal HUB-PROPOSAL', 'pqc mlkem768', 'end', 'clear crypto ikev2 sa', 'ping 192.168.12.1', 'ping 192.168.23.2', 'show crypto ikev2 sa']),
    validate: ctx => {
      const req = proposalsOf(ctx.lab, 'r2').some(p => p.pqc && p.pqc.mode === 'required');
      const a = ctx.lab.saBetween('r2', 'r3'), b = ctx.lab.saBetween('r1', 'r2');
      return req && !!(a && a.params.pqc && b && b.params.pqc);
    },
    hints: [],
  },

  /* ───────────────────────── 15 ───────────────────────── */
  {
    id: 'wrap', title: 'Where we stand', part: 'intro', devices: [],
    html: `
<p>The key exchange is done. You took the same three routers through the full arc:</p>
<table class="t">
<tr><th>Stage</th><th>Show output</th><th>Trade-off</th></tr>
<tr><td><span class="pill classic">Classical</span></td><td><code>DH Grp:20</code></td><td>Vulnerable to "harvest now, decrypt later"</td></tr>
<tr><td><span class="pill ppk">PPK</span></td><td><code>Quantum-safe Encryption using Manual PPK</code></td><td>Works on any platform, but secrets must be distributed out of band</td></tr>
<tr><td><span class="pill pqc">ML-KEM</span></td><td><code>PQC Key Exchange: ML-KEM-768</code></td><td>No extra secrets; IKEv2 fragmentation recommended</td></tr>
<tr><td><span class="pill pqc">PFS</span></td><td><code>PFS (Y/N): Y … ML-KEM-768</code></td><td><code>set pfs</code> on both sides keeps rekeys quantum-safe</td></tr>
<tr><td><span class="pill hub">Migration</span></td><td><code>pqc mlkem768 optional</code> → <code>pqc mlkem768</code></td><td>Upgrade the hub first, then the spokes at your own pace</td></tr>
</table>
<p>PPK and ML-KEM are <b>alternatives</b>, not layers you stack. Use PPK while a platform lacks ML-KEM; once it has it, ML-KEM is the cleaner path.</p>
${callout('warn', '<b>The missing half: authentication.</b> Every tunnel here still authenticates with a pre-shared key. At scale, per-tunnel PSKs don\'t work, and RSA or ECDSA certificates are forgeable by a future quantum computer. Part 10 covers ML-DSA certificates on IOS XE.')}
<p class="src">Reference: ${guide('Cisco IOS XE — Post-Quantum Cryptography on Cisco 8000 Series Secure Routers for IKEv2 Sessions')}. It also covers DMVPN and FlexVPN, the upgrade scenarios table and troubleshooting messages.</p>
<p class="src">Continue with the series on <a href="https://blogs.cisco.com/author/juliogomez" target="_blank" rel="noopener">Cisco Blogs</a>: Part 10, <i>ML-DSA Certificates on Cisco Routers</i>.</p>`,
    run: [], validate: () => true, hints: [],
  },
  ];

  const BY_ID = Object.fromEntries([...STEPS, CLASSIC_INTRO, CLASSIC_WRAP].map(x => [x.id, x]));
  const TRACKS = {
    full: { title: 'Post-Quantum Key Exchange on Cisco Routers', badge: 'v3 · 3 routers', kicker: 'IPsec Series · Part 9 — hands-on', steps: STEPS.map(x => x.id) },
    classic: { title: 'Classic Site-to-Site VPN (IKEv2 + VTI)', badge: 'Classic VPN', kicker: 'IKEv2 + VTI — the classical baseline', finish: 'Lab complete — classic IKEv2 VPN built and proven', steps: ['intro-classic', 'underlay', 'r1-classic', 'r3-classic', 'baseline', 'wrap-classic'] },
  };
  const api = { STEPS, TRACKS, BY_ID, BLOG_URL, GUIDE_URL, helpers: { chainTo, hasPolicy, proposalsOf } };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.TUTORIAL = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
