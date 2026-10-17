/* gre-steps.js — super simple lab: a GRE tunnel over a WAN (R1 ⇄ R3 through R2).
   Behaviour follows Cisco's GRE documentation (see the engine's _greState). Step shape as in v3/v5. */
(function (root) {
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const cfg = (dev, lines, note) => `<div class="cfg"><div class="cfg-head"><span class="dev-chip dev-${dev}">${dev.toUpperCase()}</span>${note ? `<span class="cfg-note">${note}</span>` : ''}</div><pre>${esc(lines.join('\n'))}</pre></div>`;
  const out = lines => `<pre class="out">${esc(lines.join('\n'))}</pre>`;
  const callout = (kind, html) => `<div class="callout ${kind}">${html}</div>`;
  const runOf = (dev, lines) => lines.map(c => [dev, c]);
  const EDU_NOTICE = callout('edu', `<b>🎓 For learning only.</b> This is a simulator to practise IOS XE commands. It is not a real router: output can differ from real platforms, so <b>don't use it to validate configurations</b>. Provided <b>as is</b>, with no warranty and no support. <a href="https://github.com/ioeacademy/spotlight-pqc/blob/main/DISCLAIMER.md" target="_blank" rel="noopener">Full disclaimer</a>.`);
  const TAC = '<a href="https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/118361-technote-gre-00.html" target="_blank" rel="noopener">Cisco: what impacts GRE tunnel states</a>';
  const KA = '<a href="https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/63760-gre-keepalives-63760.html" target="_blank" rel="noopener">Cisco: how GRE keepalives work</a>';

  /* ---------- checks (network state, not names) ---------- */
  const since = (ctx, dev, test) => ctx.lab.cmdLog.filter(e => e.seq > ctx.since && e.dev === dev && e.ok).some(test);
  const pingOk = (ctx, dev, dst, viaTunnel) => since(ctx, dev, e => e.meta && e.meta.kind === 'ping' && e.meta.dst === dst && e.meta.succ > 0 && (!viaTunnel || (e.meta.path && e.meta.path.fwd.some(h => h.via === 'tunnel'))));
  // a GRE tunnel on `dev` from its WAN address towards `peer`, with an address in the tunnel subnet
  const greTo = (lab, dev, peer) => Object.values(lab.dev(dev).ifaces).find(i => i.kind === 'tunnel' && i.tunnel.mode === 'gre ip' && i.tunnel.dest === peer && i.ip);

  const T1 = ['configure terminal', 'interface Tunnel0', ' ip address 192.168.100.1 255.255.255.252', ' tunnel source GigabitEthernet0/0/0', ' tunnel destination 192.0.23.2', 'end'];
  const T3 = ['configure terminal', 'interface Tunnel0', ' ip address 192.168.100.2 255.255.255.252', ' tunnel source GigabitEthernet0/0/0', ' tunnel destination 192.0.12.1', 'end'];
  const shown = l => l.slice(1, -1);

  const STEPS = [
    {
      id: 'g-intro', title: 'A tunnel across the WAN', part: 'intro', devices: [],
      html: `
${EDU_NOTICE}
<p>R1 and R3 each have a LAN (a loopback). Between them sits R2, the "WAN": it knows the WAN subnets but <b>nothing about the LANs</b>. A <b>GRE tunnel</b> joins R1 and R3 directly: it wraps each LAN packet in a new IP packet addressed from R1's WAN address to R3's, so R2 only ever sees WAN addresses.</p>
<table class="t mono">
<tr><th></th><th>Interface</th><th>Address</th></tr>
<tr><td>R1</td><td>Gi0/0/0 (WAN)</td><td>192.0.12.1/30</td></tr>
<tr><td>R1</td><td>Loopback1 (LAN)</td><td>10.1.1.1/24</td></tr>
<tr><td>R2</td><td>Gi0/0/0 / Gi0/0/1</td><td>192.0.12.2/30 / 192.0.23.1/30</td></tr>
<tr><td>R3</td><td>Gi0/0/0 (WAN)</td><td>192.0.23.2/30</td></tr>
<tr><td>R3</td><td>Loopback1 (LAN)</td><td>10.3.3.3/24</td></tr>
<tr><td>Tunnel0</td><td>GRE/IP</td><td>192.168.100.1 (R1) ⇄ .2 (R3), /30</td></tr>
</table>
<p>The WAN links use <b>public-style</b> addresses, as an Internet link would, each a /30 with one address per end. The third octet names the link (<b>12</b> = R1–R2, <b>23</b> = R2–R3) so they are easy to remember. These are lab addresses only: 192.0.12.0 and 192.0.23.0 belong to real networks, so the ranges <a href="https://www.rfc-editor.org/rfc/rfc5737" target="_blank" rel="noopener">RFC 5737</a> reserves for examples (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are the right choice outside a closed lab. The LANs and the tunnel use private <a href="https://www.rfc-editor.org/rfc/rfc1918" target="_blank" rel="noopener">RFC 1918</a> addresses, which the Internet does not route: that is why they need the tunnel.</p>
${callout('info', 'Type commands in the consoles on the right (<kbd>?</kbd> for help, <kbd>Tab</kbd> to complete), or use <b>▶</b> on a snippet and <b>Show Me</b>. Each step checks what the network actually does.')}`,
      run: [], validate: () => true, hints: [],
    },
    {
      id: 'g-wan', title: 'Make the WAN work', part: 'base', devices: ['r1', 'r3'],
      html: `
<p>The tunnel runs <b>between the WAN addresses</b>, so first R1 must reach 192.0.23.2 and R3 must reach 192.0.12.1. R2 already knows both WAN subnets; the spokes need a route through it:</p>
${cfg('r1', ['configure terminal', 'ip route 192.0.23.0 255.255.255.252 192.0.12.2', 'end'])}
${cfg('r3', ['configure terminal', 'ip route 192.0.12.0 255.255.255.252 192.0.23.1', 'end'])}
${cfg('r1', ['ping 192.0.23.2'], 'test')}
<div class="goal">Goal: R1 can ping R3's WAN address 192.0.23.2.</div>`,
      run: [['r1', 'enable'], ...runOf('r1', ['configure terminal', 'ip route 192.0.23.0 255.255.255.252 192.0.12.2', 'end']), ['r3', 'enable'], ...runOf('r3', ['configure terminal', 'ip route 192.0.12.0 255.255.255.252 192.0.23.1', 'end']), ['r1', 'ping 192.0.23.2']],
      validate: ctx => pingOk(ctx, 'r1', '192.0.23.2'),
      hints: [{ when: (d, c, r, lab) => d === 'r1' && /^ping 192\.0\.23\.2/.test(c) && !lab.cmdLog.slice(-1)[0].meta.succ, text: 'Both directions need a route: R1 towards 192.0.23.0/30 <i>and</i> R3 back towards 192.0.12.0/30.' }],
    },
    {
      id: 'g-r1', title: 'Create the tunnel on R1', part: 'base', devices: ['r1'],
      html: `
<p>A GRE tunnel is just an interface with an address, a <b>source</b> (where it starts) and a <b>destination</b> (where it ends). GRE is the default tunnel mode, so no <code>tunnel mode</code> line is needed:</p>
${cfg('r1', shown(T1))}
<table class="t">
<tr><td><code>ip address 192.168.100.1 …252</code></td><td>The tunnel's own subnet (/30: two addresses, one per end).</td></tr>
<tr><td><code>tunnel source Gi0/0/0</code></td><td>Outer packets leave from R1's WAN address, 192.0.12.1.</td></tr>
<tr><td><code>tunnel destination 192.0.23.2</code></td><td>…and are sent to R3's WAN address.</td></tr>
</table>
${cfg('r1', ['show ip interface brief | include Tunnel', 'show interfaces Tunnel0 | include line protocol|Tunnel protocol|Keepalive'], 'check')}
${callout('warn', '<b>Surprise:</b> Tunnel0 is already <b>up/up</b>, although R3 has no tunnel yet. Cisco: a GRE tunnel comes up as soon as its source is up and its destination is <i>routable</i>. Without keepalives it cannot know whether anything is listening at the far end.')}
<div class="goal">Goal: R1 has a GRE Tunnel0 towards 192.0.23.2, and you checked its state.</div>`,
      run: [...runOf('r1', T1), ['r1', 'show ip interface brief | include Tunnel'], ['r1', 'show interfaces Tunnel0 | include line protocol|Tunnel protocol|Keepalive']],
      validate: ctx => !!greTo(ctx.lab, 'r1', '192.0.23.2') && since(ctx, 'r1', e => /^show (ip interface brief|interfaces)/.test(e.canon)),
      hints: [
        { when: (d, c) => d === 'r1' && /^tunnel destination 192\.0\.12\.2/.test(c), text: 'The tunnel ends on <b>R3</b> (192.0.23.2). R2 only carries the outer packets.' },
        { when: (d, c) => d === 'r1' && /^tunnel mode ipsec/.test(c), text: 'That turns it into an IPsec VTI. For this lab keep GRE: <code>tunnel mode gre ip</code> (or <code>no tunnel mode</code>).' },
      ],
    },
    {
      id: 'g-r3', title: 'Mirror it on R3', part: 'base', devices: ['r3', 'r1'],
      html: `
<p>Try first: from R1, <code>ping 192.168.100.2</code>. It fails: R1 sends GRE packets to R3, but R3 has no tunnel to receive them, so it drops them. Now build the mirror image, with source and destination swapped:</p>
${cfg('r3', shown(T3))}
${cfg('r1', ['ping 192.168.100.2'], 'test')}
${callout('info', 'The topology now shows the tunnel as a dotted arc: <b>GRE · not encrypted</b>. Click it to see both ends.')}
<div class="goal">Goal: R1 pings R3's tunnel address 192.168.100.2 through the tunnel.</div>`,
      run: [...runOf('r3', ['enable', ...T3]), ['r1', 'ping 192.168.100.2']],
      validate: ctx => pingOk(ctx, 'r1', '192.168.100.2', true),
      hints: [
        { when: (d, c) => d === 'r3' && /^tunnel destination 192\.0\.23\./.test(c), text: 'On R3 the destination is R1\'s WAN address, <code>192.0.12.1</code>.' },
        { when: (d, c, r, lab) => d === 'r1' && /^ping 192\.168\.100\.2/.test(c) && !lab.cmdLog.slice(-1)[0].meta.succ && !greTo(lab, 'r3', '192.0.12.1'), text: 'R3 needs its own Tunnel0 whose source and destination mirror R1\'s.' },
      ],
    },
    {
      id: 'g-lan', title: 'Send the LANs through the tunnel', part: 'verify', devices: ['r1', 'r3'],
      html: `
<p>The tunnel works, but the LANs don't use it yet. Tell each router that the other LAN is <b>behind the tunnel</b>:</p>
${cfg('r1', ['configure terminal', 'ip route 10.3.3.0 255.255.255.0 192.168.100.2', 'end'])}
${cfg('r3', ['configure terminal', 'ip route 10.1.1.0 255.255.255.0 192.168.100.1', 'end'])}
${cfg('r1', ['ping 10.3.3.3 source Loopback1', 'traceroute 10.3.3.3'], 'test')}
<p>Expected output: the ping succeeds from R1's LAN address, and the traceroute reaches R3 in one hop.</p>
${out(['R1#ping 10.3.3.3 source Loopback1', '…', '!!!!!', 'Success rate is 100 percent (5/5)', '', 'R1#traceroute 10.3.3.3', '…', '  1 192.168.100.2 3 msec *  2 msec'])}
<p>The traceroute shows <b>one hop</b>, straight to R3: R2 is invisible, because the LAN packets travel inside GRE. R2 never learned a route to 10.1.1.0 or 10.3.3.0, and it doesn't need one.</p>
<p>The hop is listed as <code>192.168.100.2</code>, R3's tunnel address, not 10.3.3.3: a router answers a traceroute from the interface it uses to reach the sender. Without a <code>source</code>, R1's traceroute leaves from its Tunnel0 address 192.168.100.1, and R3 reaches that address through its own Tunnel0. The <code>*</code> in the middle is normal: IOS rate-limits the ICMP replies, so one of the three probes goes unanswered.</p>
${callout('warn', '<b>Don\'t route the WAN into the tunnel.</b> If the route to the tunnel destination (192.0.23.2) pointed into Tunnel0, the tunnel would carry itself: IOS logs <code>%TUN-5-RECURDOWN: Tunnel0 temporarily disabled due to recursive routing</code> and the tunnel goes down. Try it with <code>ip route 192.0.23.2 255.255.255.255 Tunnel0</code>, then remove it.')}
<div class="goal">Goal: R1 pings 10.3.3.3 from its LAN (source Loopback1), through the tunnel.</div>`,
      run: [...runOf('r1', ['configure terminal', 'ip route 10.3.3.0 255.255.255.0 192.168.100.2', 'end']), ...runOf('r3', ['configure terminal', 'ip route 10.1.1.0 255.255.255.0 192.168.100.1', 'end']), ['r1', 'ping 10.3.3.3 source Loopback1'], ['r1', 'traceroute 10.3.3.3']],
      validate: ctx => since(ctx, 'r1', e => e.meta && e.meta.kind === 'ping' && e.meta.dst === '10.3.3.3' && e.meta.succ > 0 && e.meta.src === '10.1.1.1' && e.meta.path && e.meta.path.fwd.some(h => h.via === 'tunnel')),
      hints: [
        { when: (d, c, r, lab) => d === 'r1' && /^ping 10\.3\.3\.3/.test(c) && !/source/.test(c), text: 'Add <code>source Loopback1</code>: the test is LAN to LAN. Without it, the ping leaves from the tunnel address.' },
        { when: (d, c, r, lab) => d === 'r1' && /^ping 10\.3\.3\.3/.test(c) && !lab.cmdLog.slice(-1)[0].meta.succ, text: 'The reply needs a way back: R3 must route 10.1.1.0/24 into its tunnel (next hop 192.168.100.1).' },
      ],
    },
    {
      id: 'g-mtu', title: 'Adjust the tunnel MTU', part: 'verify', devices: ['r1', 'r3'],
      html: `
<p>Every packet in the tunnel gets an extra <b>24 bytes</b>: a new 20-byte IP header and a 4-byte GRE header. The WAN still carries at most 1500 bytes, so the biggest packet that fits inside the tunnel is <b>1500 − 24 = 1476 bytes</b>. That is the tunnel's default IP MTU. See it with the <b>DF</b> (don't fragment) bit set:</p>
${cfg('r1', ['show ip interface Tunnel0 | include MTU', 'ping 10.3.3.3 source Loopback1 size 1476 df-bit', 'ping 10.3.3.3 source Loopback1 size 1477 df-bit'], 'test')}
${out(['Packet sent with the DF bit set', 'M.M.M', 'Success rate is 0 percent (0/5)'])}
<p><b>M</b> means "fragmentation needed": the packet is too big for the tunnel and DF forbids splitting it. Without DF the router fragments it: it gets through, but every big packet becomes two, which costs CPU and throughput, and many applications set DF anyway.</p>
<p>Cisco's recommendation is to lower the tunnel MTU and clamp TCP, on <b>both</b> routers:</p>
${cfg('r1', ['interface Tunnel0', ' ip mtu 1400', ' ip tcp adjust-mss 1360'])}
${cfg('r3', ['interface Tunnel0', ' ip mtu 1400', ' ip tcp adjust-mss 1360'])}
<table class="t">
<tr><td><code>ip mtu 1400</code></td><td>The largest IP packet the router sends into the tunnel. 1400 leaves room for more headers: Cisco recommends it because it "covers the most common GRE + IPsec combinations", so the value still works when you encrypt the tunnel later.</td></tr>
<tr><td><code>ip tcp adjust-mss 1360</code></td><td>Rewrites the MSS in TCP SYN packets crossing the tunnel: 1400 − 20 (IP) − 20 (TCP) = 1360. Hosts then never send TCP segments that need fragmenting, even when the ICMP messages that path MTU discovery relies on are filtered.</td></tr>
</table>
${cfg('r1', ['show ip interface Tunnel0 | include MTU', 'ping 10.3.3.3 source Loopback1 size 1400 df-bit', 'ping 10.3.3.3 source Loopback1 size 1401 df-bit'], 'check')}
<p class="src">Reference: ${'<a href="https://www.cisco.com/c/en/us/support/docs/ip/generic-routing-encapsulation-gre/25885-pmtud-ipfrag.html" target="_blank" rel="noopener">Cisco: IPv4 fragmentation, MTU, MSS and PMTUD with GRE and IPsec</a>'}.</p>
<div class="goal">Goal: Tunnel0 on R1 and R3 uses <code>ip mtu 1400</code> and <code>ip tcp adjust-mss 1360</code>, and you tested it with a DF ping.</div>`,
      run: [...runOf('r1', ['show ip interface Tunnel0 | include MTU', 'ping 10.3.3.3 source Loopback1 size 1476 df-bit', 'ping 10.3.3.3 source Loopback1 size 1477 df-bit']),
        ...runOf('r1', ['configure terminal', 'interface Tunnel0', 'ip mtu 1400', 'ip tcp adjust-mss 1360', 'end']),
        ...runOf('r3', ['configure terminal', 'interface Tunnel0', 'ip mtu 1400', 'ip tcp adjust-mss 1360', 'end']),
        ...runOf('r1', ['show ip interface Tunnel0 | include MTU', 'ping 10.3.3.3 source Loopback1 size 1400 df-bit', 'ping 10.3.3.3 source Loopback1 size 1401 df-bit'])],
      validate: ctx => ['r1', 'r3'].every(k => { const t = greTo(ctx.lab, k, k === 'r1' ? '192.0.23.2' : '192.0.12.1'); return t && t.ipMtu && t.ipMtu <= 1400 && t.mss && t.mss <= t.ipMtu - 40; })
        && since(ctx, 'r1', e => e.meta && e.meta.kind === 'ping' && / df-bit/.test(e.canon)),
      hints: [
        { when: (d, c) => /^ip tcp adjust-mss (\d+)/.test(c) && +/^ip tcp adjust-mss (\d+)/.exec(c)[1] > 1360, text: 'The MSS is the TCP payload: tunnel MTU minus 40 bytes of IP and TCP headers. With <code>ip mtu 1400</code> that is <code>1360</code>.' },
        { when: (d, c, r, lab) => /^ip mtu/.test(c) && lab.dev(d).mode === 'if' && lab.dev(d).ctx.iface !== 'Tunnel0', text: 'Set the MTU on <b>Tunnel0</b>, not on the WAN interface: the WAN still carries full 1500-byte packets.' },
      ],
    },
    {
      id: 'g-wrap', title: 'Done: a GRE tunnel', part: 'intro', devices: [],
      html: `
<p>A handful of commands per router built a tunnel that carries your LANs across a WAN that knows nothing about them.</p>
<table class="t">
<tr><th>What you saw</th><th>Why</th></tr>
<tr><td>Tunnel0 up/up before R3 existed</td><td>Line protocol only needs a working source and a <i>routable</i> destination (${TAC}).</td></tr>
<tr><td>Ping failed until R3 had a tunnel</td><td>The far end must have a tunnel with mirrored source and destination to decapsulate.</td></tr>
<tr><td>Traceroute: one hop</td><td>The WAN is hidden inside GRE.</td></tr>
<tr><td>A route change takes a few seconds to move the tunnel</td><td>IOS XE re-checks a GRE tunnel's line protocol about every 10 seconds after a route or source-address change; its own commands (<code>shutdown</code>, <code>tunnel destination</code>) act at once.</td></tr>
<tr><td><code>M.M.M</code> above 1476 bytes</td><td>GRE adds 24 bytes; <code>ip mtu 1400</code> + <code>ip tcp adjust-mss 1360</code> keep packets from needing fragmentation.</td></tr>
</table>
${callout('tip', '<b>Try recursive routing.</b> On R1: <code>ip route 192.0.23.2 255.255.255.255 192.168.100.2</code> sends the tunnel\'s own destination into the tunnel. Watch <code>%ADJ-5-PARENT</code>, then <code>%TUN-5-RECURDOWN</code>: IOS shuts the tunnel for a minute, brings it back and shuts it again while the route remains. Remove the route with <code>no ip route …</code>.')}
${callout('tip', '<b>Try keepalives.</b> On R1: <code>interface Tunnel0</code> → <code>keepalive 2 2</code>. Then shut Tunnel0 on R3: after two missed keepalives R1\'s tunnel goes down by itself (' + KA + ').')}
${callout('warn', '<b>GRE is not encrypted.</b> Anyone on the WAN can read the LAN packets. To encrypt them, turn the tunnel into an IPsec VTI: the <a href="../v5-quickstart/?track=classic">Classic VPN quick lab</a> builds one, and the PQC labs make it quantum-safe.')}`,
      run: [], validate: () => true, hints: [],
    },
  ];
  const BY_ID = Object.fromEntries(STEPS.map(s => [s.id, s]));
  const TRACKS = { gre: { title: 'Quick lab · GRE tunnel over a WAN', badge: 'GRE', kicker: 'Short lab — a simple tunnel across a WAN', finish: 'Lab complete — your LANs talk through a GRE tunnel', steps: STEPS.map(s => s.id) } };
  const api = { STEPS, TRACKS, BY_ID, DEFAULT_TRACK: 'gre' };
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.TUTORIAL = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
