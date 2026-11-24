/* ==========================================================================
   journey-steps.js — the tutorial text of the IKEv2 Packet Journey, in the labs' step format
     one intro step, then one step per phase of the capture (META[sc].phases, by name).
   Each step: { title, part, goal, html(sc, ctx) } — ctx gives numbers computed from the capture:
     ctx.bytes(phaseName) total frame bytes, ctx.frames(phaseName), ctx.M (META[sc]), ctx.other (META of the other capture)
   ========================================================================== */
(function (root) {
  const fmt = n => Number(n).toLocaleString('en-US');
  const callout = (kind, html) => `<div class="callout ${kind}">${html}</div>`;
  const DISCLAIMER = 'https://github.com/ioeacademy/spotlight-pqc/blob/main/DISCLAIMER.md';
  const filter = f => `<button type="button" class="fchip" data-f="${f.replace(/"/g, '&quot;')}" title="Apply this display filter in the capture">${f.replace(/</g, '&lt;')}</button>`;

  const EDU = callout('edu', `<b>🎓 For education only.</b> These are real captures from a lab, decoded for learning: your devices can behave differently. <a href="${DISCLAIMER}" target="_blank" rel="noopener">Full disclaimer</a>.`);

  const LAB_TABLE = `<table class="t mono">
<tr><th></th><th>Role</th><th>Interface</th><th>Address</th></tr>
<tr><td>R1</td><td>IPsec peer, initiator</td><td>r1-g1</td><td>198.51.100.1/30</td></tr>
<tr><td rowspan="2">R2</td><td rowspan="2">Transit, no IPsec</td><td>r2-g1</td><td>198.51.100.2/30</td></tr>
<tr><td>r2-g2</td><td>203.0.113.1/30</td></tr>
<tr><td>R3</td><td>IPsec peer, responder</td><td>r3-g1</td><td>203.0.113.2/30</td></tr>
</table>
<p>The tunnel protects traffic between the two sites, <code>10.1.0.0/24</code> behind R1 and <code>10.3.0.0/24</code> behind R3.</p>`;

  const INTRO = {
    title: 'Two real IKEv2 captures, one packet at a time',
    part: 'intro',
    html: (sc, ctx) => `
      ${EDU}
      <p>In this tutorial you replay a <b>real IKEv2 capture</b> across three routers, one packet at a time, and inspect every frame as Wireshark decodes it. There is nothing to configure: you watch, pause and look inside.</p>
      <p>Choose the capture to follow. You can switch at any time; the journey keeps your place.</p>
      <div class="scen" role="radiogroup" aria-label="Capture">
        <button type="button" role="radio" data-sc="classic" aria-checked="${sc === 'classic'}"><span class="t">Classical VPN</span><span class="s">X25519 · ${fmt(ctx.setup('classic'))} B · ${ctx.rtt('classic')} round trips</span></button>
        <button type="button" role="radio" data-sc="hybrid" aria-checked="${sc === 'hybrid'}"><span class="t">Hybrid post-quantum VPN</span><span class="s">X25519 + ML-KEM-768 · ${fmt(ctx.setup('hybrid'))} B · ${ctx.rtt('hybrid')} round trips</span></button>
      </div>
      <h4>The lab</h4>
      ${LAB_TABLE}
      ${callout('info', '<b>Where the capture was taken.</b> dumpcap ran on R2, interface <code>r2-g1</code>, the side facing R1. Like a SPAN port, it records both directions of link R1–R2. Link R2–R3 was not captured.')}
      <h4>How it works</h4>
      <ul>
        <li><b>Step</b> (<kbd>→</kbd>) moves one packet one hop; <b>Play</b> (<kbd>Space</kbd>) keeps going. Both are in the bar at the bottom.</li>
        <li>Frames appear in the <b>Capture</b> tab on the right as they cross the capture point. Click a frame, a field or a byte to inspect it.</li>
        <li>Each step below covers one phase of the exchange and completes when its packets have crossed. <b>▶ Play this phase</b> replays just that part.</li>
      </ul>`,
  };

  const P = {};
  P['Address resolution'] = {
    title: 'Find the next hop',
    part: 'link',
    goal: 'Watch R1 learn the MAC address of its next hop before any IKE packet can leave.',
    html: () => `
      <p>R1 knows R3's address, <code>203.0.113.2</code>, but Ethernet delivers frames by MAC address, one link at a time. R1's route to R3 goes through R2 (<code>198.51.100.2</code>), so R1 broadcasts an <b>ARP request</b> for R2's MAC address and R2 answers.</p>
      ${callout('info', 'ARP never leaves its link. R2 does the same on link R2–R3, but that link was not captured, so you only see link R1–R2 here.')}`,
  };
  P['IKE_SA_INIT'] = {
    title: 'IKE_SA_INIT: agree and exchange keys',
    part: 'ike',
    goal: 'Watch the two peers agree on algorithms and run a key exchange, in clear text.',
    html: (sc, ctx) => sc === 'classic' ? `
      <p>R1 offers <b>AES-GCM-256</b> encryption, <b>HMAC-SHA2-384</b> as PRF and an <b>X25519</b> key exchange, with its 32-byte X25519 public value and a nonce. R3 accepts and returns its own. Both routers now compute the same shared secret and derive the IKE keys: every later IKE message is encrypted.</p>
      ${callout('warn', '<b>Record now, decrypt later.</b> These two clear-text messages are all an attacker needs to keep. A future quantum computer that breaks X25519 recovers the IKE keys, and with them everything those keys protect.')}
      <p>On the wire: <b>${fmt(ctx.bytes('IKE_SA_INIT'))} bytes</b> for the two messages, on UDP 500. Try ${filter('isakmp')}.</p>` : `
      <p>The same exchange as in the classical VPN, with one extra transform in R1's proposal: <b>Additional Key Exchange 1 = ML-KEM-768</b> (transform type 6, ID 36, RFC 9370), and the notify <code>INTERMEDIATE_EXCHANGE_SUPPORTED</code>. R3 accepts both.</p>
      <p>The ML-KEM key itself is <b>not</b> sent yet: IKE_SA_INIT is clear text and IKEv2 cannot fragment it. Both routers first derive IKE keys from X25519; those keys protect the next exchange, which carries ML-KEM.</p>
      <p>On the wire: <b>${fmt(ctx.bytes('IKE_SA_INIT'))} bytes</b>, ${fmt(ctx.bytes('IKE_SA_INIT') - ctx.otherBytes('IKE_SA_INIT'))} more than the classical ${fmt(ctx.otherBytes('IKE_SA_INIT'))}. Try ${filter('isakmp')}.</p>`,
    after: () => callout('info', 'After this exchange the peers move from UDP 500 to <b>UDP 4500</b>: strongSwan\'s userspace IPsec in this lab requires UDP-encapsulated ESP, so they behave as if a NAT were in the path.'),
  };
  P['IKE_INTERMEDIATE · ML-KEM'] = {
    title: 'IKE_INTERMEDIATE: the ML-KEM round',
    part: 'pqc',
    goal: 'Watch the large post-quantum key cross the network, encrypted and split into two fragments.',
    html: (sc, ctx) => `
      <p>R1 sends its <b>ML-KEM-768 encapsulation key</b> (1,184 bytes) in a new exchange, <b>IKE_INTERMEDIATE</b> (RFC 9242), already encrypted with the X25519 keys. The IKE message is 1,249 bytes: one byte over the 1,248 bytes that strongSwan's <code>fragment_size</code> of 1,280 leaves for IKE on UDP 4500. IKEv2 splits it into <b>two fragments</b> (RFC 7383).</p>
      <p>R3 encapsulates a fresh secret to that key and returns the <b>1,088-byte ciphertext</b> in one datagram. Both routers mix the ML-KEM secret into new IKE keys: from now on, breaking X25519 alone is not enough.</p>
      ${callout('tip', 'IKE fragments are complete UDP datagrams, not IP fragments, so firewalls pass them normally.')}
      ${callout('info', `Wireshark 4.2 shows exchange type 43 as <i>Unknown</i> and ML-KEM-768 as <i>Unknown (36)</i>. Try ${filter('isakmp.exchangetype == 43')} or ${filter('frame.len > 1000')}.`)}
      <p>This round adds <b>${fmt(ctx.bytes('IKE_INTERMEDIATE · ML-KEM'))} bytes</b> and one round trip.</p>`,
  };
  P['IKE_AUTH'] = {
    title: 'IKE_AUTH: identities and the first tunnel',
    part: 'auth',
    goal: 'Watch the routers prove who they are and set up the first ESP tunnel (CHILD SA).',
    html: (sc, ctx) => `
      <p>R1 sends its identity (<code>r1.lab.example</code>), pre-shared-key authentication, the ESP proposal and the traffic selectors <code>10.1.0.0/24 ↔ 10.3.0.0/24</code>. R3 proves its own identity (<code>r3.lab.example</code>) and accepts the CHILD SA. The tunnel is up.</p>
      ${sc === 'classic'
        ? callout('warn', 'These messages are encrypted, but with keys from <b>X25519 alone</b>: a recording of them could be decrypted by a future quantum computer.')
        : callout('tip', `Same content and size as in the classical capture, but the keys now depend on <b>X25519 and ML-KEM-768</b>. Breaking X25519 alone does not reveal them.`)}
      <p>Setup complete after <b>${ctx.rtt(sc)} round trips and ${fmt(ctx.setup(sc))} bytes</b>${sc === 'hybrid' ? ` (classical: ${ctx.rtt('classic')} round trips, ${fmt(ctx.setup('classic'))} bytes). The extra cost is paid once per SA, not per packet` : ''}.</p>
      ${callout('info', 'Turn on <b>Decryption keys</b> in the Capture tab to read the identities and the proposal inside.')}`,
  };
  P['ESP traffic'] = {
    title: 'ESP: traffic through the tunnel',
    part: 'esp',
    goal: 'See what an observer on the link can, and cannot, read once the tunnel is up.',
    html: (sc, ctx) => `
      <p>Three pings from <code>10.1.0.1</code> to <code>10.3.0.1</code> and their replies, each encrypted with AES-GCM-256 in <b>ESP</b>. On the link an observer reads only the outer IP and UDP headers, the <b>SPI</b> and the <b>sequence number</b>. Each direction has its own SPI: <code>${ctx.M.spis.first[0]}</code> toward R3, <code>${ctx.M.spis.first[1]}</code> toward R1.</p>
      ${sc === 'classic'
        ? callout('warn', 'The ESP keys came from X25519 only. Recorded today, this traffic could be decrypted once X25519 is broken.')
        : callout('tip', 'The ESP keys came from X25519 + ML-KEM-768. A recording of this traffic does not help an attacker who can break only one of them.')}
      ${callout('info', `Every ESP packet is 162 bytes in <b>both</b> captures: ML-KEM costs nothing once the tunnel is up. Turn on <b>Decryption keys</b> to see the ping inside, or try ${filter('esp')}.`)}`,
  };
  P['CHILD SA rekey'] = {
    title: 'Rekey the CHILD SA',
    part: 'rekey',
    goal: 'Watch the ESP keys being replaced with a fresh key exchange (perfect forward secrecy).',
    html: (sc, ctx) => (sc === 'classic' ? `
      <p>Before the ESP SA expires, R1 sends <b>CREATE_CHILD_SA</b> with <code>REKEY_SA</code>, naming the SA to replace, and a fresh X25519 key share. R3 agrees and returns its own share and a new SPI. Then an <b>INFORMATIONAL</b> exchange deletes the old CHILD SA.</p>
      ${callout('warn', 'Forward secrecy here rests on X25519 alone.')}` : `
      <p>Before the ESP SA expires, R1 sends <b>CREATE_CHILD_SA</b> with <code>REKEY_SA</code> and a fresh X25519 share; the proposal lists ML-KEM-768 again. R3 agrees and adds <code>ADDITIONAL_KEY_EXCHANGE</code> (notify 16441) with a token that links the next round.</p>
      <p>Then <b>IKE_FOLLOWUP_KE</b> (RFC 9370) carries a brand-new ML-KEM-768 key, again in two fragments, and its ciphertext. Finally an <b>INFORMATIONAL</b> exchange deletes the old CHILD SA.</p>
      ${callout('tip', 'Every rekey runs a new ML-KEM exchange, so forward secrecy stays quantum-resistant.')}
      ${callout('info', `Wireshark 4.2 shows exchange type 44 as <i>Unknown</i>. Try ${filter('isakmp.exchangetype == 44')}.`)}`) +
      `<p>This rekey: <b>${fmt(ctx.bytes('CHILD SA rekey'))} bytes</b>${sc === 'hybrid' ? ` (classical: ${fmt(ctx.otherBytes('CHILD SA rekey'))})` : ''}.</p>`,
  };
  P['IKE SA rekey'] = {
    title: 'Rekey the IKE SA',
    part: 'rekey',
    goal: 'Watch the IKE SA itself being replaced: new IKE SPIs and new keys.',
    html: (sc, ctx) => (sc === 'classic' ? `
      <p><b>CREATE_CHILD_SA</b> again, this time for the IKE SA: new IKE SPIs and a fresh X25519 exchange. An <b>INFORMATIONAL</b> exchange then deletes the old IKE SA.</p>` : `
      <p><b>CREATE_CHILD_SA</b> again, this time for the IKE SA: new IKE SPIs and a fresh X25519 exchange, with ML-KEM-768 in the proposal and R3's <code>ADDITIONAL_KEY_EXCHANGE</code> token. <b>IKE_FOLLOWUP_KE</b> brings a new ML-KEM key and ciphertext, and an <b>INFORMATIONAL</b> exchange deletes the old IKE SA.</p>
      ${callout('tip', 'The new IKE SA keys mix X25519 and ML-KEM-768, like the first ones.')}`) +
      `<p>This rekey: <b>${fmt(ctx.bytes('IKE SA rekey'))} bytes</b>${sc === 'hybrid' ? ` (classical: ${fmt(ctx.otherBytes('IKE SA rekey'))})` : ''}.</p>`,
  };
  P['ESP on new SAs'] = {
    title: 'ESP on the new SAs',
    part: 'esp',
    goal: 'Confirm that traffic now uses the new SAs.',
    html: (sc, ctx) => `
      <p>First R2 refreshes its ARP entry for R1: routine housekeeping on link R1–R2, not part of IPsec. Then the pings run again, now with the SPIs from the rekey, <code>${ctx.M.spis.last[0]}</code> and <code>${ctx.M.spis.last[1]}</code>, and the <b>sequence numbers start again at 1</b>.</p>
      ${callout('info', `Compare an ESP frame from this phase with one from the first ESP phase: same size, new SPI, sequence back to 1. Try ${filter('esp.sequence == 1')}.`)}`,
  };
  const PART = { intro: ['Intro', 'base'], link: ['ARP', ''], ike: ['IKE', 'base'], pqc: ['ML-KEM', 'pqc'], auth: ['IKE', 'base'], esp: ['ESP', 'verify'], rekey: ['Rekey', 'base'] };

  root.JOURNEY = { INTRO, PHASES: P, PART, filter };
})(window);
