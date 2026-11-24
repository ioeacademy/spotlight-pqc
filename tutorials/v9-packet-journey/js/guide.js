/* guide.js — the "Guide" of the IKEv2 Packet Journey: which fields of the Wireshark-style decode deserve
   attention, and the floating explanation for each (what it is, why it matters).
   A rule matches a node of the protocol tree, node = [label, offset, length, source, field, children]:
     key    field name(s) to match (node[4])
     label  optional RegExp on the label (node[0])
     src    optional byte source (0 = the frame, 1 = decrypted data)
     test   optional (node, ctx) => bool, ctx = { m: frame META, sc: 'classic'|'hybrid', keys, anc: [ancestor labels] }
     title, what, why: strings or (node, ctx) => string (HTML allowed)
   The first matching rule wins; rules are tried in order. */
(function (root) {
  const hyb = (c) => c.sc === 'hybrid';
  const rekey = (c) => c.m.kind === 'CREATE_CHILD_SA' || c.m.kind === 'IKE_FOLLOWUP_KE';
  const fromR3 = (c) => c.m.dir === 'R3>R1';
  const R = [
    /* ── link and transport ── */
    { key: 'arp.dst.proto_ipv4', test: (n, c) => /who is the next hop/.test(c.m.title),
      title: 'Who has the next hop?',
      what: (n) => `The address R1 is looking for: <b>${n[0].split(': ').pop()}</b>, its next hop toward R3.`,
      why: 'Ethernet delivers frames by MAC address. Before the first IKE packet can leave, R1 needs R2\'s MAC address, and ARP asks for it on this link only.' },
    { key: 'ip.ttl', src: 0, label: /: 63$/,
      title: 'TTL 63: already routed by R2',
      what: 'The Time to Live left in the IP header: 63, one less than the 64 the sender set.',
      why: 'Frames from R3 cross R2 before they reach the capture point on r2-g1, and R2 lowers the TTL by one when it routes them. Frames from R1 are captured before R2 touches them, so they still show 64.' },
    { key: 'udp', label: /Port: 500,/,
      title: 'UDP port 500: where IKE starts',
      what: 'IKEv2 always starts on UDP port 500, in clear text.',
      why: 'After IKE_SA_INIT the peers move to port 4500: strongSwan\'s userspace IPsec in this lab uses UDP-encapsulated ESP, so they behave as if a NAT were in the path.' },
    { key: 'udpencap.non_esp_marker',
      title: 'Non-ESP marker',
      what: 'Four zero bytes in front of the IKE header (RFC 3948).',
      why: 'On UDP 4500 the same port carries both IKE and ESP. These four zero bytes say "this is IKE": an ESP packet starts with its SPI, which is never zero.' },

    /* ── IKE header ── */
    { key: 'isakmp.exchangetype',
      title: (n) => `Exchange type: ${n[0].split(': ').pop()}`,
      what: 'Which IKEv2 exchange this message belongs to: 34 IKE_SA_INIT, 35 IKE_AUTH, 36 CREATE_CHILD_SA, 37 INFORMATIONAL, <b>43 IKE_INTERMEDIATE</b> (RFC 9242) and <b>44 IKE_FOLLOWUP_KE</b> (RFC 9370).',
      why: (n) => /Unknown/.test(n[0])
        ? 'Wireshark 4.2 is older than these exchange types, so it prints <i>Unknown</i>. This is the post-quantum round, even though the tool cannot name it. Try the filter <code>isakmp.exchangetype == ' + (/43/.test(n[0]) ? '43' : '44') + '</code>.'
        : 'It tells you where you are in the negotiation. A request and its response share this type and the Message ID.' },
    { key: 'isakmp.rspi', label: /0000000000000000/,
      title: 'Responder SPI: all zeros',
      what: 'The responder\'s half of the IKE SA identifier. It is zero because R3 has not answered yet.',
      why: 'R3 fills it in its response. From then on the two SPIs name this IKE SA in every message, until an IKE SA rekey replaces them.' },

    /* ── proposal ── */
    { key: 'isakmp.tf.id.dh',
      title: 'X25519 (Curve25519, group 31)',
      what: 'The classical key exchange in the proposal: elliptic-curve Diffie-Hellman over Curve25519.',
      why: (n, c) => hyb(c)
        ? 'Still there in the hybrid VPN. The keys will depend on X25519 <b>and</b> ML-KEM-768 together, so breaking X25519 alone is not enough.'
        : 'The only key exchange in this capture. A large enough quantum computer running Shor\'s algorithm could recover the shared secret from a recording of these messages: <b>record now, decrypt later</b>.' },
    { key: ['isakmp.tf.type', 'isakmp.tf.id'], test: (n) => /Reserved to IANA \(6\)|Transform ID: 36$/.test(n[0]),
      title: 'Additional Key Exchange 1 = ML-KEM-768',
      what: 'Transform type 6 is <i>Additional Key Exchange 1</i> (RFC 9370), and ID 36 is ML-KEM-768. Wireshark 4.2 shows them as "Reserved to IANA" and a bare number.',
      why: (n, c) => rekey(c)
        ? 'Listed again in the rekey, so the new SA gets a fresh ML-KEM exchange too, in IKE_FOLLOWUP_KE.'
        : 'This one transform makes the VPN hybrid: it asks the peer for a second, post-quantum key exchange after IKE_SA_INIT.' },

    /* ── key exchange payloads ── */
    { key: 'isakmp.key_exchange.dh_group', label: /Curve25519/,
      title: 'X25519 public value',
      what: 'A Key Exchange payload with the sender\'s X25519 public value: <b>32 bytes</b>.',
      why: (n, c) => rekey(c)
        ? 'A fresh X25519 share in the rekey: perfect forward secrecy, the new keys do not depend on the old ones.'
        : hyb(c) ? 'Only 32 bytes. Compare it with the 1,184-byte ML-KEM key that follows in IKE_INTERMEDIATE.' : 'Only 32 bytes, in clear text. Together with the peer\'s value it gives both routers the same shared secret.' },
    { key: 'isakmp.key_exchange.dh_group', label: /\(36\)/,
      title: (n, c) => fromR3(c) ? 'ML-KEM-768 ciphertext' : 'ML-KEM-768 encapsulation key',
      what: (n, c) => fromR3(c)
        ? 'R3\'s ML-KEM-768 ciphertext: <b>1,088 bytes</b>. Only R1, which holds the matching private key, can recover the shared secret from it.'
        : 'R1\'s ML-KEM-768 encapsulation key: <b>1,184 bytes</b>, reassembled from two IKE fragments. Wireshark 4.2 shows the method as "Unknown (36)".',
      why: 'This is the post-quantum half of the key exchange. It travels encrypted under the X25519 keys, and its secret is mixed into the new keys, so a recording stays safe even if X25519 is broken.' },

    /* ── notifies ── */
    { key: 'isakmp.notify.msgtype', label: /16438/,
      title: 'INTERMEDIATE_EXCHANGE_SUPPORTED',
      what: 'Notify 16438 (RFC 9242): the sender can run IKE_INTERMEDIATE exchanges. Wireshark 4.2 calls it "Reserved to IANA".',
      why: 'IKE_SA_INIT cannot carry the large ML-KEM key. IKE_INTERMEDIATE gives it a place between IKE_SA_INIT and IKE_AUTH, already encrypted.' },
    { key: 'isakmp.notify.msgtype', label: /16441/,
      title: 'ADDITIONAL_KEY_EXCHANGE',
      what: 'Notify 16441 (RFC 9370), with a token chosen by R3.',
      why: 'It links the IKE_FOLLOWUP_KE exchange that follows to this CREATE_CHILD_SA, so the ML-KEM round is counted in the right rekey.' },
    { key: 'isakmp.notify.msgtype', label: /16430/,
      title: 'IKEv2 fragmentation supported',
      what: 'IKEV2_FRAGMENTATION_SUPPORTED (RFC 7383): the sender can split large IKE messages itself.',
      why: (n, c) => hyb(c)
        ? 'Needed here: the ML-KEM key does not fit in one datagram. IKE fragments are complete UDP datagrams, so they pass firewalls that drop IP fragments.'
        : 'Offered, but never used in the classical capture: every message fits in one datagram.' },
    { key: 'isakmp.notify.msgtype', label: /16393/,
      title: 'REKEY_SA',
      what: 'REKEY_SA names the CHILD SA, by its SPI, that this exchange replaces.',
      why: 'Without it, CREATE_CHILD_SA would add a second CHILD SA next to the old one instead of replacing it.' },

    /* ── fragments ── */
    { key: 'isakmp.frag.total',
      title: 'IKEv2 fragment',
      what: (n, c) => `${c.m.title.includes('2 of 2') ? 'Fragment 2' : 'Fragment 1'} of 2: an IKEv2 fragment (RFC 7383), encrypted and authenticated on its own.`,
      why: 'The message with the ML-KEM key is larger than the 1,248 bytes left for IKE in this lab, so IKEv2 split it itself instead of leaving it to IP fragmentation.' },
    { key: 'isakmp.fragments',
      title: 'Reassembled message',
      what: 'Wireshark put the two fragments back together into one IKE message.',
      why: 'Only the complete message can be read: open it to find the ML-KEM payload.' },

    /* ── encryption ── */
    { key: 'isakmp.enc.data',
      title: 'Encrypted IKE payloads',
      what: 'The payloads of this IKE message, encrypted with AES-GCM-256.',
      why: (n, c) => c.keys ? 'With the lab keys loaded, Wireshark decrypts them: see <i>Decrypted Data</i> just below.' : 'This is all an observer on the link sees. Turn on <b>Decryption keys</b> to look inside.' },
    { key: 'isakmp.enc.decrypted',
      title: 'Decrypted with the lab keys',
      what: 'What only R1 and R3 can read: the payloads inside the encrypted message.',
      why: 'Open it to see the payloads an observer cannot see. The keys are throwaway lab keys, published on purpose.' },

    /* ── IKE_AUTH ── */
    { key: 'isakmp.id.data',
      title: 'Identity',
      what: (n) => `The identity: <b>${n[0].split(':').pop().trim()}</b>.`,
      why: 'Sent encrypted, so an observer cannot tell who is connecting. The peer checks it against the identity it expects.' },
    { key: 'isakmp.auth.method',
      title: 'Authentication: pre-shared key',
      what: 'The AUTH payload proves the sender knows the pre-shared key and saw every earlier message of the exchange.',
      why: (n, c) => hyb(c)
        ? 'It also covers the IKE_INTERMEDIATE messages (RFC 9242), so an attacker cannot strip the ML-KEM round without being detected.'
        : 'It binds IKE_AUTH to IKE_SA_INIT, so an attacker in the middle cannot change the proposal unnoticed.' },
    { key: 'isakmp.typepayload', label: /Traffic Selector - (Initiator|Responder)/,
      title: 'Traffic selector',
      what: 'Which traffic the tunnel protects: 10.1.0.0/24 on R1\'s side, 10.3.0.0/24 on R3\'s side.',
      why: 'Both peers must agree on these ranges. If they do not, the CHILD SA fails with TS_UNACCEPTABLE.' },
    { key: 'isakmp.spi', test: (n, c) => c.anc.some((l) => /REKEY_SA/.test(l)),
      title: 'SPI of the SA being replaced',
      what: (n) => `<code>0x${n[0].split(': ').pop()}</code>: the inbound SPI of the old CHILD SA.`,
      why: 'Inside REKEY_SA it tells the peer which SA this rekey replaces.' },
    { key: 'isakmp.spi', test: (n, c) => c.anc.some((l) => /Proposal/.test(l)),
      title: (n) => (/\b[0-9a-f]{16}$/.test(n[0]) ? 'New IKE SA SPI' : 'ESP SPI'),
      what: (n) => /\b[0-9a-f]{16}$/.test(n[0])
        ? `<code>${n[0].split(': ').pop()}</code>: the sender's half of the identifier of the new IKE SA.`
        : `<code>0x${n[0].split(': ').pop()}</code>: the SPI on which the sender wants to <b>receive</b> ESP.`,
      why: (n) => /\b[0-9a-f]{16}$/.test(n[0]) ? 'Once the rekey completes, IKE messages carry the new SPIs and the old IKE SA is deleted.' : 'Look for it in the ESP packets travelling toward the sender. A new SPI in a rekey means a new SA with new keys.' },

    /* ── ESP ── */
    { key: 'esp.spi',
      title: 'ESP SPI',
      what: 'The Security Parameter Index: tells the receiver which SA, and so which key, decrypts this packet.',
      why: 'Visible to anyone on the path, like the sequence number. It identifies the tunnel but reveals nothing about the content.' },
    { key: 'esp.sequence',
      title: 'ESP sequence number',
      what: 'Counts the packets sent on this SA. It starts again at 1 on a new SA.',
      why: 'The receiver uses it to reject replayed packets.' },
    { key: 'esp.encrypted_data',
      title: 'The encrypted packet',
      what: 'The original packet, encrypted with AES-GCM-256.',
      why: (n, c) => c.keys ? 'With the lab keys loaded, the decrypted packet appears below.' : 'An observer sees only random-looking bytes. Turn on <b>Decryption keys</b> to see the ping inside.' },
    { key: 'ip', src: 1,
      title: 'The inner packet',
      what: (n) => `The real packet between the two sites: <b>${n[0].replace(/^.*Src: /, '').replace(', Dst: ', ' → ')}</b>.`,
      why: 'This is what the VPN protects. On the link only the outer header, 198.51.100.1 ↔ 203.0.113.2, is visible.' },
  ];

  function match(n, ctx) {
    for (const r of R) {
      const keys = Array.isArray(r.key) ? r.key : [r.key];
      if (!keys.includes(n[4])) continue;
      if (r.src !== undefined && n[3] !== r.src) continue;
      if (r.label && !r.label.test(n[0])) continue;
      if (r.test && !r.test(n, ctx)) continue;
      return r;
    }
    return null;
  }
  const val = (x, n, ctx) => (typeof x === 'function' ? x(n, ctx) : x);
  root.JOURNEY_GUIDE = { match, text: (r, n, ctx) => ({ title: val(r.title, n, ctx), what: val(r.what, n, ctx), why: val(r.why, n, ctx) }) };
})(window);
