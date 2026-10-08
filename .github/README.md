# Spotlight PQC — Cisco IOS XE post-quantum VPN simulator

Browser-based labs for learning quantum-safe IPsec VPNs on Cisco IOS XE. No routers needed.

**Live:** https://ioeacademy.github.io/spotlight-pqc/

| Lab | Link |
|---|---|
| Quick lab: classic IKEv2 VPN | [`tutorials/v5-quickstart/?track=classic`](https://ioeacademy.github.io/spotlight-pqc/tutorials/v5-quickstart/?track=classic) |
| Quick lab: post-quantum VPN (ML-KEM) | [`tutorials/v5-quickstart/?track=pqc`](https://ioeacademy.github.io/spotlight-pqc/tutorials/v5-quickstart/?track=pqc) |
| Quick lab: negotiation experiments | [`tutorials/v5-quickstart/?track=negotiate`](https://ioeacademy.github.io/spotlight-pqc/tutorials/v5-quickstart/?track=negotiate) |
| Quick lab: from classic to PQC | [`tutorials/v5-quickstart/?track=migrate`](https://ioeacademy.github.io/spotlight-pqc/tutorials/v5-quickstart/?track=migrate) |
| Classic site-to-site VPN (IKEv2 + VTI) | [`tutorials/v3-three-router/?track=classic`](https://ioeacademy.github.io/spotlight-pqc/tutorials/v3-three-router/?track=classic) |
| Post-Quantum Key Exchange on Cisco Routers (classical → PPK → ML-KEM-768 → hub-and-spoke) | [`tutorials/v3-three-router/`](https://ioeacademy.github.io/spotlight-pqc/tutorials/v3-three-router/) |
| VPN Building Blocks (prototype) | [`tutorials/v4-blocks/mockup.html`](https://ioeacademy.github.io/spotlight-pqc/tutorials/v4-blocks/mockup.html) |

The post-quantum track reproduces *Post-Quantum Key Exchange on Cisco Routers – IPsec Series Part 9*
(Cisco Blogs, Julio Gomez) on three routers R1 – R2 – R3, with syntax checked against the
[Cisco IOS XE PQC for IKEv2 guide](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/security-vpn/m-pqc-ikev2.html).

## Simulator

`tutorials/v3-three-router/js/ios-pqc-engine.js` is a DOM-free JavaScript model of IOS XE 26.02 on several routers:
CLI (abbreviations, `?`, Tab, `no`, `do`, output filters), routing, and per-tunnel IKEv2 negotiation
(proposals, `pqc mlkem768 [optional]`, RFC 8784 PPK, fragmentation, PFS, transform sets).
The supported commands are listed in [COMMANDS.md](../tutorials/v3-three-router/COMMANDS.md).

Output is validated against a ground-truth dataset captured on Cisco CML (C8000V) routers:
100% structural match on the observed records.

## Run locally

```bash
python3 -m http.server 8770
```

Then open http://localhost:8770/.

## Tests

```bash
node tutorials/v3-three-router/test/run-tests.js
node tutorials/v5-quickstart/test/run-tests.js
node tutorials/v3-three-router/test/negotiation-replay.js <negotiation-dataset-dir>
node tutorials/v3-three-router/test/groundtruth-replay.js <dataset-dir>
```

## Disclaimer

**Education only.** This simulator is for practising commands and getting familiar with
post-quantum VPN concepts and configuration steps. Output may differ from real platforms:
do not use it to validate configurations. Provided as is, without warranty or support.
Not affiliated with or endorsed by Cisco Systems, Inc. See [DISCLAIMER.md](../DISCLAIMER.md).
