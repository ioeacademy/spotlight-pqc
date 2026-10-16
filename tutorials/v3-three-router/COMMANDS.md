# Supported IOS XE commands — v3 simulator

Reference for the commands the v3 three-router engine accepts
(`js/ios-pqc-engine.js`, asset version `20261008b`, 2026-10-08).
> **Education only.** Output may differ from real platforms; do not use the simulator to validate
> configurations. See [DISCLAIMER.md](../../DISCLAIMER.md).

Anything not listed here returns `% Invalid input detected at '^' marker.`, as a real router would.

Syntax notation: `WORD` = a name, `A.B.C.D` = IPv4 address or mask, `IFACE` = interface name,
`<x-y>` = number in range, `(a|b)` = choose one, `[...]` = optional.

## 1. CLI behaviour

| Feature | Supported |
|---|---|
| Abbreviations | Any unique prefix (`sh cry ikev2 sa`, `conf t`, `int tu0`). Ambiguous prefixes return `% Ambiguous command`. |
| Context help `?` | Lists keywords or arguments at any position, with descriptions. `?` after `\|` lists the filters. |
| Tab completion | Completes a keyword when only one matches. |
| `no` form | Every config command marked ✓ in the *no* column below. |
| `do` | `do <exec command>` from any config mode. |
| Output filters | `\| include`, `\| exclude`, `\| begin`, `\| section`, `\| count` (regex, abbreviations allowed). |
| Mode fallback | A command that is invalid in a sub-mode but valid in global config is run there and exits the sub-mode, as on IOS. |
| Errors | `% Invalid input` with caret position, `% Incomplete command.`, `% Ambiguous command`. |
| History | Up/down arrows; `show history` (last 20). |
| Syslog | `%LINK`, `%LINEPROTO`, `%SYS-5-CONFIG_I`, `%IKEV2` and `%CRYPTO` messages, timestamped `*Oct  8 2026 hh:mm:ss.mmm`. |

Interface names: `GigabitEthernet`, `TwoGigabitEthernet`, `Tunnel`, `Loopback`, `Vlan`, with
abbreviations (`Gi`, `Tw`, `Tu`, `Lo`, `Vl`, `tun0`, …). Physical interfaces come from the topology
and cannot be created or deleted; `Tunnel` and `Loopback` interfaces are created on first use.

## 2. Modes and prompts

| Mode | Prompt | Entered with |
|---|---|---|
| User EXEC | `R1>` | start (tutorial) |
| Privileged EXEC | `R1#` | `enable` |
| Global config | `R1(config)#` | `configure terminal` |
| Interface | `R1(config-if)#` | `interface IFACE` |
| IKEv2 proposal | `R1(config-ikev2-proposal)#` | `crypto ikev2 proposal WORD` |
| IKEv2 policy | `R1(config-ikev2-policy)#` | `crypto ikev2 policy WORD` |
| IKEv2 keyring | `R1(config-ikev2-keyring)#` | `crypto ikev2 keyring WORD` |
| Keyring peer | `R1(config-ikev2-keyring-peer)#` | `peer WORD` |
| IKEv2 profile | `R1(config-ikev2-profile)#` | `crypto ikev2 profile WORD` |
| Transform set | `R1(cfg-crypto-trans)#` | `crypto ipsec transform-set WORD …` |
| IPsec profile | `R1(ipsec-profile)#` | `crypto ipsec profile WORD` |

`exit` goes up one level (peer → keyring, sub-mode → config, config → priv); `end` returns to privileged EXEC
from anywhere and logs `%SYS-5-CONFIG_I`.

## 3. EXEC commands

### User EXEC (`>`)
`enable`, `ping …`, `traceroute …`, `show version`, `show clock`, `show history`,
`show ip interface brief`, `show ip route [A.B.C.D]`, `show interfaces IFACE`,
`terminal length <0-512>`, `exit`, `logout`.

### Privileged EXEC (`#`)

| Command | Notes |
|---|---|
| `enable` / `disable` | |
| `configure terminal` | |
| `ping A.B.C.D [repeat <1-1000>] [source IFACE\|A.B.C.D]` | Hop-by-hop forwarding; tunnel traffic increments ESP and Tunnel counters. |
| `traceroute A.B.C.D` | Each hop answers from its interface towards the sender (through a tunnel: the far tunnel address); the last hop shows `N msec *  N msec` (ICMP rate limiting). |
| `clear crypto ikev2 sa [fast]` | Tears down IKE and child SAs; they renegotiate. |
| `clear crypto session` | Same as above. |
| `clear crypto sa` | Rekeys only the IPsec (child) SAs; applies the PFS rules. |
| `clear crypto ikev2 stats` | `Cleared crypto ikev2 statistics`. Resets the SA statistics only; the per-exchange counters keep counting from boot (as observed on IOS XE 26.02). |
| `debug crypto ikev2` | Enables IKEv2 debug messages on the console (simulator trace + error lines). |
| `debug crypto ikev2 error` | Only the `IKEv2-ERROR:(SESSION ID = n,SA ID = 1):…` lines, worded as IOS XE 26.02 prints them. |
| `clear logging` | Empties the log buffer. |
| `debug ip packet` / `debug ip icmp` / `debug ip routing` | IP debugs as IOS XE 26.02 prints them: locally originated packets only (`… routed via FIB`, `echo reply rcvd …`), `RT: add/del …` for routing-table changes. `undebug ip …` / `no debug ip …` turn one off. |
| `undebug all` / `no debug all` | Turns every debug off. |
| `write memory` / `write` / `copy running-config startup-config` | Cosmetic (`[OK]`). |
| `terminal length <0-512>`, `exit`, `logout` | No-ops. |

### `show` commands (privileged EXEC)

| Command | What it shows |
|---|---|
| `show running-config` | Full configuration in IOS order (smart defaults hidden). |
| `show running-config interface IFACE` | `Building configuration...`, `Current configuration : N bytes`, the interface block. |
| `show version` | IOS XE `26.02.01`, platform (C8000V or C8235-G2), uptime, serial, and the education-only notice. |
| `show clock` | |
| `show history` | |
| `show logging` | Log buffer. |
| `show debugging` | `IOSXE Conditional Debug Configs` layout with the active `Generic IP` debugs. |
| `show arp` / `show ip arp` | Own addresses (`-`) and learned neighbours with their age in minutes. |
| `show ip interface brief` | Sorted by name; `NVRAM` / `manual` / `unset` method. |
| `show ip route` | Codes legend, gateway of last resort, `C`/`L`/`S`/`S*` routes. |
| `show ip route A.B.C.D` | Routing entry (static or connected). |
| `show interfaces [IFACE]` | Full IOS XE layout, for one interface or all. Tunnels: linestate reason, source/destination, src-track members, key/checksum, tunnel MTU, state-change times and `Last state info`, packet counters (GRE output bytes include the 24-byte header). |
| `show crypto pqc-support` | `Supports PQC: Yes/No`. |
| `show crypto ikev2 sa [detailed]` | IKE SA with Encr/PRF/Hash/DH, `PQC Key Exchange: ML-KEM-768` (or 512/1024), PPK `, QR`, fragmentation, message IDs, `Dynamic Route Update`. `IN-NEG` row while negotiating. |
| `show crypto ikev2 session [detailed]` | Session view, including the Child SA block (`detailed`). |
| `show crypto ikev2 stats` | SA counters, `Max in nego`, quantum-resistant (QR) and manual PPK counts. |
| `show crypto ikev2 stats exchange` | Per-exchange counters (IKE_SA_INIT, IKE_INTERMEDIATE, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL, …). |
| `show crypto ikev2 proposal [NAME]` | Including `PQC Key Exchange` and the `default` proposal when active. |
| `show crypto ikev2 policy` | User policies plus `default`. |
| `show crypto ikev2 profile` | Full IOS layout (identities, auth methods, keyring, PPK keyring, lifetime). |
| `show crypto ipsec sa [detail]` | SPIs as `0xHEX(dec)`, encaps/decaps counters, transform, conn id/flow, IV size, path/IP MTU. |
| `show crypto ipsec transform-set` | Including `default`. |
| `show crypto ipsec profile` | Transform sets, PFS, IKEv2 profile, including `default`. |
| `show crypto session [detail]` | Status, peer, IKEv2 SA, IPsec flow; `Capabilities:FUQ` (Fragmentation, dynamic Update, Quantum-safe). Empty output when there are no tunnels. |

## 4. Global configuration (`(config)#`)

| Command | no | Notes |
|---|---|---|
| `hostname WORD` | | |
| `interface IFACE` | ✓ | `no` only for Tunnel/Loopback. Tunnel/Loopback numbers 0-2147483647; `interface Tunnel` alone is incomplete. |
| `ip route A.B.C.D A.B.C.D A.B.C.D` | ✓ | Next-hop static route (and default route `0.0.0.0 0.0.0.0`). |
| `ip route A.B.C.D A.B.C.D IFACE` | ✓ | Route via exit interface (e.g. `Tunnel0`). |
| `ip domain lookup` | ✓ | Accepted, no effect. |
| `crypto ikev2 proposal WORD` | ✓ | `no crypto ikev2 proposal default` disables the smart default. |
| `crypto ikev2 policy WORD` | ✓ | Same for `default`. |
| `crypto ikev2 keyring WORD` | ✓ | |
| `crypto ikev2 profile WORD` | ✓ | |
| `crypto ikev2 fragmentation [mtu <68-1500>]` | ✓ | Default MTU 576. |
| `crypto ipsec transform-set WORD esp-gcm [128\|192\|256]` | ✓ | |
| `crypto ipsec transform-set WORD esp-aes [128\|192\|256] (esp-sha-hmac\|esp-sha256-hmac\|esp-sha384-hmac\|esp-sha512-hmac)` | ✓ | |
| `crypto ipsec profile WORD` | ✓ | Refused while a tunnel still uses it. |
| `do <command>`, `end`, `exit` | | |

Entering a crypto object that is still incomplete prints the IOS warning, e.g.
`IKEv2 proposal MUST either have a set of an encryption algorithm other than aes-gcm, an integrity algorithm and a DH group configured or encryption algorithm aes-gcm, a prf algorithm and a DH group configured`.

### Interface (`(config-if)#`)

| Command | no | Applies to |
|---|---|---|
| `ip address A.B.C.D A.B.C.D` | ✓ | Rejects bad masks (`Bad mask 0xFF00FF00 for address …`) and overlapping subnets. |
| `bandwidth <1-10000000>` | ✓ | Shown as `BW` in `show interfaces`. |
| `shutdown` | ✓ | |
| `description LINE` | ✓ | |
| `switchport access vlan <1-4094>`, `switchport mode access` | ✓ | Physical (LAN switch ports). |
| `tunnel source IFACE\|A.B.C.D` | ✓ | Tunnel. A missing Loopback is created; another Tunnel is refused (`tunnel source interface is unacceptable`). |
| `tunnel destination A.B.C.D` | ✓ | Tunnel. `0.0.0.0`, `255.255.255.255` and multicast are refused (`tunnel destination address specified is invalid`). |
| `tunnel mode ipsec ipv4` / `tunnel mode gre ip` | ✓ | Tunnel. `gre ip` (the default) is a plain, unencrypted GRE tunnel. |
| `tunnel mode ipip` / `tunnel mode ipv6ip` | ✓ | Accepted; line protocol and `show interfaces` (MTU 1480, `IP/IP`, `IPv6/IP`); no data plane. `gre ipv6` / `gre multipoint` print the IOS refusal. |
| `tunnel key <0-4294967295>`, `tunnel checksum`, `tunnel path-mtu-discovery` | ✓ | Each of key and checksum adds 4 bytes (transport MTU 1472/1468) and disables fast tunneling. |
| `keepalive [<0-32767> [<1-255>]]` | ✓ | GRE tunnel keepalives: default 10 s, 3 retries; `0` turns them off. |
| `tunnel protection ipsec profile WORD` | ✓ | Tunnel (profile must exist). |
| `interface IFACE`, `end`, `exit` | | |

### IKEv2 proposal (`(config-ikev2-proposal)#`)

| Command | no | Notes |
|---|---|---|
| `encryption (aes-cbc-128\|aes-cbc-192\|aes-cbc-256\|aes-gcm-128\|aes-gcm-256)` ×1–3 | ✓ | Several values in one proposal; negotiation picks from the overlap. Each command **replaces** the list, as on IOS. |
| `integrity (sha1\|sha256\|sha384\|sha512)` ×1–3 | ✓ | |
| `group (14\|15\|16\|19\|20\|21\|24)` ×1–3 | ✓ | |
| `prf (sha1\|sha256\|sha384\|sha512)` | ✓ | |
| `pqc (mlkem512\|mlkem768\|mlkem1024)` ×1–3 `[optional]` | ✓ | Without `optional`, ML-KEM is required (there is no `required` keyword). Negotiated in IKE_INTERMEDIATE (RFC 9370). |

### IKEv2 policy (`(config-ikev2-policy)#`)
`proposal WORD` (✓ no; proposal must exist), `match address local A.B.C.D`, `match fvrf any` (accepted, no effect).

### IKEv2 keyring (`(config-ikev2-keyring)#`)
`peer WORD` (✓ no) → enters peer mode.

### Keyring peer (`(config-ikev2-keyring-peer)#`)

| Command | no | Notes |
|---|---|---|
| `address A.B.C.D [A.B.C.D]` | ✓ | |
| `pre-shared-key [0\|6] WORD` | ✓ | |
| `pre-shared-key (local\|remote) WORD` | ✓ | Asymmetric PSKs. |
| `ppk manual id WORD key [hex] WORD [required]` | ✓ | RFC 8784 manual PPK. |
| `description LINE`, `identity address A.B.C.D` | ✓ | Accepted, no effect. |

### IKEv2 profile (`(config-ikev2-profile)#`)

| Command | no |
|---|---|
| `match identity remote address A.B.C.D [A.B.C.D]` | ✓ |
| `authentication (local\|remote) pre-share [key WORD]` | ✓ |
| `keyring local WORD` | ✓ |
| `keyring ppk WORD` | ✓ |
| `lifetime <120-86400>` | ✓ |
| `identity local address A.B.C.D` | ✓ (accepted, no effect) |

### Transform set (`(cfg-crypto-trans)#`)
`mode (tunnel|transport)` (✓ no).

### IPsec profile (`(ipsec-profile)#`)

| Command | no | Notes |
|---|---|---|
| `set transform-set WORD [WORD [WORD [WORD]]]` | ✓ | 1–4 transform sets, all must exist. |
| `set ikev2-profile WORD` | ✓ | Profile must exist. |
| `set pfs` | ✓ | Inherit the IKE group. |
| `set pfs (group14\|…\|group24)` | ✓ | |
| `set pfs (group…) pqc (mlkem512\|mlkem768\|mlkem1024)` | ✓ | Hybrid PFS on CREATE_CHILD_SA rekey. |

## 5. What the engine models behind the commands

- **Smart defaults**: `default` proposal / policy / IPsec profile / transform set, used only when no complete user policy exists.
- **IKEv2 negotiation per tunnel**: proposal intersection, ML-KEM required vs optional (mismatch → `NO_PROPOSAL_CHOSEN`), PPK required/optional, identities, PSK (including asymmetric), fragmentation, transform-set match.
- **Negotiation outcomes, checked against real IOS XE 26.02 captures** (`vpn-negotiation-mismatch-teaching` dataset, `test/negotiation-replay.js`):
  - the initiator is the router that cleared the SA or sent the traffic; failed attempts alternate between the two ends;
  - no common encryption / integrity / DH group → `NO_PROPOSAL_CHOSEN` in IKE_SA_INIT, with *Received / Expected Policies* on the responder;
  - the initiator's KE payload uses its first DH group; another choice costs one `INVALID_KE_PAYLOAD` retry;
  - transform-set mismatch → the first Child SA fails inside IKE_AUTH and IOS deletes the IKE SA too;
  - different pre-shared keys → `Failed to authenticate the IKE SA` on both ends;
  - the responder has no profile for the initiator's identity → no SA; the initiator rejects the responder's identity → **half-open** tunnel (responder READY and encrypting, initiator none, `%CRYPTO-4-RECVD_PKT_INV_SPI`);
  - ML-KEM required vs none, or different parameter sets → fails like a proposal mismatch; `optional` vs none → classical, silently;
  - harmless config-exchange noise (`% IKEv2 profile not found`, `Error constructing config reply`) on healthy tunnels, as on real routers.
- **GRE tunnels** (plain, no IPsec), per Cisco TAC *Determine What Impacts GRE Tunnel Interface States* and *How GRE Keepalives Work*: line protocol up when the source is an up interface with an IP address and the destination is routable (not necessarily reachable); down with no route, a down source, recursive routing (`%TUN-5-RECURDOWN`) or unanswered keepalives. Traffic crosses only when the far end has a mirrored tunnel; otherwise the tunnel can be up/up while packets are dropped. GRE over IPsec (`tunnel protection` on a GRE tunnel) is not modelled.
- **GRE timing and messages, checked against real IOS XE 26.02 on C8000v** (`gre_cml_dataset`, `test/gre-replay.js`):
  - the tunnel's own commands (`shutdown`, `tunnel source/destination/mode`) act at once; route, source-interface and source-address changes act on a periodic check every 10 s, timed from the tunnel's creation;
  - reasons: `no IPv4 tunnel destination address`, `no IPv4 tunnel source address` (source up without an address), `no output interface` (no route, or the source is down), `interface not up`;
  - recursion: `%ADJ-5-PARENT … looped chain attempting to stack` at once, `%TUN-5-RECURDOWN` and down on the next check, a 60 s hold-down, then up again (and the loop again while the route remains);
  - a new Tunnel logs `line protocol … down` about 1.5 s after creation; a tunnel configured in one go does not log its first `up`; deleting a Tunnel is silent, deleting a Loopback logs down + administratively down;
  - a re-created Tunnel inherits the state history (`State change`, `Last state info`) of a previously deleted one, as IOS recycles interface descriptors;
  - ARP: the first ping towards an unresolved neighbour loses one probe (`.!!!!`); static-route next hops are resolved when the route is added or its interface comes up.
- **Rekey failures**: a PFS mismatch on `CREATE_CHILD_SA` keeps the IKE SA ("IKE up · no IPsec SA" in the topology).
- **PFS outcomes** on `clear crypto sa` / rekey, including mismatched groups.
- **Routing**: connected, static (next hop or exit interface), default route, hop-by-hop forwarding across R1–R2–R3, ARP learned from IKE.
- **Counters**: IPsec encaps/decaps, Tunnel interface packets/bytes, IKEv2 stats and per-exchange counters.

## 6. Not supported (examples)

Dynamic routing (OSPF, EIGRP, BGP), GRE over IPsec, mGRE/DMVPN, GRE sequencing, IPv6 transport, ACLs, NAT, crypto maps and IKEv1 (`crypto isakmp`), certificates/PKI
(`crypto pki`, `authentication rsa-sig`), DPD, VRFs, IPv6, `debug ip packet detail` / access lists, `show ip route static`, `reload`, `erase`. Output of `show logging` and `stats exchange` depends on what was
run in the session.

Verification: `node test/run-tests.js` (tutorial steps), `node test/groundtruth-replay.js <dataset-dir>`
(100% structural match on the observed CML records) and `node test/negotiation-replay.js <dataset-dir>`
(all 12 negotiation scenarios: outcome, key error lines, show-command layout), `node test/gre-replay.js <gre_cml_dataset>/cml-run1`
(941 GRE records: output, prompt, error type and syslog per step).
