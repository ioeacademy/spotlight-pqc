# Supported IOS XE commands — v3 simulator

Reference for the commands the v3 three-router engine accepts
(`js/ios-pqc-engine.js`, asset version `20261008b`, 2026-10-08).
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
| `traceroute A.B.C.D` | |
| `clear crypto ikev2 sa [fast]` | Tears down IKE and child SAs; they renegotiate. |
| `clear crypto session` | Same as above. |
| `clear crypto sa` | Rekeys only the IPsec (child) SAs; applies the PFS rules. |
| `clear crypto ikev2 stats` | `Cleared crypto ikev2 statistics`. Resets the SA statistics only; the per-exchange counters keep counting from boot (as observed on IOS XE 26.02). |
| `debug crypto ikev2` | Enables IKEv2 debug messages on the console. |
| `undebug all` / `no debug all` | |
| `write memory` / `write` / `copy running-config startup-config` | Cosmetic (`[OK]`). |
| `terminal length <0-512>`, `exit`, `logout` | No-ops. |

### `show` commands (privileged EXEC)

| Command | What it shows |
|---|---|
| `show running-config` | Full configuration in IOS order (smart defaults hidden). |
| `show running-config interface IFACE` | `Building configuration...`, `Current configuration : N bytes`, the interface block. |
| `show version` | IOS XE `26.02.01`, platform (C8000V or C8235-G2), uptime, serial. |
| `show clock` | |
| `show history` | |
| `show logging` | Log buffer. |
| `show ip interface brief` | Sorted by name; `NVRAM` / `manual` / `unset` method. |
| `show ip route` | Codes legend, gateway of last resort, `C`/`L`/`S`/`S*` routes. |
| `show ip route A.B.C.D` | Routing entry (static or connected). |
| `show interfaces IFACE` | Full IOS XE layout. For tunnels: source/destination, protection profile, tunnel MTU and real packet counters. |
| `show crypto pqc-support` | `Supports PQC: Yes/No`. |
| `show crypto ikev2 sa [detailed]` | IKE SA with Encr/PRF/Hash/DH, `PQC Key Exchange: ML-KEM-768` (or 512/1024), PPK `, QR`, fragmentation, message IDs, `Dynamic Route Update`. `IN-NEG` row while negotiating. |
| `show crypto ikev2 session [detailed]` | Session view, including the Child SA block (`detailed`). |
| `show crypto ikev2 stats` | SA counters, `Max in nego`, quantum-resistant (QR) and manual PPK counts. |
| `show crypto ikev2 stats exchange` | Per-exchange counters (IKE_SA_INIT, IKE_INTERMEDIATE, IKE_AUTH, CREATE_CHILD_SA, INFORMATIONAL, …). |
| `show crypto ikev2 proposal` | Including `PQC Key Exchange` and the `default` proposal when active. |
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
| `interface IFACE` | ✓ | `no` only for Tunnel/Loopback. |
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
| `ip address A.B.C.D A.B.C.D` | ✓ | Rejects bad masks and overlapping subnets. |
| `shutdown` | ✓ | |
| `description LINE` | ✓ | |
| `switchport access vlan <1-4094>`, `switchport mode access` | ✓ | Physical (LAN switch ports). |
| `tunnel source IFACE\|A.B.C.D` | ✓ | Tunnel |
| `tunnel destination A.B.C.D` | ✓ | Tunnel |
| `tunnel mode ipsec ipv4` / `tunnel mode gre ip` | ✓ | Tunnel |
| `tunnel protection ipsec profile WORD` | ✓ | Tunnel (profile must exist). |
| `interface IFACE`, `end`, `exit` | | |

### IKEv2 proposal (`(config-ikev2-proposal)#`)

| Command | no | Notes |
|---|---|---|
| `encryption (aes-cbc-128\|aes-cbc-192\|aes-cbc-256\|aes-gcm-128\|aes-gcm-256)` ×1–3 | ✓ | Several values in one proposal; negotiation picks the first in common. |
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
- **Failure modes**: wrong PSK (`AUTHENTICATION_FAILED`), no common proposal, IKE up but child SA failed (tunnel line protocol stays down, "IKE up · no IPsec SA" in the topology).
- **PFS outcomes** on `clear crypto sa` / rekey, including mismatched groups.
- **Routing**: connected, static (next hop or exit interface), default route, hop-by-hop forwarding across R1–R2–R3, ARP learned from IKE.
- **Counters**: IPsec encaps/decaps, Tunnel interface packets/bytes, IKEv2 stats and per-exchange counters.

## 6. Not supported (examples)

Dynamic routing (OSPF, EIGRP, BGP), ACLs, NAT, crypto maps and IKEv1 (`crypto isakmp`), certificates/PKI
(`crypto pki`, `authentication rsa-sig`), DPD, VRFs, IPv6, `show interfaces` without an interface name (returns `% Incomplete command.`),
`show ip route static`, `reload`, `erase`. Output of `show logging` and `stats exchange` depends on what was
run in the session.

Verification: `node test/run-tests.js` (tutorial steps) and `node test/groundtruth-replay.js <dataset-dir>`
(100% structural match on the observed CML records).
