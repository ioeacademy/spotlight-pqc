/* Quick-lab topology (Classic, PQC, Classic → PQC, Negotiation): the v3 lab's routers, drawn like the GRE lab —
   R2 on top inside a WAN cloud — with public-style WAN addresses (the third octet names the link).
   Based on "IPsec Series, Part 9" (Julio Gomez, Cisco Blogs):
   3 × C8235-G2 on IOS XE 26.2, wired back to back.

   The blog's bench used the routers' LAN ports with VLAN interfaces (Vlan12 / Vlan23).
   This lab uses routed WAN interfaces instead — the C8235-G2 has 2× 2.5 GE mGig WAN
   ports (Cisco 8200 Series datasheet, Table 9) — which is how a site-to-site VPN is
   normally built. Interface numbering is illustrative.

     R1 (Spoke-1) ──192.0.12.0/30── R2 (Hub/Transit) ──192.0.23.0/30── R3 (Spoke-2)
     Tw0/0/0 .1             .2 Tw0/0/0   Tw0/0/1 .1             .2 Tw0/0/0
*/
(function (root) {
  const TOPOLOGY = {
    layout: 'triangle',   // hub R2 on top inside a WAN cloud (app.js)
    devices: {
      r1: {
        hostname: 'R1', role: 'Spoke-1', model: 'C8235-G2', serial: 'FGL2633L1R1',
        interfaces: {
          'TwoGigabitEthernet0/0/0': { ip: '192.0.12.1', mask: '255.255.255.252', desc: 'WAN to R2' },
          'TwoGigabitEthernet0/0/1': {},
        },
      },
      r2: {
        hostname: 'R2', role: 'Hub/Transit', model: 'C8235-G2', serial: 'FGL2633L1R2',
        interfaces: {
          'TwoGigabitEthernet0/0/0': { ip: '192.0.12.2', mask: '255.255.255.252', desc: 'WAN to R1 (Spoke-1)' },
          'TwoGigabitEthernet0/0/1': { ip: '192.0.23.1', mask: '255.255.255.252', desc: 'WAN to R3 (Spoke-2)' },
        },
      },
      r3: {
        hostname: 'R3', role: 'Spoke-2', model: 'C8235-G2', serial: 'FGL2633L1R3',
        interfaces: {
          'TwoGigabitEthernet0/0/0': { ip: '192.0.23.2', mask: '255.255.255.252', desc: 'WAN to R2' },
          'TwoGigabitEthernet0/0/1': {},
        },
      },
    },
    links: [
      { a: ['r1', 'TwoGigabitEthernet0/0/0'], b: ['r2', 'TwoGigabitEthernet0/0/0'], label: '192.0.12.0/30', speed: '2.5 Gb' },
      { a: ['r2', 'TwoGigabitEthernet0/0/1'], b: ['r3', 'TwoGigabitEthernet0/0/0'], label: '192.0.23.0/30', speed: '2.5 Gb' },
    ],
  };
  if (typeof module === 'object' && module.exports) module.exports = TOPOLOGY;
  else root.LAB_TOPOLOGY = TOPOLOGY;
})(typeof globalThis !== 'undefined' ? globalThis : this);
