/* Lab topology — based on "IPsec Series, Part 9" (Julio Gomez, Cisco Blogs):
   3 × C8235-G2 on IOS XE 26.2, wired back to back.

   The blog's bench used the routers' LAN ports with VLAN interfaces (Vlan12 / Vlan23).
   This lab uses routed WAN interfaces instead — the C8235-G2 has 2× 2.5 GE mGig WAN
   ports (Cisco 8200 Series datasheet, Table 9) — which is how a site-to-site VPN is
   normally built. Interface numbering is illustrative.

     R1 (Spoke-1) ──10.0.12.0/24── R2 (Hub/Transit) ──10.0.23.0/24── R3 (Spoke-2)
     Tw0/0/0 .1             .2 Tw0/0/0   Tw0/0/1 .1             .2 Tw0/0/0
*/
(function (root) {
  const TOPOLOGY = {
    devices: {
      r1: {
        hostname: 'R1', role: 'Spoke-1', model: 'C8235-G2', serial: 'FGL2633L1R1',
        interfaces: {
          'TwoGigabitEthernet0/0/0': { ip: '10.0.12.1', mask: '255.255.255.0', desc: 'WAN to R2' },
          'TwoGigabitEthernet0/0/1': {},
        },
      },
      r2: {
        hostname: 'R2', role: 'Hub/Transit', model: 'C8235-G2', serial: 'FGL2633L1R2',
        interfaces: {
          'TwoGigabitEthernet0/0/0': { ip: '10.0.12.2', mask: '255.255.255.0', desc: 'WAN to R1 (Spoke-1)' },
          'TwoGigabitEthernet0/0/1': { ip: '10.0.23.1', mask: '255.255.255.0', desc: 'WAN to R3 (Spoke-2)' },
        },
      },
      r3: {
        hostname: 'R3', role: 'Spoke-2', model: 'C8235-G2', serial: 'FGL2633L1R3',
        interfaces: {
          'TwoGigabitEthernet0/0/0': { ip: '10.0.23.2', mask: '255.255.255.0', desc: 'WAN to R2' },
          'TwoGigabitEthernet0/0/1': {},
        },
      },
    },
    links: [
      { a: ['r1', 'TwoGigabitEthernet0/0/0'], b: ['r2', 'TwoGigabitEthernet0/0/0'], label: '10.0.12.0/24', speed: '2.5 Gb' },
      { a: ['r2', 'TwoGigabitEthernet0/0/1'], b: ['r3', 'TwoGigabitEthernet0/0/0'], label: '10.0.23.0/24', speed: '2.5 Gb' },
    ],
  };
  if (typeof module === 'object' && module.exports) module.exports = TOPOLOGY;
  else root.LAB_TOPOLOGY = TOPOLOGY;
})(typeof globalThis !== 'undefined' ? globalThis : this);
