/* GRE quick lab topology (same as the Packet Tracer lab), drawn as a triangle with R2 in a WAN cloud:
     R1 (Spoke-1) ──10.0.12.0/24── R2 (Hub/Transit) ──10.0.23.0/24── R3 (Spoke-2)
     Gi0/0/0 .1             .2 Gi0/0/0   Gi0/0/1 .1             .2 Gi0/0/0
     LANs: R1 Loopback1 10.1.1.1/24, R3 Loopback1 10.3.3.3/24
     Tunnel0 (GRE/IP) 192.168.100.0/30: R1 .1 (src 10.0.12.1) ⇄ R3 .2 (src 10.0.23.2)          */
(function (root) {
  const TOPOLOGY = {
    layout: 'triangle',   // hub R2 on top inside a WAN cloud (app.js)
    devices: {
      r1: {
        hostname: 'R1', role: 'Spoke-1', model: 'ISR4331', version: '17.09.04a', serial: 'FDO2213A0R1', pqcSupport: false,
        interfaces: {
          'GigabitEthernet0/0/0': { ip: '10.0.12.1', mask: '255.255.255.0', desc: 'WAN to R2' },
          'GigabitEthernet0/0/1': {},
          'Loopback1': { ip: '10.1.1.1', mask: '255.255.255.0', desc: 'LAN behind R1' },
        },
      },
      r2: {
        hostname: 'R2', role: 'Hub/Transit', model: 'ISR4331', version: '17.09.04a', serial: 'FDO2213A0R2', pqcSupport: false,
        interfaces: {
          'GigabitEthernet0/0/0': { ip: '10.0.12.2', mask: '255.255.255.0', desc: 'WAN to R1' },
          'GigabitEthernet0/0/1': { ip: '10.0.23.1', mask: '255.255.255.0', desc: 'WAN to R3' },
        },
      },
      r3: {
        hostname: 'R3', role: 'Spoke-2', model: 'ISR4331', version: '17.09.04a', serial: 'FDO2213A0R3', pqcSupport: false,
        interfaces: {
          'GigabitEthernet0/0/0': { ip: '10.0.23.2', mask: '255.255.255.0', desc: 'WAN to R2' },
          'GigabitEthernet0/0/1': {},
          'Loopback1': { ip: '10.3.3.3', mask: '255.255.255.0', desc: 'LAN behind R3' },
        },
      },
    },
    links: [
      { a: ['r1', 'GigabitEthernet0/0/0'], b: ['r2', 'GigabitEthernet0/0/0'], label: '10.0.12.0/24', speed: '1 Gb' },
      { a: ['r2', 'GigabitEthernet0/0/1'], b: ['r3', 'GigabitEthernet0/0/0'], label: '10.0.23.0/24', speed: '1 Gb' },
    ],
  };
  if (typeof module === 'object' && module.exports) module.exports = TOPOLOGY;
  else root.LAB_TOPOLOGY = TOPOLOGY;
})(typeof globalThis !== 'undefined' ? globalThis : this);
