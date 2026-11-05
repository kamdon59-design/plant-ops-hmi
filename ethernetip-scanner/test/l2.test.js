// Layer-2 discovery tests against simulated devices on an in-memory Ethernet
// segment. Each simulated device behaves like a small embedded IP stack:
// it answers ARP for its own address, accepts List Identity sent to its IP,
// its directed broadcast or 255.255.255.255, and replies — ARPing for the
// sender if it is on-subnet, for its gateway if not, or dropping the reply if
// it has no gateway.

const test = require('node:test');
const assert = require('node:assert');
const EventEmitter = require('events');
const P = require('../src/l2/packets');
const enip = require('../src/enip');
const { L2Discovery, expandTo24 } = require('../src/l2/discovery');
const { buildIdentityReply } = require('./mock-device');

class Segment {
  constructor() { this.ports = []; this.frames = []; }
  attach(onFrame) {
    const port = new EventEmitter();
    port.send = (buf) => {
      this.frames.push(buf);
      for (const p of this.ports) if (p !== port) setImmediate(() => p.emit('frame', buf));
      return true;
    };
    if (onFrame) port.on('frame', onFrame);
    this.ports.push(port);
    return port;
  }
}

class SimDevice {
  constructor(segment, { ip, mask, gateway = null, mac, name, acceptsDirected = true }) {
    Object.assign(this, { ip, mask, gateway, mac, name, acceptsDirected });
    this.arpCache = new Map();
    this.pending = new Map(); // nextHop -> frame waiting for ARP
    this.replies = 0;
    this.port = segment.attach((f) => this.rx(f));
  }
  inSubnet(ip) {
    const m = enip.ipToInt(this.mask);
    return ((enip.ipToInt(ip) & m) >>> 0) === ((enip.ipToInt(this.ip) & m) >>> 0);
  }
  rx(frame) {
    const f = P.parseFrame(frame);
    if (!f) return;
    if (f.type === 'arp') {
      if (f.op === 1 && f.targetIp === this.ip) {
        this.port.send(P.arp({ op: 2, senderMac: this.mac, senderIp: this.ip, targetMac: f.senderMac, targetIp: f.senderIp, dstMac: f.senderMac }));
      }
      if (f.op === 2 && f.dst === this.mac) {
        this.arpCache.set(f.senderIp, f.senderMac);
        const q = this.pending.get(f.senderIp);
        if (q) { this.pending.delete(f.senderIp); this.port.send(P.ethernet(f.senderMac, this.mac, P.ETH_IPV4, q)); }
      }
      return;
    }
    if (f.type !== 'udp' || f.dstPort !== 44818) return;
    if (f.dst !== this.mac && f.dst !== 'FF:FF:FF:FF:FF:FF') return;
    const directed = enip.broadcastAddress(this.ip, this.mask);
    const accepted = [this.ip, '255.255.255.255'].concat(this.acceptsDirected ? [directed] : []);
    if (!accepted.includes(f.dstIp)) return; // not for us
    // Build the reply IP packet (without Ethernet header)
    const reply = P.udp({
      srcMac: this.mac, dstMac: P.BROADCAST_MAC, srcIp: this.ip, dstIp: f.srcIp,
      srcPort: 44818, dstPort: f.srcPort, payload: buildIdentityReply({ ip: this.ip, vendorId: 1, deviceType: 0x0e, productCode: 1, major: 1, minor: 2, serial: 1, productName: this.name })
    }).subarray(14);
    const nextHop = this.inSubnet(f.srcIp) ? f.srcIp : this.gateway;
    if (!nextHop) return; // no route — drop
    this.replies++;
    const mac = this.arpCache.get(nextHop);
    if (mac) { this.port.send(P.ethernet(mac, this.mac, P.ETH_IPV4, reply)); return; }
    this.pending.set(nextHop, reply); // embedded stacks keep ~1 packet per unresolved entry
    this.port.send(P.arp({ op: 1, senderMac: this.mac, senderIp: this.ip, targetIp: nextHop }));
  }
}

const LAPTOP_MAC = '02:00:00:00:00:01';

function setup(devices) {
  const seg = new Segment();
  const sims = devices.map((d) => new SimDevice(seg, d));
  const link = seg.attach();
  const disc = new L2Discovery({ link, mac: LAPTOP_MAC, ownIps: ['192.168.1.50'] });
  return { seg, sims, disc };
}

async function findAll(disc) {
  await disc.sweep({ ranges: ['192.168.0.0/16', '172.16.0.0/12'], pps: 200000 });
  await new Promise((r) => setTimeout(r, 50));
  const out = [];
  for (const h of disc.hosts.values()) {
    const id = await disc.queryIdentity(h, { timeout: 300 });
    if (id) out.push(id);
  }
  return out.sort((a, b) => a.ip.localeCompare(b.ip));
}

test('expandTo24 covers the default private ranges', () => {
  assert.strictEqual(expandTo24(['192.168.0.0/16']).length, 256);
  assert.strictEqual(expandTo24(['172.16.0.0/12']).length, 4096);
  assert.deepStrictEqual(expandTo24(['10.1.2.0/24']), ['10.1.2']);
});

test('packets: UDP frame round-trips through the parser with a valid checksum', () => {
  const frame = P.udp({ srcMac: LAPTOP_MAC, dstMac: P.BROADCAST_MAC, srcIp: '172.16.30.239', dstIp: '172.16.30.255', srcPort: 50000, dstPort: 44818, payload: enip.buildListIdentity() });
  const f = P.parseFrame(frame);
  assert.strictEqual(f.type, 'udp');
  assert.strictEqual(f.srcIp, '172.16.30.239');
  assert.strictEqual(f.dstIp, '172.16.30.255');
  assert.strictEqual(f.payload.length, 24);
  assert.strictEqual(P.checksum(frame.subarray(14, 34)), 0); // IPv4 header checksum verifies
});

test('finds devices on other subnets (/24, /16, and gateway-configured 10.x) with no IP given', async () => {
  const { disc } = setup([
    { ip: '172.16.30.15', mask: '255.255.255.0', mac: '00:1D:9C:00:00:01', name: '1769-L33ER/A LOGIX5333ER' },
    { ip: '192.168.77.8', mask: '255.255.0.0', mac: '00:1D:9C:00:00:02', name: '1756-EN2T/D' },
    { ip: '10.20.5.7', mask: '255.255.255.0', gateway: '10.20.5.1', mac: '00:1D:9C:00:00:03', name: '2711P-T10C22D9P PanelView Plus 7' }
  ]);
  const found = await findAll(disc);
  assert.deepStrictEqual(found.map((d) => [d.ip, d.mac, d.catalog]), [
    ['10.20.5.7', '00:1D:9C:00:00:03', '2711P-T10C22D9P'],
    ['172.16.30.15', '00:1D:9C:00:00:01', '1769-L33ER/A'],
    ['192.168.77.8', '00:1D:9C:00:00:02', '1756-EN2T/D']
  ]);
  for (const d of found) assert.ok(d.suggestedLaptopIp.startsWith(d.ip.split('.').slice(0, 3).join('.')));
});

test('masks wider than /24 (/22) are found by the directed-broadcast pass', async () => {
  const { disc } = setup([{ ip: '192.168.8.20', mask: '255.255.252.0', mac: '00:1D:9C:00:00:04', name: '5069-L320ER/A' }]);
  const found = await findAll(disc);
  assert.deepStrictEqual(found.map((d) => d.ip), ['192.168.8.20']);
});

test('devices that ignore directed broadcasts are found by the fallback pass', async () => {
  const { disc } = setup([{ ip: '172.20.4.9', mask: '255.255.255.0', mac: '00:1D:9C:00:00:05', name: '1734-AENTR/B', acceptsDirected: false }]);
  const found = await findAll(disc);
  assert.deepStrictEqual(found.map((d) => d.ip), ['172.20.4.9']);
});

test('sweep is quiet: devices send almost no replies and no foreign ARP caches are touched', async () => {
  const { seg, sims, disc } = setup([
    { ip: '172.16.30.15', mask: '255.255.255.0', mac: '00:1D:9C:00:00:01', name: 'A' },
    { ip: '10.20.5.7', mask: '255.255.255.0', gateway: '10.20.5.1', mac: '00:1D:9C:00:00:03', name: 'B' }
  ]);
  await findAll(disc);
  for (const s of sims) assert.ok(s.replies <= 4, `${s.name} sent ${s.replies} replies`);
  // Every ARP reply the scanner sent went to the one device it was querying.
  const ours = seg.frames.map(P.parseFrame).filter((f) => f && f.type === 'arp' && f.op === 2 && f.senderMac === LAPTOP_MAC);
  assert.ok(ours.length >= 1);
  for (const f of ours) assert.notStrictEqual(f.dst, 'FF:FF:FF:FF:FF:FF');
});

test('passive: learns a device IP from its link-up announcement and ACD probe', async () => {
  const seg = new Segment();
  const link = seg.attach();
  const disc = new L2Discovery({ link, mac: LAPTOP_MAC, ownIps: ['192.168.1.50'] });
  const seen = [];
  disc.on('host', (h) => seen.push([h.ip, [...h.via].join()]));
  const dev = seg.attach();
  dev.send(P.arp({ op: 1, senderMac: '00:1D:9C:00:00:09', senderIp: '0.0.0.0', targetIp: '172.16.30.40' }));      // ACD probe
  dev.send(P.arp({ op: 1, senderMac: '00:1D:9C:00:00:0A', senderIp: '10.1.1.9', targetIp: '10.1.1.9' }));         // announcement
  await new Promise((r) => setTimeout(r, 20));
  assert.deepStrictEqual(seen, [['172.16.30.40', 'ACD probe'], ['10.1.1.9', 'ARP announce']]);
});

test('does not claim an address that is already in use', async () => {
  const { sims, disc } = setup([
    { ip: '172.16.30.15', mask: '255.255.255.0', mac: '00:1D:9C:00:00:01', name: 'PLC' },
    { ip: '172.16.30.239', mask: '255.255.255.0', mac: '00:1D:9C:00:00:0F', name: 'HMI at .239' }
  ]);
  const id = await disc.queryIdentity({ ip: '172.16.30.15', mac: '00:1D:9C:00:00:01' }, { timeout: 300 });
  assert.ok(id);
  assert.notStrictEqual(id.suggestedLaptopIp, '172.16.30.239');
  assert.ok(!sims[1].arpCache.has('172.16.30.239'));
});
