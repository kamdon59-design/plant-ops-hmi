// Layer-2 discovery: finds EtherNet/IP devices whose IP address is unknown and
// may be on a completely different subnet from the laptop.
//
// How a device reveals its IP:
//   1. Passive — it sends ARP (address-conflict-detection probes/announcements
//      when its link comes up, or ARP requests while talking), LLDP, or BOOTP.
//   2. Subnet probe — we broadcast a List Identity whose *source* address sits
//      inside a candidate /24 (e.g. 172.16.30.239). A device in that subnet
//      thinks the sender is local and broadcasts "who has 172.16.30.239? tell
//      172.16.30.15" before replying. That ARP request contains its IP. We
//      never answer these ARPs, so no ARP cache on the plant network is changed.
//   3. Identity query — for each discovered IP we pick an address in the same
//      /24, confirm with an RFC 5227 ARP probe that nobody owns it, then send a
//      unicast List Identity from it and answer ARP for it *only to that device*.
//      The reply is captured at layer 2 — the laptop's own IP settings are never
//      changed.

const EventEmitter = require('events');
const P = require('./packets');
const enip = require('../enip');

const PROBE_HOST = 239; // host octet used as the probe source in each /24
const ZERO_MAC = '00:00:00:00:00:00';

/** Expand CIDR ranges into /24 network bases ("a.b.c"). */
function expandTo24(cidrs) {
  const out = [];
  for (const cidr of cidrs) {
    const [base, bitsStr] = cidr.split('/');
    const bits = Math.min(24, Number(bitsStr || 24));
    const start = (enip.ipToInt(base) >>> 0) & (bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0);
    const count = 2 ** (24 - bits);
    for (let i = 0; i < count; i++) {
      const n = (start + i * 256) >>> 0;
      out.push(`${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}`);
    }
  }
  return out;
}

function prefix24(ip) { return ip.split('.').slice(0, 3).join('.'); }

function isUsableIp(ip) {
  if (!ip || ip === '0.0.0.0') return false;
  const [a, , , d] = ip.split('.').map(Number);
  if (a === 0 || a === 127 || a >= 224) return false;
  if (d === 255) return false;
  return true;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class L2Discovery extends EventEmitter {
  /**
   * @param {object} opts
   * @param {object} opts.link       { send(buf), on('frame') } — a pcap Link or a test double
   * @param {string} [opts.mac]      our MAC ("AA:BB:..."); may be set later via setOwn()
   * @param {string[]} [opts.ownIps] our IPv4 addresses on this adapter
   */
  constructor({ link, mac = '', ownIps = [] }) {
    super();
    this.link = link;
    this.mac = mac.toUpperCase();
    this.ownIps = new Set(ownIps);
    this.ownMacs = new Set(mac ? [this.mac] : []);
    this.hosts = new Map();      // ip -> { ip, mac, via:Set, firstSeen, lastSeen, name }
    this.bootp = new Map();      // mac -> lastSeen  (devices asking for an address)
    this.identities = new Map(); // ip -> identity object
    this.claims = new Map();     // our temporary ip -> MAC allowed to resolve it
    this.srcPort = 0xc000 + Math.floor(Math.random() * 0x3000);
    this.onFrame = (f) => this.handle(f);
    link.on('frame', this.onFrame);
  }

  setOwn({ mac, ips = [], otherMacs = [] }) {
    if (mac) { this.mac = mac.toUpperCase(); this.ownMacs.add(this.mac); }
    for (const m of otherMacs) if (m) this.ownMacs.add(m.toUpperCase());
    this.ownIps = new Set(ips);
  }

  stop() { this.link.removeListener('frame', this.onFrame); }

  // ── receive ───────────────────────────────────────────────────────────

  note(ip, mac, via, extra = {}) {
    if (!isUsableIp(ip) || this.ownIps.has(ip) || this.claims.has(ip)) return;
    if (!mac || mac === ZERO_MAC || this.ownMacs.has(mac)) return;
    const now = Date.now();
    let h = this.hosts.get(ip);
    if (!h) {
      h = { ip, mac, via: new Set(), firstSeen: now, lastSeen: now, lastAnnounce: 0, name: '' };
      this.hosts.set(ip, h);
      h.via.add(via);
      Object.assign(h, extra);
      if (via === 'ACD probe' || via === 'ARP announce') h.lastAnnounce = now;
      this.emit('host', h);
    } else {
      h.mac = mac;
      h.lastSeen = now;
      h.via.add(via);
      Object.assign(h, extra);
      // An address announcement from a known device means its link just came
      // up again (cable re-plugged / power cycled) — report it again.
      if ((via === 'ACD probe' || via === 'ARP announce') && now - (h.lastAnnounce || 0) > 5000) {
        h.lastAnnounce = now;
        this.emit('host', h);
      }
    }
  }

  handle(frame) {
    let f;
    try { f = P.parseFrame(frame); } catch (_) { return; }
    if (!f || this.ownMacs.has(f.src)) return;

    if (f.type === 'arp') {
      if (f.senderIp === '0.0.0.0') {
        // RFC 5227 / ACD probe: device is about to claim targetIp
        this.note(f.targetIp, f.senderMac, 'ACD probe');
      } else {
        this.note(f.senderIp, f.senderMac, f.senderIp === f.targetIp ? 'ARP announce' : 'ARP');
      }
      // Answer ARP for one of our temporary probe addresses — only to the
      // device we are querying, so nobody else's ARP cache is touched.
      const allowed = this.claims.get(f.targetIp);
      if (f.op === 1 && allowed && allowed === f.senderMac && this.mac) {
        this.link.send(P.arp({
          op: 2, senderMac: this.mac, senderIp: f.targetIp,
          targetMac: f.senderMac, targetIp: f.senderIp, dstMac: f.senderMac
        }));
      }
      if (f.op === 2) this.emit('arp-reply', f);
      return;
    }

    if (f.type === 'lldp') {
      for (const ip of f.mgmtIps) this.note(ip, f.src, 'LLDP', f.sysName ? { name: f.sysName } : {});
      return;
    }

    if (f.type === 'udp') {
      if (f.srcPort === enip.ENIP_PORT && f.dst === this.mac) {
        try {
          for (const id of enip.parseListIdentityReply(f.payload)) {
            id.ip = f.srcIp;
            id.mac = f.src;
            id.macSource = 'Ethernet';
            this.note(f.srcIp, f.src, 'EtherNet/IP');
            const isNew = !this.identities.has(f.srcIp);
            this.identities.set(f.srcIp, id);
            if (isNew) this.emit('identity', id);
          }
        } catch (_) { /* not a List Identity reply */ }
      } else if (f.dstPort === 67) {
        const mac = P.parseBootpRequest(f.payload);
        if (mac && !this.ownMacs.has(mac)) {
          const isNew = !this.bootp.has(mac);
          this.bootp.set(mac, Date.now());
          if (isNew) this.emit('bootp', mac);
        }
      } else if (f.srcIp !== '0.0.0.0') {
        this.note(f.srcIp, f.src, 'traffic');
      }
    }
  }

  // ── send ──────────────────────────────────────────────────────────────

  listIdentityFrame(srcIp, dstIp = '255.255.255.255', dstMac = P.BROADCAST_MAC) {
    return P.udp({
      srcMac: this.mac, dstMac, srcIp, dstIp,
      srcPort: this.srcPort, dstPort: enip.ENIP_PORT, payload: enip.buildListIdentity()
    });
  }

  /**
   * Make devices on unknown subnets reveal their IP addresses.
   *
   * Every probe is a List Identity *from* an address inside a candidate subnet
   * *to that subnet's directed broadcast* (e.g. 172.16.30.239 → 172.16.30.255).
   * Only devices on that subnet accept it; they ARP for the sender, which
   * reveals their IP. Every other device drops it silently at the IP layer, so
   * the sweep causes no reply traffic on the plant network.
   *
   *   pass 1  from our real IP to 255.255.255.255 — devices with a default
   *           gateway ARP for the gateway (one packet)
   *   pass 2  /16 and /24 directed broadcasts. Any mask of /24 or wider
   *           (/23, /22, /16, ...) is covered, because such a subnet's
   *           broadcast address is also the broadcast of its top /24.
   *   pass 3  the same sources sent to 255.255.255.255 — for devices whose
   *           stacks ignore subnet-directed broadcasts (some PLCs do, as an
   *           anti-"smurf" measure). This pass always runs: skipping it when
   *           another device had already answered pass 2 missed PLCs in the
   *           field. Off-subnet devices that have a gateway configured send
   *           their replies to it during this pass.
   */
  async sweep({ ranges, pps = 2000, onProgress = () => {}, shouldStop = () => false }) {
    if (!this.mac) throw new Error('adapter MAC unknown');
    this.identities.clear(); // re-read identities on every scan

    for (const ip of this.ownIps) this.link.send(this.listIdentityFrame(ip));

    const nets24 = expandTo24(ranges);
    const nets16 = [...new Set(nets24.map((n) => n.split('.').slice(0, 2).join('.')))];
    const probes = [
      ...nets16.map((n) => [`${n}.0.${PROBE_HOST}`, `${n}.255.255`]),
      ...nets24.map((n) => [`${n}.${PROBE_HOST}`, `${n}.255`])
    ];
    const send = async (list, label) => {
      const batch = Math.max(1, Math.round(pps / 50)); // a batch every 20 ms
      for (let i = 0; i < list.length; i += batch) {
        if (shouldStop()) return;
        for (const [src, dst] of list.slice(i, i + batch)) this.link.send(this.listIdentityFrame(src, dst));
        if (i % (batch * 10) === 0) onProgress(i, list.length, label);
        await sleep(20);
      }
      onProgress(list.length, list.length, label);
    };

    await send(probes, 'subnet broadcasts');
    await send(nets24.map((n) => [`${n}.${PROBE_HOST}`, '255.255.255.255']), 'wide search');
  }

  /** RFC 5227 ARP probe — resolves true if nobody answers for `ip`. */
  async isAddressFree(ip, waitMs = 400) {
    let taken = false;
    const onReply = (f) => { if (f.senderIp === ip) taken = true; };
    this.on('arp-reply', onReply);
    for (let i = 0; i < 2 && !taken; i++) {
      this.link.send(P.arp({ op: 1, senderMac: this.mac, senderIp: '0.0.0.0', targetIp: ip }));
      await sleep(waitMs / 2);
    }
    this.removeListener('arp-reply', onReply);
    const seen = this.hosts.get(ip);
    if (seen && Date.now() - seen.lastSeen < 5 * 60 * 1000) taken = true;
    return !taken;
  }

  /** Candidate source addresses in the device's subnet (assumes /24 or wider). */
  sourceCandidates(deviceIp) {
    const base = prefix24(deviceIp);
    const last = Number(deviceIp.split('.')[3]);
    // The neighbour (last ^ 1) is inside the device's subnet for any mask up
    // to /30; .239 is the probe address it may already have ARPed for.
    const list = [last ^ 1, PROBE_HOST, last + 2, last - 2, 238, 201, 101, 51]
      .filter((n) => n >= 1 && n <= 254 && n !== last)
      .map((n) => `${base}.${n}`);
    return [...new Set(list)].filter((ip) => !this.hosts.has(ip));
  }

  /**
   * Ask one device for its identity from a free address in its own subnet.
   * Resolves the identity (with `.suggestedLaptopIp`) or null.
   */
  async queryIdentity(host, { timeout = 1200, maxSources = 3 } = {}) {
    if (this.identities.has(host.ip)) return this.identities.get(host.ip);
    let tried = 0;
    let failedQueries = 0;
    for (const src of this.sourceCandidates(host.ip)) {
      if (tried >= maxSources + 1) break;
      tried++;
      if (!(await this.isAddressFree(src))) continue;

      this.claims.set(src, host.mac);
      try {
        const got = new Promise((resolve) => {
          const t = setTimeout(() => { this.removeListener('identity', on); resolve(null); }, timeout);
          const on = (id) => {
            if (id.ip === host.ip) { clearTimeout(t); this.removeListener('identity', on); resolve(id); }
          };
          this.on('identity', on);
        });
        const frame = this.listIdentityFrame(src, host.ip, host.mac);
        this.link.send(frame);
        setTimeout(() => this.link.send(frame), 300); // one retry (first may be lost while ARP resolves)
        const id = await got;
        if (id) {
          id.suggestedLaptopIp = src;
          return id;
        }
      } finally {
        // keep answering ARP briefly so a late reply isn't lost
        setTimeout(() => this.claims.delete(src), 1500);
      }
      this.emit('log', `${host.ip}: no identity reply from ${src}`);
      // Try one more free source before giving up (different mask assumptions).
      if (++failedQueries >= 2) return null;
    }
    return null;
  }
}

module.exports = { L2Discovery, expandTo24, PROBE_HOST };
