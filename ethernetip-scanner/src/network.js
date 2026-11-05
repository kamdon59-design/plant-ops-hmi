// Network adapter detection, ARP-table lookup, and the scan orchestrator.

const os = require('os');
const { execFile } = require('child_process');
const EventEmitter = require('events');
const enip = require('./enip');

const VIRTUAL_ADAPTER = /(vmware|virtualbox|vbox|hyper-v|vethernet|loopback|docker|wsl|tailscale|zerotier|vpn|tap|tun|utun|bridge|br-|veth|npcap)/i;
const WIRELESS_ADAPTER = /(wi-?fi|wlan|wireless|airport)/i;

/** Physical-looking IPv4 adapters that are up and have an address. */
function listAdapters() {
  const out = [];
  const ifaces = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(ifaces)) {
    for (const a of addrs || []) {
      if (a.family !== 'IPv4' && a.family !== 4) continue;
      if (a.internal) continue;
      out.push({
        name,
        address: a.address,
        netmask: a.netmask,
        mac: (a.mac || '').toUpperCase(),
        broadcast: enip.broadcastAddress(a.address, a.netmask),
        linkLocal: a.address.startsWith('169.254.'),
        virtual: VIRTUAL_ADAPTER.test(name),
        wireless: WIRELESS_ADAPTER.test(name)
      });
    }
  }
  return out;
}

/**
 * Polls the OS adapters and emits:
 *   'change'  (adapters)          — on any change
 *   'connected' (adapter)         — a new adapter/IP appeared (cable plugged in)
 *   'disconnected' (adapter)      — an adapter/IP disappeared
 */
class AdapterWatcher extends EventEmitter {
  constructor(intervalMs = 2000) {
    super();
    this.intervalMs = intervalMs;
    this.known = new Map();
    this.timer = null;
  }
  key(a) { return `${a.name}|${a.address}`; }
  start() {
    for (const a of listAdapters()) this.known.set(this.key(a), a);
    this.timer = setInterval(() => this.poll(), this.intervalMs);
    return [...this.known.values()];
  }
  poll() {
    const now = new Map(listAdapters().map((a) => [this.key(a), a]));
    let changed = false;
    for (const [k, a] of now) if (!this.known.has(k)) { changed = true; this.emit('connected', a); }
    for (const [k, a] of this.known) if (!now.has(k)) { changed = true; this.emit('disconnected', a); }
    this.known = now;
    if (changed) this.emit('change', [...now.values()]);
  }
  stop() { clearInterval(this.timer); }
}

// ── ARP table (fallback for MAC addresses) ───────────────────────────────

function run(cmd, args) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 4000, windowsHide: true }, (err, stdout) => resolve(err ? '' : String(stdout)));
  });
}

/** Returns Map<ip, "AA:BB:CC:DD:EE:FF"> parsed from the OS neighbour table. */
async function readArpTable() {
  const map = new Map();
  const add = (ip, mac) => {
    const norm = mac.replace(/-/g, ':').split(':').map((p) => p.padStart(2, '0')).join(':').toUpperCase();
    if (/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(norm) && norm !== 'FF:FF:FF:FF:FF:FF' && norm !== '00:00:00:00:00:00') {
      map.set(ip, norm);
    }
  };

  let text = '';
  if (process.platform === 'linux') text = await run('ip', ['neigh']);
  if (!text) text = await run('arp', process.platform === 'win32' ? ['-a'] : ['-an']);

  const re = /(\d{1,3}(?:\.\d{1,3}){3})\D+?(([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2})/gi;
  for (const line of text.split(/\r?\n/)) {
    re.lastIndex = 0;
    const m = re.exec(line);
    if (m) add(m[1], m[2]);
  }
  return map;
}

// ── Scan orchestrator ────────────────────────────────────────────────────

const PRIVATE_RANGES = ['192.168.0.0/16', '172.16.0.0/12'];
const TEN_RANGE = ['10.0.0.0/8'];

function sameSubnet(ip, ad) {
  const m = enip.ipToInt(ad.netmask);
  return ((enip.ipToInt(ip) & m) >>> 0) === ((enip.ipToInt(ad.address) & m) >>> 0);
}

async function mapLimit(items, limit, fn) {
  const queue = [...items];
  await Promise.all(Array.from({ length: Math.min(limit, queue.length) }, async () => {
    while (queue.length) await fn(queue.shift());
  }));
}

/**
 * Scan one or more adapters for EtherNet/IP devices.
 * @param {object} opts
 * @param {object[]} opts.adapters      from listAdapters()
 * @param {boolean} [opts.sweep]        also unicast every host in the adapter's subnet
 * @param {string[]} [opts.extraTargets] additional IPs to probe directly
 * @param {object} [opts.l2]            L2Manager — enables finding devices on any subnet
 * @param {boolean} [opts.anySubnet]    use layer-2 discovery (needs Npcap)
 * @param {boolean} [opts.include10]    also probe every /24 in 10.0.0.0/8 (slower)
 * @param {string[]} [opts.extraRanges] extra CIDR ranges to probe at layer 2
 * @param {(evt)=>void} [opts.onEvent]  progress callback
 */
async function scan({
  adapters, sweep = true, extraTargets = [], l2 = null, anySubnet = true,
  include10 = false, extraRanges = [], onEvent = () => {}
}) {
  const devices = new Map();
  const add = (dev, ad) => {
    const prev = devices.get(dev.ip);
    if (prev) {
      if (!prev.mac && dev.mac) { prev.mac = dev.mac; prev.macSource = dev.macSource; onEvent({ type: 'device', device: prev }); }
      return;
    }
    dev.adapter = ad.name;
    dev.otherSubnet = !sameSubnet(dev.ip, ad);
    dev.mac = dev.mac || '';
    dev.macSource = dev.macSource || '';
    devices.set(dev.ip, dev);
    onEvent({ type: 'device', device: dev });
  };

  await Promise.all(adapters.map(async (ad) => {
    // 1. Normal UDP discovery through the OS (same subnet).
    const ipPath = (async () => {
      const targets = new Set([ad.broadcast, '255.255.255.255', ...extraTargets]);
      if (sweep && !ad.linkLocal) for (const h of enip.hostsInSubnet(ad.address, ad.netmask, 1024)) targets.add(h);
      onEvent({ type: 'status', message: `Probing ${targets.size} address(es) on ${ad.name} (${ad.address})…` });
      try {
        await enip.discover({ localAddress: ad.address, targets: [...targets], timeout: 3000, onDevice: (d) => add(d, ad) });
      } catch (e) {
        onEvent({ type: 'error', message: `${ad.name}: ${e.message}` });
      }
    })();

    // 2. Layer-2 discovery — finds devices whatever subnet they are on.
    const l2Path = (async () => {
      if (!anySubnet || !l2 || !l2.ok) return;
      const listener = l2.forAdapter(ad);
      if (!listener) { onEvent({ type: 'status', message: `${ad.name}: packet capture not available on this adapter` }); return; }
      const disc = listener.disc;
      const onId = (id) => add(id, ad);
      disc.on('identity', onId);
      try {
        const ranges = [...PRIVATE_RANGES, ...(include10 ? TEN_RANGE : []), ...extraRanges];
        await disc.sweep({
          ranges,
          pps: include10 ? 4000 : 2000,
          onProgress: (done, total, label) => onEvent({
            type: 'status',
            message: `Searching all subnets on ${ad.name} (${label})… ${Math.round((done / total) * 100)}%`
          })
        });
        await new Promise((r) => setTimeout(r, 800)); // late ARPs

        // Query every host that revealed itself and isn't identified yet.
        // Hosts in our own subnet were already asked through the normal path.
        const recent = Date.now() - 15 * 60 * 1000;
        const todo = [...disc.hosts.values()].filter((h) =>
          h.lastSeen > recent && !devices.has(h.ip) && !sameSubnet(h.ip, ad));
        if (todo.length) onEvent({ type: 'status', message: `Found ${todo.length} address(es) on other subnets — asking for identity…` });
        await mapLimit(todo, 6, async (h) => {
          const id = await disc.queryIdentity(h);
          if (id) add(id, ad);
        });
      } catch (e) {
        onEvent({ type: 'error', message: `${ad.name}: ${e.message}` });
      } finally {
        disc.removeListener('identity', onId);
      }
    })();

    await Promise.all([ipPath, l2Path]);
  }));

  // MAC addresses for devices found through the OS path — CIP first, ARP as fallback.
  const list = [...devices.values()];
  const needMac = list.filter((d) => !d.mac);
  if (needMac.length) onEvent({ type: 'status', message: `Reading MAC addresses from ${needMac.length} device(s)…` });
  await Promise.all(needMac.filter((d) => !d.otherSubnet).map(async (dev) => {
    try {
      dev.mac = await enip.readMacAddress(dev.ip);
      dev.macSource = 'CIP';
    } catch (_) { /* fall through to ARP */ }
  }));
  const missing = list.filter((d) => !d.mac);
  if (missing.length) {
    const arp = await readArpTable();
    for (const d of missing) if (arp.has(d.ip)) { d.mac = arp.get(d.ip); d.macSource = 'ARP'; }
  }
  for (const d of list) if (!d.mac) d.macSource = 'unavailable';
  for (const d of list) onEvent({ type: 'device', device: d });

  return list;
}

module.exports = { listAdapters, AdapterWatcher, readArpTable, scan, sameSubnet };
