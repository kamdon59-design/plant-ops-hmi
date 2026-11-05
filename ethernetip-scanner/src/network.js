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

/**
 * Scan one or more adapters for EtherNet/IP devices.
 * @param {object} opts
 * @param {object[]} opts.adapters   from listAdapters()
 * @param {boolean} [opts.sweep]     also unicast every host in the subnet
 * @param {string[]} [opts.extraTargets] additional IPs to probe directly
 * @param {(evt)=>void} [opts.onEvent] progress callback
 */
async function scan({ adapters, sweep = true, extraTargets = [], onEvent = () => {} }) {
  const devices = new Map();

  await Promise.all(adapters.map(async (ad) => {
    const targets = new Set([ad.broadcast, '255.255.255.255', ...extraTargets]);
    if (sweep && !ad.linkLocal) for (const h of enip.hostsInSubnet(ad.address, ad.netmask, 1024)) targets.add(h);
    onEvent({ type: 'status', message: `Probing ${targets.size} address(es) on ${ad.name} (${ad.address})…` });

    try {
      await enip.discover({
        localAddress: ad.address,
        targets: [...targets],
        timeout: 3000,
        onDevice: (dev) => {
          if (devices.has(dev.ip)) return;
          dev.adapter = ad.name;
          dev.mac = '';
          dev.macSource = '';
          devices.set(dev.ip, dev);
          onEvent({ type: 'device', device: dev });
        }
      });
    } catch (e) {
      onEvent({ type: 'error', message: `${ad.name}: ${e.message}` });
    }
  }));

  // Resolve MAC addresses — CIP first (works across subnets), ARP as fallback.
  if (devices.size) onEvent({ type: 'status', message: `Reading MAC addresses from ${devices.size} device(s)…` });
  const list = [...devices.values()];
  await Promise.all(list.map(async (dev) => {
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

module.exports = { listAdapters, AdapterWatcher, readArpTable, scan };
