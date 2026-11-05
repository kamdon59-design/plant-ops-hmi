// Keeps a packet-capture listener open on every wired adapter from app start,
// so announcements a device makes the moment the cable is plugged in are not
// missed, and provides the layer-2 scan used for devices on other subnets.

const os = require('os');
const EventEmitter = require('events');
const pcap = require('./pcap');
const { L2Discovery } = require('./discovery');

const SKIP_DESC = /(loopback|wan miniport|virtual|vmware|virtualbox|hyper-v|vethernet|bluetooth|wi-?fi|wireless|802\.11|wlan|tap-|tap adapter|wireguard|tailscale|zerotier|vpn|kernel debug|npcap)/i;
const SKIP_UNIX = /^(any|lo|nflog|nfqueue|dbus|bluetooth|usbmon|ifb|docker|veth|br-|virbr|tun|tap|wl)/;

class L2Manager extends EventEmitter {
  constructor() {
    super();
    this.status = pcap.available();
    this.listeners = new Map(); // pcap device name -> { link, disc, dev }
    this.timer = null;
  }

  get ok() { return this.status.ok; }

  start() {
    if (!this.ok) return;
    this.refresh();
    this.timer = setInterval(() => this.refresh(), 5000);
  }

  stop() {
    clearInterval(this.timer);
    for (const l of this.listeners.values()) { l.disc.stop(); l.link.close(); }
    this.listeners.clear();
  }

  eligible(dev) {
    if (dev.loopback || dev.wireless) return false;
    if (process.platform === 'win32') return !SKIP_DESC.test(`${dev.description} ${dev.name}`);
    return !SKIP_UNIX.test(dev.name) && !!os.networkInterfaces()[dev.name];
  }

  /** Open listeners for new adapters and update our own MAC/IPs on existing ones. */
  refresh() {
    let devices;
    try { devices = pcap.listDevices(); } catch (e) { this.emit('error', e); return; }
    const osIfaces = os.networkInterfaces();
    const allMacs = Object.values(osIfaces).flat().map((a) => (a.mac || '').toUpperCase());

    for (const dev of devices) {
      if (!this.eligible(dev)) continue;
      let l = this.listeners.get(dev.name);
      if (!l) {
        try {
          const link = pcap.open(dev.name);
          const disc = new L2Discovery({ link });
          l = { link, disc, dev };
          link.on('error', () => { disc.stop(); this.listeners.delete(dev.name); });
          disc.on('host', (h) => this.emit('host', { ...h, via: [...h.via], pcapName: dev.name }));
          disc.on('bootp', (mac) => this.emit('bootp', { mac, pcapName: dev.name }));
          this.listeners.set(dev.name, l);
        } catch (e) {
          continue; // adapter may be disabled; try again next refresh
        }
      }
      l.dev = dev;
      // Match this capture device to the OS adapter by IP (Windows names differ).
      const ips = dev.addresses.map((a) => a.address);
      let mac = '';
      for (const [name, addrs] of Object.entries(osIfaces)) {
        for (const a of addrs || []) {
          if (ips.includes(a.address) || name === dev.name) { mac = (a.mac || '').toUpperCase(); }
        }
      }
      l.disc.setOwn({ mac, ips, otherMacs: allMacs });
    }
  }

  /** Find the listener for an OS adapter (by its IPv4 address). */
  forAdapter(adapter) {
    this.refresh();
    for (const l of this.listeners.values()) {
      if (l.dev.addresses.some((a) => a.address === adapter.address) || l.dev.name === adapter.name) return l;
    }
    return null;
  }
}

module.exports = { L2Manager };
