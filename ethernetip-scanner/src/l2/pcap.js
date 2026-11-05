// Minimal libpcap / Npcap binding through koffi (prebuilt FFI — nothing to
// compile on the user's machine). Windows needs Npcap: https://npcap.com
//
// Exposes:
//   available()          -> { ok, error }
//   listDevices()        -> [{ name, description, flags, addresses:[{address, netmask}] }]
//   open(name)           -> Link { send(buf), on('frame', buf), on('error'), close() }

const os = require('os');
const path = require('path');
const fs = require('fs');
const EventEmitter = require('events');

let lib = null;
let loadError = null;
let fn = null;

const PCAP_IF_LOOPBACK = 0x1;
const PCAP_IF_WIRELESS = 0x8;
const PCAP_IF_CONNECTION_STATUS = 0x30;
const PCAP_IF_CONNECTION_STATUS_DISCONNECTED = 0x20;

function load() {
  if (fn || loadError) return;
  let koffi;
  try {
    koffi = require('koffi');
  } catch (e) {
    loadError = `koffi module missing: ${e.message}`;
    return;
  }
  const candidates = [];
  if (process.platform === 'win32') {
    const sys = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32');
    const npcap = path.join(sys, 'Npcap');
    // wpcap.dll loads Packet.dll from its own folder; make sure Windows finds it.
    if (fs.existsSync(npcap)) process.env.PATH = `${npcap};${process.env.PATH}`;
    candidates.push(path.join(npcap, 'wpcap.dll'), 'wpcap.dll');
  } else if (process.platform === 'darwin') {
    candidates.push('libpcap.A.dylib', '/usr/lib/libpcap.A.dylib');
  } else {
    candidates.push('libpcap.so.1', 'libpcap.so.0.8', 'libpcap.so');
  }
  for (const c of candidates) {
    try { lib = koffi.load(c); break; } catch (_) { /* try next */ }
  }
  if (!lib) {
    loadError = process.platform === 'win32'
      ? 'Npcap is not installed'
      : 'libpcap is not installed';
    return;
  }

  // struct pcap_pkthdr { struct timeval ts; bpf_u_int32 caplen; bpf_u_int32 len; }
  // timeval is 2×long: 8 bytes on Windows, 16 bytes on 64-bit Unix.
  const tvSize = process.platform === 'win32' ? 8 : 2 * (os.arch().includes('64') ? 8 : 4);

  fn = {
    koffi,
    tvSize,
    findalldevs: lib.func('int pcap_findalldevs(_Out_ void **alldevs, char *errbuf)'),
    freealldevs: lib.func('void pcap_freealldevs(void *alldevs)'),
    open_live: lib.func('void *pcap_open_live(const char *dev, int snaplen, int promisc, int to_ms, char *errbuf)'),
    setnonblock: lib.func('int pcap_setnonblock(void *p, int nonblock, char *errbuf)'),
    compile: lib.func('int pcap_compile(void *p, void *fp, const char *str, int optimize, uint32_t netmask)'),
    setfilter: lib.func('int pcap_setfilter(void *p, void *fp)'),
    freecode: lib.func('void pcap_freecode(void *fp)'),
    next_ex: lib.func('int pcap_next_ex(void *p, _Out_ void **hdr, _Out_ void **data)'),
    sendpacket: lib.func('int pcap_sendpacket(void *p, const uint8_t *buf, int size)'),
    geterr: lib.func('const char *pcap_geterr(void *p)'),
    close: lib.func('void pcap_close(void *p)'),
    // struct pcap_if { next; name; description; addresses; flags }
    pcap_if: koffi.struct('pcap_if_t', {
      next: 'void *', name: 'const char *', description: 'const char *', addresses: 'void *', flags: 'uint32_t'
    }),
    // struct pcap_addr { next; addr; netmask; broadaddr; dstaddr }
    pcap_addr: koffi.struct('pcap_addr_t', {
      next: 'void *', addr: 'void *', netmask: 'void *', broadaddr: 'void *', dstaddr: 'void *'
    })
  };
}

function available() {
  load();
  return fn ? { ok: true } : { ok: false, error: loadError };
}

function readSockaddrIPv4(ptr) {
  if (!ptr) return null;
  const b = Buffer.from(fn.koffi.decode(ptr, fn.koffi.array('uint8', 8)));
  // BSD/macOS: [len][family]; Linux/Windows: little-endian u16 family
  const family = process.platform === 'darwin' ? b[1] : b.readUInt16LE(0);
  if (family !== 2) return null; // AF_INET
  return `${b[4]}.${b[5]}.${b[6]}.${b[7]}`;
}

function listDevices() {
  load();
  if (!fn) return [];
  const out = [null];
  const err = Buffer.alloc(512);
  if (fn.findalldevs(out, err) !== 0) throw new Error(err.toString('latin1').replace(/\0.*$/, ''));
  const devices = [];
  let p = out[0];
  while (p) {
    const d = fn.koffi.decode(p, fn.pcap_if);
    const addresses = [];
    let a = d.addresses;
    while (a) {
      const pa = fn.koffi.decode(a, fn.pcap_addr);
      const address = readSockaddrIPv4(pa.addr);
      if (address) addresses.push({ address, netmask: readSockaddrIPv4(pa.netmask) || '' });
      a = pa.next;
    }
    devices.push({
      name: d.name,
      description: d.description || '',
      flags: d.flags,
      loopback: !!(d.flags & PCAP_IF_LOOPBACK),
      wireless: !!(d.flags & PCAP_IF_WIRELESS),
      disconnected: (d.flags & PCAP_IF_CONNECTION_STATUS) === PCAP_IF_CONNECTION_STATUS_DISCONNECTED,
      addresses
    });
    p = d.next;
  }
  if (out[0]) fn.freealldevs(out[0]);
  return devices;
}

class Link extends EventEmitter {
  constructor(name, filter) {
    super();
    load();
    if (!fn) throw new Error(loadError);
    this.name = name;
    const err = Buffer.alloc(512);
    this.handle = fn.open_live(name, 2048, 0, 10, err);
    if (!this.handle) throw new Error(err.toString('latin1').replace(/\0.*$/, '') || 'pcap_open_live failed');
    fn.setnonblock(this.handle, 1, err);

    if (filter) {
      const prog = Buffer.alloc(16); // struct bpf_program { u_int len; bpf_insn *insns; }
      if (fn.compile(this.handle, prog, filter, 1, 0xffffffff) === 0) {
        fn.setfilter(this.handle, prog);
        fn.freecode(prog);
      }
    }
    this.timer = setInterval(() => this.poll(), 15);
  }

  poll() {
    if (!this.handle) return;
    for (let i = 0; i < 1000; i++) {
      const hdr = [null];
      const data = [null];
      const r = fn.next_ex(this.handle, hdr, data);
      if (r === 1) {
        const caplen = fn.koffi.decode(hdr[0], fn.tvSize, 'uint32_t');
        const frame = Buffer.from(fn.koffi.decode(data[0], fn.koffi.array('uint8', caplen)));
        this.emit('frame', frame);
      } else if (r === 0) {
        return; // nothing waiting
      } else {
        const msg = fn.geterr(this.handle);
        this.close();
        this.emit('error', new Error(msg || `pcap_next_ex returned ${r}`));
        return;
      }
    }
  }

  send(frame) {
    if (!this.handle) return false;
    return fn.sendpacket(this.handle, frame, frame.length) === 0;
  }

  close() {
    clearInterval(this.timer);
    if (this.handle) { fn.close(this.handle); this.handle = null; }
  }
}

const DEFAULT_FILTER = 'arp or ether proto 0x88cc or udp port 44818 or udp port 67 or udp port 68 or (vlan and (arp or udp port 44818))';

function open(name, filter = DEFAULT_FILTER) {
  return new Link(name, filter);
}

module.exports = { available, listDevices, open };
