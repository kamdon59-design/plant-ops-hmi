// EtherNet/IP (CIP over Ethernet) discovery — pure Node.js, no native modules.
//
// Discovery uses the encapsulation "List Identity" command (0x0063) sent over
// UDP to port 44818. Every EtherNet/IP device (ControlLogix, CompactLogix,
// Micro800, PanelView, PowerFlex, POINT I/O, Stratix, ...) must answer it with
// its Identity Object: vendor, device type, product code, firmware revision,
// serial number and product name.
//
// The MAC address is not part of List Identity, so for each device we open a
// short TCP session and read the Ethernet Link Object (class 0xF6, instance 1,
// attribute 3 = Physical Address). If that fails, the caller falls back to the
// OS ARP table.

const dgram = require('dgram');
const net = require('net');

const ENIP_PORT = 44818;

const CMD = {
  LIST_IDENTITY: 0x0063,
  REGISTER_SESSION: 0x0065,
  UNREGISTER_SESSION: 0x0066,
  SEND_RR_DATA: 0x006f
};

const VENDORS = {
  1: 'Rockwell Automation / Allen-Bradley'
};

// CIP device profile types (Volume 1, chapter 6)
const DEVICE_TYPES = {
  0x00: 'Generic Device',
  0x02: 'AC Drive',
  0x03: 'Motor Overload',
  0x04: 'Limit Switch',
  0x05: 'Inductive Proximity Switch',
  0x06: 'Photoelectric Sensor',
  0x07: 'General Purpose Discrete I/O',
  0x09: 'Resolver',
  0x0a: 'General Purpose Analog I/O',
  0x0c: 'Communications Adapter',
  0x0e: 'Programmable Logic Controller',
  0x10: 'Position Controller',
  0x13: 'DC Drive',
  0x15: 'Contactor',
  0x16: 'Motor Starter',
  0x17: 'Soft Start',
  0x18: 'Human-Machine Interface',
  0x1a: 'Mass Flow Controller',
  0x1b: 'Pneumatic Valve',
  0x1c: 'Vacuum Pressure Gauge',
  0x1d: 'Process Control Valve',
  0x1e: 'Residual Gas Analyzer',
  0x1f: 'DC Power Generator',
  0x20: 'RF Power Generator',
  0x21: 'Turbomolecular Vacuum Pump',
  0x22: 'Encoder',
  0x23: 'Safety Discrete I/O',
  0x24: 'Fluid Flow Controller',
  0x25: 'CIP Motion Drive',
  0x26: 'CompoNet Repeater',
  0x28: 'CIP Modbus Device',
  0x29: 'CIP Modbus Translator',
  0x2a: 'Safety Analog I/O',
  0x2b: 'Generic Device (keyable)',
  0x2c: 'Managed Ethernet Switch'
};

// ── Encapsulation helpers ────────────────────────────────────────────────

function buildHeader(command, dataLength = 0, session = 0) {
  const buf = Buffer.alloc(24);
  buf.writeUInt16LE(command, 0);
  buf.writeUInt16LE(dataLength, 2);
  buf.writeUInt32LE(session, 4);
  // status (4), sender context (8), options (4) all zero
  return buf;
}

function buildListIdentity() {
  return buildHeader(CMD.LIST_IDENTITY);
}

// Pull a likely Allen-Bradley catalog number (e.g. "1769-L33ER", "2711P-T10C22D9P")
// out of the product name string.
function extractCatalog(productName) {
  const m = /\b(\d{4}[A-Z]?-[A-Z0-9]+(?:[/-][A-Z0-9]+)*)\b/i.exec(productName || '');
  return m ? m[1] : '';
}

// Parse a List Identity reply. Returns an array of identity objects (a reply
// normally contains one CIP Identity item).
function parseListIdentityReply(buf) {
  if (buf.length < 26) throw new Error('reply too short');
  const command = buf.readUInt16LE(0);
  if (command !== CMD.LIST_IDENTITY) throw new Error(`unexpected command 0x${command.toString(16)}`);
  const status = buf.readUInt32LE(8);
  if (status !== 0) throw new Error(`encapsulation status 0x${status.toString(16)}`);

  let off = 24;
  const itemCount = buf.readUInt16LE(off); off += 2;
  const results = [];

  for (let i = 0; i < itemCount && off + 4 <= buf.length; i++) {
    const typeId = buf.readUInt16LE(off);
    const len = buf.readUInt16LE(off + 2);
    const start = off + 4;
    off = start + len;
    if (typeId !== 0x000c || off > buf.length) continue; // 0x0C = CIP Identity

    let p = start;
    const protocolVersion = buf.readUInt16LE(p); p += 2;
    // sockaddr_in is big-endian
    p += 2; // sin_family
    const port = buf.readUInt16BE(p); p += 2;
    const ip = `${buf[p]}.${buf[p + 1]}.${buf[p + 2]}.${buf[p + 3]}`; p += 4;
    p += 8; // sin_zero
    const vendorId = buf.readUInt16LE(p); p += 2;
    const deviceType = buf.readUInt16LE(p); p += 2;
    const productCode = buf.readUInt16LE(p); p += 2;
    const revMajor = buf[p]; const revMinor = buf[p + 1]; p += 2;
    const statusWord = buf.readUInt16LE(p); p += 2;
    const serial = buf.readUInt32LE(p); p += 4;
    const nameLen = buf[p]; p += 1;
    const productName = buf.toString('latin1', p, p + nameLen).replace(/\0+$/, '').trim(); p += nameLen;
    const state = p < start + len ? buf[p] : null;

    results.push({
      ip,
      port,
      protocolVersion,
      vendorId,
      vendor: VENDORS[vendorId] || `Vendor ${vendorId}`,
      deviceType,
      deviceTypeName: DEVICE_TYPES[deviceType] || `Type 0x${deviceType.toString(16)}`,
      productCode,
      firmware: `${revMajor}.${String(revMinor).padStart(3, '0')}`,
      revision: { major: revMajor, minor: revMinor },
      status: statusWord,
      serial: serial.toString(16).toUpperCase().padStart(8, '0'),
      productName,
      catalog: extractCatalog(productName),
      state
    });
  }
  return results;
}

// ── IPv4 helpers ─────────────────────────────────────────────────────────

function ipToInt(ip) {
  return ip.split('.').reduce((acc, o) => ((acc << 8) | (parseInt(o, 10) & 255)) >>> 0, 0);
}
function intToIp(n) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}
function broadcastAddress(ip, netmask) {
  const m = ipToInt(netmask);
  return intToIp(((ipToInt(ip) & m) | (~m >>> 0)) >>> 0);
}
function hostsInSubnet(ip, netmask, maxHosts = 1024) {
  const m = ipToInt(netmask);
  const network = (ipToInt(ip) & m) >>> 0;
  const size = (~m >>> 0) + 1;
  if (size - 2 > maxHosts || size < 4) return [];
  const self = ipToInt(ip);
  const out = [];
  for (let n = network + 1; n < network + size - 1; n++) if (n !== self) out.push(intToIp(n));
  return out;
}

// ── Discovery over UDP ───────────────────────────────────────────────────

/**
 * Send List Identity on one adapter and collect replies.
 * @param {object} opts
 * @param {string} opts.localAddress  adapter IPv4 to send from
 * @param {string[]} opts.targets     broadcast and/or unicast addresses
 * @param {number} [opts.timeout]     ms to listen for replies
 * @param {number} [opts.port]        remote port (default 44818)
 * @param {(dev)=>void} [opts.onDevice]
 */
function discover({ localAddress, targets, timeout = 3000, port = ENIP_PORT, onDevice }) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    const found = new Map();
    let done = false;

    const finish = () => {
      if (done) return;
      done = true;
      try { sock.close(); } catch (_) { /* ignore */ }
      resolve([...found.values()]);
    };

    sock.on('error', (err) => {
      if (done) return;
      done = true;
      try { sock.close(); } catch (_) { /* ignore */ }
      reject(err);
    });

    sock.on('message', (msg, rinfo) => {
      try {
        for (const dev of parseListIdentityReply(msg)) {
          // Prefer the address the reply came from; the embedded socket
          // address can be 0.0.0.0 or a stale value on some devices.
          dev.ip = rinfo.address;
          if (found.has(dev.ip)) continue;
          found.set(dev.ip, dev);
          if (onDevice) onDevice(dev);
        }
      } catch (_) { /* not an EtherNet/IP reply — ignore */ }
    });

    sock.bind({ address: localAddress, port: 0 }, async () => {
      try { sock.setBroadcast(true); } catch (_) { /* ignore */ }
      const pkt = buildListIdentity();
      // Pace unicast sweeps so we don't flood small embedded stacks.
      for (let i = 0; i < targets.length && !done; i++) {
        sock.send(pkt, port, targets[i], () => {});
        if (i % 32 === 31) await new Promise((r) => setTimeout(r, 5));
      }
      setTimeout(finish, timeout);
    });
  });
}

// ── MAC address via CIP (Ethernet Link Object) ───────────────────────────

function buildRegisterSession() {
  const data = Buffer.alloc(4);
  data.writeUInt16LE(1, 0); // protocol version
  data.writeUInt16LE(0, 2); // options
  return Buffer.concat([buildHeader(CMD.REGISTER_SESSION, 4), data]);
}

function buildGetAttributeSingle(session, classId, instance, attribute) {
  // CIP request: Get_Attribute_Single (0x0E) with an 8-bit logical path
  const cip = Buffer.from([0x0e, 0x03, 0x20, classId, 0x24, instance, 0x30, attribute]);
  const cpf = Buffer.alloc(16);
  let o = 0;
  cpf.writeUInt32LE(0, o); o += 4;      // interface handle (CIP)
  cpf.writeUInt16LE(5, o); o += 2;      // timeout (s)
  cpf.writeUInt16LE(2, o); o += 2;      // item count
  cpf.writeUInt16LE(0x0000, o); o += 2; // null address item
  cpf.writeUInt16LE(0, o); o += 2;
  cpf.writeUInt16LE(0x00b2, o); o += 2; // unconnected data item
  cpf.writeUInt16LE(cip.length, o);
  const data = Buffer.concat([cpf, cip]);
  return Buffer.concat([buildHeader(CMD.SEND_RR_DATA, data.length, session), data]);
}

// Extracts the CIP response payload from a SendRRData reply.
function parseSendRRDataReply(buf) {
  const status = buf.readUInt32LE(8);
  if (status !== 0) throw new Error(`encapsulation status 0x${status.toString(16)}`);
  let off = 24 + 6; // interface handle + timeout
  const count = buf.readUInt16LE(off); off += 2;
  for (let i = 0; i < count; i++) {
    const type = buf.readUInt16LE(off);
    const len = buf.readUInt16LE(off + 2);
    off += 4;
    if (type === 0x00b2) {
      const cip = buf.subarray(off, off + len);
      const generalStatus = cip[2];
      const extSize = cip[3];
      if (generalStatus !== 0) throw new Error(`CIP status 0x${generalStatus.toString(16)}`);
      return cip.subarray(4 + extSize * 2);
    }
    off += len;
  }
  throw new Error('no unconnected data item in reply');
}

function formatMac(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
}

/**
 * Open a TCP encapsulation session and read the MAC address.
 * Resolves to "AA:BB:CC:DD:EE:FF" or rejects.
 */
function readMacAddress(ip, { port = ENIP_PORT, timeout = 2500, localAddress } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection({ host: ip, port, localAddress });
    let rx = Buffer.alloc(0);
    let session = 0;
    let stage = 'register';

    const fail = (err) => { sock.destroy(); reject(err); };
    const timer = setTimeout(() => fail(new Error('timeout')), timeout);

    sock.on('connect', () => sock.write(buildRegisterSession()));
    sock.on('error', (e) => { clearTimeout(timer); fail(e); });
    sock.on('data', (chunk) => {
      rx = Buffer.concat([rx, chunk]);
      while (rx.length >= 24) {
        const total = 24 + rx.readUInt16LE(2);
        if (rx.length < total) return;
        const pkt = rx.subarray(0, total);
        rx = rx.subarray(total);
        try {
          if (stage === 'register') {
            if (pkt.readUInt32LE(8) !== 0) throw new Error('RegisterSession refused');
            session = pkt.readUInt32LE(4);
            stage = 'get';
            sock.write(buildGetAttributeSingle(session, 0xf6, 1, 3));
          } else if (stage === 'get') {
            const data = parseSendRRDataReply(pkt);
            if (data.length < 6) throw new Error('short MAC attribute');
            clearTimeout(timer);
            sock.end(buildHeader(CMD.UNREGISTER_SESSION, 0, session));
            resolve(formatMac(data.subarray(0, 6)));
            stage = 'done';
          }
        } catch (e) {
          clearTimeout(timer);
          fail(e);
          return;
        }
      }
    });
  });
}

module.exports = {
  ENIP_PORT,
  CMD,
  VENDORS,
  DEVICE_TYPES,
  buildHeader,
  buildListIdentity,
  buildGetAttributeSingle,
  parseListIdentityReply,
  parseSendRRDataReply,
  extractCatalog,
  formatMac,
  broadcastAddress,
  hostsInSubnet,
  ipToInt,
  intToIp,
  discover,
  readMacAddress
};
