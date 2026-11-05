// Raw Ethernet frame building/parsing: Ethernet II, ARP, IPv4/UDP, LLDP, BOOTP.
// Pure functions — no I/O — so they can be unit tested.

const BROADCAST_MAC = Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
const ETH_ARP = 0x0806;
const ETH_IPV4 = 0x0800;
const ETH_LLDP = 0x88cc;
const ETH_VLAN = 0x8100;

function macToBuf(mac) {
  if (Buffer.isBuffer(mac)) return mac;
  return Buffer.from(String(mac).split(/[:-]/).map((h) => parseInt(h, 16)));
}
function macToStr(buf) {
  return [...buf].map((b) => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
}
function ipToBuf(ip) {
  return Buffer.from(ip.split('.').map(Number));
}
function bufToIp(buf, off = 0) {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

function ethernet(dst, src, type, payload) {
  const hdr = Buffer.alloc(14);
  macToBuf(dst).copy(hdr, 0);
  macToBuf(src).copy(hdr, 6);
  hdr.writeUInt16BE(type, 12);
  const frame = Buffer.concat([hdr, payload]);
  // pad to the 60-byte Ethernet minimum (FCS added by the NIC)
  return frame.length < 60 ? Buffer.concat([frame, Buffer.alloc(60 - frame.length)]) : frame;
}

/** ARP request/reply. op 1 = request, 2 = reply. */
function arp({ op, senderMac, senderIp, targetMac, targetIp, dstMac }) {
  const p = Buffer.alloc(28);
  p.writeUInt16BE(1, 0);        // hardware: Ethernet
  p.writeUInt16BE(ETH_IPV4, 2); // protocol: IPv4
  p[4] = 6; p[5] = 4;
  p.writeUInt16BE(op, 6);
  macToBuf(senderMac).copy(p, 8);
  ipToBuf(senderIp).copy(p, 14);
  macToBuf(targetMac || '00:00:00:00:00:00').copy(p, 18);
  ipToBuf(targetIp).copy(p, 24);
  return ethernet(dstMac || BROADCAST_MAC, senderMac, ETH_ARP, p);
}

function checksum(buf) {
  let sum = 0;
  for (let i = 0; i < buf.length - 1; i += 2) sum += buf.readUInt16BE(i);
  if (buf.length % 2) sum += buf[buf.length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

let ipId = Math.floor(Math.random() * 0xffff);

/** Ethernet + IPv4 + UDP frame. */
function udp({ srcMac, dstMac, srcIp, dstIp, srcPort, dstPort, payload }) {
  const u = Buffer.alloc(8 + payload.length);
  u.writeUInt16BE(srcPort, 0);
  u.writeUInt16BE(dstPort, 2);
  u.writeUInt16BE(u.length, 4);
  payload.copy(u, 8);
  // UDP checksum over pseudo-header
  const pseudo = Buffer.alloc(12);
  ipToBuf(srcIp).copy(pseudo, 0);
  ipToBuf(dstIp).copy(pseudo, 4);
  pseudo[9] = 17;
  pseudo.writeUInt16BE(u.length, 10);
  const c = checksum(Buffer.concat([pseudo, u]));
  u.writeUInt16BE(c === 0 ? 0xffff : c, 6);

  const ip = Buffer.alloc(20);
  ip[0] = 0x45;
  ip.writeUInt16BE(20 + u.length, 2);
  ipId = (ipId + 1) & 0xffff;
  ip.writeUInt16BE(ipId, 4);
  ip[8] = 64;  // TTL
  ip[9] = 17;  // UDP
  ipToBuf(srcIp).copy(ip, 12);
  ipToBuf(dstIp).copy(ip, 16);
  ip.writeUInt16BE(checksum(ip), 10);
  return ethernet(dstMac, srcMac, ETH_IPV4, Buffer.concat([ip, u]));
}

/**
 * Parse an Ethernet frame into a small descriptive object, or null.
 *   { type:'arp', op, senderMac, senderIp, targetMac, targetIp, src, dst }
 *   { type:'udp', srcIp, dstIp, srcPort, dstPort, payload, src, dst }
 *   { type:'lldp', mgmtIps:[], sysName, src, dst }
 */
function parseFrame(frame) {
  if (frame.length < 14) return null;
  const dst = macToStr(frame.subarray(0, 6));
  const src = macToStr(frame.subarray(6, 12));
  let type = frame.readUInt16BE(12);
  let off = 14;
  if (type === ETH_VLAN && frame.length >= 18) { type = frame.readUInt16BE(16); off = 18; }

  if (type === ETH_ARP && frame.length >= off + 28) {
    const a = frame.subarray(off);
    if (a.readUInt16BE(2) !== ETH_IPV4 || a[4] !== 6 || a[5] !== 4) return null;
    return {
      type: 'arp', src, dst,
      op: a.readUInt16BE(6),
      senderMac: macToStr(a.subarray(8, 14)),
      senderIp: bufToIp(a, 14),
      targetMac: macToStr(a.subarray(18, 24)),
      targetIp: bufToIp(a, 24)
    };
  }

  if (type === ETH_IPV4 && frame.length >= off + 20) {
    const ip = frame.subarray(off);
    const ihl = (ip[0] & 0x0f) * 4;
    if ((ip[0] >> 4) !== 4 || ip[9] !== 17 || ip.length < ihl + 8) return null;
    if (ip.readUInt16BE(6) & 0x1fff) return null; // non-first fragment
    const total = Math.min(ip.readUInt16BE(2), ip.length);
    const u = ip.subarray(ihl, total);
    return {
      type: 'udp', src, dst,
      srcIp: bufToIp(ip, 12),
      dstIp: bufToIp(ip, 16),
      srcPort: u.readUInt16BE(0),
      dstPort: u.readUInt16BE(2),
      payload: u.subarray(8, Math.min(u.readUInt16BE(4), u.length))
    };
  }

  if (type === ETH_LLDP) {
    const out = { type: 'lldp', src, dst, mgmtIps: [], sysName: '', sysDesc: '' };
    let p = off;
    while (p + 2 <= frame.length) {
      const hdr = frame.readUInt16BE(p);
      const t = hdr >> 9;
      const len = hdr & 0x1ff;
      const v = frame.subarray(p + 2, p + 2 + len);
      p += 2 + len;
      if (t === 0) break;
      if (t === 5) out.sysName = v.toString('utf8');
      if (t === 6) out.sysDesc = v.toString('utf8');
      // Management address: [addr len][subtype 1 = IPv4][4 bytes]...
      if (t === 8 && v.length >= 6 && v[0] === 5 && v[1] === 1) out.mgmtIps.push(bufToIp(v, 2));
    }
    return out;
  }
  return null;
}

/** BOOTP/DHCP client request → client hardware address, or null. */
function parseBootpRequest(payload) {
  if (payload.length < 34 || payload[0] !== 1 || payload[1] !== 1 || payload[2] !== 6) return null;
  return macToStr(payload.subarray(28, 34));
}

module.exports = {
  BROADCAST_MAC, ETH_ARP, ETH_IPV4, ETH_LLDP,
  macToBuf, macToStr, ipToBuf, bufToIp,
  ethernet, arp, udp, checksum, parseFrame, parseBootpRequest
};
