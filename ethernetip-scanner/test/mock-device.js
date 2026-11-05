// A tiny fake EtherNet/IP device for testing without plant hardware.
// Answers UDP List Identity and the TCP Get_Attribute_Single request for the
// Ethernet Link Object MAC address.
//
//   node test/mock-device.js            # listens on 0.0.0.0:44818
//   node test/mock-device.js 127.0.0.2  # listens on a specific address

const dgram = require('dgram');
const net = require('net');

function buildIdentityReply(id) {
  const name = Buffer.from(id.productName, 'latin1');
  const item = Buffer.alloc(2 + 16 + 2 + 2 + 2 + 2 + 2 + 4 + 1 + name.length + 1);
  let p = 0;
  item.writeUInt16LE(1, p); p += 2;               // protocol version
  item.writeUInt16BE(2, p); p += 2;               // AF_INET
  item.writeUInt16BE(44818, p); p += 2;
  id.ip.split('.').forEach((o) => { item[p++] = Number(o); });
  p += 8;
  item.writeUInt16LE(id.vendorId, p); p += 2;
  item.writeUInt16LE(id.deviceType, p); p += 2;
  item.writeUInt16LE(id.productCode, p); p += 2;
  item[p++] = id.major; item[p++] = id.minor;
  item.writeUInt16LE(0x0060, p); p += 2;          // status
  item.writeUInt32LE(id.serial, p); p += 4;
  item[p++] = name.length; name.copy(item, p); p += name.length;
  item[p++] = 3;                                  // state: operational

  const data = Buffer.alloc(2 + 4);
  data.writeUInt16LE(1, 0);                       // item count
  data.writeUInt16LE(0x000c, 2);
  data.writeUInt16LE(item.length, 4);
  const body = Buffer.concat([data, item]);
  const hdr = Buffer.alloc(24);
  hdr.writeUInt16LE(0x0063, 0);
  hdr.writeUInt16LE(body.length, 2);
  return Buffer.concat([hdr, body]);
}

function startMock({ address = '0.0.0.0', port = 44818, identity } = {}) {
  const id = Object.assign({
    ip: address === '0.0.0.0' ? '127.0.0.1' : address,
    vendorId: 1,
    deviceType: 0x0e,
    productCode: 166,
    major: 33,
    minor: 11,
    serial: 0x60c4a1b2,
    productName: '1769-L33ER/A LOGIX5333ER',
    mac: [0x00, 0x1d, 0x9c, 0xc8, 0x4a, 0x10]
  }, identity);

  const udp = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  let inFlight = 0;
  udp.on('message', (msg, rinfo) => {
    if (msg.length >= 24 && msg.readUInt16LE(0) === 0x0063) {
      // Like a real embedded stack: replies that can't be delivered (no route,
      // unresolved gateway) are dropped rather than queued without limit.
      if (inFlight > 8) return;
      inFlight++;
      udp.send(buildIdentityReply(id), rinfo.port, rinfo.address, () => { inFlight--; });
    }
  });
  udp.on('error', () => {});

  const tcp = net.createServer((sock) => {
    let rx = Buffer.alloc(0);
    sock.on('data', (chunk) => {
      rx = Buffer.concat([rx, chunk]);
      while (rx.length >= 24) {
        const total = 24 + rx.readUInt16LE(2);
        if (rx.length < total) return;
        const pkt = rx.subarray(0, total);
        rx = rx.subarray(total);
        const cmd = pkt.readUInt16LE(0);
        if (cmd === 0x0065) {
          const reply = Buffer.from(pkt);
          reply.writeUInt32LE(0x12345678, 4);
          sock.write(reply);
        } else if (cmd === 0x006f) {
          const cip = Buffer.concat([Buffer.from([0x8e, 0, 0, 0]), Buffer.from(id.mac)]);
          const cpf = Buffer.alloc(16);
          cpf.writeUInt16LE(2, 6);
          cpf.writeUInt16LE(0x00b2, 12);
          cpf.writeUInt16LE(cip.length, 14);
          const body = Buffer.concat([cpf, cip]);
          const hdr = Buffer.from(pkt.subarray(0, 24));
          hdr.writeUInt16LE(body.length, 2);
          sock.write(Buffer.concat([hdr, body]));
        } else if (cmd === 0x0066) {
          sock.end();
        }
      }
    });
    sock.on('error', () => {});
  });

  return new Promise((resolve) => {
    udp.bind(port, address, () => {
      tcp.listen(port, address, () => {
        resolve({
          udpPort: udp.address().port,
          tcpPort: tcp.address().port,
          close: () => { udp.close(); tcp.close(); }
        });
      });
    });
  });
}

module.exports = { startMock, buildIdentityReply };

if (require.main === module) {
  const address = process.argv[2] || '0.0.0.0';
  startMock({ address }).then(() => console.log(`Mock EtherNet/IP device (1769-L33ER) listening on ${address}:44818`));
}
