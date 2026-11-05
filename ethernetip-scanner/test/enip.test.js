const test = require('node:test');
const assert = require('node:assert');
const enip = require('../src/enip');
const { startMock, buildIdentityReply } = require('./mock-device');

test('List Identity request is a 24-byte header with command 0x63', () => {
  const pkt = enip.buildListIdentity();
  assert.strictEqual(pkt.length, 24);
  assert.strictEqual(pkt.readUInt16LE(0), 0x0063);
  assert.strictEqual(pkt.readUInt16LE(2), 0);
});

test('parses a List Identity reply', () => {
  const reply = buildIdentityReply({
    ip: '192.168.1.10', vendorId: 1, deviceType: 0x18, productCode: 102, major: 12, minor: 1,
    serial: 0xabcdef01, productName: '2711P-T10C22D9P PanelView Plus 7'
  });
  const [d] = enip.parseListIdentityReply(reply);
  assert.strictEqual(d.ip, '192.168.1.10');
  assert.strictEqual(d.vendor, 'Rockwell Automation / Allen-Bradley');
  assert.strictEqual(d.deviceTypeName, 'Human-Machine Interface');
  assert.strictEqual(d.productCode, 102);
  assert.strictEqual(d.firmware, '12.001');
  assert.strictEqual(d.serial, 'ABCDEF01');
  assert.strictEqual(d.productName, '2711P-T10C22D9P PanelView Plus 7');
  assert.strictEqual(d.catalog, '2711P-T10C22D9P');
  assert.strictEqual(d.state, 3);
});

test('extracts catalog numbers', () => {
  assert.strictEqual(enip.extractCatalog('1769-L33ER/A LOGIX5333ER'), '1769-L33ER/A');
  assert.strictEqual(enip.extractCatalog('1756-EN2T/D'), '1756-EN2T/D');
  assert.strictEqual(enip.extractCatalog('2080-LC50-24QWB'), '2080-LC50-24QWB');
  assert.strictEqual(enip.extractCatalog('5069-L320ER/A'), '5069-L320ER/A');
  assert.strictEqual(enip.extractCatalog('PowerFlex 525'), '');
});

test('subnet helpers', () => {
  assert.strictEqual(enip.broadcastAddress('192.168.1.57', '255.255.255.0'), '192.168.1.255');
  assert.strictEqual(enip.broadcastAddress('10.20.3.4', '255.255.252.0'), '10.20.3.255');
  const hosts = enip.hostsInSubnet('192.168.1.57', '255.255.255.0');
  assert.strictEqual(hosts.length, 253);
  assert.ok(!hosts.includes('192.168.1.57'));
  assert.deepStrictEqual(enip.hostsInSubnet('169.254.1.1', '255.255.0.0', 1024), []);
});

test('discovers a mock device over UDP and reads its MAC over TCP', async () => {
  const mock = await startMock({ address: '127.0.0.1', port: 0 });
  try {
    const seen = [];
    const found = await enip.discover({
      localAddress: '127.0.0.1', targets: ['127.0.0.1'], port: mock.udpPort, timeout: 500,
      onDevice: (d) => seen.push(d)
    });
    assert.strictEqual(found.length, 1);
    assert.strictEqual(seen.length, 1);
    assert.strictEqual(found[0].ip, '127.0.0.1');
    assert.strictEqual(found[0].catalog, '1769-L33ER/A');
    assert.strictEqual(found[0].firmware, '33.011');
    assert.strictEqual(found[0].deviceTypeName, 'Programmable Logic Controller');

    const mac = await enip.readMacAddress('127.0.0.1', { port: mock.tcpPort });
    assert.strictEqual(mac, '00:1D:9C:C8:4A:10');
  } finally {
    mock.close();
  }
});

test('readMacAddress rejects when nothing is listening', async () => {
  await assert.rejects(enip.readMacAddress('127.0.0.1', { port: 1, timeout: 500 }));
});
