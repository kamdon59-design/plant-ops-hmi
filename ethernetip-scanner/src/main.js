const { app, BrowserWindow, ipcMain, dialog, shell, nativeTheme } = require('electron');
const path = require('path');
const fs = require('fs');
const { listAdapters, AdapterWatcher, scan, sameSubnet } = require('./network');
const { L2Manager } = require('./l2/manager');

let win;
let watcher;
let l2;
let scanning = false;

function createWindow() {
  win = new BrowserWindow({
    width: 1200,
    height: 760,
    minWidth: 820,
    minHeight: 500,
    autoHideMenuBar: true,
    backgroundColor: nativeTheme.shouldUseDarkColors ? '#0f141a' : '#f4f6f9',
    title: 'EtherNet/IP Device Scanner',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    show: false
  });
  win.loadFile(path.join(__dirname, 'index.html'));
  win.once('ready-to-show', () => win.show());
}

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

async function runScan(opts = {}) {
  if (scanning) return { busy: true };
  scanning = true;
  try {
    let adapters = listAdapters().filter((a) => !a.virtual);
    if (opts.adapter) adapters = adapters.filter((a) => a.name === opts.adapter);
    if (!adapters.length) {
      send('scan-event', { type: 'error', message: 'No active network adapter found. Plug in an Ethernet cable.' });
      return { devices: [] };
    }
    send('scan-event', { type: 'start', adapters });
    const extraTargets = (opts.extraTargets || []).filter((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip));
    const devices = await scan({
      adapters,
      sweep: opts.sweep !== false,
      extraTargets,
      l2,
      anySubnet: opts.anySubnet !== false,
      include10: !!opts.include10,
      onEvent: (evt) => send('scan-event', evt)
    });
    send('scan-event', { type: 'done', count: devices.length });
    return { devices };
  } catch (e) {
    send('scan-event', { type: 'error', message: e.message });
    return { devices: [], error: e.message };
  } finally {
    scanning = false;
  }
}

ipcMain.handle('set-theme', (_e, mode) => {
  nativeTheme.themeSource = ['light', 'dark'].includes(mode) ? mode : 'system';
  if (win && !win.isDestroyed()) win.setBackgroundColor(nativeTheme.shouldUseDarkColors ? '#0f141a' : '#f4f6f9');
});

ipcMain.handle('get-adapters', () => listAdapters());
ipcMain.handle('get-capture-status', () => (l2 ? l2.recheck() : { ok: false, error: 'not started' }));
ipcMain.handle('open-npcap', () => shell.openExternal('https://npcap.com/#download'));
ipcMain.handle('scan', (_e, opts) => runScan(opts));

ipcMain.handle('open-web', (_e, ip) => {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) shell.openExternal(`http://${ip}/`);
});

ipcMain.handle('export-csv', async (_e, devices) => {
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const { canceled, filePath } = await dialog.showSaveDialog(win, {
    title: 'Export device list',
    defaultPath: `enip-scan-${stamp}.csv`,
    filters: [{ name: 'CSV', extensions: ['csv'] }]
  });
  if (canceled || !filePath) return { saved: false };
  const cols = ['ip', 'mac', 'catalog', 'productName', 'firmware', 'serial', 'vendor', 'deviceTypeName', 'productCode', 'adapter', 'otherSubnet', 'suggestedLaptopIp'];
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const header = ['IP Address', 'MAC Address', 'Part Number', 'Product Name', 'Firmware', 'Serial', 'Vendor', 'Device Type', 'Product Code', 'Adapter', 'Other Subnet', 'Laptop IP To Use'];
  const lines = [header.map(esc).join(',')].concat(devices.map((d) => cols.map((c) => esc(d[c])).join(',')));
  fs.writeFileSync(filePath, lines.join('\r\n'));
  return { saved: true, filePath };
});

app.whenReady().then(() => {
  createWindow();

  // Packet capture (Npcap) listens on every wired adapter from launch, so a
  // device announcing its IP the moment the cable is plugged in is caught.
  l2 = new L2Manager();
  l2.start();
  l2.on('ready', () => send('capture-status', l2.status));
  l2.on('host', (h) => {
    // Tell the renderer about addresses seen outside the laptop's subnets;
    // it starts a scan (if auto-scan is on) to read their identity.
    const own = listAdapters();
    if (own.some((a) => sameSubnet(h.ip, a))) return;
    send('scan-event', { type: 'host-seen', host: h, message: `Device announced ${h.ip} (${h.via.join(', ')})` });
  });

  // Auto-scan whenever a new (non-virtual) adapter gets an IP — i.e. the
  // Ethernet cable was plugged in and the port came up.
  watcher = new AdapterWatcher(2000);
  watcher.start();
  watcher.on('change', (adapters) => send('adapters', adapters));
  watcher.on('connected', (ad) => {
    if (ad.virtual) return;
    // The renderer starts the scan (if auto-scan is enabled) after a short
    // settle delay so DHCP / APIPA addressing has finished.
    send('scan-event', { type: 'link-up', adapter: ad, message: `Link up on ${ad.name} (${ad.address})` });
  });
  watcher.on('disconnected', (ad) => {
    if (!ad.virtual) send('scan-event', { type: 'link', message: `Link down on ${ad.name} (${ad.address})` });
  });
});

app.on('window-all-closed', () => {
  if (watcher) watcher.stop();
  if (l2) l2.stop();
  app.quit();
});
