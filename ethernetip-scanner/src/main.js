const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const { listAdapters, AdapterWatcher, scan } = require('./network');

let win;
let watcher;
let scanning = false;

function createWindow() {
  win = new BrowserWindow({
    width: 1200,
    height: 760,
    minWidth: 820,
    minHeight: 500,
    autoHideMenuBar: true,
    backgroundColor: '#0e1208',
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

ipcMain.handle('get-adapters', () => listAdapters());
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
  const cols = ['ip', 'mac', 'catalog', 'productName', 'firmware', 'serial', 'vendor', 'deviceTypeName', 'productCode', 'adapter'];
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const header = ['IP Address', 'MAC Address', 'Part Number', 'Product Name', 'Firmware', 'Serial', 'Vendor', 'Device Type', 'Product Code', 'Adapter'];
  const lines = [header.map(esc).join(',')].concat(devices.map((d) => cols.map((c) => esc(d[c])).join(',')));
  fs.writeFileSync(filePath, lines.join('\r\n'));
  return { saved: true, filePath };
});

app.whenReady().then(() => {
  createWindow();

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
  app.quit();
});
