const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');

let mainWindow;

// Save files to user data folder — persists across app updates
// On Windows: C:\Users\[username]\AppData\Roaming\plant-ops-hmi\
function getDataPath(filename) {
  const userDataDir = app.getPath('userData');
  if (!fs.existsSync(userDataDir)) {
    fs.mkdirSync(userDataDir, { recursive: true });
  }
  return path.join(userDataDir, filename);
}

const DEFAULT_CONFIG = {
  adminPassword: 'admin1234',
  kioskMode: true,
  title: 'Plant Operations Console',
  subtitle: 'Food & Beverage — Kiosk Mode'
};

const DEFAULT_CONNECTIONS = [];

function readJSON(filePath, defaultValue) {
  try {
    if (!fs.existsSync(filePath)) {
      fs.writeFileSync(filePath, JSON.stringify(defaultValue, null, 2));
      return defaultValue;
    }
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    console.error('Error reading', filePath, e);
    return defaultValue;
  }
}

function writeJSON(filePath, data) {
  try {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    return true;
  } catch (e) {
    console.error('Error writing', filePath, e);
    return false;
  }
}

function createWindow() {
  const configFile = getDataPath('config.json');
  const config = readJSON(configFile, DEFAULT_CONFIG);

  mainWindow = new BrowserWindow({
    fullscreen: true,
    frame: false,
    kiosk: config.kioskMode,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    backgroundColor: '#1a1f14',
    show: false
  });

  mainWindow.loadFile(path.join(__dirname, 'index.html'));
  mainWindow.once('ready-to-show', () => mainWindow.show());

  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (input.control && input.shift && input.key === 'A') {
      mainWindow.webContents.send('show-admin');
    }
    if (input.control && input.shift && input.key === 'Q') {
      app.quit();
    }
  });
}

ipcMain.handle('get-connections', () => readJSON(getDataPath('connections.json'), DEFAULT_CONNECTIONS));
ipcMain.handle('save-connections', (e, connections) => writeJSON(getDataPath('connections.json'), connections));
ipcMain.handle('get-config', () => readJSON(getDataPath('config.json'), DEFAULT_CONFIG));
ipcMain.handle('save-config', (e, config) => writeJSON(getDataPath('config.json'), config));

ipcMain.handle('verify-password', (event, password) => {
  const config = readJSON(getDataPath('config.json'), DEFAULT_CONFIG);
  return password === config.adminPassword;
});

ipcMain.handle('launch-url', (event, url) => {
  try {
    let finalUrl = url;
    if (!/^[a-zA-Z][a-zA-Z0-9+\-.]*:\/\//.test(url)) finalUrl = 'http://' + url;
    shell.openExternal(finalUrl);
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('launch-vnc', (event, target) => {
  try {
    const { exec } = require('child_process');
    const vncPaths = [
      'C:\\Program Files\\RealVNC\\VNC Viewer\\vncviewer.exe',
      'C:\\Program Files (x86)\\RealVNC\\VNC Viewer\\vncviewer.exe'
    ];
    let vncExe = vncPaths.find(p => fs.existsSync(p));
    if (!vncExe) return { success: false, error: 'RealVNC Viewer not found.' };
    exec(`"${vncExe}" ${target}`, (err) => { if (err) console.error('VNC error:', err); });
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

ipcMain.handle('launch-app', (event, execPath) => {
  try {
    const { exec } = require('child_process');
    exec(`"${execPath}"`, (err) => { if (err) console.error('Launch error:', err); });
    return { success: true };
  } catch (e) { return { success: false, error: e.message }; }
});

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
