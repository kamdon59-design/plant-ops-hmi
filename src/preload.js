const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('hmiAPI', {
  getConnections:  ()           => ipcRenderer.invoke('get-connections'),
  saveConnections: (data)       => ipcRenderer.invoke('save-connections', data),
  getConfig:       ()           => ipcRenderer.invoke('get-config'),
  saveConfig:      (data)       => ipcRenderer.invoke('save-config', data),
  verifyPassword:  (pwd)        => ipcRenderer.invoke('verify-password', pwd),
  launchUrl:       (url)        => ipcRenderer.invoke('launch-url', url),
  launchApp:       (path)       => ipcRenderer.invoke('launch-app', path),
  launchVnc:       (target)     => ipcRenderer.invoke('launch-vnc', target),
  onShowAdmin:     (callback)   => ipcRenderer.on('show-admin', callback)
});
