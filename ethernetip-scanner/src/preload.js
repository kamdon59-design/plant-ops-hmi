const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('scannerAPI', {
  getAdapters:   ()        => ipcRenderer.invoke('get-adapters'),
  scan:          (opts)    => ipcRenderer.invoke('scan', opts),
  exportCsv:     (devices) => ipcRenderer.invoke('export-csv', devices),
  setTheme:      (mode)    => ipcRenderer.invoke('set-theme', mode),
  openWeb:       (ip)      => ipcRenderer.invoke('open-web', ip),
  onScanEvent:   (cb)      => ipcRenderer.on('scan-event', (_e, evt) => cb(evt)),
  onAdapters:    (cb)      => ipcRenderer.on('adapters', (_e, data) => cb(data))
});
