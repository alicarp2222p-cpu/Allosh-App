
// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    onNgrokUrl: (callback) => ipcRenderer.on('ngrok-url', (event, url) => callback(url))
});