const { contextBridge, ipcRenderer } = require('electron');

async function invoke(channel) {
  const reply = await ipcRenderer.invoke(channel);
  if (reply?.ok === true) return reply.data;
  throw new Error('管理员启动暂时未完成，请重试。');
}

// The locked page has no controller, license, file-selection or proxy API.
contextBridge.exposeInMainWorld('mcAdminGate', Object.freeze({
  info: () => invoke('mc-admin:info'),
  restart: () => invoke('mc-admin:restart'),
  minimize: () => invoke('mc-admin:minimize'),
  close: () => invoke('mc-admin:close'),
}));
