const { contextBridge, ipcRenderer } = require('electron');

async function invoke(channel, ...args) {
  let reply;
  try { reply = await ipcRenderer.invoke(channel, ...args); }
  catch { throw new Error('桌面服务暂时无法响应，请重新打开主窗口。（DESKTOP_UNAVAILABLE）'); }
  if (reply?.ok === true) return reply.data;
  const code = typeof reply?.error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(reply.error.code) ? reply.error.code : 'DESKTOP_ACTION_FAILED';
  const message = typeof reply?.error?.message === 'string' && reply.error.message.length <= 400 ? reply.error.message : '桌面操作未完成，请查看主窗口状态。';
  const error = new Error(`${message}（${code}）`); error.code = code; throw error;
}

contextBridge.exposeInMainWorld('mcDesktop', Object.freeze({
  isDesktop: true,
  platform: process.platform,
  minimize: () => invoke('mc-window:minimize'),
  close: () => invoke('mc-window:close'),
  quit: () => invoke('mc-window:quit'),
  getInfo: () => invoke('mc-window:info'),
  setWindowLayout: preset => invoke('mc-window:layout', preset),
  revealDiagnostics: () => invoke('mc-window:diagnostics'),
  openClientLog: () => invoke('mc-window:client-log'),
  repairNetwork: () => invoke('mc-window:repair-network'),
  getClaudeBackground: () => invoke('mc-claude:background'),
  openClaudeServices: () => invoke('mc-claude:services'),
  disableClaudeStartup: () => invoke('mc-claude:disable-startup'),
  restoreClaudeStartup: () => invoke('mc-claude:restore-startup'),
  getApplications: () => invoke('mc-applications:list'),
  launchApplication: id => invoke('mc-applications:launch', id),
  stopApplication: id => invoke('mc-applications:stop', id),
  licenseAdminStatus: () => invoke('mc-license-admin:status'),
  licenseAdminSelectStore: () => invoke('mc-license-admin:select-store'),
  licenseAdminCreateStore: () => invoke('mc-license-admin:create-store'),
  licenseAdminGenerate: input => invoke('mc-license-admin:generate', input),
  licenseAdminExportDelivery: input => invoke('mc-license-admin:export-delivery', input),
  exportSupportReport: () => invoke('mc-window:support-report'),
}));
