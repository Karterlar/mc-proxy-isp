import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

async function bridge(invoke) {
  let api;
  vm.runInNewContext(await readFile(new URL('../preload.cjs', import.meta.url), 'utf8'), {
    process: { platform: 'win32' }, require: id => { assert.equal(id, 'electron'); return { contextBridge: { exposeInMainWorld: (name, value) => { assert.equal(name, 'mcDesktop'); api = value; } }, ipcRenderer: { invoke } }; },
  });
  return api;
}

test('preload unwraps desktop results while exposing only the fixed immutable API', async () => {
  const calls = [];
  const api = await bridge(async (...args) => { calls.push(args); return { ok: true, data: { started: true } }; });
  assert.equal(Object.isFrozen(api), true);
  assert.equal((await api.launchApplication('terminal')).started, true);
  assert.deepEqual(calls, [['mc-applications:launch', 'terminal']]);
  assert.equal(Object.hasOwn(api, 'invoke'), false);
  assert.equal(Object.hasOwn(api, 'disableClaudeStartupCompat'), false);
  await api.getInfo(); assert.equal(calls.at(-1)[0], 'mc-window:info');
  await api.setWindowLayout('tall');assert.deepEqual(calls.at(-1),['mc-window:layout','tall']);
  await api.stopApplication('claude-desktop'); assert.deepEqual(calls.at(-1), ['mc-applications:stop', 'claude-desktop']);
  await api.getClaudeBackground('ignored'); assert.deepEqual(calls.at(-1), ['mc-claude:background']);
  await api.openClaudeServices('ignored'); assert.deepEqual(calls.at(-1), ['mc-claude:services']);
  await api.disableClaudeStartup('ignored'); assert.deepEqual(calls.at(-1), ['mc-claude:disable-startup']);
  await api.restoreClaudeStartup('ignored'); assert.deepEqual(calls.at(-1), ['mc-claude:restore-startup']);
  await api.quit(); assert.deepEqual(calls.at(-1), ['mc-window:quit']);
  await api.licenseAdminStatus(); assert.deepEqual(calls.at(-1), ['mc-license-admin:status']);
  await api.licenseAdminSelectStore(); assert.deepEqual(calls.at(-1), ['mc-license-admin:select-store']);
  await api.licenseAdminCreateStore(); assert.deepEqual(calls.at(-1), ['mc-license-admin:create-store']);
  await api.licenseAdminGenerate({ action: 'trial' }); assert.equal(calls.at(-1)[0], 'mc-license-admin:generate');
});

test('preload preserves public codes and converts lost IPC or malformed responses to safe errors', async () => {
  const denied = await bridge(async () => ({ ok: false, error: { code: 'APPLICATION_PROXY_UNVERIFIED', message: '代理出口尚未核验。' } }));
  await assert.rejects(denied.launchApplication('terminal'), error => error.code === 'APPLICATION_PROXY_UNVERIFIED' && error.message.includes('APPLICATION_PROXY_UNVERIFIED'));
  const lost = await bridge(async () => { throw new Error('raw secret source file'); });
  await assert.rejects(lost.getInfo(), error => error.message.includes('DESKTOP_UNAVAILABLE') && !error.message.includes('secret'));
  const malformed = await bridge(async () => ({ ok: false, error: { code: 'untrusted code', message: {} } }));
  await assert.rejects(malformed.getApplications(), error => error.code === 'DESKTOP_ACTION_FAILED');
});
