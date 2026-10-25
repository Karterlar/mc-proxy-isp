import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

test('the locked window exposes only its four fixed startup operations', async () => {
  const source = await readFile(new URL('../admin-preload.cjs', import.meta.url), 'utf8');
  const calls = []; let api;
  const context = vm.createContext({ require: name => {
    assert.equal(name, 'electron');
    return { contextBridge: { exposeInMainWorld: (name, value) => { assert.equal(name, 'mcAdminGate'); api = value; } },
      ipcRenderer: { invoke: async (...args) => { calls.push(args); return { ok: true, data: 'ok' }; } } };
  } });
  vm.runInContext(source, context);
  assert.deepEqual(Object.keys(api), ['info', 'restart', 'minimize', 'close']);
  assert.equal(Object.isFrozen(api), true);
  for (const [name, channel] of [['info', 'mc-admin:info'], ['restart', 'mc-admin:restart'], ['minimize', 'mc-admin:minimize'], ['close', 'mc-admin:close']]) {
    assert.equal(await api[name]('untrusted renderer argument'), 'ok');
    assert.deepEqual(calls.at(-1), [channel]);
  }
});

test('a rejected startup operation keeps private main-process errors out of the locked renderer', async () => {
  const source = await readFile(new URL('../admin-preload.cjs', import.meta.url), 'utf8'); let api;
  vm.runInNewContext(source, { require: () => ({ contextBridge: { exposeInMainWorld: (_name, value) => { api = value; } },
    ipcRenderer: { invoke: async () => ({ ok: false, error: { message: 'private path and credentials' } }) } }) });
  await assert.rejects(api.restart(), error => !error.message.includes('private') && error.message.includes('管理员'));
});
