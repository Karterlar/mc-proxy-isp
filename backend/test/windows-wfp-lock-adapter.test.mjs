import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { createWindowsWfpLockAdapter, sanitizeWfpLockDiagnostic } from '../src/windows-wfp-lock.mjs';

const id = 'dcf6b070-78c7-4b7a-9186-4785fc414383';
const input = { id, binding: 'a'.repeat(64), endpoint: { ip: '192.0.2.9', port: 443, protocol: 'UDP' },
  corePath: path.resolve('test-only/$(literal)-sing-box.exe'), includeTun: true, tunAlias: 'ProxyPilot' };
const empty = { present: false, verified: true, serviceReady: false, bootProtected: false, tunCurrent: false, ownedFilterCount: 0 };
function fixture() {
  const calls = []; let error = null, response = { ok: true, value: empty };
  const helperPath = path.resolve('test-only/MCProxy.NetworkLock.exe');
  const adapter = createWindowsWfpLockAdapter({ platform: 'win32', helperPath,
    execFile: (file, args, options, callback) => {
      const call = { file, args, options }; calls.push(call);
      return { stdin: { on() {}, end(value) { call.input = JSON.parse(value); setImmediate(() => callback(error, typeof response === 'string' ? response : JSON.stringify(response))); } } };
    } });
  return { adapter, calls, helperPath, respond: value => { response = value; }, error: value => { error = value; } };
}

test('native requests travel as bounded stdin data with a fixed executable, no shell or command interpolation', async () => {
  const f = fixture(); await f.adapter.apply(input);
  const call = f.calls[0]; assert.equal(call.file, f.helperPath); assert.deepEqual(call.args, []);
  assert.equal(call.options.shell, false); assert.equal(call.options.windowsHide, true);
  assert.equal(call.options.timeout, 10000); assert.equal(call.options.maxBuffer, 128 * 1024);
  assert.deepEqual(call.input, { operation: 'apply', ...input });
  assert.ok(!('env' in call.options)); assert.ok(!('password' in call.input));
  await f.adapter.clear({ id, expectedFingerprint: 'b'.repeat(64), privateCredential: 'never-transmitted' });
  assert.deepEqual(f.calls[1].input, { operation: 'clear', id, expectedFingerprint: 'b'.repeat(64) });
});

test('untrusted input cannot widen endpoint, interface or ownership conditions', async () => {
  const f = fixture();
  for (const changed of [{ id: 'invalid' }, { binding: 'invalid' }, { endpoint: { ...input.endpoint, protocol: 'Any' } },
    { endpoint: { ...input.endpoint, port: 0 } }, { endpoint: { ...input.endpoint, ip: 'example.com' } },
    { corePath: 'relative.exe' }, { tunAlias: 'foreign VPN' }, { expectedFingerprint: 'invalid' }, { includeTun: 'true' }]) {
    await assert.rejects(async () => f.adapter.apply({ ...input, ...changed }), { code: 'NETWORK_LOCK_INPUT_INVALID' });
  }
  await assert.rejects(async () => f.adapter.clear({ id }), { code: 'NETWORK_LOCK_INPUT_INVALID' });
  assert.deepEqual(f.calls, []);
});

test('helper errors, timeouts and malformed output remain distinct without revealing stderr, private paths or native messages', async () => {
  const f = fixture();
  f.respond({ ok: false, code: 'NETWORK_LOCK_CONFLICT', diagnostic: { nativeCode: 87, message: 'PRIVATE_SECRET', target: 'C:\\PRIVATE_SECRET' } });
  await assert.rejects(f.adapter.inspect(), cause => {
    assert.equal(cause.code, 'NETWORK_LOCK_CONFLICT'); assert.equal(cause.diagnostic.nativeCode, 87);
    assert.ok(!JSON.stringify(cause).includes('PRIVATE_SECRET')); return true;
  });
  f.error(Object.assign(new Error('PRIVATE_SECRET'), { code: 1 }));
  await assert.rejects(f.adapter.inspect(), { code: 'NETWORK_LOCK_CONFLICT' });
  f.error(null);
  f.respond({ ok: false, code: 'PRIVATE_SECRET' }); await assert.rejects(f.adapter.inspect(), { code: 'NETWORK_LOCK_WFP_FAILED' });
  for (const response of ['PRIVATE_SECRET', { ok: true, value: {} }, { ok: true, value: { ...empty, ownedFilterCount: 1 } }]) {
    f.respond(response); await assert.rejects(f.adapter.inspect(), { code: 'NETWORK_LOCK_RESPONSE_INVALID' });
  }
  f.error(Object.assign(new Error('PRIVATE_SECRET'), { killed: true }));
  await assert.rejects(f.adapter.inspect(), { code: 'NETWORK_LOCK_TIMEOUT' });
  f.respond(''); f.error(Object.assign(new Error('PRIVATE_SECRET'), { code: 'ENOENT' }));
  await assert.rejects(f.adapter.inspect(), { code: 'NETWORK_LOCK_HELPER_UNAVAILABLE' });
  assert.deepEqual(sanitizeWfpLockDiagnostic({ operation: 'inspect', category: 'PRIVATE_SECRET', nativeCode: Infinity, message: 'PRIVATE_SECRET' }),
    { operation: 'inspect', command: 'MCProxy.NetworkLock.exe' });
});

test('verified observations require complete owned metadata and a ready service; partial policies remain present', async () => {
  const f = fixture();
  const value = { ...input, present: true, verified: true, serviceReady: true, bootProtected: false, tunCurrent: true,
    ownedFilterCount: 12, tunLuid: '123456', fingerprint: 'b'.repeat(64) };
  f.respond({ ok: true, value });
  const inspected = await f.adapter.inspect(); assert.equal(inspected.present, true); assert.equal(inspected.verified, true);
  assert.ok(!('includeTun' in inspected)); assert.ok(!('tunAlias' in inspected));
  for (const changed of [{ serviceReady: false }, { fingerprint: 'invalid' }, { tunLuid: '0' }, { tunLuid: '18446744073709551616' }]) {
    f.respond({ ok: true, value: { ...value, ...changed } });
    await assert.rejects(f.adapter.inspect(), { code: 'NETWORK_LOCK_RESPONSE_INVALID' });
  }
  f.respond({ ok: true, value: { ...value, verified: false, serviceReady: false, privateMetadata: 'PRIVATE_SECRET' } });
  const partial = await f.adapter.inspect(); assert.equal(partial.present, true); assert.equal(partial.verified, false);
  assert.ok(!JSON.stringify(partial).includes('PRIVATE_SECRET'));
});
