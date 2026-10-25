import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, readFile, writeFile, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { createLicenseAdmin, validateAdminRequest } from '../licensing-admin.mjs';
import { publicKeyHash, signDeviceRequest } from '../../backend/src/license-format.mjs';

function application() {
  const pair = generateKeyPairSync('ed25519');
  return JSON.stringify(signDeviceRequest({ version: 1, action: 'offline', requestId: randomUUID(), deviceId: 'a'.repeat(64),
    devicePublicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }) }, pair.privateKey));
}
const trial = () => ({ action: 'trial', applicationText: application(), resourcesReady: true,
  ispExpiresAt: '2027-01-01T00:00:00Z', offlineDays: 1 });

async function fixture(t, changes = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'mc-license-admin-'));
  t.after(async () => { assert(path.basename(root).startsWith('mc-license-admin-')); await rm(root, { recursive: true, force: true }); });
  const directory = path.join(root, 'private'); await mkdir(directory);
  const keys = generateKeyPairSync('ed25519'), calls = [], state = { key: keys.publicKey.export({ type: 'spki', format: 'pem' }), chosen: directory,
    output: path.join(root, 'customer.json'), closes: 0, initialized: 0 };
  const api = createLicenseAdmin({ enabled: true, settingsPath: path.join(root, 'selection.json'),
    chooseStore: async () => state.chosen, chooseNewStore: async () => state.chosen,
    chooseOutput: async () => state.output,
    loadTools: async () => ({ openStore: async () => ({ publicKey: state.key, keyId: 'known-root', store: { close: () => { state.closes++; } } }),
      initializeLicensing: async () => { state.initialized++; },
      runLicensingAction: async value => { calls.push(value); return value.action === 'customers'
        ? { customers: [], orders: [], summary: { trialCount: 0 } }
        : { action: value.action, license: { licenseId: 'e0bc1a32-60ed-4c3d-9b04-64d3c8e1ec33', plan: 'isp-1d-trial' } }; },
    }), ...changes });
  return { api, state, calls, root, directory };
}

test('licensed and mock bridges do not load signing tools or create private state', async () => {
  const never = () => assert.fail('disabled signer must not load or open files');
  for (const options of [{ enabled: false }, { enabled: true, mock: true }]) {
    const api = createLicenseAdmin({ ...options, loadTools: never, chooseStore: never, chooseOutput: never });
    assert.equal((await api.status()).configured, false);
    await assert.rejects(api.selectStore(), { code: options.mock ? 'LICENSE_ADMIN_MOCK_UNAVAILABLE' : 'LICENSE_ADMIN_UNAVAILABLE' });
    await assert.rejects(api.generate(trial()), { code: options.mock ? 'LICENSE_ADMIN_MOCK_UNAVAILABLE' : 'LICENSE_ADMIN_UNAVAILABLE' });
    await assert.rejects(api.exportDelivery({}), { code: options.mock ? 'LICENSE_ADMIN_MOCK_UNAVAILABLE' : 'LICENSE_ADMIN_UNAVAILABLE' });
  }
});

test('signing request validation rejects path injection, malformed proofs and unconfirmed payment', () => {
  const input = trial(), valid = validateAdminRequest(input);
  assert.equal(valid.offlineDays, 1); assert.equal(valid.paid, false); assert.equal(valid.ispExpiresAt, Date.parse(input.ispExpiresAt));
  for (const bad of [{ ...input, configPath: 'private-key' }, { ...input, outputPath: 'private-key' }, { ...input, offlineDays: 30 },
    { ...input, orderId: 'fake-paid-trial' }, { ...input, applicationText: '{"request":{}}' }, { ...input, applicationText: 'a'.repeat(8193) }]) {
    assert.throws(() => validateAdminRequest(bad));
  }
  assert.equal(validateAdminRequest({ ...input, action: 'activate', orderId: 'paid-1' }).paid, false);
  assert.equal(validateAdminRequest({ action: 'renew', licenseId: 'e0bc1a32-60ed-4c3d-9b04-64d3c8e1ec33', orderId: 'retry-paid' }).resourcesReady, false);
  assert.throws(() => validateAdminRequest({ ...input, action: 'activate' }), { code: 'PAYMENT_NOT_CONFIRMED' });
  assert.throws(() => validateAdminRequest({ ...input, resourcesReady: false }), { code: 'RESOURCE_NOT_READY' });
  assert.throws(() => validateAdminRequest({ action: 'refresh', licenseId: '../../key' }), { code: 'LICENSE_ADMIN_ARGUMENT_INVALID' });
});

test('choosing an existing store pins its public key and persists no signing secret', async t => {
  const f = await fixture(t);
  assert.equal((await f.api.status()).configured, false);
  const status = await f.api.selectStore();
  assert.equal(status.configured, true); assert.equal(status.publicKeyFingerprint, publicKeyHash(f.state.key));
  assert.equal(f.state.initialized, 0);
  const data = JSON.parse(await readFile(path.join(f.root, 'selection.json'), 'utf8'));
  assert.deepEqual(Object.keys(data).sort(), ['directory', 'fingerprint', 'version']);
  f.state.key = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  await assert.rejects(f.api.status(), { code: 'LICENSE_ADMIN_STORE_CHANGED' });
});

test('native save cancellation does not sign or charge and generated requests cannot select a path', async t => {
  const f = await fixture(t); await f.api.selectStore(); f.calls.length = 0;
  f.state.output = null; assert.deepEqual(await f.api.generate(trial()), { canceled: true }); assert.equal(f.calls.length, 0);
  f.state.output = path.join(f.root, 'customer.json');
  const saved = await f.api.generate(trial()); assert.equal(saved.saved, true); assert.equal(saved.filePath, f.state.output);
  assert.equal(f.calls[0].configPath, path.join(f.directory, 'server-config.json'));
  assert.equal(f.calls[0].outputPath, f.state.output); assert.equal(f.calls[0].paid, false);
});

test('switching keys while the native save dialog is open fails before signing', async t => {
  let f;
  f = await fixture(t, { chooseOutput: async () => {
    f.state.key = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
    return path.join(f.root, 'customer.json');
  } });
  await f.api.selectStore(); f.calls.length = 0;
  await assert.rejects(f.api.generate(trial()), { code: 'LICENSE_ADMIN_STORE_CHANGED' }); assert.equal(f.calls.length, 0);
});

test('duplicate signing is blocked while local status remains independently readable', async t => {
  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const f = await fixture(t, { chooseOutput: async () => { await pending; return null; } });
  await f.api.selectStore(); const first = f.api.generate(trial());
  assert.equal(f.api.isBusy(), true);
  await assert.rejects(f.api.generate(trial()), { code: 'LICENSE_ADMIN_BUSY' });
  assert.equal((await f.api.status()).configured, true);
  release(); await first; assert.equal(f.api.isBusy(), false);
});

test('selection settings reject hard links and recover through explicit native reselection', async t => {
  const f = await fixture(t); const file = path.join(f.root, 'selection.json');
  await writeFile(file, '{}'); await link(file, path.join(f.root, 'linked.json'));
  await assert.rejects(f.api.status(), { code: 'LICENSE_ADMIN_SETTINGS_INVALID' });
  await assert.rejects(f.api.selectStore(), { code: 'LICENSE_ADMIN_SETTINGS_INVALID' });
  await rm(path.join(f.root, 'linked.json')); await rm(file);
  assert.equal((await f.api.selectStore()).configured, true);
});
