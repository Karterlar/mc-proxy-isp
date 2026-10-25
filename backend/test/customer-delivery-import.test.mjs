import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { createCustomerDelivery, parseCustomerDelivery } from '../src/customer-delivery.mjs';
import { createCustomerDeliveryImporter } from '../src/customer-delivery-import.mjs';
import { createOnboardingManager } from '../src/onboarding.mjs';
import { createImportedVpnStore } from '../src/imported-vpn-store.mjs';
import { createLicenseClient } from '../src/license-client.mjs';
import { signLicense } from '../src/license-format.mjs';
import { vpnYamlNode } from './vpn-fixture.mjs';

const stamp = Date.now(), DAY = 86400000;
const dependencies = { createPrivateDirectory: target => mkdir(target, { mode: 0o700 }), shortlistImportedNodes: async nodes => ({ nodes, screening: {} }) };
const verified = () => ({ mock: false, expectedExitIps: ['203.0.113.8'], checks: [{ source: 'ipify', ip: '203.0.113.8' }, { source: 'cloudflare', ip: '203.0.113.8' }], latencyMs: 80 });
async function fixture(t, options = {}) {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.delivery-import-test-'));
  const keys = generateKeyPairSync('ed25519'), licenseConfig = { version: 1, mode: 'required', serviceUrl: '', publicKeys: { test: keys.publicKey.export({ type: 'spki', format: 'pem' }) } };
  const licenseClient = createLicenseClient({ config: licenseConfig, stateDir: path.join(root, '.license'), getDeviceIdentity: async () => 'synthetic-delivery-device', now: () => stamp,
    dependencies: { ...dependencies, monotonic: () => 0 }, request: () => assert.fail('offline licensing must not contact a server') });
  await licenseClient.initialize(); const state = licenseClient.status(), licenseId = randomUUID();
  const issue = changes => signLicense({ version: 2, licenseId, deviceId: state.deviceId, deviceKeyHash: state.deviceKeyHash, generation: 1,
    plan: 'isp-30d-single', status: 'active', issuedAt: stamp, expiresAt: stamp + 30 * DAY, offlineUntil: stamp + DAY,
    resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: null, ...changes }, { keyId: 'test', privateKey: keys.privateKey });
  await licenseClient.importLicense(JSON.stringify(issue({})));
  const onboarding = createOnboardingManager({ runtimeRoot: root, now: () => stamp, dependencies });
  await onboarding.saveConfiguration({ type: 'socks', host: '192.0.2.1', port: 1080, username: 'old-user', password: 'old-pass', connectionMode: 'vpn-import', expectedExitIps: ['203.0.113.7'] }, {
    prepareConfiguration: async value => { value.config.listen.port = 18765; return value; },
  });
  await onboarding.preferences({ browser: 'chrome', takeoverMode: 'smart', autoOptimize: false, fresh: false, completed: true });
  const vpnConfigStore = createImportedVpnStore({ stateDir: path.join(root, '.vpn-config'), dependencies });
  const old = await vpnConfigStore.import(JSON.stringify({ proxies: [vpnYamlNode({ name: 'old', server: 'old.invalid' })] }), { subscription: { url: 'https://subscriptions.invalid/secret-old', lastUpdatedAt: new Date(stamp).toISOString() } });
  await vpnConfigStore.select(1, { expectedId: old.id });
  const source = { licenseText: `${JSON.stringify(issue({ generation: 2, offlineUntil: stamp + 2 * DAY }))}\n`, connectionMode: 'vpn-import', takeoverMode: 'global',
    isp: { type: 'socks', host: '192.0.2.55', port: 35959, username: 'new-user', password: 'new-password', expectedExitIps: ['203.0.113.8'] },
    vpnText: JSON.stringify({ proxies: [vpnYamlNode({ name: 'first', server: 'first.invalid' }), vpnYamlNode({ name: 'second', server: 'second.invalid' })] }) };
  const calls = [], settings = { runtimeRoot: root, licenseConfig, licenseClient, onboarding, vpnConfigStore, now: () => stamp, dependencies,
    setupVerifier: { verify: async input => { calls.push(input); return verified(); } }, ...options };
  t.after(async () => { await licenseClient.close(); assert(path.basename(root).startsWith('.delivery-import-test-')); await rm(root, { recursive: true, force: true }); });
  const bytes = async () => Promise.all(['config.json', 'upstream.secrets.env', '.vpn-config/nodes.json', '.onboarding/preferences.json', '.license/state.json', '.license/device.json'].map(file => readFile(path.join(root, file), 'utf8')));
  return { root, settings, calls, source, create: () => createCustomerDeliveryImporter(settings), issue, bytes, onboarding, licenseClient, vpnConfigStore };
}

test('real staged import preserves local port/browser choice and original license identity, verifies VPN+ISP and clears old subscription', async t => {
  const f = await fixture(t), before = await f.bytes(), completedAt = (await f.onboarding.status()).completedAt;
  const receipt = path.join(f.root, '.onboarding', 'fingerprint-default-1.6.2.json');
  await assert.rejects(readFile(receipt), { code: 'ENOENT' });
  f.settings.setupVerifier.verify = async input => {
    f.calls.push(input);
    assert.equal(input.config.listen.port, 18765);
    assert.equal(input.secrets.ISP_PASSWORD, f.source.isp.password);
    assert.equal(input.config.connectionMode, 'vpn-import');
    assert.equal(f.licenseClient.status().generation, 1);
    assert.equal((await f.onboarding.configuration()).host, '192.0.2.1');
    if (input.vpnNode.server === 'first.invalid') throw Object.assign(new Error('probe failed'), { code: 'SETUP_CHECK_FAILED' });
    return verified();
  };
  const importer = f.create(), preview = importer.preview(createCustomerDelivery(f.source));
  assert.equal(preview.license.verified, true); assert.equal(preview.vpn.supported, 2);
  const result = await importer.import(parseCustomerDelivery(createCustomerDelivery(f.source)));
  assert.equal(result.imported, true); assert.equal(result.verification.nodeIndex, 2); assert.equal(f.calls.length, 2);
  const saved = JSON.parse(await readFile(path.join(f.root, 'config.json'), 'utf8'));
  assert.equal(saved.listen.port, 18765); assert.equal(saved.upstream.host, f.source.isp.host);
  const preferences = await f.onboarding.status();
  assert.equal(preferences.preferences.browser, 'chrome'); assert.equal(preferences.preferences.takeoverMode, 'global');
  assert.equal(preferences.preferences.autoOptimize, false); assert.equal(preferences.completedAt, completedAt);
  assert.equal((await f.vpnConfigStore.status()).subscription.configured, false);
  assert.equal((await f.vpnConfigStore.status()).selectedIndex, 2);
  assert.equal(f.licenseClient.status().generation, 2);
  assert.equal((await f.bytes())[5], before[5], 'device identity bytes must remain unchanged');
  await assert.rejects(readFile(receipt), { code: 'ENOENT' }, 'import must not create a retired browser-default receipt');
  assert.equal((await readdir(path.join(f.root, '.customer-delivery'))).some(file => file.startsWith('stage-')), false);
});

test('a committed import retains an existing retired browser receipt and the selected fingerprint browser', async t => {
  const f = await fixture(t), receipt = path.join(f.root, '.onboarding', 'fingerprint-default-1.6.2.json');
  const original = '{"version":1,"appliedAt":"2026-10-12T00:00:00.000Z"}\n';
  await writeFile(receipt, original);
  await f.onboarding.preferences({ browser: 'fingerprint' });
  assert.equal((await f.create().import(createCustomerDelivery(f.source))).imported, true);
  assert.equal((await f.onboarding.status()).preferences.browser, 'fingerprint');
  assert.equal(await readFile(receipt, 'utf8'), original);
});

test('all failed candidate probes leave exact configuration, credentials, preferences and license bytes unchanged', async t => {
  const f = await fixture(t), before = await f.bytes();
  f.settings.setupVerifier.verify = async () => { throw Object.assign(new Error('expected failure'), { code: 'SETUP_CHECK_FAILED' }); };
  await assert.rejects(f.create().import(createCustomerDelivery(f.source)), { code: 'VPN_IMPORT_NO_ROUTE' });
  assert.deepEqual(await f.bytes(), before);
  assert.equal((await readdir(path.join(f.root, '.customer-delivery'))).some(file => file.startsWith('stage-')), false);
});

test('original license replay refusal rolls the prepared new configuration back', async t => {
  const f = await fixture(t), before = await f.bytes(), receipt = path.join(f.root, '.onboarding', 'fingerprint-default-1.6.2.json');
  const original = '{"version":1,"appliedAt":"2026-10-12T00:00:00.000Z"}\n';
  await writeFile(receipt, original);
  const real = f.settings.licenseClient;
  f.settings.licenseClient = { status: real.status, initialize: real.initialize, importLicense: async () => { throw Object.assign(new Error('LICENSE_REPLAY'), { code: 'LICENSE_REPLAY' }); } };
  await assert.rejects(f.create().import(createCustomerDelivery(f.source)), { code: 'LICENSE_REPLAY' });
  assert.deepEqual(await f.bytes(), before);
  assert.equal(await readFile(receipt, 'utf8'), original);
});

test('unsupported mode, foreign license and mocked real-mode verification cannot change the runtime', async t => {
  const f = await fixture(t), before = await f.bytes();
  const alternative = { ...f.source, connectionMode: 'relay' }; delete alternative.vpnText;
  assert.throws(() => f.create().preview(createCustomerDelivery(alternative)), { code: 'DELIVERY_MODE_UNSUPPORTED' });
  assert.throws(() => f.create().preview(createCustomerDelivery({ ...f.source, licenseText: JSON.stringify(f.issue({ deviceId: 'a'.repeat(64) })) })), { code: 'DEVICE_MISMATCH' });
  f.settings.setupVerifier.verify = async () => ({ ...verified(), mock: true });
  await assert.rejects(f.create().import(createCustomerDelivery(f.source)), { code: 'DELIVERY_VERIFICATION_MOCKED' });
  assert.deepEqual(await f.bytes(), before);
});

test('cancel while verifying never commits, and a subsequent retry succeeds', async t => {
  const f = await fixture(t), before = await f.bytes(), abort = new AbortController();
  f.settings.setupVerifier.verify = async () => { abort.abort(); return verified(); };
  const importer = f.create();
  await assert.rejects(importer.import(createCustomerDelivery(f.source), { signal: abort.signal }), { code: 'CONNECTION_CANCELED' });
  assert.deepEqual(await f.bytes(), before);
  f.settings.setupVerifier.verify = async () => verified();
  assert.equal((await importer.import(createCustomerDelivery(f.source))).imported, true);
});

test('external legacy configuration remains usable when delivery importer is unused and recovery has no pending journal', async t => {
  const f = await fixture(t);
  const importer = createCustomerDeliveryImporter({ ...f.settings, configPath: path.resolve(f.root, '..', 'external-config.json') });
  assert.deepEqual(await importer.recover(), { recovered: false });
  await assert.rejects(importer.import(createCustomerDelivery(f.source)), { code: 'DELIVERY_PATH_INVALID' });
});

test('a committed import returns its staged public status even if subsequent real status readers become unavailable', async t => {
  const f = await fixture(t), realImport = f.licenseClient.importLicense;
  f.settings.licenseClient = { status: f.licenseClient.status, initialize: f.licenseClient.initialize, importLicense: async text => {
    const result = await realImport(text);
    f.settings.onboarding.configuration = async () => assert.fail('post-commit config read must not affect success');
    f.settings.onboarding.status = async () => assert.fail('post-commit onboarding read must not affect success');
    f.settings.vpnConfigStore.status = async () => assert.fail('post-commit VPN read must not affect success');
    return result;
  } };
  const result = await f.create().import(createCustomerDelivery(f.source));
  assert.equal(result.imported, true); assert.equal(result.configuration.host, f.source.isp.host);
  assert.equal(result.vpn.subscription.configured, false);
});

test('mock preview/import never reads or writes runtime files and cannot start verification', async () => {
  const source = { licenseText: JSON.stringify(signLicense({ version: 2, licenseId: randomUUID(), deviceId: 'a'.repeat(64), deviceKeyHash: 'b'.repeat(64), generation: 1,
    plan: 'isp-30d-single', status: 'active', issuedAt: stamp, expiresAt: stamp + 30 * DAY, offlineUntil: stamp + DAY,
    resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: null }, { keyId: 'test', privateKey: generateKeyPairSync('ed25519').privateKey })),
    connectionMode: 'vpn-import', takeoverMode: 'global', vpnText: JSON.stringify({ proxies: [vpnYamlNode()] }),
    isp: { type: 'socks', host: '192.0.2.55', port: 1080, username: 'user', password: 'pass', expectedExitIps: [] } };
  const never = () => assert.fail('mock must not touch filesystem/network');
  const importer = createCustomerDeliveryImporter({ mock: true, runtimeRoot: path.resolve('.cache', 'never-created-delivery'),
    setupVerifier: { verify: never }, dependencies: { readFile: never, lstat: never, createPrivateDirectory: never }, licenseClient: { status: () => ({ required: true }) } });
  assert.equal(importer.preview(createCustomerDelivery(source)).license.verified, false);
  assert.deepEqual(await importer.recover(), { recovered: false, mock: true });
  assert.equal((await importer.import(createCustomerDelivery(source))).imported, false);
});
