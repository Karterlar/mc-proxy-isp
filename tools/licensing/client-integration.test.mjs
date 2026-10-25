import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import path from 'node:path';
import { createLicenseClient } from '../../backend/src/license-client.mjs';
import { LicenseStore } from './store.mjs';
import { createLicensingServer } from './service.mjs';

const DAY = 86400000;
test('real loopback client/service lifecycle activates, caches, renews, expires, revokes and rebinds without a proxy core', async t => {
  const base = path.resolve('.cache'); await mkdir(base, { recursive: true });
  const directory = await mkdtemp(path.join(base, 'billing-e2e-'));
  const pair = generateKeyPairSync('ed25519'), keyId = 'integration';
  let clock = Date.now();
  const store = new LicenseStore(':memory:', { privateKey: pair.privateKey, keyId, now: () => clock });
  const server = createLicensingServer(store);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const clients = [];
  t.after(async () => {
    await Promise.all(clients.map(client => client.close()));
    await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
    store.close(); await rm(directory, { recursive: true, force: true });
  });
  const config = { version: 1, mode: 'required', serviceUrl: `http://127.0.0.1:${server.address().port}`,
    publicKeys: { [keyId]: pair.publicKey.export({ type: 'spki', format: 'pem' }) } };
  const clientOptions = name => ({ config, stateDir: path.join(directory, name), now: () => clock,
    getDeviceIdentity: async () => `synthetic-machine-${name}`,
    dependencies: { allowLoopback: true, monotonic: () => 0, createPrivateDirectory: target => mkdir(target, { mode: 0o700 }), timeoutMs: 1000 } });
  const client = createLicenseClient(clientOptions('first')); clients.push(client); await client.initialize();
  const purchase = { orderId: 'test-first', paid: true, resourcesReady: true, ispExpiresAt: clock + 90 * DAY, vpsExpiresAt: null };
  const card = store.issueCard(purchase);
  assert.equal((await client.activate(card.card)).allowed, true);
  const id = client.status().licenseId, paidExpiry = client.status().expiresAt;
  const retry = await client.activate(card.card);
  assert.equal(retry.licenseId, id); assert.equal(retry.expiresAt, paidExpiry);
  const restarted = createLicenseClient(clientOptions('first')); clients.push(restarted); await restarted.initialize();
  assert.equal(restarted.assertAllowed().licenseId, id, 'disk cache binds to the same synthetic device and key');
  await client.refresh();
  await assert.rejects(restarted.refresh(), { code: 'LICENSE_STATE_CONFLICT' }, 'parallel clients must not overwrite a newer cache');
  const renewed = store.renew(id, { ...purchase, orderId: 'test-renew' });
  await client.refresh(); assert.equal(client.status().expiresAt, paidExpiry + 30 * DAY);
  assert.equal(store.renew(id, { ...purchase, orderId: 'test-renew' }).payload.expiresAt, renewed.payload.expiresAt);
  clock += 3 * DAY + 1;
  assert.throws(() => client.assertAllowed(), { code: 'LICENSE_REFRESH_REQUIRED' });
  assert.equal((await client.refresh()).allowed, true);
  const replacement = createLicenseClient(clientOptions('replacement')); clients.push(replacement); await replacement.initialize();
  const rebind = store.rebind(id, JSON.parse(replacement.deviceApplication()));
  assert.equal((await replacement.importLicense(JSON.stringify(rebind))).licenseId, id);
  assert.equal((await client.refresh()).allowed, false, 'the old device receives the authenticated replacement binding');
  assert.throws(() => client.assertAllowed(), { code: 'LICENSE_DEVICE_MISMATCH' });
  store.revoke(id);
  assert.equal((await replacement.refresh()).status, 'revoked');
  assert.throws(() => replacement.assertAllowed(), { code: 'LICENSE_REVOKED' });
});

test('offline-first activation and failed real service refresh retain only the valid signed lease', async t => {
  const base = path.resolve('.cache'); await mkdir(base, { recursive: true });
  const directory = await mkdtemp(path.join(base, 'billing-offline-e2e-'));
  const pair = generateKeyPairSync('ed25519'); let clock = Date.now();
  const store = new LicenseStore(':memory:', { privateKey: pair.privateKey, keyId: 'offline', now: () => clock });
  const server = createLicensingServer(store); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const client = createLicenseClient({ stateDir: path.join(directory, '.license'), now: () => clock,
    getDeviceIdentity: async () => 'synthetic-offline-machine',
    config: { version: 1, mode: 'required', serviceUrl: `http://127.0.0.1:${server.address().port}`, publicKeys: { offline: pair.publicKey.export({ type: 'spki', format: 'pem' }) } },
    dependencies: { allowLoopback: true, monotonic: () => 0, createPrivateDirectory: target => mkdir(target, { mode: 0o700 }), timeoutMs: 250 } });
  t.after(async () => { await client.close(); if (server.listening) await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }); store.close(); await rm(directory, { recursive: true, force: true }); });
  await client.initialize();
  const signed = store.activateOffline(JSON.parse(client.deviceApplication()), { orderId: 'offline-paid', paid: true, resourcesReady: true, ispExpiresAt: clock + 30 * DAY, vpsExpiresAt: null, offlineDays: 3 });
  assert.equal((await client.importLicense(JSON.stringify(signed))).allowed, true);
  await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
  await assert.rejects(client.refresh());
  assert.equal(client.assertAllowed().allowed, true, 'an unreachable service cannot revoke the current lease');
  clock += 3 * DAY + 1;
  assert.throws(() => client.assertAllowed(), { code: 'LICENSE_REFRESH_REQUIRED' });
});

test('real v2 signed delivery keeps customer ISP and included resource reminders separate from software access across restart', async t => {
  const base = path.resolve('.cache'); await mkdir(base, { recursive: true });
  const directory = await mkdtemp(path.join(base, 'billing-v2-e2e-'));
  const pair = generateKeyPairSync('ed25519'); const start = Date.UTC(2026, 9, 7); let clock = start;
  const store = new LicenseStore(':memory:', { privateKey: pair.privateKey, keyId: 'v2-integration', now: () => clock });
  const clients = [];
  t.after(async () => { await Promise.all(clients.map(client => client.close())); store.close(); await rm(directory, { recursive: true, force: true }); });
  const makeClient = async name => {
    const client = createLicenseClient({ stateDir: path.join(directory, name), now: () => clock,
      getDeviceIdentity: async () => `synthetic-v2-${name}`,
      config: { version: 1, mode: 'required', publicKeys: { 'v2-integration': pair.publicKey.export({ type: 'spki', format: 'pem' }) } },
      dependencies: { monotonic: () => 0, createPrivateDirectory: target => mkdir(target, { mode: 0o700 }) } });
    clients.push(client); await client.initialize(); return client;
  };
  const customer = await makeClient('customer'), included = await makeClient('included');
  const customerToken = store.activateOffline(JSON.parse(customer.deviceApplication()), {
    orderId: 'self-managed-isp', paid: true, resourcesMode: 'customer', offlineDays: 30,
  });
  assert.equal(customerToken.payload.version, 2); assert.equal(customerToken.payload.resourcesMode, 'customer');
  assert.equal(customerToken.payload.ispExpiresAt, null); assert.equal(customerToken.payload.vpsExpiresAt, null);
  assert.equal(customerToken.payload.offlineUntil, start + 30 * DAY);
  assert.equal((await customer.importLicense(customerToken)).allowed, true);
  const includedToken = store.trialOffline(JSON.parse(included.deviceApplication()), {
    resourcesReady: true, ispExpiresAt: start + DAY / 4, offlineDays: 1,
  });
  assert.equal(includedToken.payload.version, 2); assert.equal(includedToken.payload.resourcesMode, 'included');
  assert.equal(includedToken.payload.offlineUntil, start + DAY, 'the signed offline window covers the software trial');
  assert.equal((await included.importLicense(includedToken)).allowed, true);
  await customer.close(); await included.close(); clock += DAY / 2;
  const restartedCustomer = await makeClient('customer'), restartedIncluded = await makeClient('included');
  assert.equal(restartedCustomer.assertAllowed().allowed, true);
  assert.equal(restartedIncluded.assertAllowed().allowed, true, 'an expired included ISP reminder cannot suspend software access');
  assert.equal(restartedIncluded.status().ispExpiresAt, start + DAY / 4);
  clock = start + DAY;
  assert.throws(() => restartedIncluded.assertAllowed(), { code: 'LICENSE_EXPIRED' });
  assert.equal(restartedCustomer.assertAllowed().allowed, true);
  clock = start + 30 * DAY;
  assert.throws(() => restartedCustomer.assertAllowed(), { code: 'LICENSE_EXPIRED' });
});
