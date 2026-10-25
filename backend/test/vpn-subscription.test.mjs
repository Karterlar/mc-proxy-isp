import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createVpnSubscriptionManager, requestSubscription, validateSubscriptionUrl, parseSubscriptionUserInfo } from '../src/vpn-subscription.mjs';
import { createImportedVpnStore } from '../src/imported-vpn-store.mjs';
import { vpnYamlNode } from './vpn-fixture.mjs';

const input = () => JSON.stringify({ proxies: [vpnYamlNode(), vpnYamlNode({ name: 'Alias' })], rules: ['MATCH,DIRECT'] });
const lease = () => ({ binding: 'a'.repeat(64), revision: 3, corePort: 17890, url: 'http://127.0.0.1:23456/', exitStatus: 'verified', mock: false });
async function fixture(t) {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.subscription-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stateDir = path.join(root, 'private');
  return { store: createImportedVpnStore({ stateDir }), file: path.join(stateDir, 'nodes.json') };
}

test('subscription userinfo exposes only bounded counters and provider expiry, never arbitrary header text', () => {
  assert.deepEqual(parseSubscriptionUserInfo('upload=1; download=2; total=100; expire=1791849600; url=PRIVATE_TOKEN'), { upload: 1, download: 2, total: 100, expire: 1791849600 });
  for (const header of [null, ['upload=1'], 'PRIVATE_TOKEN', 'upload=-1', 'total=1.1', 'upload=9007199254740992', 'expire=9999999999999',
    'upload=1;upload=2', 'upload=1\r\nPRIVATE_TOKEN', 'x'.repeat(1025)]) assert.equal(parseSubscriptionUserInfo(header), null);
  assert.deepEqual(parseSubscriptionUserInfo('total=0;expire=0'), { total: 0, expire: 0 });
});

test('provider metadata is committed with its subscription and cleared when source or manual node configuration changes', async t => {
  const f = await fixture(t); let response = { body: input(), usage: { expire: 1791849600, upload: 1, download: 2, total: 100 } };
  const manager = createVpnSubscriptionManager({ store: f.store, getProxyLease: lease, now: () => 1000, request: async () => response });
  const first = await manager.refresh({ url: 'https://subscription.fixture/list?token=PRIVATE_A' });
  assert.deepEqual(first.subscription.usage, response.usage);
  assert.doesNotMatch(JSON.stringify(first.subscription), /PRIVATE_A|subscription\.fixture/);
  response = { body: input(), usage: null };
  await manager.refresh({ url: 'https://subscription.fixture/list?token=PRIVATE_B' });
  assert.equal((await manager.status()).usage, undefined);
  response = { body: input(), usage: { expire: 1791849600 } };
  await manager.refresh();
  await f.store.import(input()); assert.equal((await manager.status()).configured, true);
  await f.store.import(JSON.stringify({ proxies: [vpnYamlNode({ name: 'New file', server: 'changed.fixture' })] }));
  assert.deepEqual(await manager.status(), { configured: false, lastUpdatedAt: null });
  assert.doesNotMatch(await readFile(f.file, 'utf8'), /PRIVATE_A|PRIVATE_B|1791849600/);
});

test('explicit proxied HTTPS refresh atomically stores only normalized nodes and private source while unchanged refresh keeps identity and selection', async t => {
  const f = await fixture(t); let requests = 0, checks = 0;
  const manager = createVpnSubscriptionManager({ store: f.store, getProxyLease: async () => { checks++; return lease(); }, now: () => 1_000,
    request: async (url, options) => {
      assert.equal(url, 'https://subscription.fixture/list?token=PRIVATE_SOURCE_TOKEN'); assert.equal(options.proxyPort, 23456);
      assert.equal(options.maxBytes, 1024 * 1024); assert.equal(options.timeoutMs, 10_000); assert.equal(options.signal.aborted, false);
      requests++; return input();
    } });
  const first = await manager.refresh({ url: 'https://subscription.fixture/list?token=PRIVATE_SOURCE_TOKEN', expectedId: null });
  assert.equal(first.supported, 1); assert.equal(first.duplicates, 1); assert.equal(requests, 1); assert.equal(checks, 2);
  assert.deepEqual(await manager.status(), { configured: true, lastUpdatedAt: '1970-01-01T00:00:01.000Z' });
  assert.doesNotMatch(JSON.stringify(first), /PRIVATE_SOURCE_TOKEN|subscription\.fixture|11111111|public_key/);
  const raw = await readFile(f.file, 'utf8'); assert.match(raw, /PRIVATE_SOURCE_TOKEN/); assert.doesNotMatch(raw, /MATCH,DIRECT|"rules"/);
  await f.store.select(1); const second = await manager.refresh({ expectedId: first.id });
  assert.equal(second.id, first.id); assert.equal(second.selectedIndex, 1); assert.equal(second.changeSummary.unchanged, true);
  await manager.clear({ expectedId: first.id }); assert.equal((await manager.status()).configured, false);
  assert.doesNotMatch(await readFile(f.file, 'utf8'), /PRIVATE_SOURCE_TOKEN/);
});

test('URL policy rejects direct insecure, local, credential-bearing and ambiguous inputs before any lease or request', async () => {
  for (const url of ['http://subscription.fixture/list', 'https://user:PRIVATE_PASSWORD@subscription.fixture/list', 'https://127.0.0.1/list',
    'https://[::1]/list', 'https://[::ffff:127.0.0.1]/list', 'https://10.2.3.4/list', 'https://192.168.0.1/list',
    'https://172.16.0.1/list', 'https://100.64.0.1/list', 'https://router.local/list', 'https://router.lan/list', 'https://localhost/list',
    'https://subscription.fixture/list#PRIVATE_FRAGMENT', 'https://subscription.fixture/\nPRIVATE_TOKEN']) {
    assert.throws(() => validateSubscriptionUrl(url), cause => cause.code === 'VPN_SUBSCRIPTION_URL_INVALID' && !cause.message.includes('PRIVATE_'));
  }
  const manager = createVpnSubscriptionManager({ store: createImportedVpnStore({ mock: true }), getProxyLease: () => assert.fail('invalid URL cannot acquire network'), request: () => assert.fail('invalid URL cannot download') });
  await assert.rejects(manager.refresh({ url: 'http://subscription.fixture/list' }), { code: 'VPN_SUBSCRIPTION_URL_INVALID' });
  assert.equal(validateSubscriptionUrl('https://subscription.fixture/list?token=PRIVATE_TOKEN'), 'https://subscription.fixture/list?token=PRIVATE_TOKEN');
});

test('unverified, mocked, non-loopback or missing-bound leases reject without requesting the subscription', async () => {
  for (const change of [{ exitStatus: 'unverified' }, { mock: true }, { binding: undefined }, { corePort: undefined }, { revision: -1 }, { url: 'http://192.0.2.1:23456/' }, { url: 'http://localhost:23456/' }, { url: 'http://127.0.0.1:23456/extra' }]) {
    const manager = createVpnSubscriptionManager({ store: createImportedVpnStore({ mock: true }), getProxyLease: async () => ({ ...lease(), ...change }), request: () => assert.fail('unsafe lease cannot be used') });
    await assert.rejects(manager.refresh({ url: 'https://subscription.fixture/list' }), { code: 'VPN_SUBSCRIPTION_PROXY_REQUIRED' });
  }
});

test('failed, oversized, unsupported and timed-out refresh preserve old bytes and abort the download with no credential disclosure', async t => {
  const f = await fixture(t); await f.store.import(input()); const before = await readFile(f.file);
  for (const request of [async () => { throw new Error('PRIVATE_SOURCE_TOKEN'); }, async () => 'x'.repeat(1024 * 1024 + 1), async () => 'proxies: []']) {
    const manager = createVpnSubscriptionManager({ store: f.store, getProxyLease: async () => lease(), request });
    await assert.rejects(manager.refresh({ url: 'https://subscription.fixture/list?token=PRIVATE_SOURCE_TOKEN' }), cause => {
      assert.ok(['VPN_SUBSCRIPTION_REQUEST_FAILED', 'VPN_SUBSCRIPTION_TOO_LARGE', 'VPN_IMPORT_NO_SUPPORTED_NODES'].includes(cause.code));
      assert.doesNotMatch(JSON.stringify({ message: cause.message, code: cause.code }), /PRIVATE_SOURCE_TOKEN/); return true;
    });
    assert.deepEqual(await readFile(f.file), before);
  }
  let aborted = false;
  const stalled = createVpnSubscriptionManager({ store: f.store, getProxyLease: async () => lease(), timeoutMs: 15, request: async (url, { signal }) => new Promise(resolve => signal.addEventListener('abort', () => { aborted = true; resolve(input()); }, { once: true })) });
  await assert.rejects(stalled.refresh({ url: 'https://subscription.fixture/list' }), { code: 'VPN_SUBSCRIPTION_TIMEOUT' });
  assert.equal(aborted, true); assert.deepEqual(await readFile(f.file), before);
});

test('route replacement and concurrent selection changes during download cannot commit or borrow a new session', async t => {
  const f = await fixture(t); await f.store.import(input()); const before = await readFile(f.file);
  let checks = 0;
  const replaced = createVpnSubscriptionManager({ store: f.store, getProxyLease: async () => ({ ...lease(), binding: (++checks === 1 ? 'a' : 'b').repeat(64) }), request: async () => input() });
  await assert.rejects(replaced.refresh({ url: 'https://subscription.fixture/list' }), { code: 'VPN_SUBSCRIPTION_ROUTE_CHANGED' });
  assert.deepEqual(await readFile(f.file), before);
  const raced = createVpnSubscriptionManager({ store: f.store, getProxyLease: async () => lease(), request: async () => { await f.store.select(1); return input(); } });
  await assert.rejects(raced.refresh({ url: 'https://subscription.fixture/list' }), { code: 'VPN_IMPORT_CONFLICT' });
  assert.equal((await f.store.status()).selectedIndex, 1); assert.equal((await raced.status()).configured, false);
});

test('native rejected CONNECT only touches its isolated loopback proxy and never falls back to target DNS or a public socket', async t => {
  const requests = [], sockets = new Set();
  const server = net.createServer(socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.once('data', bytes => {
    requests.push(bytes.toString('ascii')); socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
  }); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  await assert.rejects(requestSubscription('https://subscription.fixture/list?token=PRIVATE_TOKEN', { proxyPort: server.address().port, timeoutMs: 500 }), { code: 'VPN_SUBSCRIPTION_REQUEST_FAILED' });
  assert.equal(requests.length, 1); assert.match(requests[0], /^CONNECT subscription\.fixture:443 HTTP\/1\.1/);
  assert.doesNotMatch(requests[0], /PRIVATE_TOKEN|\/list/);
});
