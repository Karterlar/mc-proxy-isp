import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import https from 'node:https';
import tls from 'node:tls';
import { once } from 'node:events';
import { X509Certificate } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, readdir, writeFile, rename, rm, symlink } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createRelayManager, requestRelay, validateRelayEnrollment } from '../src/relay-client.mjs';
import { UserError } from '../src/config.mjs';
import { relayCertificate } from './relay-fixture.mjs';
import { relayTlsFixture } from './relay-tls-fixture.mjs';

const enrollment = (certificate = relayCertificate) => ({ version: 1, type: 'mc-proxy-relay', host: '127.0.0.1', port: 443,
  tlsServerName: 'localhost', certificate, certificateSha256: new X509Certificate(certificate).fingerprint256.replaceAll(':', ''),
  username: 'test-account-private', password: 'SECRET-DO-NOT-LOG', label: 'Oregon relay' });

async function fixture(t, dependencies = {}) {
  const cache = fileURLToPath(new URL('../../.cache/', import.meta.url));
  await mkdir(cache, { recursive: true });
  const root = await mkdtemp(path.join(cache, 'mc-proxy-relay-client-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const events = [];
  const options = { runtimeRoot: root, dependencies: { createPrivateDirectory: async directory => { events.push('private-directory'); await mkdir(directory); },
    restrictDirectory: async () => { events.push('restrict-acl'); }, now: () => Date.parse('2026-10-03T09:00:00Z'), ...dependencies } };
  return { root, events, options, manager: createRelayManager(options) };
}

test('relay enrollment validates fixed address, identity and matching PEM fingerprint before persistence', () => {
  const original = enrollment();
  const valid = validateRelayEnrollment({ ...original, certificateSha256: new X509Certificate(original.certificate).fingerprint256.toLowerCase() });
  assert.equal(valid.certificateSha256, original.certificateSha256);
  for (const change of [ { host: 'relay.test' }, { host: {} }, { port: 0 }, { type: 'other' }, { certificate: 'invalid' }, { certificateSha256: '0'.repeat(64) },
    { tlsServerName: 'wrong-host.test' }, { username: 'invalid:username' }, { password: 'invalid\npassword' }, { token: 'unsupported' }, { label: 'x'.repeat(81) } ]) {
    assert.throws(() => validateRelayEnrollment({ ...original, ...change }), error => error.code === 'RELAY_ENROLLMENT_INVALID' && !error.message.includes(original.password));
  }
});

test('private enrollment import is atomic and public status never exposes account, credential or certificate', async t => {
  const f = await fixture(t);
  assert.deepEqual(await f.manager.status(), { configured: false, mock: false });
  await assert.rejects(f.manager.credentials(), { code: 'RELAY_NOT_CONFIGURED' });
  const result = await f.manager.importEnrollment(enrollment());
  assert.equal(result.configured, true); assert.equal(result.accountHint, 'te•••te');
  assert.equal(result.checkStatus, 'unchecked'); assert.equal(result.checkedAt, null); assert.equal(result.errorCode, null);
  assert.deepEqual(f.events, ['private-directory', 'restrict-acl']);
  assert.deepEqual(await readdir(path.join(f.root, '.relay')), ['enrollment.json']);
  const publicText = JSON.stringify(await f.manager.status());
  for (const secret of [enrollment().username, enrollment().password, enrollment().certificate, enrollment().certificateSha256]) assert.equal(publicText.includes(secret), false);
  const saved = JSON.parse(await readFile(path.join(f.root, '.relay', 'enrollment.json'), 'utf8'));
  assert.deepEqual(saved, enrollment());
  const credentials = await f.manager.credentials();
  assert.equal(credentials.relay.tls.certificate, relayCertificate); assert.equal(credentials.secrets.RELAY_PASSWORD, enrollment().password);
  credentials.secrets.RELAY_PASSWORD = 'changed';
  assert.equal((await f.manager.credentials()).secrets.RELAY_PASSWORD, enrollment().password);
});

test('interrupted private replacement retains original enrollment and removes the staged secret', async t => {
  let rejectRename = false;
  const f = await fixture(t, { rename: async (...args) => { if (rejectRename) throw new Error('SECRET-DO-NOT-LOG raw fs error'); return rename(...args); } });
  await f.manager.importEnrollment(enrollment()); rejectRename = true;
  await assert.rejects(f.manager.importEnrollment({ ...enrollment(), password: 'new-password' }), error => error.code === 'RELAY_STORAGE_FAILED' && !error.message.includes('SECRET'));
  assert.equal((await f.manager.credentials()).secrets.RELAY_PASSWORD, enrollment().password);
  assert.deepEqual(await readdir(path.join(f.root, '.relay')), ['enrollment.json']);
});

test('linked relay directory is never read or written and malformed private files are controlled errors', async t => {
  const f = await fixture(t); const external = path.join(f.root, 'external'); await mkdir(external);
  await writeFile(path.join(external, 'enrollment.json'), JSON.stringify(enrollment()));
  await symlink(external, path.join(f.root, '.relay'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(f.manager.status(), { code: 'RELAY_PATH_INVALID' });
  await assert.rejects(f.manager.importEnrollment(enrollment()), { code: 'RELAY_PATH_INVALID' });
  assert.deepEqual(await readdir(external), ['enrollment.json']);
  const g = await fixture(t); await mkdir(path.join(g.root, '.relay'));
  await writeFile(path.join(g.root, '.relay', 'enrollment.json'), '{"password":"SECRET-DO-NOT-LOG" invalid}');
  await assert.rejects(g.manager.status(), error => error.code === 'RELAY_ENROLLMENT_INVALID' && !error.message.includes('SECRET'));
});

test('mock enrollment, checks and revision-based bind/clear never access native dependencies', async () => {
  const forbidden = () => { throw new Error('Native dependency called in mock mode'); };
  const manager = createRelayManager({ mock: true, dependencies: Object.fromEntries(['lstat', 'realpath', 'readFile', 'rename', 'rm', 'open', 'createPrivateDirectory', 'writePrivate', 'restrictDirectory', 'request'].map(name => [name, forbidden])) });
  assert.equal((await manager.status()).configured, false);
  await manager.importEnrollment(enrollment());
  const before = await manager.check(); assert.equal(before.bindingRevision, 0); assert.equal(before.upstream, null);
  assert.equal(before.checkStatus, 'ready'); assert.equal(before.errorCode, null);
  assert.equal((await manager.status()).checkStatus, 'ready');
  const first = await manager.bind({ host: 'isp.test', port: 1080 }, before.bindingRevision);
  assert.equal(first.bindingRevision, 1);
  assert.equal((await manager.status()).checkStatus, 'unchecked', 'a changed ISP binding needs a new explicit check');
  assert.equal((await manager.bind({ host: 'isp.test', port: 1080 }, 1)).bindingRevision, 1, 'same binding is idempotent');
  await assert.rejects(manager.bind({ host: 'other.test', port: 1080 }, 0), { code: 'RELAY_BINDING_CONFLICT' });
  await assert.rejects(manager.clear(0), { code: 'RELAY_BINDING_CONFLICT' });
  await assert.rejects(manager.clear(), { code: 'RELAY_REVISION_REQUIRED' });
  assert.equal((await manager.clear(1)).bindingRevision, 2);
  assert.equal((await manager.check()).upstream, null);
  await assert.rejects(manager.importEnrollment({ ...enrollment(), password: '' }), { code: 'RELAY_ENROLLMENT_INVALID' });
  assert.equal((await manager.status()).checkStatus, 'ready', 'an invalid import preserves the saved enrollment and its check');
  await manager.importEnrollment(enrollment());
  assert.equal((await manager.status()).checkStatus, 'unchecked', 'reimporting even the same file clears old observations');
});

test('relay checks separate saved configuration from safe availability, failure and recovery observations', async t => {
  let cause = null, stamp = Date.parse('2026-10-03T09:00:00Z');
  const response = { ok: true, upstream: { host: 'isp.test', port: 1080 }, bindingRevision: 4, activeTunnels: 0, maxTunnels: 24 };
  const f = await fixture(t, { now: () => stamp, request: async selected => {
    if (cause) throw cause;
    return { ...response, account: selected.username, password: selected.password, body: 'SECRET response detail' };
  } });
  await f.manager.importEnrollment(enrollment());
  assert.equal((await f.manager.check()).checkStatus, 'ready');
  for (const [code, checkStatus, failure] of [
    ['RELAY_AUTH_FAILED', 'auth-failed', new UserError('RELAY_AUTH_FAILED', 'SECRET raw credentials/body')],
    ['RELAY_DISABLED', 'disabled', new UserError('RELAY_DISABLED', 'SECRET raw server reply')],
    ['RELAY_TLS_FAILED', 'unavailable', new UserError('RELAY_TLS_FAILED', 'SECRET certificate/socket detail')],
    ['RELAY_TIMEOUT', 'unavailable', new UserError('RELAY_TIMEOUT', 'SECRET timeout detail')],
    ['RELAY_UNREACHABLE', 'unavailable', Object.assign(new Error('SECRET unknown error'), { code: 'untrusted_SECRET' })],
  ]) {
    stamp += 1000; cause = failure;
    await assert.rejects(f.manager.check(), error => error.code === code && !error.message.includes('SECRET'));
    const status = await f.manager.status();
    assert.equal(status.configured, true); assert.equal(status.checkStatus, checkStatus); assert.equal(status.errorCode, code);
    assert.equal(status.checkedAt, new Date(stamp).toISOString());
    assert.equal(status.bindingRevision, undefined, 'failed checks cannot retain a stale success acknowledgement');
    for (const secret of [enrollment().username, enrollment().password, enrollment().certificate, 'raw server reply', 'untrusted_SECRET']) assert.equal(JSON.stringify(status).includes(secret), false);
    assert.equal((await f.manager.credentials()).secrets.RELAY_PASSWORD, enrollment().password, 'availability failures cannot discard a saved registration');
  }
  cause = null; stamp += 1000;
  const recovered = await f.manager.check();
  assert.equal(recovered.checkStatus, 'ready'); assert.equal(recovered.errorCode, null); assert.equal(recovered.checkedAt, new Date(stamp).toISOString());
  assert.equal(recovered.bindingRevision, 4); assert.equal((await f.manager.status()).errorCode, null);
  cause = new UserError('RELAY_AUTH_FAILED', 'SECRET'); await assert.rejects(f.manager.check());
  const imported = await f.manager.importEnrollment({ ...enrollment(), password: 'replacement-test-password' });
  assert.equal(imported.configured, true); assert.equal(imported.checkStatus, 'unchecked'); assert.equal(imported.checkedAt, null); assert.equal(imported.errorCode, null);
  assert.equal((await f.manager.credentials()).secrets.RELAY_PASSWORD, 'replacement-test-password');
});

test('a late failed check cannot attach its account state to an externally replaced enrollment', async t => {
  let entered, rejectRequest;
  const started = new Promise(resolve => { entered = resolve; });
  const f = await fixture(t, { request: () => { entered(); return new Promise((_, reject) => { rejectRequest = reject; }); } });
  await f.manager.importEnrollment(enrollment());
  const checking = f.manager.check(); const rejected = assert.rejects(checking, { code: 'RELAY_AUTH_FAILED' });
  await started;
  await writeFile(path.join(f.root, '.relay', 'enrollment.json'), JSON.stringify({ ...enrollment(), password: 'external-replacement-test' }));
  rejectRequest(new UserError('RELAY_AUTH_FAILED', 'SECRET account reply')); await rejected;
  const status = await f.manager.status();
  assert.equal(status.configured, true); assert.equal(status.checkStatus, 'unchecked'); assert.equal(status.errorCode, null); assert.equal(status.checkedAt, null);
  assert.equal((await f.manager.credentials()).secrets.RELAY_PASSWORD, 'external-replacement-test');
});

test('loopback TLS status failures remain configured, redact bodies, and recover without reimport or automatic routing changes', { timeout: 10000 }, async t => {
  let mode = 'ready', hits = 0;
  const server = https.createServer(relayTlsFixture.selfSignedLeaf, (_request, response) => {
    hits++;
    if (mode === 'timeout') return;
    if (mode === '401') { response.writeHead(401); response.end('SECRET non-JSON authentication reply'); return; }
    if (mode === '403') { response.writeHead(403); response.end(JSON.stringify({ error: 'SECRET disabled account', password: enrollment().password })); return; }
    response.end(JSON.stringify(mode === 'invalid' ? { ok: false, account: enrollment().username, body: enrollment().password }
      : { ok: true, upstream: null, bindingRevision: 0, activeTunnels: 0, maxTunnels: 12, password: enrollment().password }));
  });
  const sockets = new Set();
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  const f = await fixture(t, { request: (selected, options) => requestRelay(selected, { ...options, timeoutMs: 250 }) });
  const selected = { ...enrollment(relayTlsFixture.selfSignedLeaf.cert), port: server.address().port };
  await f.manager.importEnrollment(selected);
  assert.equal((await f.manager.status()).checkStatus, 'unchecked'); assert.equal(hits, 0, 'import/status do not issue a connectivity check');
  assert.equal((await f.manager.check()).checkStatus, 'ready');
  for (const [next, code, checkStatus] of [
    ['401', 'RELAY_AUTH_FAILED', 'auth-failed'], ['403', 'RELAY_DISABLED', 'disabled'],
    ['invalid', 'RELAY_RESPONSE_INVALID', 'unavailable'], ['timeout', 'RELAY_TIMEOUT', 'unavailable'],
  ]) {
    mode = next; const before = hits;
    await assert.rejects(f.manager.check(), error => error.code === code && !error.message.includes('SECRET')
      && (code !== 'RELAY_AUTH_FAILED' || error.message === '账号认证失败或已停用，请联系管理员核验。'));
    const status = await f.manager.status();
    assert.equal(status.configured, true); assert.equal(status.checkStatus, checkStatus); assert.equal(status.errorCode, code); assert.ok(status.checkedAt);
    assert.equal(JSON.stringify(status).includes(enrollment().password), false); assert.equal(hits, before + 1, 'there is no retry or automatic fallback');
  }
  server.setSecureContext(relayTlsFixture.wrongHostLeaf); const beforeTls = hits;
  await assert.rejects(f.manager.check(), { code: 'RELAY_TLS_FAILED' });
  assert.equal((await f.manager.status()).checkStatus, 'unavailable'); assert.equal(hits, beforeTls, 'failed TLS cannot transmit credentials');
  server.setSecureContext(relayTlsFixture.selfSignedLeaf); mode = 'ready';
  const recovered = await f.manager.check();
  assert.equal(recovered.checkStatus, 'ready'); assert.equal(recovered.errorCode, null); assert.equal((await f.manager.status()).errorCode, null);
  await f.manager.importEnrollment(selected);
  assert.equal((await f.manager.status()).checkStatus, 'unchecked'); assert.equal((await f.manager.status()).checkedAt, null);
});

test('remote CAS requests carry the observed revision and only verified status fields reach the caller', async t => {
  const requests = []; let revision = 4; let upstream = { host: 'old.test', port: 1080 };
  const f = await fixture(t, { request: async (selected, request) => {
    assert.equal(selected.password, enrollment().password); requests.push(request);
    if (request.method === 'GET') return { ok: true, account: selected.username, enabled: true, upstream, bindingRevision: revision, activeTunnels: 0, maxTunnels: 24, unexpected: selected.password };
    if (request.body.expectedRevision !== revision) throw new UserError('RELAY_BINDING_CONFLICT', 'raw SECRET must be scrubbed');
    revision++; upstream = request.method === 'DELETE' ? null : { host: request.body.host, port: request.body.port };
    return { ok: true, upstream, bindingRevision: revision };
  } });
  await f.manager.importEnrollment(enrollment());
  const before = await f.manager.check(); assert.equal(before.checkedAt, '2026-10-03T09:00:00.000Z');
  assert.equal(JSON.stringify(before).includes('SECRET'), false); assert.equal(before.account, undefined);
  const changed = await f.manager.bind({ host: 'new.test', port: 9000 }, before.bindingRevision);
  await assert.rejects(f.manager.bind({ host: 'stale.test', port: 9000 }, 4), error => error.code === 'RELAY_BINDING_CONFLICT' && !error.message.includes('SECRET'));
  await f.manager.clear(changed.bindingRevision);
  assert.deepEqual(requests.map(item => [item.method, item.pathname, item.body?.expectedRevision]), [
    ['GET', '/v1/status', undefined], ['POST', '/v1/upstream', 4], ['POST', '/v1/upstream', 4], ['DELETE', '/v1/upstream', 5],
  ]);
});

test('invalid remote state or wrong mutation acknowledgement never becomes a verified relay binding', async t => {
  let response;
  const f = await fixture(t, { request: async () => response }); await f.manager.importEnrollment(enrollment());
  for (const bad of [ { ok: false }, { ok: true, upstream: null, bindingRevision: -1, activeTunnels: 0, maxTunnels: 1 },
    { ok: true, upstream: { host: 'https://bad.test', port: 443 }, bindingRevision: 1, activeTunnels: 0, maxTunnels: 1 },
    { ok: true, upstream: null, bindingRevision: 1, activeTunnels: '0', maxTunnels: 1 } ]) {
    response = bad; await assert.rejects(f.manager.check(), { code: 'RELAY_RESPONSE_INVALID' });
  }
  response = { ok: true, upstream: { host: 'different.test', port: 443 }, bindingRevision: 2 };
  await assert.rejects(f.manager.bind({ host: 'isp.test', port: 443 }, 1), { code: 'RELAY_RESPONSE_INVALID' });
  await assert.rejects(f.manager.clear(1), { code: 'RELAY_RESPONSE_INVALID' });
});

const binary = process.env.SING_BOX_BIN;
test('pinned CA:false leaf works in Electron while replacement leaves, hostname errors and expiry fail before credentials', { timeout: 10000 }, async t => {
  let hits = 0;
  const server = https.createServer(relayTlsFixture.selfSignedLeaf, (_request, response) => {
    hits++; response.end(JSON.stringify({ ok: true, upstream: null, bindingRevision: 0, activeTunnels: 0, maxTunnels: 12 }));
  });
  const sockets = new Set();
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  const port = server.address().port;
  const rawHandshake = ca => new Promise((resolve, reject) => {
    const socket = tls.connect({ host: '127.0.0.1', port, servername: 'localhost', ca, rejectUnauthorized: true, allowPartialTrustChain: true,
      checkServerIdentity: (_host, cert) => tls.checkServerIdentity('localhost', cert) });
    socket.once('secureConnect', () => { const authorized = socket.authorized; socket.destroy(); resolve(authorized); });
    socket.once('error', reject); socket.setTimeout(2000, () => socket.destroy(new Error('TLS test timed out')));
  });
  assert.equal(new X509Certificate(relayTlsFixture.selfSignedLeaf.cert).ca, false);
  assert.equal((await requestRelay({ ...enrollment(relayTlsFixture.selfSignedLeaf.cert), port })).maxTunnels, 12);
  assert.equal(hits, 1);

  // A different leaf signed by the enrolled CA and valid for the same hostname
  // passes normal trust/name verification, but must still fail the exact leaf pin.
  server.setSecureContext(relayTlsFixture.sameHostLeaf);
  assert.equal(await rawHandshake(relayTlsFixture.ca.cert), true);
  await assert.rejects(requestRelay({ ...enrollment(relayTlsFixture.ca.cert), port }), { code: 'RELAY_TLS_FAILED' });
  assert.equal(hits, 1, 'trusted replacement certificate must not receive credentials');

  server.setSecureContext(relayTlsFixture.wrongHostLeaf);
  await assert.rejects(rawHandshake(relayTlsFixture.ca.cert), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
  await assert.rejects(requestRelay({ ...enrollment(relayTlsFixture.ca.cert), port }), { code: 'RELAY_TLS_FAILED' });
  assert.equal(hits, 1, 'hostname failure must not receive credentials');

  server.setSecureContext(relayTlsFixture.expiredLeaf);
  await assert.rejects(rawHandshake(relayTlsFixture.expiredLeaf.cert), { code: 'CERT_HAS_EXPIRED' });
  await assert.rejects(requestRelay({ ...enrollment(relayTlsFixture.expiredLeaf.cert), port }), { code: 'RELAY_TLS_FAILED' });
  assert.equal(hits, 1, 'expired pinned certificate must not receive credentials');
});

test('direct TLS relay API ignores proxy env, verifies CA/name/fingerprint, bounds responses and never follows redirects', { skip: !binary, timeout: 15000 }, async t => {
  const pair = () => {
    const result = spawnSync(binary, ['generate', 'tls-keypair', 'localhost'], { encoding: 'utf8', windowsHide: true }); assert.equal(result.status, 0);
    return { key: result.stdout.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)[0], cert: result.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)[0] };
  };
  const trusted = pair(); const other = pair(); let mode = 'status'; let hits = 0; let posted;
  const sockets = new Set();
  const server = https.createServer(trusted, (request, response) => {
    hits++; assert.equal(request.headers.authorization, `Basic ${Buffer.from(`${enrollment().username}:${enrollment().password}`).toString('base64')}`);
    let text = ''; request.on('data', chunk => { text += chunk; });
    request.on('end', () => {
      posted = text ? JSON.parse(text) : undefined;
      if (mode === 'timeout') return;
      if (mode === 'large') { response.end('x'.repeat(40000)); return; }
      if (mode === 'redirect') { response.writeHead(302, { location: '/redirect-target' }); response.end('{}'); return; }
      if (mode === '401') { response.writeHead(401); response.end('{"error":"SECRET-DO-NOT-LOG"}'); return; }
      if (mode === '409') { response.writeHead(409); response.end('{"error":"binding_revision_conflict","detail":"SECRET-DO-NOT-LOG"}'); return; }
      response.end(JSON.stringify(request.method === 'GET' ? { ok: true, upstream: null, bindingRevision: 0, activeTunnels: 0, maxTunnels: 12 }
        : { ok: true, upstream: { host: posted.host, port: posted.port }, bindingRevision: 1 }));
    });
  });
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); });
  const selected = { ...enrollment(trusted.cert), port: server.address().port };
  const originalHttp = process.env.HTTP_PROXY; const originalHttps = process.env.HTTPS_PROXY;
  process.env.HTTP_PROXY = 'http://127.0.0.1:1'; process.env.HTTPS_PROXY = 'http://127.0.0.1:1';
  try {
    assert.equal((await requestRelay(selected)).maxTunnels, 12);
    await requestRelay(selected, { method: 'POST', pathname: '/v1/upstream', body: { host: 'isp.test', port: 1080, expectedRevision: 0 } });
    assert.deepEqual(posted, { host: 'isp.test', port: 1080, expectedRevision: 0 });
    const beforeTls = hits;
    await assert.rejects(requestRelay({ ...enrollment(other.cert), port: selected.port }), { code: 'RELAY_TLS_FAILED' });
    assert.equal(hits, beforeTls, 'untrusted TLS must fail before sending authentication');
    assert.throws(() => requestRelay({ ...selected, certificateSha256: '0'.repeat(64) }), { code: 'RELAY_ENROLLMENT_INVALID' });
    assert.throws(() => requestRelay({ ...selected, tlsServerName: 'wrong.test' }), { code: 'RELAY_ENROLLMENT_INVALID' });
    for (const [next, code] of [['401', 'RELAY_AUTH_FAILED'], ['409', 'RELAY_BINDING_CONFLICT'], ['large', 'RELAY_RESPONSE_INVALID'], ['redirect', 'RELAY_RESPONSE_INVALID'], ['timeout', 'RELAY_TIMEOUT']]) {
      mode = next; const before = hits;
      await assert.rejects(requestRelay(selected, { timeoutMs: 250 }), error => error.code === code && !error.message.includes('SECRET'));
      assert.equal(hits, before + 1, 'every call issues one direct request without redirects or retries');
    }
  } finally {
    if (originalHttp === undefined) delete process.env.HTTP_PROXY; else process.env.HTTP_PROXY = originalHttp;
    if (originalHttps === undefined) delete process.env.HTTPS_PROXY; else process.env.HTTPS_PROXY = originalHttps;
  }
});
