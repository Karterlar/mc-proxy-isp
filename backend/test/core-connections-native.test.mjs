import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';
import dgram from 'node:dgram';
import http from 'node:http';
import https from 'node:https';
import { once } from 'node:events';
import { buildSingBox } from '../src/config.mjs';
import { allocateCoreApiPort, requestCoreConnections, createCoreConnectionObserver } from '../src/core-connections.mjs';
import { requestViaProxy } from '../src/probe.mjs';
import { launchWindowsCore, closeWindowsCore } from '../src/windows-core-process.mjs';

const binary = fileURLToPath(new URL('../.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe', import.meta.url));
const native = process.platform === 'win32';
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const close = server => new Promise(resolve => server.close(resolve));
async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  if (child.privateConsole) return closeWindowsCore({ pid: child.pid, executable: binary, createdAt: child.createdAt });
  const exited = once(child, 'exit'); child.kill(); await exited;
}
async function start(config, file, { privateConsole = false } = {}) {
  await writeFile(file, JSON.stringify(config), { mode: 0o600 });
  const check = spawnSync(binary, ['check', '-c', file], { windowsHide: true, encoding: 'utf8', timeout: 5000 });
  assert.equal(check.status, 0, `Synthetic core schema: ${check.error?.code || check.stderr}`);
  const child = privateConsole ? await launchWindowsCore(binary, file, { prepare: async pid => assert.ok(Number.isSafeInteger(pid) && pid > 0) })
    : spawn(binary, ['run', '-c', file], { windowsHide: true, stdio: 'ignore' });
  child.privateConsole = privateConsole;
  let monitorError; child.on('error', cause => { monitorError = cause; });
  for (let i = 0; i < 100; i++) {
    const ready = await new Promise(resolve => { const socket = net.connect(config.inbounds[0].listen_port, '127.0.0.1');
      socket.once('connect', () => { socket.destroy(); resolve(true); }); socket.once('error', () => resolve(false)); });
    if (ready) return child;
    if (monitorError) throw Object.assign(new Error(`Core monitor stage ${monitorError.diagnostic?.operation || 'unknown'} code ${monitorError.diagnostic?.nativeCode || 0}`), { code: monitorError.code });
    assert.equal(child.exitCode, null, 'Core exited before isolated fixture readiness'); await wait(20);
  }
  await stop(child); throw new Error('Isolated core did not become ready');
}
const config = (port, upstreamPort) => ({ version: 1, listen: { host: '127.0.0.1', port },
  upstream: { type: 'http', host: '127.0.0.1', port: upstreamPort, auth: 'password' },
  probe: { exitUrl: 'https://localhost/', expectedExitIps: ['203.0.113.8'], timeoutMs: 1000 } });
const secrets = { ISP_USERNAME: 'synthetic-isp-user', ISP_PASSWORD: 'synthetic-isp-password' };

test('fixed 1.14.2 validates both routing modes and traffic gate with private API and persistent Fake-IP without opening TUN', { skip: !native }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'mc-core-observation-schema-'));
  try {
    for (const routingMode of ['safe-rules', 'global']) for (const trafficGate of [false, true]) {
      const file = join(root, `${routingMode}-${trafficGate}.json`), rendered = buildSingBox(config(17890, 1080), secrets, { mode: 'tun', routingMode, trafficGate,
        coreApi: { port: 17991, secret: 'a'.repeat(64) }, fakeIpCache: { path: join(root, 'mapping.db'), id: 'b'.repeat(64) },
        applicationPaths: ['C:\\Fixture\\Claude.exe'] });
      await writeFile(file, JSON.stringify(rendered));
      const result = spawnSync(binary, ['check', '-c', file], { windowsHide: true, encoding: 'utf8', timeout: 5000 });
      assert.equal(result.status, 0, `Synthetic ${routingMode} schema: ${result.stderr}`);
    }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('real pinned core observes a trusted HTTPS stream through authenticated ISP and rejects a wrong API secret', { skip: !native, timeout: 15000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'mc-core-observation-live-')); let child, destination, isp, release;
  const sockets = new Set();
  try {
    const pair = spawnSync(binary, ['generate', 'tls-keypair', 'localhost'], { windowsHide: true, encoding: 'utf8', timeout: 5000 });
    assert.equal(pair.status, 0);
    const key = pair.stdout.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)?.[0];
    const cert = pair.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0];
    let reached; const arrived = new Promise(resolve => { reached = resolve; });
    destination = https.createServer({ key, cert }, (_, response) => { response.writeHead(200, { 'content-type': 'application/json' });
      response.write('{"ip":'); release = () => response.end('"203.0.113.8"}'); reached(); });
    const targetPort = await listen(destination);
    isp = http.createServer((_, response) => { response.writeHead(405); response.end(); });
    isp.on('connect', (request, client, head) => {
      assert.equal(request.headers['proxy-authorization'], `Basic ${Buffer.from(`${secrets.ISP_USERNAME}:${secrets.ISP_PASSWORD}`).toString('base64')}`);
      assert.equal(request.url, `localhost:${targetPort}`);
      const remote = net.connect(targetPort, '127.0.0.1');
      for (const socket of [client, remote]) { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); socket.on('error', () => { client.destroy(); remote.destroy(); }); }
      remote.once('connect', () => { client.write('HTTP/1.1 200 Connection Established\r\n\r\n'); if (head.length) remote.write(head); client.pipe(remote); remote.pipe(client); });
    });
    const ispPort = await listen(isp), proxyPort = await allocateCoreApiPort(), api = { port: await allocateCoreApiPort(), secret: 'd'.repeat(64) };
    child = await start(buildSingBox(config(proxyPort, ispPort), secrets, { coreApi: api }), join(root, 'core.json'));
    await assert.rejects(requestCoreConnections({ ...api, secret: 'e'.repeat(64) }), { code: 'CORE_API_AUTH_FAILED' });
    const pending = requestViaProxy(`https://localhost:${targetPort}/`, { proxyPort, timeoutMs: 5000, ca: cert });
    await arrived;
    const observer = createCoreConnectionObserver(), observed = await observer.read({ api, sessionId: 'synthetic' });
    assert.ok(observed.connections.some(record => record.route === 'isp' && record.inbound === 'explicit-proxy' && record.active));
    assert.doesNotMatch(JSON.stringify(observed), /synthetic-isp-password|localhost|external_controller|dddddddd/);
    release(); assert.equal(JSON.parse(await pending).ip, '203.0.113.8');
  } finally {
    release?.(); await stop(child); for (const socket of sockets) socket.destroy();
    if (isp) await close(isp); if (destination) await close(destination); await rm(root, { recursive: true, force: true });
  }
});

async function dns(port, hostname, type = 1) {
  const question = Buffer.concat([...hostname.split('.').map(label => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])), Buffer.from([0, 0, type, 0, 1])]);
  const header = Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
  const socket = dgram.createSocket('udp4');
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { socket.close(); reject(new Error('Isolated DNS fixture timed out')); }, 2000);
    socket.once('error', cause => { clearTimeout(timer); socket.close(); reject(cause); });
    socket.once('message', response => { clearTimeout(timer); socket.close(); assert.equal(response.readUInt16BE(6), 1); resolve(response.subarray(-(type === 1 ? 4 : 16)).toString('hex')); });
    socket.send(Buffer.concat([header, question]), port, '127.0.0.1');
  });
}

test('private console normal Close preserves dual-stack Fake-IP across an immediate isolated restart without swapping domains', { skip: !native, timeout: 30000 }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'mc-core-fakeip-live-')); let child;
  try {
    const port = await allocateCoreApiPort(), dnsPort = await allocateCoreApiPort();
    const rendered = buildSingBox(config(port, 1080), secrets, { mode: 'tun', coreApi: { port: await allocateCoreApiPort(), secret: 'f'.repeat(64) },
      fakeIpCache: { path: join(root, 'mapping.db'), id: 'b'.repeat(64) } });
    // Only the real DNS router and persistence run; no host TUN, DNS server,
    // route or firewall is installed or changed by this fixture.
    rendered.inbounds = rendered.inbounds.filter(inbound => inbound.type !== 'tun');
    rendered.inbounds.push({ type: 'direct', tag: 'fixture-dns', listen: '127.0.0.1', listen_port: dnsPort, network: 'udp' });
    rendered.route = { final: 'isp-upstream', rules: [{ inbound: ['fixture-dns'], action: 'hijack-dns' }] };
    child = await start(rendered, join(root, 'core.json'), { privateConsole: true });
    assert.equal(await dns(dnsPort, 'localhost'), '7f000001');
    assert.equal(await dns(dnsPort, 'localhost', 28), '00000000000000000000000000000001');
    const first4 = await dns(dnsPort, 'first.invalid'), first6 = await dns(dnsPort, 'first.invalid', 28);
    await stop(child);
    child = await start(rendered, join(root, 'core.json'), { privateConsole: true });
    const second4 = await dns(dnsPort, 'second.invalid'), second6 = await dns(dnsPort, 'second.invalid', 28);
    assert.notEqual(second4, first4); assert.notEqual(second6, first6);
    assert.equal(await dns(dnsPort, 'first.invalid'), first4); assert.equal(await dns(dnsPort, 'first.invalid', 28), first6);
    assert.equal(await dns(dnsPort, 'localhost'), '7f000001');
    assert.equal(await dns(dnsPort, 'localhost', 28), '00000000000000000000000000000001');
  } finally { await stop(child); await rm(root, { recursive: true, force: true }); }
});
