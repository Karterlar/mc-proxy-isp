import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import https from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseVpnYaml } from '../src/vpn-yaml.mjs';
import { requestViaProxy } from '../src/probe.mjs';
import { allocateSetupPort } from '../src/setup-verification.mjs';
import { relayTlsFixture } from './relay-tls-fixture.mjs';
import { nativeProtocolShapes, liveProtocolCases, fixturePassword, fixtureUuid } from './vpn-protocol-fixture.mjs';

const corePath = fileURLToPath(new URL('../.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe', import.meta.url));
const cacheRoot = fileURLToPath(new URL('../../.cache/', import.meta.url));
const native = promisify(execFile);
async function fixtureDirectory(prefix) { return mkdtemp(path.join(cacheRoot, prefix)); }
async function removeFixture(directory) {
  const relative = path.relative(cacheRoot, path.resolve(directory));
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative), 'recursive cleanup stays inside the isolated cache');
  await rm(directory, { recursive: true, force: true });
}

test('pinned core accepts eight imported protocols and the bounded TCP transports without opening a connection', { timeout: 30000 }, async t => {
  if (process.platform !== 'win32') return t.skip('bundled Windows core');
  await access(corePath);
  const directory = await fixtureDirectory('vpn-protocol-schema-');
  try {
    const version = await native(corePath, ['version'], { windowsHide: true, timeout: 6000 });
    assert.match(version.stdout, /sing-box version 1\.14\.2(?:\s|$)/);
    for (const [label, outbound] of nativeProtocolShapes) {
      const file = path.join(directory, `${label}.json`);
      await writeFile(file, JSON.stringify({ log: { disabled: true },
        inbounds: [{ type: 'http', listen: '127.0.0.1', listen_port: 17890 }],
        outbounds: [outbound], route: { final: 'vpn-entry' } }));
      await assert.doesNotReject(native(corePath, ['check', '-c', file], { windowsHide: true, timeout: 6000 }), `${label} schema`);
    }
  } finally { await removeFixture(directory); }
});

for (const fixture of liveProtocolCases) {
  test(`native ${fixture.label} -> authenticated ISP -> trusted HTTPS rejects credentials and VPN outage without bypass`, { timeout: 60000 }, async t => {
    if (process.platform !== 'win32') return t.skip('bundled Windows core');
    await access(corePath);
    const { buildTestConfig, startTestCore } = await import('../../tools/offline-vpn-test/offline-vpn-test.mjs');
    const directory = await fixtureDirectory(`vpn-protocol-${fixture.label}-`);
    const sockets = new Set(); const children = [];
    const track = socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.on('error', () => {}); return socket; };
    const tracked = server => { server.on('connection', track); return server; };
    let requests = 0, ispRequests = 0, denyIsp = false;
    const target = tracked(https.createServer({ key: relayTlsFixture.sameHostLeaf.key, cert: relayTlsFixture.sameHostLeaf.cert }, (_, response) => {
      requests++; response.writeHead(200, { 'content-type': 'application/json' }); response.end('{"ip":"198.51.100.8"}');
    }));
    const isp = tracked(net.createServer(socket => {
      let buffer = Buffer.alloc(0);
      const read = data => {
        buffer = Buffer.concat([buffer, data]); const end = buffer.indexOf('\r\n\r\n'); if (end < 0) return;
        socket.removeListener('data', read); ispRequests++;
        const headers = buffer.subarray(0, end).toString().toLowerCase();
        if (denyIsp || !headers.includes(`proxy-authorization: basic ${Buffer.from('fixture-user:fixture-password').toString('base64')}`.toLowerCase())) {
          socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n'); return;
        }
        assert.ok(headers.startsWith(`connect localhost:${target.address().port} `));
        const remote = track(net.connect({ host: '127.0.0.1', port: target.address().port }, () => {
          socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
          if (buffer.length > end + 4) remote.write(buffer.subarray(end + 4));
          socket.pipe(remote); remote.pipe(socket);
        }));
        remote.once('error', () => socket.destroy()); socket.once('close', () => remote.destroy());
      };
      socket.on('data', read);
    }));
    let client, vpn;
    try {
      await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
      await new Promise(resolve => isp.listen(0, '127.0.0.1', resolve));
      const serverPort = await allocateSetupPort();
      const inbound = { type: fixture.type, listen: '127.0.0.1', listen_port: serverPort };
      if (fixture.type === 'shadowsocks') Object.assign(inbound, { method: 'aes-128-gcm', password: fixturePassword });
      if (fixture.type === 'vmess') inbound.users = [{ uuid: fixtureUuid }];
      if (fixture.type === 'trojan') { inbound.users = [{ password: fixturePassword }]; inbound.tls = { enabled: true, certificate: [relayTlsFixture.sameHostLeaf.cert], key: [relayTlsFixture.sameHostLeaf.key] }; }
      if (fixture.transport) inbound.transport = fixture.transport;
      vpn = await startTestCore({ corePath, configPath: path.join(directory, 'vpn-server.json'), rendered: {
        log: { level: 'error' }, inbounds: [inbound],
        dns: { servers: [{ type: 'hosts', tag: 'fixture-dns', predefined: { 'isp-at-vpn.invalid': '127.0.0.1' } }] },
        // Direct is confined to this isolated server fixture, not the client.
        outbounds: [{ type: 'direct', tag: 'fixture-only', domain_resolver: 'fixture-dns' }], route: { final: 'fixture-only' },
      } }); children.push(vpn);
      const parsed = parseVpnYaml(JSON.stringify({ proxies: [{ name: `Synthetic ${fixture.label}`, server: '127.0.0.1', port: serverPort, ...fixture.node }] }));
      assert.equal(parsed.nodes.length, 1, `${fixture.label} is accepted by the application parser`);
      const proxyPort = await allocateSetupPort(); let vpnPort = await allocateSetupPort(); while (vpnPort === proxyPort) vpnPort = await allocateSetupPort();
      const config = { version: 1, connectionMode: 'vpn-import', listen: { host: '127.0.0.1', port: proxyPort },
        upstream: { type: 'http', host: 'isp-at-vpn.invalid', port: isp.address().port, auth: 'password' },
        probe: { exitUrl: `https://localhost:${target.address().port}/`, expectedExitIps: ['198.51.100.8'], timeoutMs: 1000 } };
      const render = node => {
        const result = buildTestConfig(config, { ISP_USERNAME: 'fixture-user', ISP_PASSWORD: 'fixture-password' }, node, { proxyPort, vpnPort, nodeIp: '127.0.0.1' });
        assert.equal(result.outbounds.length, 2); assert.equal(result.outbounds.some(outbound => outbound.type === 'direct'), false);
        assert.equal(result.outbounds.find(outbound => outbound.tag === 'isp-upstream').detour, 'vpn-entry');
        assert.equal(result.dns, undefined, 'ISP DNS stays at the imported VPN instead of local bootstrap');
        // Test-only CA. Imported configurations cannot turn off TLS verification.
        if (fixture.type === 'trojan') result.outbounds.find(outbound => outbound.tag === 'vpn-entry').tls.certificate = relayTlsFixture.ca.cert;
        return result;
      };
      client = await startTestCore({ corePath, configPath: path.join(directory, 'client.json'), rendered: render(parsed.nodes[0].outbound) }); children.push(client);
      const request = () => requestViaProxy(new URL(config.probe.exitUrl), { proxyPort, timeoutMs: 2500, ca: relayTlsFixture.ca.cert });
      assert.equal(JSON.parse(await request()).ip, '198.51.100.8'); assert.equal(requests, 1); assert.equal(ispRequests, 1);
      denyIsp = true; await assert.rejects(request()); assert.equal(requests, 1, 'failed ISP authentication cannot reach target directly'); denyIsp = false;
      await client.stop();
      const wrongNode = structuredClone(parsed.nodes[0].outbound);
      if (fixture.type === 'vmess') wrongNode.uuid = '99999999-2222-4333-8444-555555555555'; else wrongNode.password = 'wrong-synthetic-password';
      client = await startTestCore({ corePath, configPath: path.join(directory, 'wrong-vpn.json'), rendered: render(wrongNode) }); children.push(client);
      const beforeWrong = ispRequests; await assert.rejects(request()); assert.equal(ispRequests, beforeWrong, 'failed VPN authentication cannot dial ISP directly'); assert.equal(requests, 1);
      await client.stop();
      client = await startTestCore({ corePath, configPath: path.join(directory, 'after-auth.json'), rendered: render(parsed.nodes[0].outbound) }); children.push(client);
      const beforeOutage = ispRequests; await vpn.stop(); await assert.rejects(request()); assert.equal(ispRequests, beforeOutage, 'VPN outage cannot dial ISP directly'); assert.equal(requests, 1);
    } finally {
      for (const child of children.reverse()) await child.stop();
      for (const socket of sockets) socket.destroy();
      await new Promise(resolve => target.close(resolve)); await new Promise(resolve => isp.close(resolve));
      await removeFixture(directory);
    }
  });
}
