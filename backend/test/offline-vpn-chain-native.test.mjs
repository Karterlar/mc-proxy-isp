import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import https from 'node:https';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildTestConfig, startTestCore } from '../../tools/offline-vpn-test/offline-vpn-test.mjs';
import { parseVpnYaml } from '../src/vpn-yaml.mjs';
import { requestViaProxy } from '../src/probe.mjs';
import { allocateSetupPort } from '../src/setup-verification.mjs';
import { relayTlsFixture } from './relay-tls-fixture.mjs';

const corePath = fileURLToPath(new URL('../.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe', import.meta.url));
const native = promisify(execFile);

test('native Reality VPN -> authenticated ISP -> trusted HTTPS, with no ISP bypass on outage', { timeout: 90000 }, async t => {
  if (process.platform !== 'win32') return t.skip('bundled Windows core');
  await access(corePath);
  const directory = await mkdtemp(path.join(tmpdir(), 'mc-vpn-reality-fixture-'));
  const sockets = new Set();
  const track = server => server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  let targetRequests = 0, ispRequests = 0, denyAuth = false, client, vpnServer;
  const target = track(https.createServer({ key: relayTlsFixture.sameHostLeaf.key, cert: relayTlsFixture.sameHostLeaf.cert, minVersion: 'TLSv1.3' }, (request, response) => {
    targetRequests++; response.writeHead(200, { 'content-type': 'application/json' }); response.end('{"ip":"198.51.100.8"}');
  }));
  const isp = track(net.createServer(socket => {
    let buffer = Buffer.alloc(0);
    const read = data => {
      buffer = Buffer.concat([buffer, data]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      socket.removeListener('data', read); ispRequests++;
      const headers = buffer.subarray(0, end).toString();
      if (denyAuth || !headers.toLowerCase().includes(`proxy-authorization: basic ${Buffer.from('fixture-user:fixture-password').toString('base64')}`.toLowerCase())) {
        socket.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n'); return;
      }
      const remote = net.connect({ host: '127.0.0.1', port: target.address().port }, () => {
        socket.write('HTTP/1.1 200 Connection established\r\n\r\n');
        if (buffer.length > end + 4) remote.write(buffer.subarray(end + 4));
        socket.pipe(remote); remote.pipe(socket);
      });
      sockets.add(remote); remote.once('close', () => sockets.delete(remote));
      remote.once('error', () => socket.destroy()); socket.once('close', () => remote.destroy());
    };
    socket.on('data', read); socket.on('error', () => {});
  }));
  try {
    await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
    await new Promise(resolve => isp.listen(0, '127.0.0.1', resolve));
    const generated = await native(corePath, ['generate', 'reality-keypair'], { windowsHide: true, timeout: 6000 });
    const privateKey = generated.stdout.match(/PrivateKey:\s*(\S+)/)?.[1];
    const publicKey = generated.stdout.match(/PublicKey:\s*(\S+)/)?.[1];
    assert.ok(privateKey && publicKey, 'core generated Reality keypair');
    const uuid = 'bf000d23-0752-40b4-affe-68f7707a9661';
    const serverPort = await allocateSetupPort();
    vpnServer = await startTestCore({ corePath, configPath: path.join(directory, 'server.json'), rendered: {
      log: { level: 'error' },
      inbounds: [{ type: 'vless', tag: 'fixture-vpn', listen: '127.0.0.1', listen_port: serverPort,
        users: [{ uuid, flow: 'xtls-rprx-vision' }], tls: { enabled: true, server_name: 'localhost', reality: {
          enabled: true, handshake: { server: '127.0.0.1', server_port: target.address().port }, private_key: privateKey, short_id: ['0123456789abcdef'],
        } } }],
      // Direct exists only in this loopback server fixture, never in the client.
      outbounds: [{ type: 'direct', tag: 'fixture-only' }], route: { final: 'fixture-only' },
    } });
    const yaml = `proxies:\n  - name: loopback fixture\n    type: vless\n    server: 127.0.0.1\n    port: ${serverPort}\n    uuid: ${uuid}\n    network: tcp\n    tls: true\n    servername: localhost\n    flow: xtls-rprx-vision\n    packet-encoding: xudp\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: ${publicKey}\n      short-id: 0123456789abcdef\n`;
    const parsed = parseVpnYaml(yaml);
    assert.equal(parsed.nodes.length, 1);
    const proxyPort = await allocateSetupPort();
    let vpnPort = await allocateSetupPort(); while (vpnPort === proxyPort) vpnPort = await allocateSetupPort();
    const config = { version: 1, connectionMode: 'vpn-compat', listen: { host: '127.0.0.1', port: proxyPort },
      upstream: { type: 'http', host: '127.0.0.1', port: isp.address().port, auth: 'password' },
      probe: { exitUrl: 'https://api.ipify.org?format=json', expectedExitIps: ['198.51.100.8'], timeoutMs: 2000 },
    };
    client = await startTestCore({ corePath, configPath: path.join(directory, 'client.json'), rendered: buildTestConfig(config,
      { ISP_USERNAME: 'fixture-user', ISP_PASSWORD: 'fixture-password' }, parsed.nodes[0].outbound, { proxyPort, vpnPort, nodeIp: '127.0.0.1' }) });
    const url = new URL(`https://localhost:${target.address().port}/`);
    const options = { proxyPort, timeoutMs: 5000, ca: relayTlsFixture.ca.cert };
    assert.equal(JSON.parse(await requestViaProxy(url, options)).ip, '198.51.100.8');
    assert.equal(ispRequests, 1); assert.equal(targetRequests, 1);
    denyAuth = true;
    await assert.rejects(requestViaProxy(url, options));
    assert.equal(targetRequests, 1, 'failed ISP authentication must never reach HTTPS directly');
    denyAuth = false;
    const before = ispRequests;
    await vpnServer.stop();
    await assert.rejects(requestViaProxy(url, options));
    assert.equal(ispRequests, before, 'VPN outage cannot dial the ISP directly');
    assert.equal(targetRequests, 1);
  } finally {
    await client?.stop(); await vpnServer?.stop();
    for (const socket of sockets) socket.destroy();
    await new Promise(resolve => target.close(resolve)); await new Promise(resolve => isp.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});
