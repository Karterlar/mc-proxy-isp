import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { once } from 'node:events';
import { buildSingBox } from '../src/config.mjs';
import { requestViaProxy } from '../src/probe.mjs';

const binary = process.env.SING_BOX_BIN;

test('official Windows sing-box survives stderr reader loss and later failed loopback requests', { skip: !binary || process.platform !== 'win32', timeout: 10000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mc-proxy-core-log-pipe-'));
  let child;
  try {
    const localPort = await freePort(); const unavailablePort = await freePort();
    const config = { version: 1, listen: { host: '127.0.0.1', port: localPort },
      upstream: { type: 'http', host: '127.0.0.1', port: unavailablePort, auth: 'none' },
      probe: { exitUrl: `https://127.0.0.1:${unavailablePort}/`, expectedExitIps: [], timeoutMs: 1000 } };
    child = await start(buildSingBox(config, {}), join(dir, 'local-http.json'), { detached: true, stdio: ['ignore', 'ignore', 'pipe'] });
    let diagnostic = '';
    child.stderr.on('data', chunk => { diagnostic += String(chunk); });
    const failRequest = () => assert.rejects(requestViaProxy(config.probe.exitUrl, { proxyPort: localPort, timeoutMs: 1000 }));
    await failRequest();
    for (let attempt = 0; attempt < 40 && !diagnostic.includes('ERROR'); attempt++) await new Promise(resolve => setTimeout(resolve, 25));
    assert.match(diagnostic, /ERROR/, 'A refused local upstream must exercise the real core log writer');
    // The closed Windows pipe reader releases the same logging handle as an
    // exited desktop. Later error writes must not terminate its detached core.
    const closed = once(child.stderr, 'close'); child.stderr.destroy(); await closed;
    for (let attempt = 0; attempt < 3; attempt++) {
      await failRequest();
      await new Promise(resolve => setTimeout(resolve, 100));
      assert.equal(child.exitCode, null, 'Broken stderr pipe must not exit the detached core');
      assert.equal(child.signalCode, null);
      const socket = net.connect(localPort, '127.0.0.1');
      await once(socket, 'connect'); socket.destroy();
    }
  } finally {
    if (child) await stop(child);
    await rm(dir, { recursive: true, force: true });
  }
});

test('official sing-box validates TUN, dual-stack routes and proxied DoH without opening an interface', { skip: !binary }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'proxypilot-tun-schema-'));
  try {
    for (const type of ['http', 'socks']) {
      const config = { version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type, host: 'gateway.provider.test', port: 443, auth: 'none' }, probe: { exitUrl: 'https://api.ipify.org', expectedExitIps: ['203.0.113.8'], timeoutMs: 1000 } };
      if (type === 'http') config.upstream.tls = { enabled: true, serverName: 'gateway.provider.test' };
      const schemaPath = join(dir, `${type}-tun.json`);
      await writeFile(schemaPath, JSON.stringify(buildSingBox(config, {}, { mode: 'tun', upstreamIp: '192.0.2.1' })));
      const checked = spawnSync(binary, ['check', '-c', schemaPath], { encoding: 'utf8', windowsHide: true });
      assert.equal(checked.status, 0, `Pinned core must accept ${type} TUN schema: ${checked.stderr}`);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

async function listen(server) { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return server.address().port; }
const close = server => new Promise(resolve => server.close(resolve));
async function freePort() { const server = net.createServer(); const port = await listen(server); await close(server); return port; }
async function stop(child) { if (child.exitCode !== null || child.signalCode !== null) return; const exited = once(child, 'exit'); child.kill(); await exited; }
async function start(config, path, spawnOptions = {}) {
  await writeFile(path, JSON.stringify(config), { mode: 0o600 });
  const check = spawnSync(binary, ['check', '-c', path], { encoding: 'utf8', windowsHide: true });
  assert.equal(check.status, 0, 'Official sing-box binary must accept the generated configuration');
  const child = spawn(binary, ['run', '-c', path], { stdio: 'ignore', windowsHide: true, ...spawnOptions });
  for (let count = 0; count < 60; count++) {
    const ok = await new Promise(resolve => {
      const socket = net.connect(config.inbounds[0].listen_port, '127.0.0.1');
      socket.once('connect', () => { socket.destroy(); resolve(true); });
      socket.once('error', () => resolve(false));
    });
    if (ok) return child;
    if (child.exitCode !== null) throw new Error('sing-box exited before its loopback listener became ready');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  await stop(child); throw new Error('sing-box startup timeout');
}
test('official sing-box: authenticated HTTP, HTTPS and SOCKS chains, HTTPS probe, wrong credentials, and upstream outage', { skip: !binary, timeout: 20000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'proxypilot-core-'));
  const children = [];
  let target;
  try {
    const version = spawnSync(binary, ['version'], { encoding: 'utf8', windowsHide: true });
    assert.match(version.stdout, /sing-box version 1\.14\.2(?:\s|$)/);
    const pair = spawnSync(binary, ['generate', 'tls-keypair', 'localhost'], { encoding: 'utf8', windowsHide: true });
    assert.equal(pair.status, 0);
    const key = pair.stdout.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)?.[0];
    const cert = pair.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0];
    assert.ok(key && cert);
    let destinationRequests = 0;
    let destinationConnections = 0;
    target = https.createServer({ key, cert }, (_, response) => { destinationRequests++; response.setHeader('content-type', 'application/json'); response.end('{"ip":"203.0.113.8"}'); });
    target.on('connection', () => { destinationConnections++; });
    const targetPort = await listen(target);
    const targetUrl = `https://localhost:${targetPort}/`;
    for (const protocol of ['http', 'https', 'socks']) {
      const type = protocol === 'https' ? 'http' : protocol;
      const upstreamPort = await freePort(); const relayPort = await freePort();
      const inbound = { type, listen: '127.0.0.1', listen_port: upstreamPort, users: [{ username: 'test-user', password: 'test-password' }] };
      if (protocol === 'https') inbound.tls = { enabled: true, certificate: [cert], key: [key] };
      const upstream = await start({ log: { disabled: true }, dns: { servers: [{ type: 'hosts', tag: 'bootstrap', predefined: { localhost: '127.0.0.1' } }] }, inbounds: [inbound], outbounds: [{ type: 'direct', domain_resolver: { server: 'bootstrap', strategy: 'ipv4_only' } }] }, join(dir, `${protocol}-upstream.json`));
      children.push(upstream);
      const config = { version: 1, listen: { host: '127.0.0.1', port: relayPort }, upstream: { type, host: '127.0.0.1', port: upstreamPort, auth: 'password' }, probe: { exitUrl: targetUrl, expectedExitIps: ['203.0.113.8'], timeoutMs: 1000 } };
      if (protocol === 'https') config.upstream.tls = { enabled: true, serverName: 'localhost' };
      const rendered = password => {
        const generated = buildSingBox(config, { ISP_USERNAME: 'test-user', ISP_PASSWORD: password });
        // Test-only trust anchor; production still requires a publicly trusted provider certificate.
        if (protocol === 'https') generated.outbounds[0].tls.certificate = cert;
        return generated;
      };
      const relay = await start(rendered('test-password'), join(dir, `${protocol}-relay.json`));
      children.push(relay);
      const body = await requestViaProxy(targetUrl, { proxyPort: relayPort, timeoutMs: 3000, ca: cert });
      assert.deepEqual(JSON.parse(body), { ip: '203.0.113.8' });
      await stop(relay);
      const wrongRelay = await start(rendered('incorrect'), join(dir, `${protocol}-wrong-auth.json`));
      children.push(wrongRelay);
      const beforeWrongAuth = destinationConnections;
      await assert.rejects(requestViaProxy(targetUrl, { proxyPort: relayPort, timeoutMs: 1000, ca: cert }));
      assert.equal(destinationConnections, beforeWrongAuth, 'Bad credentials must not cause direct destination access');
      await stop(wrongRelay);
      const relayAfter = await start(rendered('test-password'), join(dir, `${protocol}-relay-after.json`));
      children.push(relayAfter);
      await stop(upstream);
      const beforeOutage = destinationConnections;
      await assert.rejects(requestViaProxy(targetUrl, { proxyPort: relayPort, timeoutMs: 1000, ca: cert }));
      assert.equal(destinationConnections, beforeOutage, 'Upstream outage must not cause direct destination access');
      await stop(relayAfter);
    }
    assert.equal(destinationRequests, 3);
    const config = { version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type: 'http', host: 'gateway.test', port: 443, auth: 'none', tls: { enabled: true, serverName: 'gateway.test' } }, probe: { exitUrl: 'https://api.ipify.org', expectedExitIps: [], timeoutMs: 1000 } };
    const tlsPath = join(dir, 'tls-schema.json');
    await writeFile(tlsPath, JSON.stringify(buildSingBox(config, {})));
    assert.equal(spawnSync(binary, ['check', '-c', tlsPath], { stdio: 'ignore', windowsHide: true }).status, 0, 'HTTP TLS and upstream DNS fields must pass the actual pinned core schema');
  } finally {
    for (const child of children) await stop(child);
    if (target) await close(target);
    await rm(dir, { recursive: true, force: true });
  }
});

test('official sing-box: encrypted relay detour, remote ISP DNS, both authentication layers and fail-closed outages', { skip: !binary, timeout: 30000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'mc-proxy-relay-chain-'));
  const children = []; const servers = []; const sockets = new Set();
  const pair = () => {
    const result = spawnSync(binary, ['generate', 'tls-keypair', 'localhost'], { encoding: 'utf8', windowsHide: true });
    assert.equal(result.status, 0);
    const key = result.stdout.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)?.[0];
    const cert = result.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0];
    assert.ok(key && cert); return { key, cert };
  };
  const track = socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.on('error', () => {}); return socket; };
  try {
    const trusted = pair(); const untrusted = pair();
    let destinationConnections = 0; let destinationRequests = 0;
    const target = https.createServer(trusted, (_, response) => { destinationRequests++; response.end('{"ip":"203.0.113.8"}'); });
    servers.push(target); target.on('connection', socket => { destinationConnections++; track(socket); });
    const targetPort = await listen(target); const targetUrl = `https://localhost:${targetPort}/`;
    for (const type of ['http', 'socks']) {
      const upstreamPort = await freePort(); const localPort = await freePort();
      const upstreamConfig = { log: { disabled: true }, dns: { servers: [{ type: 'hosts', tag: 'target-dns', predefined: { localhost: '127.0.0.1' } }] },
        inbounds: [{ type, listen: '127.0.0.1', listen_port: upstreamPort, users: [{ username: 'isp-user', password: 'isp-secret' }] }],
        outbounds: [{ type: 'direct', domain_resolver: { server: 'target-dns', strategy: 'ipv4_only' } }] };
      let upstream = await start(upstreamConfig, join(dir, `${type}-isp.json`)); children.push(upstream);
      const observedHosts = []; let authenticatedConnects = 0;
      const relay = https.createServer(trusted, (_, response) => { response.writeHead(405); response.end(); });
      servers.push(relay); relay.on('connection', track);
      relay.on('connect', (request, client, head) => {
        track(client); observedHosts.push(request.url);
        if (request.headers['proxy-authorization'] !== `Basic ${Buffer.from('relay-user:relay-secret').toString('base64')}`) { client.end('HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n'); return; }
        authenticatedConnects++;
        // This hostname does not resolve anywhere on the client. Only the test
        // relay knows how to map it to the fake ISP's loopback listener.
        if (request.url !== `isp-only-at-relay.invalid:${upstreamPort}`) { client.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'); return; }
        const upstreamSocket = track(net.connect(upstreamPort, '127.0.0.1'));
        upstreamSocket.once('error', () => client.destroy()); client.once('error', () => upstreamSocket.destroy());
        client.once('close', () => upstreamSocket.destroy()); upstreamSocket.once('close', () => client.destroy());
        upstreamSocket.once('connect', () => {
          client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
          if (head.length) upstreamSocket.write(head);
          upstreamSocket.pipe(client); client.pipe(upstreamSocket);
        });
      });
      const relayPort = await listen(relay);
      const config = { version: 1, listen: { host: '127.0.0.1', port: localPort },
        upstream: { type, host: 'isp-only-at-relay.invalid', port: upstreamPort, auth: 'password' },
        relay: { type: 'http', host: '127.0.0.1', port: relayPort, auth: 'password', tls: { enabled: true, serverName: 'localhost', certificate: trusted.cert } },
        probe: { exitUrl: targetUrl, expectedExitIps: ['203.0.113.8'], timeoutMs: 1000 } };
      const secrets = { ISP_USERNAME: 'isp-user', ISP_PASSWORD: 'isp-secret', RELAY_USERNAME: 'relay-user', RELAY_PASSWORD: 'relay-secret' };
      const tunPath = join(dir, `${type}-chain-tun-schema.json`);
      await writeFile(tunPath, JSON.stringify(buildSingBox(config, secrets, { mode: 'tun' })));
      const tunChecked = spawnSync(binary, ['check', '-c', tunPath], { encoding: 'utf8', windowsHide: true });
      assert.equal(tunChecked.status, 0, `Relay TUN config must validate without local ISP DNS: ${tunChecked.stderr}`);
      async function attempt(name, { credentials = secrets, selected = config, success = false, noRelayRequest = false } = {}) {
        const local = await start(buildSingBox(selected, credentials), join(dir, `${type}-${name}.json`)); children.push(local);
        const beforeConnections = destinationConnections; const beforeRequests = observedHosts.length;
        try {
          const request = requestViaProxy(targetUrl, { proxyPort: localPort, timeoutMs: 1500, ca: trusted.cert });
          if (success) assert.deepEqual(JSON.parse(await request), { ip: '203.0.113.8' });
          else {
            await assert.rejects(request);
            assert.equal(destinationConnections, beforeConnections, `${name} must not connect directly to destination`);
          }
          if (noRelayRequest) assert.equal(observedHosts.length, beforeRequests, `${name} must fail before CONNECT or relay credentials are transmitted`);
        } finally { await stop(local); }
      }
      await attempt('success', { success: true });
      assert.equal(authenticatedConnects, 1); assert.deepEqual(observedHosts, [`isp-only-at-relay.invalid:${upstreamPort}`]);
      await attempt('wrong-relay-password', { credentials: { ...secrets, RELAY_PASSWORD: 'incorrect' } });
      await attempt('wrong-isp-password', { credentials: { ...secrets, ISP_PASSWORD: 'incorrect' } });
      await attempt('untrusted-relay-cert', { selected: { ...config, relay: { ...config.relay, tls: { ...config.relay.tls, certificate: untrusted.cert } } }, noRelayRequest: true });
      await attempt('wrong-relay-name', { selected: { ...config, relay: { ...config.relay, tls: { ...config.relay.tls, serverName: 'wrong-relay.invalid' } } }, noRelayRequest: true });
      await stop(upstream);
      await attempt('isp-outage');
      upstream = await start(upstreamConfig, join(dir, `${type}-isp-restarted.json`)); children.push(upstream);
      for (const socket of sockets) socket.destroy();
      await close(relay);
      await attempt('relay-outage', { noRelayRequest: true });
      await stop(upstream);
    }
    assert.equal(destinationRequests, 2, 'Only authenticated full-chain requests reach the destination');
  } finally {
    for (const child of children) await stop(child);
    for (const socket of sockets) socket.destroy();
    for (const server of servers) if (server.listening) await close(server);
    await rm(dir, { recursive: true, force: true });
  }
});

test('official sing-box: VPN compatibility HTTP/SOCKS entries preserve remote ISP DNS, authentication and fail-closed routing', { skip: !binary, timeout: 30000 }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'mc-proxy-vpn-chain-'));
  const children = []; const servers = []; const sockets = new Set();
  const track = socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); socket.on('error', () => {}); return socket; };
  const pipe = (client, upstream) => {
    client.once('close', () => upstream.destroy()); upstream.once('close', () => client.destroy());
    client.once('error', () => upstream.destroy()); upstream.once('error', () => client.destroy());
    client.pipe(upstream); upstream.pipe(client);
  };
  try {
    assert.match(spawnSync(binary, ['version'], { encoding: 'utf8', windowsHide: true }).stdout, /sing-box version 1\.14\.2(?:\s|$)/);
    const pair = spawnSync(binary, ['generate', 'tls-keypair', 'localhost'], { encoding: 'utf8', windowsHide: true });
    assert.equal(pair.status, 0);
    const key = pair.stdout.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)?.[0];
    const cert = pair.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0];
    assert.ok(key && cert);
    let targetConnections = 0; let targetRequests = 0;
    const target = https.createServer({ key, cert }, (_, response) => { targetRequests++; response.end('{"ip":"203.0.113.8"}'); });
    servers.push(target); target.on('connection', socket => { targetConnections++; track(socket); });
    const targetUrl = `https://localhost:${await listen(target)}/`;
    for (const vpnType of ['http', 'socks']) for (const ispType of ['http', 'socks']) await t.test(`${vpnType} VPN entry -> authenticated ${ispType} ISP`, async () => {
      const name = `${vpnType}-${ispType}`; const ispHost = `${name}-isp-only-at-vpn.invalid`;
      const ispCorePort = await freePort(); const localPort = await freePort();
      const isp = await start({ log: { disabled: true },
        dns: { servers: [{ type: 'hosts', tag: 'target-dns', predefined: { localhost: '127.0.0.1' } }] },
        inbounds: [{ type: ispType, listen: '127.0.0.1', listen_port: ispCorePort, users: [{ username: 'isp-user', password: 'isp-secret' }] }],
        outbounds: [{ type: 'direct', domain_resolver: { server: 'target-dns', strategy: 'ipv4_only' } }],
      }, join(dir, `${name}-isp.json`)); children.push(isp);
      let ispConnections = 0;
      const ispFront = net.createServer(client => {
        ispConnections++; track(client);
        const upstream = track(net.connect(ispCorePort, '127.0.0.1')); pipe(client, upstream);
      });
      servers.push(ispFront); const ispPort = await listen(ispFront);
      const observedHosts = []; let entry; let entryServer; let vpnPort;
      if (vpnType === 'http') {
        entryServer = http.createServer((_, response) => { response.writeHead(405); response.end(); });
        servers.push(entryServer); entryServer.on('connection', track);
        entryServer.on('connect', (request, client, head) => {
          track(client); observedHosts.push(request.url);
          // Only this entry maps the synthetic ISP hostname. The client has
          // no resolver configured and cannot resolve a .invalid address.
          if (request.url !== `${ispHost}:${ispPort}`) { client.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n'); return; }
          const upstream = track(net.connect(ispPort, '127.0.0.1'));
          upstream.once('error', () => client.destroy()); client.once('close', () => upstream.destroy());
          upstream.once('connect', () => {
            client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            if (head.length) upstream.write(head);
            pipe(client, upstream);
          });
        });
        vpnPort = await listen(entryServer);
      } else {
        vpnPort = await freePort();
        entry = await start({ log: { disabled: true },
          dns: { servers: [{ type: 'hosts', tag: 'vpn-only-dns', predefined: { [ispHost]: '127.0.0.1' } }] },
          inbounds: [{ type: 'socks', listen: '127.0.0.1', listen_port: vpnPort }],
          outbounds: [{ type: 'direct', domain_resolver: { server: 'vpn-only-dns', strategy: 'ipv4_only' } }],
        }, join(dir, `${name}-vpn.json`)); children.push(entry);
      }
      const config = { version: 1, connectionMode: 'vpn-compat', listen: { host: '127.0.0.1', port: localPort },
        upstream: { type: ispType, host: ispHost, port: ispPort, auth: 'password' },
        probe: { exitUrl: targetUrl, expectedExitIps: ['203.0.113.8'], timeoutMs: 1000 } };
      const vpnProxy = { type: vpnType, host: '127.0.0.1', port: vpnPort };
      const credentials = { ISP_USERNAME: 'isp-user', ISP_PASSWORD: 'isp-secret' };
      async function attempt(label, selected, secrets, success = false, noIspAccess = false) {
        const rendered = buildSingBox(selected, secrets, { mode: 'http', vpnProxy });
        assert.equal(rendered.dns, undefined); assert.equal(rendered.outbounds[0].domain_resolver, undefined);
        assert.equal(rendered.outbounds[0].detour, 'vpn-entry');
        const client = await start(rendered, join(dir, `${name}-${label}.json`)); children.push(client);
        const beforeTarget = targetConnections; const beforeIsp = ispConnections;
        try {
          const request = requestViaProxy(targetUrl, { proxyPort: localPort, timeoutMs: 1500, ca: cert });
          if (success) {
            assert.deepEqual(JSON.parse(await request), { ip: '203.0.113.8' });
            assert.equal(ispConnections, beforeIsp + 1, 'The authenticated ISP must receive the full chain connection');
          } else {
            await assert.rejects(request);
            assert.equal(targetConnections, beforeTarget, `${label} must never connect directly to the reachable HTTPS target`);
            if (noIspAccess) assert.equal(ispConnections, beforeIsp, `${label} must never bypass the unavailable VPN entry to the reachable ISP`);
            else assert.equal(ispConnections, beforeIsp + 1, 'Wrong credentials must actually reach ISP authentication');
          }
        } finally { await stop(client); }
      }
      await attempt('success', config, credentials, true);
      if (vpnType === 'http') assert.deepEqual(observedHosts, [`${ispHost}:${ispPort}`]);
      await attempt('wrong-isp-auth', config, { ...credentials, ISP_PASSWORD: 'incorrect' });
      if (entry) await stop(entry);
      if (entryServer) { for (const socket of sockets) socket.destroy(); await close(entryServer); }
      // Keep the ISP and HTTPS destination reachable by local IP. Failure now
      // demonstrates missing-entry refusal, rather than an unresolvable ISP.
      assert.equal(isp.exitCode, null); assert.equal(ispFront.listening, true); assert.equal(target.listening, true);
      await attempt('vpn-outage', { ...config, upstream: { ...config.upstream, host: '127.0.0.1' } }, credentials, false, true);
      await stop(isp); for (const socket of sockets) socket.destroy(); await close(ispFront);
    });
    assert.equal(targetRequests, 4, 'Only the four authenticated full-chain requests may reach HTTPS');
  } finally {
    for (const child of children) await stop(child);
    for (const socket of sockets) socket.destroy();
    for (const server of servers) if (server.listening) await close(server);
    await rm(dir, { recursive: true, force: true });
  }
});
