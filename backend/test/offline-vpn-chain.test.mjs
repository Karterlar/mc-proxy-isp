import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { mkdtemp, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildTestConfig, assertExitChecks, classifyCoreOutput, tcpCheck, checkNodeTransport, startTestCore } from '../../tools/offline-vpn-test/offline-vpn-test.mjs';
import { allocateSetupPort } from '../src/setup-verification.mjs';
import { vpnOutbound } from './vpn-fixture.mjs';

const config = {
  version: 1, connectionMode: 'vpn-compat', listen: { host: '127.0.0.1', port: 17890 },
  upstream: { type: 'http', host: 'isp.example.net', port: 8443, auth: 'password', tls: { enabled: true, serverName: 'isp.example.net' } },
  probe: { exitUrl: 'https://api.ipify.org?format=json', expectedExitIps: ['198.51.100.8'], timeoutMs: 5000 },
};
const node = vpnOutbound({ server: 'gateway.example.net' });
const secret = { ISP_USERNAME: 'test-user', ISP_PASSWORD: 'test-private-password' };
const corePath = fileURLToPath(new URL('../.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe', import.meta.url));

test('imported node is the only ISP dialer and DNS/route settings cannot bypass it', () => {
  const result = buildTestConfig(config, secret, node, { proxyPort: 28991, vpnPort: 28992, nodeIp: '127.0.0.1' });
  assert.deepEqual(result.outbounds.map(outbound => [outbound.tag, outbound.type]), [['isp-upstream', 'http'], ['vpn-entry', 'vless']]);
  assert.equal(result.outbounds[0].detour, 'vpn-entry');
  assert.equal(result.outbounds[0].server, 'isp.example.net');
  assert.equal(result.outbounds[0].tls.server_name, 'isp.example.net');
  assert.equal(result.outbounds[0].domain_resolver, undefined);
  assert.equal(result.outbounds[1].server, '127.0.0.1');
  assert.equal(result.outbounds[1].tls.server_name, 'localhost');
  assert.equal(result.dns, undefined);
  assert.equal(result.route.final, 'isp-upstream');
  assert.deepEqual(result.route.rules, [{ inbound: ['vpn-diagnostic'], outbound: 'vpn-entry' }]);
  assert.ok(result.inbounds.every(inbound => inbound.type === 'http' && inbound.listen === '127.0.0.1'));
  assert.equal(config.listen.port, 17890);
  assert.equal(node.server, 'gateway.example.net');
});

test('VPN success cannot qualify an unpinned, mismatched or inconsistent ISP exit', () => {
  for (const [checks, expected, code] of [
    [[], ['198.51.100.8'], 'ISP_EXIT_CHECK_FAILED'],
    [[{ ip: '198.51.100.8' }, { ip: '198.51.100.8' }], [], 'ISP_EXIT_PIN_REQUIRED'],
    [[{ ip: '198.51.100.8' }, { ip: '198.51.100.9' }], ['198.51.100.8'], 'ISP_EXIT_INCONSISTENT'],
    [[{ ip: '198.51.100.9' }, { ip: '198.51.100.9' }], ['198.51.100.8'], 'ISP_EXIT_PIN_MISMATCH'],
  ]) assert.throws(() => assertExitChecks(checks, expected), error => error.code === code);
  assert.doesNotThrow(() => assertExitChecks([{ ip: '2001:db8::1' }, { ip: '2001:0db8:0:0:0:0:0:1' }], ['2001:db8::1']));
});

test('core diagnostic classification exposes codes without credentials or raw endpoints', () => {
  const raw = 'tls handshake failed for private-user:private-password@secret.example; reality verification failed; i/o timeout';
  const codes = classifyCoreOutput(raw);
  assert.ok(codes.includes('CORE_TLS_HANDSHAKE_FAILED'));
  assert.ok(codes.includes('CORE_CONNECTION_TIMEOUT'));
  assert.ok(!JSON.stringify(codes).includes('private-'));
  assert.deepEqual(classifyCoreOutput('normal warning without an error'), []);
});

test('TCP readiness failure closes its owned socket and cannot fall back to another route', async () => {
  const port = await allocateSetupPort();
  await assert.rejects(tcpCheck('127.0.0.1', port, 300), error => error.code === 'NODE_TCP_FAILED');
  const server = net.createServer(socket => socket.destroy());
  await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
  try { await tcpCheck('127.0.0.1', port, 300); }
  finally { await new Promise(resolve => server.close(resolve)); }
});

test('QUIC imported nodes reach protocol verification without requiring an unrelated TCP listener', async () => {
  let calls = 0;
  const tcp = async () => { calls++; throw new Error('a TCP dial must not occur for a QUIC node'); };
  for (const type of ['hysteria2', 'tuic']) assert.equal(await checkNodeTransport('127.0.0.1', { type, server_port: 443 }, { tcp }), 'not-applicable');
  assert.equal(calls, 0);
  await assert.rejects(checkNodeTransport('127.0.0.1', { type: 'vmess', server_port: 443 }, { tcp }));
  assert.equal(calls, 1, 'TCP nodes keep the original reachability prerequisite');
});

test('native temporary core stops and releases both private listeners', async t => {
  if (process.platform !== 'win32') return t.skip('Windows bundled core');
  await access(corePath);
  const directory = await mkdtemp(path.join(tmpdir(), 'mc-vpn-core-test-'));
  const proxyPort = await allocateSetupPort();
  let vpnPort = await allocateSetupPort();
  while (vpnPort === proxyPort) vpnPort = await allocateSetupPort();
  let core;
  try {
    core = await startTestCore({ corePath, configPath: path.join(directory, 'fixture.json'), rendered: buildTestConfig(config, secret, node, { proxyPort, vpnPort, nodeIp: '127.0.0.1' }) });
    assert.equal(core.alive(), true);
    await tcpCheck('127.0.0.1', vpnPort, 500);
    await core.stop();
    assert.equal(core.alive(), false);
    await assert.rejects(tcpCheck('127.0.0.1', proxyPort, 500));
    await assert.rejects(tcpCheck('127.0.0.1', vpnPort, 500));
  } finally { await core?.stop(); await rm(directory, { recursive: true, force: true }); }
});
