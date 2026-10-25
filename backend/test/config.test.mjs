import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { validateConfig, parseSecrets, buildSingBox, validateSecrets, validateVpnProxy, validateCoreApi, validateFakeIpCache } from '../src/config.mjs';
import { createPrivateDirectory } from '../src/private-files.mjs';
import { relayFixture, relaySecrets } from './relay-fixture.mjs';
import { vpnOutbound } from './vpn-fixture.mjs';
import { nativeProtocolShapes } from './vpn-protocol-fixture.mjs';

export function fixture() {
  return { version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type: 'socks', host: '127.0.0.1', port: 1080, auth: 'password' }, probe: { exitUrl: 'https://api.ipify.org?format=json', expectedExitIps: [], timeoutMs: 1000 } };
}
const secret = { ISP_USERNAME: 'user', ISP_PASSWORD: 'p@ss:"\\word' };
test('TUN traffic gate only prepends DNS and routing rejection and preserves normal ISP routing', () => {
  for (const routingMode of ['safe-rules', 'global']) {
    const options = { mode: 'tun', routingMode, coreApi: { port: 17991, secret: 'a'.repeat(64) } };
    const normal = buildSingBox(fixture(), secret, options);
    const gated = buildSingBox(fixture(), secret, { ...options, trafficGate: true });
    assert.deepEqual(gated.route.rules.shift(), { clash_mode: 'mc-blocked', action: 'reject' });
    assert.deepEqual(gated.dns.rules.shift(), { clash_mode: 'mc-blocked', action: 'reject' });
    assert.equal(gated.experimental.clash_api.default_mode, 'mc-active');
    delete gated.experimental.clash_api.default_mode;
    assert.deepEqual(gated, normal, 'Active gate must leave every existing routing, DNS, inbound and outbound option intact');
  }
  assert.throws(() => buildSingBox(fixture(), secret, { mode: 'tun', trafficGate: true }), { code: 'CORE_TRAFFIC_GATE_INVALID' });
  assert.throws(() => buildSingBox(fixture(), secret, { mode: 'http', trafficGate: true, coreApi: { port: 17991, secret: 'a'.repeat(64) } }), { code: 'CORE_TRAFFIC_GATE_INVALID' });
});
test('imported VPN renders only ISP via validated Reality node with pre-resolved VPN server and remote ISP DNS', () => {
  const vpnNode = vpnOutbound();
  for (const type of ['http', 'socks']) {
    const config = { ...fixture(), connectionMode: 'vpn-import', upstream: { ...fixture().upstream, type, host: 'only-vpn-can-resolve.invalid' } };
    const rendered = buildSingBox(config, secret, { mode: 'http', vpnNode, vpnNodeIp: '192.0.2.9' });
    assert.deepEqual(rendered.inbounds.map(item => item.type), ['http']);
    assert.deepEqual(rendered.outbounds.map(item => item.tag), ['isp-upstream', 'vpn-entry']);
    assert.equal(rendered.outbounds[0].server, config.upstream.host); assert.equal(rendered.outbounds[0].detour, 'vpn-entry');
    assert.equal(rendered.outbounds[0].domain_resolver, undefined); assert.equal(rendered.dns, undefined);
    assert.equal(rendered.outbounds[1].server, '192.0.2.9'); assert.equal(rendered.outbounds[1].tls.server_name, 'localhost');
    assert.equal(rendered.route.final, 'isp-upstream'); assert.equal(rendered.outbounds.some(item => ['direct', 'selector'].includes(item.type)), false);
    assert.equal(vpnNode.server, 'vpn.private.invalid');
    assert.throws(() => buildSingBox(config, secret, { vpnNode }), { code: 'VPN_NODE_RESOLVE_FAILED' });
    assert.throws(() => buildSingBox(config, secret), { code: 'VPN_NODE_REQUIRED' });
    assert.throws(() => buildSingBox(config, secret, { mode: 'tun', vpnNode }), { code: 'VPN_NODE_RESOLVE_FAILED' });
    assert.throws(() => buildSingBox(config, secret, { vpnNode, vpnProxy: { type: 'http', host: '127.0.0.1', port: 1088 } }), { code: 'VPN_PROXY_INVALID' });
    assert.throws(() => validateConfig({ ...config, relay: relayFixture() }), { code: 'CONFIG_INVALID' });
  }
  assert.throws(() => buildSingBox(fixture(), secret, { vpnNode }), { code: 'VPN_NODE_INVALID' });
});

test('imported global TUN captures dual-stack TCP and DNS while only VPN entry uses the physical interface', () => {
  const config = { ...fixture(), connectionMode: 'vpn-import', upstream: { ...fixture().upstream, host: 'remote-only-isp.invalid' } };
  const rendered = buildSingBox(config, secret, { mode: 'tun', vpnNode: vpnOutbound(), vpnNodeIp: '192.0.2.9', upstreamIp: '192.0.2.200' });
  assert.deepEqual(rendered.inbounds.map(item => item.type), ['http', 'tun']);
  assert.deepEqual(rendered.inbounds[1].route_address, ['0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1']);
  assert.equal(rendered.route.auto_detect_interface, true); assert.equal(rendered.route.final, 'isp-upstream');
  assert.equal(rendered.outbounds[0].server, 'remote-only-isp.invalid'); assert.equal(rendered.outbounds[0].detour, 'vpn-entry');
  assert.equal(rendered.outbounds[0].domain_resolver, undefined);
  assert.equal(rendered.outbounds[1].server, '192.0.2.9'); assert.equal(rendered.outbounds[1].tls.server_name, 'localhost');
  assert.equal(rendered.outbounds[1].detour, undefined);
  assert.deepEqual(rendered.outbounds.map(item => item.tag), ['isp-upstream', 'vpn-entry', 'private-direct']);
  assert.equal(rendered.dns.servers.find(server => server.tag === 'isp-doh').detour, 'isp-upstream');
  assert.deepEqual(rendered.dns.servers.find(server => server.tag === 'isp-fakeip'), { type: 'fakeip', tag: 'isp-fakeip', inet4_range: '198.18.0.0/15', inet6_range: 'fc00::/18' });
  assert.deepEqual(rendered.dns.rules, [{ domain: ['localhost'], action: 'route', server: 'callback-hosts' }, { query_type: ['A', 'AAAA'], action: 'route', server: 'isp-fakeip' }]);
  assert.ok(rendered.route.rules.some(rule => rule.port === 53 && rule.action === 'hijack-dns'));
  assert.ok(rendered.route.rules.some(rule => rule.network === 'udp' && rule.action === 'reject'));
});

test('pinned core validates imported global TCP and QUIC configurations without starting TUN', { timeout: 30000 }, async t => {
  if (process.platform !== 'win32') return t.skip('bundled Windows core');
  const corePath = fileURLToPath(new URL('../.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe', import.meta.url));
  const dir = await mkdtemp(join(tmpdir(), 'proxypilot-imported-tun-schema-'));
  try {
    const config = { ...fixture(), connectionMode: 'vpn-import', upstream: { ...fixture().upstream, host: 'isp.invalid' } };
    const nodes = [vpnOutbound(), ...nativeProtocolShapes.filter(([label]) => ['ss-aes128', 'vmess-ws', 'trojan', 'hysteria2', 'tuic'].includes(label)).map(([, node]) => node)];
    for (const [index, vpnNode] of nodes.entries()) {
      const file = join(dir, `${index}.json`);
      await writeFile(file, JSON.stringify(buildSingBox(config, secret, { mode: 'tun', vpnNode, vpnNodeIp: '192.0.2.9' })));
      const checked = spawnSync(corePath, ['check', '-c', file], { windowsHide: true, encoding: 'utf8', timeout: 6000 });
      assert.equal(checked.status, 0, `synthetic ${vpnNode.type} imported TUN schema: ${checked.error?.code || checked.stderr}`);
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('imported protocols cannot loop into the owned listener through literal or resolved loopback addresses', () => {
  const config = { ...fixture(), connectionMode: 'vpn-import' };
  for (const host of ['127.0.0.1', '127.0.0.2', '0.0.0.0', '::1', '::', '::ffff:127.0.0.1', '0:0:0:0:0:ffff:7f00:1']) {
    const vpnNode = { type: 'http', tag: 'vpn-entry', server: host, server_port: config.listen.port };
    assert.throws(() => buildSingBox(config, secret, { vpnNode }), { code: 'VPN_NODE_INVALID' });
    assert.equal(buildSingBox(config, secret, { vpnNode: { ...vpnNode, server_port: 7890 } }).outbounds[1].server_port, 7890);
  }
  assert.throws(() => buildSingBox(config, secret, { vpnNode: { type: 'socks', tag: 'vpn-entry', server: 'local-proxy.invalid', server_port: config.listen.port, version: '5', network: 'tcp' }, vpnNodeIp: '127.0.0.1' }), { code: 'VPN_NODE_INVALID' });
});
test('rejects public listener, credential URLs, unsupported routing, insecure TLS and non-HTTPS probes', () => {
  for (const mutate of [
    c => { c.listen.host = '0.0.0.0'; },
    c => { c.upstream.host = 'http://user:password@host'; },
    c => { c.route = { final: 'direct' }; },
    c => { c.upstream.tls = { enabled: true, serverName: 'example.com', insecure: true }; },
    c => { c.probe.exitUrl = 'http://example.com'; }
  ]) { const config = fixture(); mutate(config); assert.throws(() => validateConfig(config)); }
});
test('SOCKS TCP configuration has exactly one ISP outbound and no direct fallback', () => {
  const generated = buildSingBox(fixture(), secret);
  assert.equal(generated.outbounds.length, 1);
  assert.equal(generated.outbounds[0].network, 'tcp');
  assert.equal(generated.route.final, 'isp-upstream');
  assert.equal(generated.inbounds[0].listen, '127.0.0.1');
  assert.equal(generated.outbounds[0].password, secret.ISP_PASSWORD);
});

test('VPN compatibility renders only the ISP HTTP proxy path and rejects TUN', () => {
  for (const type of ['http', 'socks']) {
    const config = { ...fixture(), connectionMode: 'vpn-compat', upstream: { ...fixture().upstream, type, host: 'gateway.provider.test' } };
    assert.equal(validateConfig(config), config);
    const rendered = buildSingBox(config, secret, { mode: 'http' });
    assert.deepEqual(rendered.inbounds.map(inbound => inbound.type), ['http']);
    assert.deepEqual(rendered.outbounds.map(outbound => outbound.tag), ['isp-upstream']);
    assert.equal(rendered.outbounds[0].server, config.upstream.host);
    assert.equal(rendered.outbounds[0].detour, undefined);
    assert.equal(rendered.route.final, 'isp-upstream');
    assert.equal(rendered.outbounds.some(outbound => ['direct', 'selector'].includes(outbound.type)), false);
    assert.throws(() => buildSingBox(config, secret, { mode: 'tun', upstreamIp: '192.0.2.99' }), { code: 'VPN_COMPAT_HTTP_ONLY' });
  }
});

test('connection mode is optional for legacy configs but VPN compatibility forbids relay data and credentials', () => {
  assert.equal(validateConfig(fixture()).connectionMode, undefined);
  assert.equal(validateConfig({ ...fixture(), connectionMode: 'relay' }).connectionMode, 'relay');
  for (const connectionMode of ['direct', 'vpn', '', null, true]) assert.throws(() => validateConfig({ ...fixture(), connectionMode }), { code: 'CONFIG_INVALID' });
  const config = { ...fixture(), connectionMode: 'vpn-compat' };
  assert.throws(() => validateConfig({ ...config, relay: relayFixture() }), { code: 'CONFIG_INVALID' });
  assert.throws(() => buildSingBox(config, { ...secret, ...relaySecrets }), { code: 'SECRETS_INVALID' });
});

test('VPN local HTTP and SOCKS detours resolve the ISP remotely without relay, TUN or direct fallback', () => {
  const config = { ...fixture(), connectionMode: 'vpn-compat', upstream: { type: 'http', host: 'remote-resolves-only.invalid', port: 443, auth: 'password', tls: { enabled: true, serverName: 'gateway.provider.test' } } };
  for (const type of ['http', 'socks']) for (const host of ['127.0.0.1', '::1']) {
    const vpnProxy = { type, host, port: 1088 };
    assert.equal(validateVpnProxy(vpnProxy, config.listen.port), vpnProxy);
    const rendered = buildSingBox(config, secret, { mode: 'http', vpnProxy });
    assert.deepEqual(rendered.outbounds.map(outbound => outbound.tag), ['isp-upstream', 'vpn-entry']);
    const [isp, vpn] = rendered.outbounds;
    assert.equal(isp.detour, 'vpn-entry'); assert.equal(isp.server, config.upstream.host);
    assert.equal(isp.tls.server_name, config.upstream.tls.serverName); assert.equal(isp.domain_resolver, undefined);
    assert.equal(vpn.type, type); assert.equal(vpn.server, host); assert.equal(vpn.server_port, vpnProxy.port);
    if (type === 'socks') { assert.equal(vpn.version, '5'); assert.equal(vpn.network, 'tcp'); }
    assert.equal(rendered.dns, undefined);
    assert.equal(rendered.route.final, 'isp-upstream');
    assert.deepEqual(rendered.inbounds.map(inbound => inbound.type), ['http']);
    assert.equal(rendered.outbounds.some(outbound => ['direct', 'selector'].includes(outbound.type)), false);
    assert.equal(config.vpnProxy, undefined);
  }
});

test('VPN local detour rejects remote, credentialed, ambiguous and recursive endpoints', () => {
  const good = { type: 'http', host: '127.0.0.1', port: 1088 };
  for (const value of [null, [], {}, { ...good, type: 'socks5' }, { ...good, host: 'localhost' }, { ...good, host: '192.0.2.1' }, { ...good, port: 1023 }, { ...good, port: 65536 }, { ...good, port: '1088' }, { ...good, password: 'private' }, { ...good, port: fixture().listen.port }]) assert.throws(() => validateVpnProxy(value, fixture().listen.port), { code: 'VPN_PROXY_INVALID' });
  assert.throws(() => buildSingBox(fixture(), secret, { vpnProxy: good }), { code: 'VPN_PROXY_INVALID' });
  assert.throws(() => buildSingBox({ ...fixture(), connectionMode: 'vpn-compat' }, secret, { mode: 'tun', vpnProxy: good }), { code: 'VPN_COMPAT_HTTP_ONLY' });
});

test('TUN captures both IP families, hijacks DNS before blocking UDP, and carries DoH over the ISP', () => {
  const generated = buildSingBox(fixture(), secret, { mode: 'tun' });
  const tun = generated.inbounds.find(inbound => inbound.type === 'tun');
  assert.equal(tun.auto_route, true); assert.equal(tun.strict_route, true); assert.equal(tun.dns_mode, 'hijack');
  assert.deepEqual(tun.route_address, ['0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1']);
  assert.ok(tun.address.some(address => address.includes(':')));
  assert.equal(generated.route.auto_detect_interface, true);
  assert.deepEqual(generated.route.rules.slice(0, 2), [
    { inbound: ['system-tun'], port: 53, action: 'hijack-dns' },
    { inbound: ['system-tun'], network: 'udp', action: 'reject' },
  ]);
  assert.equal(generated.dns.final, 'isp-doh');
  assert.ok(generated.dns.servers.filter(server => !['fakeip', 'hosts'].includes(server.type)).every(server => server.type === 'https' && server.detour === 'isp-upstream' && server.tls.insecure === false));
  assert.ok(generated.dns.servers.some(server => server.type === 'fakeip'));
  assert.deepEqual(generated.dns.rules, [{ domain: ['localhost'], action: 'route', server: 'callback-hosts' }, { query_type: ['A', 'AAAA'], action: 'route', server: 'isp-fakeip' }]);
  assert.deepEqual(generated.dns.servers.find(server => server.type === 'hosts'), { type: 'hosts', tag: 'callback-hosts', predefined: { localhost: ['127.0.0.1', '::1'] } });
  assert.deepEqual(generated.outbounds.map(outbound => outbound.tag), ['isp-upstream', 'private-direct']);
  assert.equal(generated.outbounds[1].domain_resolver, 'isp-doh');
});

test('TUN requires pre-resolved provider hostname and preserves TLS identity', () => {
  const config = fixture();
  config.upstream = { type: 'http', host: 'gateway.provider.test', port: 443, auth: 'password', tls: { enabled: true, serverName: 'gateway.provider.test' } };
  assert.throws(() => buildSingBox(config, secret, { mode: 'tun' }), { code: 'UPSTREAM_RESOLVE_FAILED' });
  const generated = buildSingBox(config, secret, { mode: 'tun', upstreamIp: '192.0.2.1' });
  assert.equal(generated.outbounds[0].server, '192.0.2.1');
  assert.equal(generated.outbounds[0].tls.server_name, 'gateway.provider.test');
  assert.equal(generated.outbounds[0].domain_resolver, undefined);
  assert.equal(generated.dns.servers.some(server => server.type === 'local'), false);
  assert.throws(() => buildSingBox(config, secret, { mode: 'direct' }), { code: 'PROXY_MODE_INVALID' });
});
test('HTTP TLS enforces certificate verification and bootstrap DNS resolves only upstream hostname', () => {
  const config = fixture();
  config.upstream = { type: 'http', host: 'gateway.provider.test', port: 443, auth: 'password', tls: { enabled: true, serverName: 'gateway.provider.test' } };
  const generated = buildSingBox(config, secret);
  assert.equal(generated.outbounds[0].tls.insecure, false);
  assert.equal(generated.outbounds[0].domain_resolver, 'bootstrap');
  assert.deepEqual(generated.dns.servers, [{ type: 'local', tag: 'bootstrap' }]);
  assert.equal(generated.route.rules, undefined);
});
test('secrets parsing never evaluates shell substitutions and rejects duplicates and excess bytes', () => {
  assert.equal(parseSecrets('ISP_USERNAME=abc\nISP_PASSWORD=$(do-not-execute)#literal').ISP_PASSWORD, '$(do-not-execute)#literal');
  assert.equal(parseSecrets('ISP_PASSWORD=" a\\\"b "').ISP_PASSWORD, ' a"b ');
  assert.throws(() => parseSecrets('ISP_PASSWORD=x\nISP_PASSWORD=y'));
  assert.throws(() => validateSecrets(fixture(), { ISP_USERNAME: 'u', ISP_PASSWORD: '字'.repeat(100) }));
});

test('relay schema refuses local-DNS bootstrap, plaintext, anonymous access and unsafe certificate options', () => {
  for (const mutate of [
    relay => { relay.host = 'relay.test'; },
    relay => { relay.type = 'socks'; },
    relay => { relay.port = 0; },
    relay => { relay.auth = 'none'; },
    relay => { delete relay.tls; },
    relay => { relay.tls.enabled = false; },
    relay => { relay.tls.insecure = true; },
    relay => { relay.tls.certificate = '-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----'; },
    relay => { relay.tls.certificate += '\n-----BEGIN PRIVATE KEY-----\nprivate\n-----END PRIVATE KEY-----'; },
  ]) {
    const config = { ...fixture(), relay: relayFixture() }; mutate(config.relay);
    assert.throws(() => validateConfig(config), { code: 'CONFIG_INVALID' });
  }
});

test('relay chain leaves ISP hostname to remote CONNECT and keeps final traffic and DNS on the ISP', () => {
  const config = { ...fixture(), upstream: { ...fixture().upstream, host: 'only-relay-can-resolve.invalid' }, relay: relayFixture() };
  for (const mode of ['http', 'tun']) {
    const rendered = buildSingBox(config, { ...secret, ...relaySecrets }, { mode, upstreamIp: '192.0.2.99' });
    const isp = rendered.outbounds[0]; const relay = rendered.outbounds[1];
    assert.equal(isp.server, config.upstream.host); assert.equal(isp.detour, 'relay-entry');
    assert.equal(isp.domain_resolver, undefined);
    assert.equal(relay.server, config.relay.host); assert.equal(relay.server_port, 443);
    assert.equal(relay.username, relaySecrets.RELAY_USERNAME); assert.equal(relay.password, relaySecrets.RELAY_PASSWORD);
    assert.deepEqual(relay.tls.certificate, [config.relay.tls.certificate]); assert.equal(relay.tls.insecure, false);
    assert.equal(rendered.route.final, 'isp-upstream');
    assert.equal(rendered.outbounds.some(item => item.type === 'selector'), false);
    assert.equal(rendered.outbounds.some(item => item.type === 'direct'), mode === 'tun');
    assert.equal(rendered.dns?.servers.some(server => server.type === 'local') || false, false);
    if (mode === 'tun') assert.ok(rendered.dns.servers.filter(server => !['fakeip', 'hosts'].includes(server.type)).every(server => server.detour === 'isp-upstream'));
  }
});

test('relay credentials require both values and never become an unauthenticated or ambiguous chain', () => {
  const config = { ...fixture(), relay: relayFixture() };
  assert.deepEqual(parseSecrets('RELAY_USERNAME="relay-test-user"\nRELAY_PASSWORD="relay-test-password"'), relaySecrets);
  assert.deepEqual(validateSecrets(config, { ...secret, ...relaySecrets }), { ...secret, ...relaySecrets });
  for (const credentials of [secret, { ...secret, RELAY_USERNAME: 'user' }, { ...secret, ...relaySecrets, RELAY_USERNAME: 'bad:user' }, { ...secret, ...relaySecrets, RELAY_PASSWORD: 'new\nline' }]) {
    assert.throws(() => validateSecrets(config, credentials), { code: 'SECRETS_INVALID' });
  }
  assert.throws(() => validateSecrets(fixture(), { ...secret, ...relaySecrets }), { code: 'SECRETS_INVALID' });
  assert.throws(() => parseSecrets('RELAY_PASSWORD=one\nRELAY_PASSWORD=two'), { code: 'SECRETS_INVALID' });
});
test('CLI never echoes secret values in validation output or malformed JSON error', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'proxypilot-redaction-'));
  try {
    const configPath = join(dir, 'config.json'); const secretsPath = join(dir, 'secrets.env');
    await writeFile(configPath, JSON.stringify(fixture()));
    await writeFile(secretsPath, 'ISP_USERNAME=DO_NOT_LOG_USERNAME\nISP_PASSWORD=DO_NOT_LOG_PASSWORD', { mode: 0o600 });
    const cli = fileURLToPath(new URL('../src/cli.mjs', import.meta.url));
    let result = spawnSync(process.execPath, [cli, 'validate', '--config', configPath, '--secrets', secretsPath], { encoding: 'utf8' });
    assert.equal(result.status, 0);
    assert.doesNotMatch(result.stdout + result.stderr, /DO_NOT_LOG/);
    await writeFile(configPath, '{"password":"DO_NOT_LOG_PASSWORD" broken json');
    result = spawnSync(process.execPath, [cli, 'validate', '--config', configPath, '--secrets', secretsPath], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.doesNotMatch(result.stdout + result.stderr, /DO_NOT_LOG/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});
test('private output refuses to overwrite any existing directory', async () => {
  const parent = await mkdtemp(join(tmpdir(), 'proxypilot-output-'));
  const path = join(parent, 'private');
  try {
    await createPrivateDirectory(path);
    assert.equal(await readFile(join(path, '.gitignore'), 'utf8'), '*\n');
    await assert.rejects(createPrivateDirectory(path), /already exists/);
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('owned core API and fake-IP persistence accept only strict private runtime inputs and preserve the ISP final', () => {
  const cache = { path: join(tmpdir(), 'private mapping.db'), id: 'b'.repeat(64) }, api = { port: 17991, secret: 'a'.repeat(64) };
  for (const routingMode of ['safe-rules', 'global']) {
    const rendered = buildSingBox(fixture(), secret, { mode: 'tun', routingMode, coreApi: api, fakeIpCache: cache });
    assert.deepEqual(rendered.experimental, { clash_api: { external_controller: '127.0.0.1:17991', secret: api.secret, access_control_allow_origin: ['http://127.0.0.1'] },
      cache_file: { enabled: true, path: cache.path, cache_id: cache.id, store_fakeip: true } });
    assert.equal(rendered.route.final, 'isp-upstream');
    assert.equal(rendered.route.rules.some(rule => rule.type === 'logical'), routingMode === 'safe-rules');
    assert.equal(rendered.route.rules.find(rule => rule.action === 'sniff').timeout, '300ms');
    assert.equal(rendered.inbounds.some(inbound => inbound.sniff_override_destination !== undefined), false);
  }
  for (const bad of [null, { ...api, port: fixture().listen.port }, { ...api, host: '0.0.0.0' }, { ...api, secret: 'short' }]) assert.throws(() => validateCoreApi(bad, fixture().listen.port), { code: 'CORE_API_INVALID' });
  for (const bad of [null, { ...cache, path: '../public.db' }, { ...cache, id: '../escape' }, { ...cache, extra: true }]) assert.throws(() => validateFakeIpCache(bad), { code: 'FAKE_IP_CACHE_INVALID' });
  assert.throws(() => buildSingBox(fixture(), secret, { mode: 'http', fakeIpCache: cache }), { code: 'FAKE_IP_CACHE_INVALID' });
  assert.throws(() => buildSingBox(fixture(), secret, { mode: 'http', routingMode: 'safe-rules' }), { code: 'ROUTING_MODE_INVALID' });
});
