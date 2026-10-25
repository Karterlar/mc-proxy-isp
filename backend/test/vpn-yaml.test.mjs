import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { parseVpnYaml, parseVpnConfig, validateVpnOutbound, vpnOutboundIdentity } from '../src/vpn-yaml.mjs';
import { vpnOutbound } from './vpn-fixture.mjs';

const publicKey = Buffer.from(Array.from({ length: 32 }, (_, index) => index + 1)).toString('base64url');
const node = () => ({ name: 'test node', type: 'vless', server: '127.0.0.1', port: 443,
  uuid: '11111111-2222-4333-8444-555555555555', network: 'tcp', tls: true, servername: 'localhost',
  flow: 'xtls-rprx-vision', 'packet-encoding': 'xudp', 'client-fingerprint': 'chrome',
  'reality-opts': { 'public-key': publicKey, 'short-id': '0123456789abcdef' }, udp: true });
const parseNodes = nodes => parseVpnYaml(JSON.stringify({ proxies: nodes }));

test('private complete outbound identity removes only exact copies and is independent of object key order', () => {
  const original = vpnOutbound();
  const reordered = Object.fromEntries(Object.entries(original).reverse());
  reordered.tls = Object.fromEntries(Object.entries(original.tls).reverse());
  assert.equal(vpnOutboundIdentity(reordered), vpnOutboundIdentity(original));
  const parsed = parseVpnConfig(JSON.stringify({ outbounds: [original, { ...reordered, tag: 'Different display name' },
    { ...original, uuid: '22222222-2222-4333-8444-555555555555' }, { ...original, tls: { ...original.tls, server_name: 'other.test' } },
    { ...original, server_port: 8443 }] }));
  assert.equal(parsed.total, 5); assert.deepEqual(parsed.nodes.map(node => node.index), [1, 3, 4, 5]);
  assert.deepEqual(parsed.duplicates, [{ index: 2, duplicateOf: 1, code: 'VPN_NODE_DUPLICATE' }]);
  assert.deepEqual(parsed.unsupported, []); assert.doesNotMatch(JSON.stringify(parsed.duplicates), /11111111|localhost|public_key|[a-f0-9]{64}/);
  assert.deepEqual(parseNodes([node(), { ...node(), name: 'Alias' }]).duplicates, parsed.duplicates);
});

test('generic import recognizes five local formats and never fetches URLs or root instructions', () => {
  const plain = 'vless://11111111-2222-4333-8444-555555555555@127.0.0.1:443?security=none&type=tcp#Test%20VLESS';
  const samples = [
    ['share-uri', plain], ['base64-subscription', Buffer.from(plain).toString('base64')],
    ['sing-box', JSON.stringify({ outbounds: [{ type: 'vless', tag: 'JSON node', server: '127.0.0.1', server_port: 443, uuid: node().uuid }], dns: { servers: ['https://PRIVATE_SUBSCRIPTION.invalid'] }, route: { final: 'direct' } })],
    ['surge-ini', '[General]\nscript=PRIVATE_SCRIPT\n[Proxy]\nINI HTTP = http, 127.0.0.1, 8080, username=fixture, password=fixture\n[Rule]\nFINAL,DIRECT'],
    ['clash-yaml', JSON.stringify({ proxies: [node()], rules: ['MATCH,DIRECT'] })],
  ];
  for (const [format, input] of samples) {
    const parsed = parseVpnConfig(input); assert.equal(parsed.format, format); assert.equal(parsed.nodes.length, 1); assert.deepEqual(parsed.unsupported, []);
    assert.equal(parsed.nodes[0].outbound.tag, 'vpn-entry'); assert.equal(parsed.nodes[0].transport, 'tcp');
    assert.doesNotMatch(JSON.stringify(parsed), /PRIVATE_SCRIPT|PRIVATE_SUBSCRIPTION|MATCH,DIRECT|route/);
  }
  const unnamed = parseVpnConfig(plain.split('#')[0]); assert.equal(unnamed.nodes[0].name, 'Node 1');
  assert.deepEqual(parseVpnConfig('https://PRIVATE_SUBSCRIPTION.invalid/config').unsupported, [{ index: 1, code: 'VPN_NODE_URI_INVALID' }]);
  assert.throws(() => parseVpnConfig(Buffer.from(Buffer.from(plain).toString('base64')).toString('base64')), { code: 'VPN_CONFIG_FORMAT_UNSUPPORTED' });
});

test('eight protocols and supported WebSocket, gRPC, HTTP upgrade and HTTP transports map to strict core fields', () => {
  const base = { name: 'Fixture', server: '127.0.0.1', port: 443 };
  const protocols = [
    { ...base, type: 'ss', cipher: 'aes-128-gcm', password: 'fixture-password' },
    { ...base, type: 'vmess', uuid: node().uuid, cipher: 'auto', alterId: 0 },
    { ...base, type: 'vless', uuid: node().uuid },
    { ...base, type: 'trojan', password: 'fixture-password', sni: 'localhost' },
    { ...base, type: 'hysteria2', password: 'fixture-password', sni: 'localhost' },
    { ...base, type: 'tuic', uuid: node().uuid, password: 'fixture-password', sni: 'localhost', 'congestion-controller': 'bbr' },
    { ...base, type: 'http', username: 'fixture', password: 'fixture' },
    { ...base, type: 'socks5', username: 'fixture', password: 'fixture' },
  ];
  const parsed = parseVpnConfig(JSON.stringify({ proxies: protocols }));
  assert.deepEqual(parsed.nodes.map(item => item.protocol), ['ss', 'vmess', 'vless', 'trojan', 'hysteria2', 'tuic', 'http', 'socks']);
  assert.deepEqual(parsed.nodes.map(item => item.transport), ['tcp', 'tcp', 'tcp', 'tcp', 'quic', 'quic', 'tcp', 'tcp']);
  for (const [network, field, options, expected] of [
    ['ws', 'ws-opts', { path: '/fixture', headers: { Host: 'localhost' } }, { type: 'ws', path: '/fixture', headers: { Host: 'localhost' } }],
    ['grpc', 'grpc-opts', { 'grpc-service-name': 'fixture' }, { type: 'grpc', service_name: 'fixture' }],
    ['httpupgrade', 'http-upgrade-opts', { path: '/fixture' }, { type: 'httpupgrade', path: '/fixture' }],
    ['h2', 'h2-opts', { host: ['localhost'], path: '/fixture' }, { type: 'http', host: ['localhost'], path: '/fixture' }],
  ]) {
    const result = parseVpnConfig(JSON.stringify({ proxies: [{ ...protocols[1], network, [field]: options }] }));
    assert.equal(result.nodes.length, 1); assert.deepEqual(result.nodes[0].outbound.transport, expected);
  }
  assert.equal(validateVpnOutbound(vpnOutbound()).tls.server_name, 'localhost');
});

test('URI credentials, VMess base64, Reality and TLS identities stay private and retain explicit semantics', () => {
  const encoded = Buffer.from('aes-256-gcm:fixture-password').toString('base64url');
  const vmess = Buffer.from(JSON.stringify({ v: '2', ps: 'VMess', add: '127.0.0.1', port: '443', id: node().uuid, aid: '0', scy: 'auto', net: 'ws', type: 'none', path: '/fixture', host: 'localhost', tls: 'tls', sni: 'localhost' })).toString('base64');
  const uris = ['ss://' + encoded + '@127.0.0.1:8388#SS', 'vmess://' + vmess,
    'vless://' + node().uuid + '@127.0.0.1:443?security=reality&type=tcp&fp=chrome&pbk=' + publicKey + '&sid=0123456789abcdef&sni=localhost&flow=xtls-rprx-vision#Reality',
    'trojan://fixture-password@127.0.0.1:443?sni=localhost#Trojan',
    'hysteria2://fixture-user:fixture-password@127.0.0.1:443?sni=localhost#Hy2',
    'tuic://' + node().uuid + ':fixture-password@127.0.0.1:443?sni=localhost&congestion_control=bbr#TUIC',
    'https://fixture:fixture@localhost:443#HTTP', 'socks5://fixture:fixture@127.0.0.1:1080#SOCKS'];
  const parsed = parseVpnConfig(uris.join('\n'));
  assert.equal(parsed.nodes.length, 8); assert.deepEqual(parsed.unsupported, []);
  assert.equal(parsed.nodes[4].outbound.password, 'fixture-user:fixture-password');
  assert.equal(parsed.nodes[6].outbound.tls.server_name, 'localhost');
  assert.equal(parsed.nodes[2].outbound.tls.reality.public_key, publicKey);
  assert.deepEqual(parseVpnConfig(Buffer.from(uris.join('\n')).toString('base64')).nodes, parsed.nodes);
  assert.equal(parseVpnConfig('http://fixture:fixture@localhost:80').nodes[0].outbound.server_port, 80);
  assert.equal(parseVpnConfig('https://fixture:fixture@localhost').nodes.length, 0, 'an explicit proxy port is required');
});

test('unknown query, plugins, insecure TLS and local certificate paths are reported per-node with no values', () => {
  for (const input of [
    'vless://' + node().uuid + '@127.0.0.1:443?security=tls&insecure=1#Unsafe',
    'ss://YWVzLTEyOC1nY206Zml4dHVyZQ@127.0.0.1:8388?plugin=PRIVATE_PLUGIN',
    'http://fixture:fixture@localhost:8080?unknown=PRIVATE_QUERY',
    'vless://' + node().uuid + '@127.0.0.1:443?type=grpc&serviceName=fixture&path=PRIVATE_IGNORED_PATH',
    JSON.stringify({ outbounds: [{ ...vpnOutbound(), tls: { ...vpnOutbound().tls, certificate_path: 'PRIVATE_FILE' } }] }),
    JSON.stringify({ outbounds: [{ type: 'selector', tag: 'PRIVATE_SELECTOR', outbounds: ['direct'] }, { type: 'direct', tag: 'PRIVATE_DIRECT' }] }),
  ]) {
    const parsed = parseVpnConfig(input); assert.equal(parsed.nodes.length, 0); assert.ok(parsed.unsupported.length > 0);
    assert.doesNotMatch(JSON.stringify(parsed.unsupported), /PRIVATE_/);
  }
});

test('generic input and normalized alias expansion retain byte and node limits before returning a partial import', () => {
  const uri = 'vless://' + node().uuid + '@127.0.0.1:443?security=none';
  assert.throws(() => parseVpnConfig(Array.from({ length: 257 }, () => uri).join('\n')), { code: 'VPN_YAML_NODE_LIMIT' });
  assert.throws(() => parseVpnConfig('x'.repeat(1024 * 1024 + 1)), { code: 'VPN_YAML_SIZE_INVALID' });
  const aliases = 'proxies:\n  - &node\n    name: alias\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: aes-128-gcm\n    password: ' + 'x'.repeat(8192) + '\n' + Array.from({ length: 255 }, () => '  - *node').join('\n');
  assert.throws(() => parseVpnConfig(aliases), { code: 'VPN_YAML_SIZE_INVALID' });
  const headerAlias = 'proxies:\n  - type: vmess\n    server: 127.0.0.1\n    port: 443\n    uuid: ' + node().uuid + '\n    network: ws\n    ws-opts:\n      headers:\n        X-First: &part ' + 'x'.repeat(8192) + '\n' + Array.from({ length: 31 }, (_, index) => '        X-' + index + ': [' + Array(16).fill('*part').join(', ') + ']').join('\n');
  assert.deepEqual(parseVpnConfig(headerAlias).unsupported, [{ index: 1, code: 'VPN_NODE_TRANSPORT_UNSUPPORTED' }]);
});

test('V2Ray and Xray JSON map only one explicit peer per outbound and keep unsafe stream settings unsupported', () => {
  const entries = [
    { protocol: 'vmess', tag: 'Xray VMess', settings: { vnext: [{ address: '127.0.0.1', port: 443, users: [{ id: node().uuid, alterId: 0, security: 'auto' }] }] }, streamSettings: { network: 'ws', security: 'tls', tlsSettings: { serverName: 'localhost', allowInsecure: false }, wsSettings: { path: '/fixture' } } },
    { protocol: 'vless', settings: { vnext: [{ address: '127.0.0.1', port: 443, users: [{ id: node().uuid, encryption: 'none', flow: 'xtls-rprx-vision' }] }] }, streamSettings: { network: 'tcp', security: 'reality', realitySettings: { serverName: 'localhost', fingerprint: 'chrome', publicKey, shortId: '0123456789abcdef', show: false } } },
    { protocol: 'trojan', settings: { servers: [{ address: '127.0.0.1', port: 443, password: 'fixture' }] }, streamSettings: { network: 'grpc', security: 'tls', tlsSettings: { serverName: 'localhost' }, grpcSettings: { serviceName: 'fixture', multiMode: false } } },
    { protocol: 'shadowsocks', settings: { servers: [{ address: '127.0.0.1', port: 8388, method: 'aes-128-gcm', password: 'fixture' }] } },
  ];
  const parsed = parseVpnConfig(JSON.stringify({ outbounds: entries, routing: { rules: ['PRIVATE_IGNORED'] }, dns: { servers: ['PRIVATE_IGNORED'] } }));
  assert.equal(parsed.format, 'v2ray-json'); assert.equal(parsed.nodes.length, 4); assert.deepEqual(parsed.unsupported, []);
  assert.equal(parsed.nodes[1].name, 'Node 2'); assert.equal(parsed.nodes[1].outbound.tls.reality.public_key, publicKey);
  assert.deepEqual(parsed.nodes[0].outbound.transport, { type: 'ws', path: '/fixture' });
  assert.doesNotMatch(JSON.stringify(parsed), /PRIVATE_IGNORED|routing|dns/);
  for (const mutate of [value => { value.streamSettings.tlsSettings.allowInsecure = true; }, value => { value.streamSettings.sockopt = { mark: 1 }; }, value => { value.settings.vnext.push(value.settings.vnext[0]); }, value => { value.streamSettings.wsSettings.unknown = 'PRIVATE_VALUE'; }]) {
    const bad = structuredClone(entries[0]); mutate(bad); const result = parseVpnConfig(JSON.stringify({ outbounds: [bad] }));
    assert.equal(result.nodes.length, 0); assert.equal(result.unsupported.length, 1); assert.doesNotMatch(JSON.stringify(result.unsupported), /PRIVATE_VALUE/);
  }
});

test('normalized outbound validation reuses strict Reality mapping without accepting custom routing or TLS bypass', () => {
  const valid = parseNodes([node()]).nodes[0].outbound;
  assert.deepEqual(validateVpnOutbound(valid), valid);
  const changes = [value => { value.detour = 'direct'; }, value => { value.domain_resolver = 'local'; }, value => { value.tls.insecure = true; },
    value => { value.tls.reality.private_key = 'NEVER_LOG_SECRET'; }, value => { value.tls.utls.enabled = false; }, value => { value.network = 'udp'; }, value => { value.type = 'direct'; }];
  for (const mutate of changes) { const bad = structuredClone(valid); mutate(bad); assert.throws(() => validateVpnOutbound(bad), cause => /^VPN_NODE_/.test(cause.code) && !cause.message.includes('NEVER_LOG_SECRET')); }
});

test('Reality without an explicit uTLS fingerprint is rejected across formats without inventing a TLS strategy', () => {
  const clash = node(); delete clash['client-fingerprint'];
  const native = vpnOutbound(); delete native.tls.utls;
  assert.throws(() => validateVpnOutbound(native), { code: 'VPN_NODE_FINGERPRINT_UNSUPPORTED' });
  const inputs = [
    JSON.stringify({ proxies: [clash] }), JSON.stringify({ outbounds: [native] }),
    'vless://' + node().uuid + '@127.0.0.1:443?security=reality&pbk=' + publicKey + '&sid=0123456789abcdef&sni=localhost',
    JSON.stringify({ outbounds: [{ protocol: 'vless', settings: { vnext: [{ address: '127.0.0.1', port: 443, users: [{ id: node().uuid, encryption: 'none' }] }] },
      streamSettings: { security: 'reality', realitySettings: { serverName: 'localhost', publicKey, shortId: '0123456789abcdef' } } }] }),
  ];
  for (const input of inputs) {
    const parsed = parseVpnConfig(input);
    assert.equal(parsed.nodes.length, 0); assert.deepEqual(parsed.unsupported, [{ index: 1, code: 'VPN_NODE_FINGERPRINT_UNSUPPORTED' }]);
  }
  assert.deepEqual(validateVpnOutbound(vpnOutbound()), vpnOutbound());
});

test('Mihomo Reality fields map to a single strict TCP VLESS outbound', () => {
  const result = parseVpnYaml(`proxies:\n  - name: " test\\nnode\\u001b "\n    type: vless\n    server: 127.0.0.1\n    port: 443\n    uuid: 11111111-2222-4333-8444-555555555555\n    network: tcp\n    tls: true\n    servername: localhost\n    flow: xtls-rprx-vision\n    packet-encoding: xudp\n    client-fingerprint: chrome\n    udp: true\n    skip-cert-verify: false\n    reality-opts:\n      public-key: ${publicKey}\n      short-id: "0123456789abcdef"\n      x-label: ignored\n    x-source: ignored\n`);
  assert.equal(result.total, 1); assert.deepEqual(result.unsupported, []);
  assert.equal(result.nodes[0].index, 1); assert.equal(result.nodes[0].name, 'testnode');
  assert.deepEqual(result.nodes[0].outbound, { type: 'vless', tag: 'vpn-entry', server: '127.0.0.1', server_port: 443,
    uuid: node().uuid, network: 'tcp', flow: 'xtls-rprx-vision', packet_encoding: 'xudp',
    tls: { enabled: true, server_name: 'localhost', insecure: false, utls: { enabled: true, fingerprint: 'chrome' }, reality: { enabled: true, public_key: publicKey, short_id: '0123456789abcdef' } } });
});

test('unsupported nodes keep original one-based indices without exposing their values', () => {
  const result = parseNodes([{ ...node(), type: 'ss', password: 'PRIVATE_PASSWORD' }, node(), { ...node(), network: 'ws', 'ws-opts': { headers: { Authorization: 'PRIVATE_AUTH' } } }, { ...node(), 'skip-cert-verify': true }]);
  assert.equal(result.total, 4); assert.deepEqual(result.nodes.map(item => item.index), [2]);
  assert.deepEqual(result.unsupported, [{ index: 1, code: 'VPN_NODE_FIELD_UNSUPPORTED' }, { index: 3, code: 'VPN_NODE_FLOW_UNSUPPORTED' }, { index: 4, code: 'VPN_NODE_TLS_UNSAFE' }]);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_PASSWORD|PRIVATE_AUTH/);
});

test('unknown routing, transport, insecure TLS and malformed identity fields are never silently dropped', () => {
  for (const changes of [
    { detour: 'direct' }, { dialer: 'direct' }, { network: 'grpc' }, { tls: false }, { 'skip-cert-verify': 'false' },
    { flow: 'unknown' }, { 'packet-encoding': 'packetaddr' }, { 'client-fingerprint': 'unknown' },
    { server: 'https://credential@host' }, { port: '443' }, { port: 0 }, { port: 65536 }, { uuid: 'PRIVATE_UUID' },
    { servername: 'bad hostname' }, { udp: 'true' }, { name: {} }, { 'reality-opts': null },
    { 'reality-opts': { 'public-key': 'PRIVATE_KEY', 'short-id': '' } },
    { 'reality-opts': { 'public-key': publicKey, 'short-id': 1234 } },
    { 'reality-opts': { 'public-key': publicKey, 'short-id': 'f' } },
    { 'reality-opts': { 'public-key': publicKey, 'short-id': '0123456789abcdef00' } },
    { 'reality-opts': { 'public-key': publicKey, 'short-id': '', 'private-key': 'PRIVATE_KEY' } },
  ]) {
    const result = parseNodes([{ ...node(), ...changes }]);
    assert.equal(result.nodes.length, 0); assert.equal(result.unsupported.length, 1);
    assert.doesNotMatch(JSON.stringify(result), /PRIVATE_|credential|direct/);
  }
});

test('root rules, DNS, subscriptions and metadata are not executed or copied', () => {
  const input = { proxies: [node()], rules: ['MATCH,DIRECT'], dns: { nameserver: ['https://PRIVATE_TOKEN.invalid'] },
    'proxy-providers': { remote: { url: 'https://PRIVATE_TOKEN.invalid', path: 'private' } } };
  const result = parseVpnYaml(JSON.stringify(input));
  assert.deepEqual(result, parseNodes([node()]));
  assert.equal(Object.keys(result.nodes[0].outbound).includes('dns'), false);
});

test('JSON schema rejects executable tags, duplicate keys and multiple documents with sanitized errors', () => {
  for (const text of [
    'proxies: !!js/function "function(){return PRIVATE_TOKEN}"',
    'proxies: []\nproxies: PRIVATE_TOKEN',
    'proxies: []\n---\nPRIVATE_TOKEN',
    'proxies: [ PRIVATE_TOKEN',
    'proxies: [ {type: vless, type: PRIVATE_TOKEN} ]',
  ]) assert.throws(() => parseVpnYaml(text), error => error.code === 'VPN_YAML_INVALID' && !error.message.includes('PRIVATE_TOKEN') && error.cause === undefined);
  assert.equal(parseVpnYaml('proxies: []').total, 0);
  for (const text of ['', '{}', 'proxies: {}', '- type: vless']) assert.throws(() => parseVpnYaml(text), { code: 'VPN_YAML_PROXIES_INVALID' });
});

test('byte and node limits are enforced before returning any partial result', () => {
  assert.throws(() => parseVpnYaml(null), { code: 'VPN_YAML_SIZE_INVALID' });
  assert.throws(() => parseVpnYaml(`proxies: []\n#${'字'.repeat(350000)}`), { code: 'VPN_YAML_SIZE_INVALID' });
  assert.throws(() => parseNodes(Array.from({ length: 257 }, node)), { code: 'VPN_YAML_NODE_LIMIT' });
  const bounded = parseNodes(Array.from({ length: 256 }, node));
  assert.equal(bounded.total, 256); assert.equal(bounded.nodes.length, 1); assert.equal(bounded.duplicates.length, 255);
  const missingName = node(); delete missingName.name; delete missingName.network; delete missingName.flow; delete missingName['packet-encoding'];
  assert.equal(parseNodes([missingName]).nodes[0].name, 'Node 1');
});

test('pinned sing-box 1.14.2 accepts converted synthetic Reality fields without opening an interface', { skip: process.platform !== 'win32' }, async t => {
  const binary = path.resolve(import.meta.dirname, '../.cache/core/sing-box-1.14.2-windows-amd64/sing-box.exe');
  const directory = await mkdtemp(path.resolve(import.meta.dirname, '.vpn-yaml-core-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  assert.match(spawnSync(binary, ['version'], { windowsHide: true, encoding: 'utf8' }).stdout, /sing-box version 1\.14\.2(?:\s|$)/);
  for (const fingerprint of ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized']) {
    const outbound = parseNodes([{ ...node(), 'client-fingerprint': fingerprint }]).nodes[0].outbound;
    const file = path.join(directory, 'core.json');
    await writeFile(file, JSON.stringify({ log: { disabled: true }, inbounds: [{ type: 'http', listen: '127.0.0.1', listen_port: 17890 }], outbounds: [outbound], route: { final: 'vpn-entry' } }));
    const checked = spawnSync(binary, ['check', '-c', file], { windowsHide: true, encoding: 'utf8' });
    assert.equal(checked.status, 0, `Pinned core must accept the synthetic ${fingerprint} mapping`);
  }
  const noFingerprint = vpnOutbound(); delete noFingerprint.tls.utls;
  const file = path.join(directory, 'missing-fingerprint.json');
  await writeFile(file, JSON.stringify({ log: { disabled: true }, inbounds: [{ type: 'http', listen: '127.0.0.1', listen_port: 17890 }], outbounds: [noFingerprint], route: { final: 'vpn-entry' } }));
  const rejected = spawnSync(binary, ['check', '-c', file], { windowsHide: true, encoding: 'utf8' });
  assert.notEqual(rejected.status, 0, 'Pinned core must reject Reality without uTLS');
  assert.ok(/[Uu][Tt][Ll][Ss].*(required|missing|need)|require.*[Uu][Tt][Ll][Ss]/.test(rejected.stderr || ''), 'Pinned core reports the uTLS requirement');
});
