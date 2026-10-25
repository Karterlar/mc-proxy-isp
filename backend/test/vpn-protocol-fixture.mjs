// Synthetic loopback credentials only. Never import a user's subscription here.
export const fixtureUuid = '11111111-2222-4333-8444-555555555555';
export const fixturePassword = 'synthetic-vpn-password';
export const fixtureTls = { enabled: true, server_name: 'localhost', insecure: false };
const base = { tag: 'vpn-entry', server: '127.0.0.1', server_port: 443 };
export const nativeProtocolShapes = [
  ['ss-aes128', { type: 'shadowsocks', ...base, method: 'aes-128-gcm', password: fixturePassword, network: 'tcp' }],
  ['ss-chacha', { type: 'shadowsocks', ...base, method: 'chacha20-ietf-poly1305', password: fixturePassword, network: 'tcp' }],
  ['ss-2022', { type: 'shadowsocks', ...base, method: '2022-blake3-aes-128-gcm', password: Buffer.alloc(16, 7).toString('base64'), network: 'tcp' }],
  ['vmess', { type: 'vmess', ...base, uuid: fixtureUuid, security: 'auto', alter_id: 0, network: 'tcp' }],
  ['vless', { type: 'vless', ...base, uuid: fixtureUuid, network: 'tcp', tls: fixtureTls }],
  ['trojan', { type: 'trojan', ...base, password: fixturePassword, network: 'tcp', tls: fixtureTls }],
  ['hysteria2', { type: 'hysteria2', ...base, password: fixturePassword, network: 'tcp', tls: fixtureTls }],
  ['tuic', { type: 'tuic', ...base, uuid: fixtureUuid, password: fixturePassword, congestion_control: 'bbr', network: 'tcp', tls: fixtureTls }],
  ['http', { type: 'http', ...base, username: 'fixture-user', password: fixturePassword }],
  ['socks', { type: 'socks', ...base, version: '5', username: 'fixture-user', password: fixturePassword, network: 'tcp' }],
];
for (const type of ['vmess', 'vless', 'trojan']) {
  for (const transport of [
    { type: 'ws', path: '/fixture' }, { type: 'grpc', service_name: 'fixture' },
    { type: 'httpupgrade', path: '/fixture' }, { type: 'http', host: ['localhost'], path: '/fixture' },
  ]) nativeProtocolShapes.push([`${type}-${transport.type}`, { ...nativeProtocolShapes.find(([, node]) => node.type === type)[1], transport }]);
}

export const liveProtocolCases = [
  { label: 'ss', type: 'shadowsocks', node: { type: 'ss', cipher: 'aes-128-gcm', password: fixturePassword } },
  { label: 'vmess', type: 'vmess', node: { type: 'vmess', uuid: fixtureUuid, alterId: 0, cipher: 'auto' } },
  { label: 'vmess-ws', type: 'vmess', node: { type: 'vmess', uuid: fixtureUuid, alterId: 0, cipher: 'auto', network: 'ws', 'ws-opts': { path: '/fixture' } }, transport: { type: 'ws', path: '/fixture' } },
  { label: 'trojan', type: 'trojan', node: { type: 'trojan', password: fixturePassword, tls: true, sni: 'localhost' } },
];
