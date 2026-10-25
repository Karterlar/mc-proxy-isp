import { parseVpnYaml } from '../src/vpn-yaml.mjs';

export const vpnYamlNode = (changes = {}) => ({ name: 'Imported test node', type: 'vless', server: 'vpn.private.invalid', port: 443,
  uuid: '11111111-2222-4333-8444-555555555555', network: 'tcp', tls: true, servername: 'localhost', flow: 'xtls-rprx-vision',
  'packet-encoding': 'xudp', 'client-fingerprint': 'chrome', 'reality-opts': { 'public-key': Buffer.alloc(32, 7).toString('base64url'), 'short-id': '0123456789abcdef' }, ...changes });
export const vpnOutbound = (changes = {}) => parseVpnYaml(JSON.stringify({ proxies: [vpnYamlNode(changes)] })).nodes[0].outbound;
