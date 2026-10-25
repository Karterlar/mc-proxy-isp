import { load, JSON_SCHEMA } from 'js-yaml';
import { createHash } from 'node:crypto';
import { UserError, validHost } from './config.mjs';

const fail = code => { throw new UserError(code, 'VPN input contains an invalid or unsupported configuration'); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, allowed) => object(value) && Object.keys(value).every(key => allowed.includes(key));
const keys = (value, allowed) => object(value) && Object.keys(value).every(key => allowed.includes(key) || key.startsWith('x-'));
const text = (value, max = 8192) => typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f-\u009f]/.test(value);
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(value);
const fingerprints = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq', 'random', 'randomized'];
const methods = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'];
const securities = ['auto', 'none', 'zero', 'aes-128-gcm', 'chacha20-poly1305'];
const cleanName = (value, index) => {
  if (value !== undefined && (typeof value !== 'string' || value.length > 1024)) fail('VPN_NODE_INVALID');
  return (value || '').replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, '').trim().slice(0, 120) || 'Node ' + index;
};
const number = value => typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
const list = value => Array.isArray(value) ? value : typeof value === 'string' ? value.split(',').map(item => item.trim()) : value;
const duration = value => typeof value === 'string' && /^\d{1,5}(?:\.\d{1,3})?(?:ms|s|m)$/.test(value);
export const VPN_NODE_ERROR_CODES = Object.freeze(['VPN_NODE_INVALID', 'VPN_NODE_TYPE_UNSUPPORTED', 'VPN_NODE_FIELD_UNSUPPORTED', 'VPN_NODE_TRANSPORT_UNSUPPORTED', 'VPN_NODE_TLS_UNSAFE', 'VPN_NODE_FLOW_UNSUPPORTED', 'VPN_NODE_PACKET_ENCODING_UNSUPPORTED', 'VPN_NODE_FINGERPRINT_UNSUPPORTED', 'VPN_NODE_REALITY_INVALID', 'VPN_NODE_METHOD_UNSUPPORTED', 'VPN_NODE_PLUGIN_UNSUPPORTED', 'VPN_NODE_URI_INVALID']);
export function vpnNodeMetadata(outbound) {
  return { protocol: outbound.type === 'shadowsocks' ? 'ss' : outbound.type, transport: ['hysteria2', 'tuic'].includes(outbound.type) ? 'quic' : outbound.transport?.type || 'tcp' };
}
// Private identity includes credentials, TLS and transport; never deduplicate by server alone.
export function vpnOutboundIdentity(outbound) {
  const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
  return createHash('sha256').update(JSON.stringify(canonical(outbound))).digest('hex');
}
export function deduplicateVpnNodes(nodes) {
  const identities = new Map(), unique = [], duplicates = [];
  for (const node of [...nodes].sort((a, b) => a.index - b.index)) {
    const identity = vpnOutboundIdentity(node.outbound);
    if (identities.has(identity)) duplicates.push({ index: node.index, duplicateOf: identities.get(identity), code: 'VPN_NODE_DUPLICATE' });
    else { identities.set(identity, node.index); unique.push(node); }
  }
  return { nodes: unique, duplicates };
}
function headers(value) {
  if (!object(value) || Object.keys(value).length > 32 || Object.entries(value).some(([key, item]) => !/^[A-Za-z0-9!#$%&'*+.^_\x60|~-]{1,80}$/.test(key) || !(text(item) || Array.isArray(item) && item.length <= 16 && item.every(part => text(part)))) || Buffer.byteLength(JSON.stringify(value), 'utf8') > 32768) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
}
function validateTls(value, type) {
  if (!exact(value, ['enabled', 'server_name', 'insecure', 'alpn', 'min_version', 'max_version', 'utls', 'reality', 'certificate']) || value.enabled !== true || value.insecure !== false || !validHost(value.server_name)) fail('VPN_NODE_TLS_UNSAFE');
  if (value.alpn !== undefined && (!Array.isArray(value.alpn) || value.alpn.length > 16 || !value.alpn.length || value.alpn.some(item => !text(item, 255)))) fail('VPN_NODE_TLS_UNSAFE');
  for (const key of ['min_version', 'max_version']) if (value[key] !== undefined && !['1.2', '1.3'].includes(value[key])) fail('VPN_NODE_TLS_UNSAFE');
  if (value.certificate !== undefined && (!Array.isArray(value.certificate) || !value.certificate.length || value.certificate.length > 8 || value.certificate.some(item => typeof item !== 'string' || item.length > 16384 || !/^\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*$/.test(item)))) fail('VPN_NODE_TLS_UNSAFE');
  if (value.utls !== undefined && (!exact(value.utls, ['enabled', 'fingerprint']) || value.utls.enabled !== true || !fingerprints.includes(value.utls.fingerprint) || ['hysteria2', 'tuic', 'socks', 'shadowsocks'].includes(type))) fail('VPN_NODE_FINGERPRINT_UNSUPPORTED');
  if (value.reality !== undefined) {
    const reality = value.reality;
    if (type !== 'vless' || !exact(reality, ['enabled', 'public_key', 'short_id']) || reality.enabled !== true || typeof reality.public_key !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(reality.public_key) || Buffer.from(reality.public_key, 'base64url').toString('base64url') !== reality.public_key || typeof reality.short_id !== 'string' || !/^(?:[a-f0-9]{2}){0,8}$/i.test(reality.short_id)) fail('VPN_NODE_REALITY_INVALID');
    if (value.utls === undefined) fail('VPN_NODE_FINGERPRINT_UNSUPPORTED');
  }
}
function validateTransport(value) {
  const allowed = {
    ws: ['type', 'path', 'headers', 'max_early_data', 'early_data_header_name'],
    grpc: ['type', 'service_name', 'idle_timeout', 'ping_timeout', 'permit_without_stream'],
    httpupgrade: ['type', 'host', 'path', 'headers'],
    http: ['type', 'host', 'path', 'method', 'headers', 'idle_timeout', 'ping_timeout'],
  };
  if (!allowed[value?.type] || !exact(value, allowed[value.type])) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  if (value.path !== undefined && (!text(value.path, 2048) || !value.path.startsWith('/'))) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  if (value.host !== undefined && !(value.type === 'http' ? Array.isArray(value.host) && value.host.length > 0 && value.host.length <= 16 && value.host.every(validHost) : validHost(value.host))) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  if (value.headers !== undefined) headers(value.headers);
  if (value.service_name !== undefined && !text(value.service_name, 512)) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  if (value.method !== undefined && !/^[A-Z]{1,20}$/.test(value.method)) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  for (const key of ['idle_timeout', 'ping_timeout']) if (value[key] !== undefined && !duration(value[key])) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  if (value.permit_without_stream !== undefined && typeof value.permit_without_stream !== 'boolean') fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  if (value.max_early_data !== undefined && (!Number.isInteger(value.max_early_data) || value.max_early_data < 0 || value.max_early_data > 65536)) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  if (value.early_data_header_name !== undefined && !/^[A-Za-z0-9-]{1,80}$/.test(value.early_data_header_name)) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
}

// No detour, selector, resolver, external file, or executable option is accepted.
// Preserve validated property order so previously saved Reality hashes stay stable.
export function validateVpnOutbound(value) {
  const specific = {
    shadowsocks: ['method', 'password'], vmess: ['uuid', 'security', 'alter_id', 'packet_encoding'],
    vless: ['uuid', 'flow', 'packet_encoding'], trojan: ['password'],
    hysteria2: ['password', 'obfs', 'up_mbps', 'down_mbps'],
    tuic: ['uuid', 'password', 'congestion_control', 'udp_relay_mode', 'zero_rtt_handshake', 'heartbeat'],
    http: ['username', 'password'], socks: ['version', 'username', 'password'],
  };
  if (!specific[value?.type]) fail('VPN_NODE_TYPE_UNSUPPORTED');
  if (!exact(value, ['type', 'tag', 'server', 'server_port', 'network', 'tls', 'transport', 'connect_timeout', ...specific[value.type]])) fail('VPN_NODE_FIELD_UNSUPPORTED');
  if (value.tag !== 'vpn-entry' || !validHost(value.server) || !Number.isInteger(value.server_port) || value.server_port < 1 || value.server_port > 65535 || value.network !== undefined && value.network !== 'tcp' || value.connect_timeout !== undefined && !duration(value.connect_timeout)) fail('VPN_NODE_INVALID');
  if (['vmess', 'vless', 'tuic'].includes(value.type) && !uuid(value.uuid)) fail('VPN_NODE_INVALID');
  if (['shadowsocks', 'trojan', 'hysteria2', 'tuic'].includes(value.type) && !text(value.password)) fail('VPN_NODE_INVALID');
  if (value.type === 'shadowsocks') {
    if (!methods.includes(value.method)) fail('VPN_NODE_METHOD_UNSUPPORTED');
    if (value.method.startsWith('2022-')) {
      const length = value.method.includes('aes-128') ? 16 : 32;
      if (value.password.split(':').some(key => !/^[A-Za-z0-9+/]+={0,2}$/.test(key) || Buffer.from(key, 'base64').length !== length || Buffer.from(key, 'base64').toString('base64') !== key)) fail('VPN_NODE_INVALID');
    }
  }
  if (value.type === 'vmess' && (value.security !== undefined && !securities.includes(value.security) || value.alter_id !== undefined && (!Number.isInteger(value.alter_id) || value.alter_id < 0 || value.alter_id > 65535))) fail('VPN_NODE_INVALID');
  if (value.flow !== undefined && (value.flow !== 'xtls-rprx-vision' || !value.tls || value.transport)) fail('VPN_NODE_FLOW_UNSUPPORTED');
  if (value.packet_encoding !== undefined && value.packet_encoding !== 'xudp') fail('VPN_NODE_PACKET_ENCODING_UNSUPPORTED');
  if (value.tls !== undefined) { if (['shadowsocks', 'socks'].includes(value.type)) fail('VPN_NODE_TLS_UNSAFE'); validateTls(value.tls, value.type); }
  if (['hysteria2', 'tuic'].includes(value.type) && !value.tls) fail('VPN_NODE_TLS_UNSAFE');
  if (value.transport !== undefined) { if (!['vmess', 'vless', 'trojan'].includes(value.type)) fail('VPN_NODE_TRANSPORT_UNSUPPORTED'); validateTransport(value.transport); }
  if (['http', 'socks'].includes(value.type)) {
    if (value.username !== undefined && !text(value.username) || value.password !== undefined && !text(value.password) || Boolean(value.username) !== Boolean(value.password)) fail('VPN_NODE_INVALID');
    if (value.type === 'http' && value.username?.includes(':')) fail('VPN_NODE_INVALID');
    if (value.type === 'socks' && (value.version !== undefined && value.version !== '5' || [value.username, value.password].some(item => item && Buffer.byteLength(item) > 255))) fail('VPN_NODE_INVALID');
  }
  if (value.obfs !== undefined && (!exact(value.obfs, ['type', 'password']) || value.obfs.type !== 'salamander' || !text(value.obfs.password))) fail('VPN_NODE_FIELD_UNSUPPORTED');
  for (const key of ['up_mbps', 'down_mbps']) if (value[key] !== undefined && (!Number.isInteger(value[key]) || value[key] < 1 || value[key] > 100000)) fail('VPN_NODE_INVALID');
  if (value.congestion_control !== undefined && !['bbr', 'cubic', 'new_reno'].includes(value.congestion_control)) fail('VPN_NODE_INVALID');
  if (value.udp_relay_mode !== undefined && !['native', 'quic'].includes(value.udp_relay_mode)) fail('VPN_NODE_INVALID');
  if (value.zero_rtt_handshake !== undefined && typeof value.zero_rtt_handshake !== 'boolean' || value.heartbeat !== undefined && !duration(value.heartbeat)) fail('VPN_NODE_INVALID');
  return structuredClone(value);
}

const commonFields = ['name', 'type', 'server', 'port', 'network', 'tls', 'servername', 'sni', 'server-name', 'udp', 'skip-cert-verify', 'client-fingerprint', 'alpn', 'reality-opts', 'ws-opts', 'grpc-opts', 'http-opts', 'h2-opts', 'http-upgrade-opts'];
function clashTls(node, type) {
  if (node['skip-cert-verify'] !== undefined && node['skip-cert-verify'] !== false) fail('VPN_NODE_TLS_UNSAFE');
  if (node.tls !== undefined && typeof node.tls !== 'boolean') fail('VPN_NODE_TLS_UNSAFE');
  const enabled = node.tls === true || node.tls === undefined && ['trojan', 'hysteria2', 'hy2', 'tuic', 'https'].includes(type);
  if (!enabled) {
    if (node['reality-opts'] || node['client-fingerprint'] || node.alpn || node.servername || node.sni || node['server-name']) fail('VPN_NODE_TLS_UNSAFE');
    return undefined;
  }
  const identities = [node.servername, node.sni, node['server-name']].filter(value => value !== undefined);
  if (identities.some(value => value !== identities[0])) fail('VPN_NODE_TLS_UNSAFE');
  const tls = { enabled: true, server_name: identities[0] || node.server, insecure: false };
  if (node.alpn !== undefined) tls.alpn = list(node.alpn);
  if (node['client-fingerprint'] !== undefined) tls.utls = { enabled: true, fingerprint: node['client-fingerprint'] };
  if (node['reality-opts'] !== undefined) {
    const reality = node['reality-opts'];
    if (!keys(reality, ['public-key', 'short-id'])) fail('VPN_NODE_REALITY_INVALID');
    tls.reality = { enabled: true, public_key: reality['public-key'], short_id: reality['short-id'] };
  }
  return tls;
}
function clashTransport(node) {
  const network = node.network || 'tcp';
  const optionFields = { ws: 'ws-opts', grpc: 'grpc-opts', http: 'http-opts', h2: 'h2-opts', httpupgrade: 'http-upgrade-opts' };
  for (const field of Object.values(optionFields)) if (node[field] !== undefined && field !== optionFields[network]) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  if (network === 'tcp') return undefined;
  if (!optionFields[network]) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  const options = node[optionFields[network]] || {};
  const allowed = network === 'grpc' ? ['grpc-service-name'] : ['path', 'headers', 'host', ...(network === 'ws' ? ['max-early-data', 'early-data-header-name'] : [])];
  if (!keys(options, allowed)) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  const transport = { type: network === 'h2' ? 'http' : network };
  if (network === 'grpc') { if (options['grpc-service-name'] !== undefined) transport.service_name = options['grpc-service-name']; }
  else {
    if (options.path !== undefined) transport.path = Array.isArray(options.path) && options.path.length === 1 ? options.path[0] : options.path;
    if (options.headers !== undefined) { headers(options.headers); transport.headers = structuredClone(options.headers); }
    if (options.host !== undefined) transport.host = transport.type === 'http' ? list(options.host) : options.host;
    if (options['max-early-data'] !== undefined) transport.max_early_data = options['max-early-data'];
    if (options['early-data-header-name'] !== undefined) transport.early_data_header_name = options['early-data-header-name'];
  }
  return transport;
}
function normalizeClash(node) {
  if (!object(node)) fail('VPN_NODE_INVALID');
  const type = { ss: 'shadowsocks', socks5: 'socks', https: 'http', hy2: 'hysteria2' }[node.type] || node.type;
  const specific = { shadowsocks: ['cipher', 'password'], vmess: ['uuid', 'alterId', 'cipher', 'packet-encoding'], vless: ['uuid', 'flow', 'packet-encoding'], trojan: ['password'], hysteria2: ['password', 'obfs', 'obfs-password', 'up', 'down'], tuic: ['uuid', 'password', 'congestion-controller', 'udp-relay-mode', 'reduce-rtt', 'heartbeat-interval'], http: ['username', 'password'], socks: ['username', 'password'] };
  if (!specific[type]) fail('VPN_NODE_TYPE_UNSUPPORTED');
  if (node.plugin !== undefined || node['plugin-opts'] !== undefined) fail('VPN_NODE_PLUGIN_UNSUPPORTED');
  if (!keys(node, [...commonFields, ...specific[type]])) fail('VPN_NODE_FIELD_UNSUPPORTED');
  if (!Number.isInteger(node.port) || node.port < 1 || node.port > 65535 || node.udp !== undefined && typeof node.udp !== 'boolean') fail('VPN_NODE_INVALID');
  const outbound = { type, tag: 'vpn-entry', server: node.server, server_port: node.port };
  if (['vmess', 'vless', 'tuic'].includes(type)) outbound.uuid = node.uuid;
  if (['shadowsocks', 'trojan', 'hysteria2', 'tuic'].includes(type)) outbound.password = node.password;
  if (type === 'shadowsocks') outbound.method = node.cipher;
  if (type === 'vmess') { outbound.security = node.cipher || 'auto'; outbound.alter_id = node.alterId ?? 0; }
  if (type === 'socks') outbound.version = '5';
  if (['http', 'socks'].includes(type)) for (const key of ['username', 'password']) if (node[key] !== undefined && node[key] !== '') outbound[key] = node[key];
  if (type !== 'http') outbound.network = 'tcp';
  if (node.flow !== undefined) outbound.flow = node.flow;
  if (node['packet-encoding'] !== undefined) outbound.packet_encoding = node['packet-encoding'];
  const tls = clashTls(node, node.type); if (tls) outbound.tls = tls;
  const transport = clashTransport(node); if (transport) outbound.transport = transport;
  if (type === 'hysteria2') {
    if (node.obfs !== undefined || node['obfs-password'] !== undefined) outbound.obfs = { type: node.obfs, password: node['obfs-password'] };
    for (const [source, key] of [['up', 'up_mbps'], ['down', 'down_mbps']]) if (node[source] !== undefined) outbound[key] = typeof node[source] === 'string' && /^\d+\s*Mbps$/i.test(node[source]) ? Number(node[source].replace(/\s*Mbps$/i, '')) : node[source];
  }
  if (type === 'tuic') for (const [source, key] of [['congestion-controller', 'congestion_control'], ['udp-relay-mode', 'udp_relay_mode'], ['reduce-rtt', 'zero_rtt_handshake'], ['heartbeat-interval', 'heartbeat']]) if (node[source] !== undefined) outbound[key] = node[source];
  return validateVpnOutbound(outbound);
}

function checkSize(input) { if (typeof input !== 'string' || Buffer.byteLength(input, 'utf8') > 1024 * 1024) fail('VPN_YAML_SIZE_INVALID'); }
function collect(values, normalize, format) {
  if (values.length > 256) fail('VPN_YAML_NODE_LIMIT');
  const nodes = []; const unsupported = []; let normalizedBytes = 0;
  for (const [offset, value] of values.entries()) {
    const index = offset + 1;
    let node;
    try { const { name, outbound } = normalize(value, index); node = { index, name: cleanName(name, index), ...vpnNodeMetadata(outbound), outbound }; }
    catch (cause) { unsupported.push({ index, code: VPN_NODE_ERROR_CODES.includes(cause?.code) ? cause.code : 'VPN_NODE_INVALID' }); continue; }
    normalizedBytes += Buffer.byteLength(JSON.stringify(node), 'utf8');
    if (normalizedBytes > 1024 * 1024) fail('VPN_YAML_SIZE_INVALID');
    nodes.push(node);
  }
  return { format, total: values.length, ...deduplicateVpnNodes(nodes), unsupported };
}
function yamlDocument(input) {
  try { return load(input, { schema: JSON_SCHEMA, json: false }); } catch { fail('VPN_YAML_INVALID'); }
}
// Existing consumers keep their original result shape and original node hashes.
export function parseVpnYaml(input) {
  checkSize(input); const document = yamlDocument(input);
  if (!object(document) || !Object.hasOwn(document, 'proxies') || !Array.isArray(document.proxies)) fail('VPN_YAML_PROXIES_INVALID');
  const result = collect(document.proxies, node => ({ name: node?.name, outbound: normalizeClash(node) }), 'clash-yaml');
  return { total: result.total, nodes: result.nodes.map(({ index, name, outbound }) => ({ index, name, outbound })), unsupported: result.unsupported, duplicates: result.duplicates };
}

function decode64(input) {
  const cleaned = input.replace(/\s+/g, '');
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(cleaned) || cleaned.replace(/=/g, '').length % 4 === 1) fail('VPN_NODE_URI_INVALID');
  const bytes = Buffer.from(cleaned, 'base64');
  if (bytes.toString('base64url') !== cleaned.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_') || bytes.length > 1024 * 1024) fail('VPN_NODE_URI_INVALID');
  const decoded = bytes.toString('utf8'); if (!Buffer.from(decoded).equals(bytes)) fail('VPN_NODE_URI_INVALID'); return decoded;
}
const decode = input => { try { return decodeURIComponent(input); } catch { fail('VPN_NODE_URI_INVALID'); } };
function normalizeUri(input) {
  if (!text(input, 1024 * 1024)) fail('VPN_NODE_URI_INVALID');
  if (input.startsWith('vmess://')) {
    let entry; try { entry = JSON.parse(decode64(input.slice(8))); } catch { fail('VPN_NODE_URI_INVALID'); }
    if (!exact(entry, ['v', 'ps', 'add', 'port', 'id', 'aid', 'scy', 'net', 'type', 'host', 'path', 'tls', 'sni', 'alpn', 'fp', 'allowInsecure'])) fail('VPN_NODE_FIELD_UNSUPPORTED');
    if (entry.v !== undefined && ![2, '2'].includes(entry.v) || entry.type !== undefined && !['', 'none'].includes(entry.type) || entry.allowInsecure !== undefined && ![false, 0, '0', 'false'].includes(entry.allowInsecure) || entry.tls !== undefined && !['', 'tls', 'none'].includes(entry.tls)) fail('VPN_NODE_TLS_UNSAFE');
    const node = { type: 'vmess', name: entry.ps, server: entry.add, port: number(entry.port), uuid: entry.id, alterId: number(entry.aid ?? 0), cipher: entry.scy || 'auto', network: entry.net || 'tcp', tls: entry.tls === 'tls' };
    if (entry.tls === 'tls') { if (entry.sni) node.sni = entry.sni; if (entry.fp) node['client-fingerprint'] = entry.fp; if (entry.alpn) node.alpn = list(entry.alpn); }
    else if (entry.sni || entry.fp || entry.alpn) fail('VPN_NODE_TLS_UNSAFE');
    uriTransport(node, entry.path, entry.host); return { name: node.name, outbound: normalizeClash(node) };
  }
  let source = input;
  if (source.startsWith('ss://') && !source.slice(5).split('#')[0].includes('@')) source = 'ss://' + decode64(source.slice(5).split('#')[0]) + (source.includes('#') ? '#' + source.split('#').slice(1).join('#') : '');
  let url; try { url = new URL(source); } catch { fail('VPN_NODE_URI_INVALID'); }
  const type = { 'ss:': 'ss', 'vless:': 'vless', 'trojan:': 'trojan', 'hy2:': 'hysteria2', 'hysteria2:': 'hysteria2', 'tuic:': 'tuic', 'http:': 'http', 'https:': 'https', 'socks:': 'socks5', 'socks5:': 'socks5' }[url.protocol];
  if (!type) fail('VPN_NODE_TYPE_UNSUPPORTED');
  const declaredPort = url.port || source.match(/\/\/(?:[^/?#]*@)?(?:\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?#]|$)/)?.[1];
  if (!declaredPort || url.pathname && url.pathname !== '/') fail('VPN_NODE_URI_INVALID');
  const allowed = ['security', 'type', 'sni', 'servername', 'peer', 'fp', 'alpn', 'allowInsecure', 'insecure', 'allow-insecure', 'encryption', 'flow', 'packetEncoding', 'pbk', 'sid', 'path', 'host', 'serviceName', 'obfs', 'obfs-password', 'upmbps', 'downmbps', 'congestion_control', 'udp_relay_mode', 'reduce_rtt', 'heartbeat'];
  if ([...url.searchParams.keys()].some(key => key === 'plugin')) fail('VPN_NODE_PLUGIN_UNSUPPORTED');
  if ([...url.searchParams.keys()].some(key => !allowed.includes(key)) || new Set(url.searchParams.keys()).size !== [...url.searchParams.keys()].length) fail('VPN_NODE_FIELD_UNSUPPORTED');
  const get = key => url.searchParams.get(key);
  for (const key of ['allowInsecure', 'insecure', 'allow-insecure']) if (get(key) !== null && !['0', 'false'].includes(get(key))) fail('VPN_NODE_TLS_UNSAFE');
  const node = { type, name: url.hash ? decode(url.hash.slice(1)) : undefined, server: url.hostname.replace(/^\[|\]$/g, ''), port: number(declaredPort), network: get('type') || 'tcp' };
  const user = decode(url.username); const password = decode(url.password);
  if (type === 'ss') {
    if (url.search) fail('VPN_NODE_FIELD_UNSUPPORTED');
    const credentials = password ? user + ':' + password : decode64(user); const colon = credentials.indexOf(':');
    if (colon < 1) fail('VPN_NODE_URI_INVALID'); node.cipher = credentials.slice(0, colon); node.password = credentials.slice(colon + 1);
  } else if (['vless', 'tuic'].includes(type)) { node.uuid = user; if (type === 'tuic') node.password = password; else if (password) fail('VPN_NODE_URI_INVALID'); }
  else if (['trojan', 'hysteria2'].includes(type)) { if (password && type === 'trojan') fail('VPN_NODE_URI_INVALID'); node.password = password ? user + ':' + password : user; }
  else { if (user) node.username = user; if (password) node.password = password; }
  const defaultTls = ['trojan', 'hysteria2', 'tuic', 'https'].includes(type);
  const security = get('security') || (defaultTls ? 'tls' : 'none');
  if (!['none', 'tls', 'reality'].includes(security)) fail('VPN_NODE_TLS_UNSAFE');
  node.tls = security !== 'none';
  const identities = [get('sni'), get('servername'), get('peer')].filter(item => item !== null);
  if (identities.some(item => item !== identities[0])) fail('VPN_NODE_TLS_UNSAFE');
  if (identities.length) node.sni = identities[0]; if (get('fp')) node['client-fingerprint'] = get('fp'); if (get('alpn')) node.alpn = list(get('alpn'));
  if (get('encryption') !== null && (type !== 'vless' || get('encryption') !== 'none')) fail('VPN_NODE_FIELD_UNSUPPORTED');
  if (get('flow') !== null) { if (type !== 'vless') fail('VPN_NODE_FLOW_UNSUPPORTED'); node.flow = get('flow'); }
  if (get('packetEncoding') !== null) { if (type !== 'vless') fail('VPN_NODE_PACKET_ENCODING_UNSUPPORTED'); node['packet-encoding'] = get('packetEncoding'); }
  if (security === 'reality') node['reality-opts'] = { 'public-key': get('pbk'), 'short-id': get('sid') ?? '' };
  else if (get('pbk') !== null || get('sid') !== null) fail('VPN_NODE_REALITY_INVALID');
  uriTransport(node, get('path'), get('host'), get('serviceName'));
  for (const key of ['obfs', 'obfs-password', 'upmbps', 'downmbps']) if (get(key) !== null) {
    if (type !== 'hysteria2') fail('VPN_NODE_FIELD_UNSUPPORTED'); node[{ upmbps: 'up', downmbps: 'down' }[key] || key] = key.endsWith('mbps') ? number(get(key)) : get(key);
  }
  for (const key of ['congestion_control', 'udp_relay_mode', 'reduce_rtt', 'heartbeat']) if (get(key) !== null) {
    if (type !== 'tuic') fail('VPN_NODE_FIELD_UNSUPPORTED');
    if (key === 'reduce_rtt' && !['0', '1', 'false', 'true'].includes(get(key))) fail('VPN_NODE_INVALID');
    node[{ congestion_control: 'congestion-controller', udp_relay_mode: 'udp-relay-mode', reduce_rtt: 'reduce-rtt', heartbeat: 'heartbeat-interval' }[key]] = key === 'reduce_rtt' ? ['1', 'true'].includes(get(key)) : get(key);
  }
  return { name: node.name, outbound: normalizeClash(node) };
}
function uriTransport(node, path, host, serviceName) {
  if (node.network === 'tcp') { if (path || host || serviceName) fail('VPN_NODE_TRANSPORT_UNSUPPORTED'); return; }
  if (node.network === 'grpc') { if (host || path && serviceName && path !== serviceName) fail('VPN_NODE_TRANSPORT_UNSUPPORTED'); node['grpc-opts'] = { ...(serviceName || path ? { 'grpc-service-name': serviceName || path } : {}) }; return; }
  if (serviceName) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  const field = { ws: 'ws-opts', http: 'http-opts', h2: 'h2-opts', httpupgrade: 'http-upgrade-opts' }[node.network];
  if (!field) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  node[field] = { ...(path ? { path } : {}), ...(host ? node.network === 'ws' ? { headers: { Host: host } } : { host: ['http', 'h2'].includes(node.network) ? list(host) : host } : {}) };
}
function splitIni(input) {
  const parts = []; let part = ''; let quote = null;
  for (const character of input) {
    if ((character === '"' || character === "'") && (!quote || quote === character)) quote = quote ? null : character;
    if (character === ',' && !quote) { parts.push(part.trim()); part = ''; } else part += character;
  }
  if (quote) fail('VPN_NODE_INVALID'); parts.push(part.trim()); return parts;
}
function iniNode(line) {
  const match = line.match(/^([^=]+)=(.*)$/); if (!match) fail('VPN_NODE_INVALID');
  const parts = splitIni(match[2]); const type = parts.shift()?.toLowerCase(); const server = parts.shift(); const port = number(parts.shift());
  const options = {};
  for (const part of parts) {
    const offset = part.indexOf('='); if (offset < 1) fail('VPN_NODE_FIELD_UNSUPPORTED');
    const key = part.slice(0, offset).trim().toLowerCase(); let value = part.slice(offset + 1).trim();
    if (Object.hasOwn(options, key)) fail('VPN_NODE_FIELD_UNSUPPORTED');
    if (/^".*"$/.test(value)) { try { value = JSON.parse(value); } catch { fail('VPN_NODE_INVALID'); } }
    else if (/^'.*'$/.test(value)) value = value.slice(1, -1);
    options[key] = value;
  }
  const allowed = ['username', 'password', 'encrypt-method', 'tls', 'sni', 'skip-cert-verify', 'ws', 'ws-path', 'ws-headers', 'grpc-service-name', 'client-fingerprint', 'alpn', 'congestion-controller', 'udp-relay-mode', 'obfs', 'obfs-password'];
  if (!Object.keys(options).every(key => allowed.includes(key))) fail('VPN_NODE_FIELD_UNSUPPORTED');
  const node = { name: match[1].trim(), type, server, port };
  for (const key of ['tls', 'skip-cert-verify', 'ws']) if (options[key] !== undefined && !['true', 'false'].includes(options[key])) fail('VPN_NODE_INVALID');
  if (options.tls !== undefined) node.tls = options.tls === 'true'; if (options['skip-cert-verify'] !== undefined) node['skip-cert-verify'] = options['skip-cert-verify'] === 'true';
  for (const key of ['sni', 'password', 'client-fingerprint', 'alpn', 'congestion-controller', 'udp-relay-mode', 'obfs', 'obfs-password']) if (options[key] !== undefined) node[key] = options[key];
  if (['vmess', 'vless', 'tuic'].includes(type)) node.uuid = options.username; else if (options.username !== undefined) node.username = options.username;
  if (options['encrypt-method'] !== undefined) node.cipher = options['encrypt-method'];
  if (options.ws === 'true') node.network = 'ws'; else if (options['ws-path'] || options['ws-headers']) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  if (node.network === 'ws') {
    if (options['ws-headers']) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
    node['ws-opts'] = { ...(options['ws-path'] ? { path: options['ws-path'] } : {}) };
  }
  if (options['grpc-service-name'] !== undefined) { if (node.network) fail('VPN_NODE_TRANSPORT_UNSUPPORTED'); node.network = 'grpc'; node['grpc-opts'] = { 'grpc-service-name': options['grpc-service-name'] }; }
  return { name: node.name, outbound: normalizeClash(node) };
}
function normalizeXray(entry) {
  if (!exact(entry, ['protocol', 'tag', 'settings', 'streamSettings'])) fail('VPN_NODE_FIELD_UNSUPPORTED');
  const type = { shadowsocks: 'ss', socks: 'socks5' }[entry.protocol] || entry.protocol;
  if (!['ss', 'vmess', 'vless', 'trojan', 'http', 'socks5'].includes(type)) fail('VPN_NODE_TYPE_UNSUPPORTED');
  const settings = entry.settings;
  const vnext = ['vmess', 'vless'].includes(type);
  if (!exact(settings, [vnext ? 'vnext' : 'servers']) || !Array.isArray(settings[vnext ? 'vnext' : 'servers']) || settings[vnext ? 'vnext' : 'servers'].length !== 1) fail('VPN_NODE_FIELD_UNSUPPORTED');
  const server = settings[vnext ? 'vnext' : 'servers'][0];
  if (!exact(server, ['address', 'port', ...(vnext ? ['users'] : type === 'ss' ? ['method', 'password'] : type === 'trojan' ? ['password'] : ['users', 'version'])])) fail('VPN_NODE_FIELD_UNSUPPORTED');
  const node = { type, name: entry.tag, server: server.address, port: server.port };
  if (vnext) {
    if (!Array.isArray(server.users) || server.users.length !== 1 || !exact(server.users[0], ['id', 'alterId', 'security', 'encryption', 'flow', 'level'])) fail('VPN_NODE_FIELD_UNSUPPORTED');
    const user = server.users[0]; node.uuid = user.id;
    if (user.level !== undefined && user.level !== 0) fail('VPN_NODE_FIELD_UNSUPPORTED');
    if (type === 'vmess') { if (user.encryption !== undefined || user.flow !== undefined) fail('VPN_NODE_FIELD_UNSUPPORTED'); node.alterId = user.alterId ?? 0; node.cipher = user.security || 'auto'; }
    else { if (user.alterId !== undefined || user.security !== undefined || user.encryption !== undefined && user.encryption !== 'none') fail('VPN_NODE_FIELD_UNSUPPORTED'); if (user.flow !== undefined) node.flow = user.flow; }
  } else if (type === 'ss') { node.cipher = server.method; node.password = server.password; }
  else if (type === 'trojan') node.password = server.password;
  else {
    if (server.version !== undefined && !['5', 5].includes(server.version)) fail('VPN_NODE_FIELD_UNSUPPORTED');
    if (server.users !== undefined) {
      if (!Array.isArray(server.users) || server.users.length > 1 || server.users.some(user => !exact(user, ['user', 'pass']))) fail('VPN_NODE_FIELD_UNSUPPORTED');
      if (server.users.length) { node.username = server.users[0].user; node.password = server.users[0].pass; }
    }
  }
  const stream = entry.streamSettings || {};
  if (!exact(stream, ['network', 'security', 'tlsSettings', 'realitySettings', 'wsSettings', 'grpcSettings', 'httpupgradeSettings', 'httpSettings', 'tcpSettings'])) fail('VPN_NODE_FIELD_UNSUPPORTED');
  const network = stream.network || 'tcp'; node.network = network === 'raw' ? 'tcp' : network;
  const transportFields = { ws: 'wsSettings', grpc: 'grpcSettings', httpupgrade: 'httpupgradeSettings', http: 'httpSettings', h2: 'httpSettings', tcp: 'tcpSettings', raw: 'tcpSettings' };
  if (!transportFields[network]) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  for (const field of new Set(Object.values(transportFields))) if (stream[field] !== undefined && field !== transportFields[network]) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  const options = stream[transportFields[network]] || {};
  if (node.network === 'tcp') {
    if (Object.keys(options).length && (!exact(options, ['header']) || !exact(options.header, ['type']) || options.header.type !== 'none')) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
  } else if (network === 'grpc') {
    if (!exact(options, ['serviceName', 'multiMode']) || options.multiMode !== undefined && options.multiMode !== false) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
    node['grpc-opts'] = { ...(options.serviceName ? { 'grpc-service-name': options.serviceName } : {}) };
  } else {
    if (!exact(options, ['path', 'host', 'headers', ...(network === 'ws' ? ['maxEarlyData', 'earlyDataHeaderName'] : [])])) fail('VPN_NODE_TRANSPORT_UNSUPPORTED');
    node[{ ws: 'ws-opts', httpupgrade: 'http-upgrade-opts', http: 'http-opts', h2: 'h2-opts' }[network]] = { ...Object.fromEntries(['path', 'host', 'headers'].filter(key => options[key] !== undefined).map(key => [key, options[key]])), ...(options.maxEarlyData !== undefined ? { 'max-early-data': options.maxEarlyData } : {}), ...(options.earlyDataHeaderName !== undefined ? { 'early-data-header-name': options.earlyDataHeaderName } : {}) };
  }
  const security = stream.security || 'none';
  if (!['none', 'tls', 'reality'].includes(security)) fail('VPN_NODE_TLS_UNSAFE');
  node.tls = security !== 'none';
  if (security === 'none') { if (stream.tlsSettings !== undefined || stream.realitySettings !== undefined) fail('VPN_NODE_TLS_UNSAFE'); }
  else {
    if (stream[security === 'tls' ? 'realitySettings' : 'tlsSettings'] !== undefined) fail('VPN_NODE_TLS_UNSAFE');
    const tls = stream[security === 'tls' ? 'tlsSettings' : 'realitySettings'] || {};
    if (!exact(tls, ['serverName', 'allowInsecure', 'alpn', 'fingerprint', ...(security === 'reality' ? ['publicKey', 'shortId', 'show'] : [])]) || tls.allowInsecure !== undefined && tls.allowInsecure !== false || tls.show !== undefined && tls.show !== false) fail('VPN_NODE_TLS_UNSAFE');
    if (tls.serverName !== undefined) node.sni = tls.serverName; if (tls.alpn !== undefined) node.alpn = tls.alpn;
    if (tls.fingerprint !== undefined) node['client-fingerprint'] = tls.fingerprint;
    if (security === 'reality') node['reality-opts'] = { 'public-key': tls.publicKey, 'short-id': tls.shortId ?? '' };
  }
  return { name: node.name, outbound: normalizeClash(node) };
}
function parseKnown(input, allowBase64) {
  const trimmed = input.replace(/^\uFEFF/, '').trim();
  if (/^\s*\[Proxy\]\s*$/im.test(trimmed)) {
    let inProxy = false; const lines = [];
    for (const line of trimmed.split(/\r?\n/)) { const section = line.trim().match(/^\[([^\]]+)\]$/); if (section) { inProxy = section[1].toLowerCase() === 'proxy'; continue; } if (inProxy && line.trim() && !/^\s*[#;]/.test(line)) lines.push(line.trim()); }
    return collect(lines, iniNode, 'surge-ini');
  }
  const uriLines = trimmed.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith('#'));
  if (uriLines.length && uriLines.every(line => /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(line))) return collect(uriLines, normalizeUri, 'share-uri');
  if (allowBase64 && /^[A-Za-z0-9+/_=\s-]+$/.test(trimmed) && !/^proxies\b/.test(trimmed)) {
    let decoded; try { decoded = decode64(trimmed); } catch { fail('VPN_CONFIG_FORMAT_UNSUPPORTED'); }
    const result = parseKnown(decoded, false); return { ...result, format: 'base64-subscription' };
  }
  const document = yamlDocument(trimmed);
  if (object(document) && Array.isArray(document.proxies)) return collect(document.proxies, node => ({ name: node?.name, outbound: normalizeClash(node) }), 'clash-yaml');
  if (object(document) && (Array.isArray(document.outbounds) || document.type || document.protocol)) {
    const outbounds = document.outbounds || [document];
    const xray = outbounds.some(node => object(node) && node.protocol !== undefined);
    return collect(outbounds, node => {
      if (object(node) && node.protocol !== undefined) return normalizeXray(node);
      if (!object(node)) fail('VPN_NODE_INVALID'); const outbound = { ...node, tag: 'vpn-entry' };
      if (outbound.tls && outbound.tls.insecure === undefined) outbound.tls = { ...outbound.tls, insecure: false };
      if (outbound.tls && outbound.tls.server_name === undefined) outbound.tls = { ...outbound.tls, server_name: node.server };
      return { name: node.tag, outbound: validateVpnOutbound(outbound) };
    }, xray ? 'v2ray-json' : 'sing-box');
  }
  fail('VPN_CONFIG_FORMAT_UNSUPPORTED');
}
export function parseVpnConfig(input) { checkSize(input); return parseKnown(input, true); }
