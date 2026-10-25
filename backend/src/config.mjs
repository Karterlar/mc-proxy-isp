import { readFile, stat } from 'node:fs/promises';
import { isIP } from 'node:net';
import { X509Certificate } from 'node:crypto';
import path from 'node:path';
import { validateVpnOutbound } from './vpn-yaml.mjs';
import { buildTunRoutingPolicy } from './routing-policy.mjs';

export class UserError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const fail = (field, rule) => { throw new UserError('CONFIG_INVALID', `${field}: ${rule}`); };
const object = (value, field, keys) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(field, 'must be an object');
  if (Object.keys(value).some(key => !keys.includes(key))) fail(field, 'contains unsupported fields; credentials belong in the secrets file');
};
const port = (value, field) => {
  if (!Number.isInteger(value) || value < 1024 || value > 65535) fail(field, 'must be an integer between 1024 and 65535');
};
export function validHost(value) {
  return typeof value === 'string' && value.length <= 253 && (isIP(value) !== 0 || /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(value));
}
export function validateConfig(config) {
  object(config, 'config', ['version', 'listen', 'upstream', 'probe', 'relay', 'connectionMode']);
  if (config.version !== 1) fail('version', 'must be 1');
  if (config.connectionMode !== undefined && !['relay', 'vpn-compat', 'vpn-import'].includes(config.connectionMode)) fail('connectionMode', 'must be relay, vpn-compat or vpn-import');
  if (['vpn-compat', 'vpn-import'].includes(config.connectionMode) && config.relay !== undefined) fail('relay', 'must be omitted in VPN modes');
  object(config.listen, 'listen', ['host', 'port']);
  if (config.listen.host !== '127.0.0.1') fail('listen.host', 'must be 127.0.0.1 for the private local proxy listener');
  port(config.listen.port, 'listen.port');
  const up = config.upstream;
  object(up, 'upstream', ['type', 'host', 'port', 'auth', 'tls']);
  if (!['socks', 'http'].includes(up.type)) fail('upstream.type', 'must be socks or http');
  if (!validHost(up.host)) fail('upstream.host', 'must be a hostname or IP without URL or credentials');
  if (up.host.endsWith('.example')) fail('upstream.host', 'replace the example provider hostname');
  if (!Number.isInteger(up.port) || up.port < 1 || up.port > 65535) fail('upstream.port', 'must be between 1 and 65535');
  if (!['none', 'password'].includes(up.auth)) fail('upstream.auth', 'must be none or password');
  if (up.tls !== undefined) {
    object(up.tls, 'upstream.tls', ['enabled', 'serverName']);
    if (up.type !== 'http' || up.tls.enabled !== true) fail('upstream.tls', 'only enabled TLS on HTTP CONNECT is supported; omit this object for plaintext');
    if (!validHost(up.tls.serverName)) fail('upstream.tls.serverName', 'must match the provider TLS certificate');
  }
  if (config.relay !== undefined) {
    const relay = config.relay;
    object(relay, 'relay', ['type', 'host', 'port', 'auth', 'tls']);
    if (relay.type !== 'http') fail('relay.type', 'must be http CONNECT');
    if (typeof relay.host !== 'string' || !isIP(relay.host)) fail('relay.host', 'must be a fixed IP address so startup never needs local DNS');
    if (!Number.isInteger(relay.port) || relay.port < 1 || relay.port > 65535) fail('relay.port', 'must be between 1 and 65535');
    if (relay.auth !== 'password') fail('relay.auth', 'authenticated relay access is required');
    object(relay.tls, 'relay.tls', ['enabled', 'serverName', 'certificate']);
    if (relay.tls.enabled !== true || !validHost(relay.tls.serverName)) fail('relay.tls', 'verified TLS and a valid certificate identity are required');
    const pem = relay.tls.certificate;
    if (typeof pem !== 'string' || pem.length > 16384 || !/^\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*$/.test(pem)) fail('relay.tls.certificate', 'must contain one PEM certificate');
    try { new X509Certificate(pem); } catch { fail('relay.tls.certificate', 'must be a valid X.509 certificate'); }
  }
  object(config.probe, 'probe', ['exitUrl', 'expectedExitIps', 'timeoutMs']);
  let url;
  try { url = new URL(config.probe.exitUrl); } catch { fail('probe.exitUrl', 'must be an HTTPS URL'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) fail('probe.exitUrl', 'must be HTTPS without credentials or fragment');
  if (!Array.isArray(config.probe.expectedExitIps) || config.probe.expectedExitIps.some(ip => typeof ip !== 'string' || !isIP(ip))) fail('probe.expectedExitIps', 'must be an array of IP addresses');
  if (!Number.isInteger(config.probe.timeoutMs) || config.probe.timeoutMs < 500 || config.probe.timeoutMs > 120000) fail('probe.timeoutMs', 'must be between 500 and 120000');
  return config;
}
export function parseSecrets(text) {
  const secrets = {};
  for (const [index, original] of text.replace(/^\uFEFF/, '').split(/\r?\n/).entries()) {
    const line = original.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^(ISP_USERNAME|ISP_PASSWORD|RELAY_USERNAME|RELAY_PASSWORD)=(.*)$/);
    if (!match || Object.hasOwn(secrets, match[1])) throw new UserError('SECRETS_INVALID', `Secrets line ${index + 1}: invalid or duplicate key`);
    let value = match[2].trim();
    if (value.startsWith('"')) {
      try { value = JSON.parse(value); } catch { throw new UserError('SECRETS_INVALID', `Secrets line ${index + 1}: invalid JSON quoted value`); }
    }
    if (typeof value !== 'string' || /[\x00-\x1f\x7f]/.test(value)) throw new UserError('SECRETS_INVALID', `Secrets line ${index + 1}: value must be a single line string`);
    secrets[match[1]] = value;
  }
  return secrets;
}
export function validateSecrets(config, secrets) {
  if (!secrets || typeof secrets !== 'object' || Array.isArray(secrets) || Object.entries(secrets).some(([key, value]) => !['ISP_USERNAME', 'ISP_PASSWORD', 'RELAY_USERNAME', 'RELAY_PASSWORD'].includes(key) || typeof value !== 'string' || /[\x00-\x1f\x7f]/.test(value))) throw new UserError('SECRETS_INVALID', 'Proxy credentials must be supported single-line strings');
  const username = secrets.ISP_USERNAME || '';
  const password = secrets.ISP_PASSWORD || '';
  if (config.upstream.auth === 'password' && (!username || !password)) throw new UserError('SECRETS_INVALID', 'Both ISP_USERNAME and ISP_PASSWORD are required');
  if (config.upstream.auth === 'none' && (username || password)) throw new UserError('SECRETS_INVALID', 'Remove credentials when upstream.auth is none');
  if (config.upstream.type === 'http' && username.includes(':')) throw new UserError('SECRETS_INVALID', 'HTTP Basic username cannot contain a colon');
  if (config.upstream.type === 'socks' && [username, password].some(value => Buffer.byteLength(value) > 255)) throw new UserError('SECRETS_INVALID', 'SOCKS5 credentials must each be at most 255 UTF-8 bytes');
  const relayUsername = secrets.RELAY_USERNAME || '';
  const relayPassword = secrets.RELAY_PASSWORD || '';
  if (config.relay && (!relayUsername || !relayPassword)) throw new UserError('SECRETS_INVALID', 'Both RELAY_USERNAME and RELAY_PASSWORD are required');
  if (!config.relay && (relayUsername || relayPassword)) throw new UserError('SECRETS_INVALID', 'Remove relay credentials when no relay is configured');
  if (relayUsername.includes(':')) throw new UserError('SECRETS_INVALID', 'Relay HTTP Basic username cannot contain a colon');
  return secrets;
}
export async function loadConfig(path) {
  let contents;
  try { contents = await readFile(path, 'utf8'); } catch { throw new UserError('CONFIG_READ_FAILED', 'Cannot read the configuration file'); }
  let config;
  try { config = JSON.parse(contents.replace(/^\uFEFF/, '')); } catch { throw new UserError('CONFIG_INVALID', 'Configuration must be valid JSON'); }
  return validateConfig(config);
}
export async function loadSecrets(path, config) {
  let contents;
  try {
    const info = await stat(path);
    if (process.platform !== 'win32' && (info.mode & 0o077)) throw new UserError('SECRETS_PERMISSIONS', 'Run chmod 600 on the secrets file before continuing');
    contents = await readFile(path, 'utf8');
  } catch (error) {
    if (error instanceof UserError) throw error;
    throw new UserError('SECRETS_READ_FAILED', 'Cannot read the local secrets file');
  }
  return validateSecrets(config, parseSecrets(contents));
}
export const FAKE_IP_NETWORK = Object.freeze({ ipv4: '198.18.0.0/15', ipv6: 'fc00::/18' });
export const TUN_NETWORK = Object.freeze({
  interfaceName: 'ProxyPilot',
  addresses: Object.freeze(['172.30.255.1/30', 'fdfe:dcba:9876::1/126']),
  dnsAddresses: Object.freeze(['172.30.255.2', 'fdfe:dcba:9876::2']),
  routes: Object.freeze(['0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1']),
});

export function validateTransportMode(mode) {
  if (!['http', 'tun'].includes(mode)) throw new UserError('PROXY_MODE_INVALID', 'Proxy transport mode must be http or tun');
  return mode;
}

export function validateTunRoutingMode(mode) {
  if (!['safe-rules', 'global'].includes(mode)) throw new UserError('ROUTING_MODE_INVALID', 'Owned TUN routing must use safe-rules or global');
  return mode;
}

export function validateVpnProxy(value, listenPort) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['type', 'host', 'port'].includes(key)) || !['http', 'socks'].includes(value.type) || !['127.0.0.1', '::1'].includes(value.host) || !Number.isInteger(value.port) || value.port < 1024 || value.port > 65535 || value.port === listenPort) throw new UserError('VPN_PROXY_INVALID', 'VPN proxy must be a loopback HTTP or SOCKS endpoint distinct from the private listener');
  return value;
}

export function validateCoreApi(value, listenPort) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['port', 'secret'].includes(key))
    || !Number.isInteger(value.port) || value.port < 1024 || value.port > 65535 || value.port === listenPort || !/^[a-f0-9]{64}$/.test(value.secret || '')) {
    throw new UserError('CORE_API_INVALID', 'Core observation requires a private loopback port and a random secret');
  }
  return value;
}

export function validateFakeIpCache(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !['path', 'id'].includes(key))
    || typeof value.path !== 'string' || !path.isAbsolute(value.path) || /[\x00-\x1f]/.test(value.path) || !/^[a-f0-9]{64}$/.test(value.id || '')) {
    throw new UserError('FAKE_IP_CACHE_INVALID', 'Fake-IP persistence requires a controlled absolute private path and cache identity');
  }
  return value;
}

// Two-argument calls retain the SSH/CLI HTTP-only format. The desktop runtime
// explicitly selects TUN. With a relay, even the provider hostname is resolved
// remotely by its CONNECT endpoint; no client bootstrap DNS is required.
export function buildSingBox(config, secrets, options = {}) {
  validateConfig(config); validateSecrets(config, secrets);
  const mode = validateTransportMode(options.mode || 'http');
  if (mode !== 'tun' && options.routingMode !== undefined) throw new UserError('ROUTING_MODE_INVALID', 'HTTP mode has no system routing policy');
  const routingMode = mode === 'tun' ? validateTunRoutingMode(options.routingMode === undefined ? 'safe-rules' : options.routingMode) : undefined;
  if (config.connectionMode === 'vpn-compat' && mode !== 'http') throw new UserError('VPN_COMPAT_HTTP_ONLY', 'External VPN compatibility requires the private HTTP proxy');
  const vpnProxy = options.vpnProxy === undefined ? null : validateVpnProxy(options.vpnProxy, config.listen.port);
  if (vpnProxy && config.connectionMode !== 'vpn-compat') throw new UserError('VPN_PROXY_INVALID', 'A local VPN proxy requires VPN compatibility mode');
  if (options.vpnNode !== undefined && config.connectionMode !== 'vpn-import') throw new UserError('VPN_NODE_INVALID', 'An imported VPN node requires VPN import mode');
  if (config.connectionMode === 'vpn-import' && options.vpnNode === undefined) throw new UserError('VPN_NODE_REQUIRED', 'Select and verify an imported VPN node before starting');
  const vpnNode = options.vpnNode === undefined ? null : validateVpnOutbound(options.vpnNode);
  if (vpnNode && !isIP(vpnNode.server)) {
    if (!isIP(options.vpnNodeIp || '')) throw new UserError('VPN_NODE_RESOLVE_FAILED', 'Resolve the imported VPN server before building its private core configuration');
    vpnNode.server = options.vpnNodeIp;
  }
  if (vpnNode && vpnNode.server_port === config.listen.port) {
    const host = isIP(vpnNode.server) === 6 ? new URL(`http://[${vpnNode.server}]/`).hostname.slice(1, -1) : vpnNode.server;
    if (/^127\./.test(host) || ['0.0.0.0', '::', '::1'].includes(host) || /^::ffff:(?:127\.|7f[0-9a-f]{2}:)/i.test(host)) {
      throw new UserError('VPN_NODE_INVALID', 'An imported node must not dial the application own proxy listener');
    }
  }
  const up = config.upstream;
  const outbound = { type: up.type, tag: 'isp-upstream', server: up.host, server_port: up.port, connect_timeout: '10s' };
  if (mode === 'tun' && !config.relay && !vpnNode && !isIP(up.host)) {
    if (!isIP(options.upstreamIp || '')) throw new UserError('UPSTREAM_RESOLVE_FAILED', 'Resolve the provider hostname to an IP before enabling TUN');
    outbound.server = options.upstreamIp;
  }
  if (up.type === 'socks') Object.assign(outbound, { version: '5', network: 'tcp' });
  if (up.auth === 'password') Object.assign(outbound, { username: secrets.ISP_USERNAME, password: secrets.ISP_PASSWORD });
  if (up.tls) outbound.tls = { enabled: true, server_name: up.tls.serverName, insecure: false, min_version: '1.2' };
  const outbounds = [outbound];
  if (config.relay) {
    const relay = config.relay;
    outbound.detour = 'relay-entry';
    outbounds.push({ type: 'http', tag: 'relay-entry', server: relay.host, server_port: relay.port,
      username: secrets.RELAY_USERNAME, password: secrets.RELAY_PASSWORD, connect_timeout: '10s',
      tls: { enabled: true, server_name: relay.tls.serverName, insecure: false, min_version: '1.2', certificate: [relay.tls.certificate] } });
  } else if (vpnNode) {
    outbound.detour = 'vpn-entry';
    outbounds.push(vpnNode);
  } else if (vpnProxy) {
    outbound.detour = 'vpn-entry';
    outbounds.push({ type: vpnProxy.type, tag: 'vpn-entry', server: vpnProxy.host, server_port: vpnProxy.port, connect_timeout: '10s', ...(vpnProxy.type === 'socks' ? { version: '5', network: 'tcp' } : {}) });
  }
  const result = {
    log: { level: 'warn', timestamp: true },
    inbounds: [{ type: 'http', tag: 'ssh-http', listen: '127.0.0.1', listen_port: config.listen.port }],
    outbounds,
    route: { final: 'isp-upstream' }
  };
  if (options.coreApi !== undefined) {
    const api = validateCoreApi(options.coreApi, config.listen.port);
    // An empty list becomes wildcard CORS in 1.14.2. The backend sends no Origin;
    // this fixed origin does not grant the renderer access to the secret API.
    result.experimental = { clash_api: { external_controller: `127.0.0.1:${api.port}`, secret: api.secret, access_control_allow_origin: ['http://127.0.0.1'] } };
  }
  if (options.fakeIpCache !== undefined) {
    if (mode !== 'tun') throw new UserError('FAKE_IP_CACHE_INVALID', 'Fake-IP persistence is only used by the owned TUN');
    const cache = validateFakeIpCache(options.fakeIpCache);
    result.experimental = { ...result.experimental, cache_file: { enabled: true, path: cache.path, cache_id: cache.id, store_fakeip: true } };
  }
  if (mode === 'tun') {
    result.inbounds.push({
      type: 'tun', tag: 'system-tun', interface_name: TUN_NETWORK.interfaceName,
      address: [...TUN_NETWORK.addresses], mtu: 1500,
      auto_route: true, strict_route: true, dns_mode: 'hijack',
      dns_address: [...TUN_NETWORK.dnsAddresses], route_address: [...TUN_NETWORK.routes],
    });
    result.dns = {
      servers: [{ type: 'fakeip', tag: 'isp-fakeip', inet4_range: FAKE_IP_NETWORK.ipv4, inet6_range: FAKE_IP_NETWORK.ipv6 },
        { type: 'https', tag: 'isp-doh', server: '1.1.1.1', server_port: 443,
        path: '/dns-query', tls: { enabled: true, server_name: 'cloudflare-dns.com', insecure: false }, detour: 'isp-upstream' }],
      // Preserve the requested hostname across captured IPv4/IPv6 connections.
      // Residential HTTP/SOCKS providers may reset literal IPv6 CONNECT targets
      // although domain CONNECT works. Fake-IP maps both families back to the
      // domain before routing; non-address queries still use DoH via the ISP.
      rules: [{ query_type: ['A', 'AAAA'], action: 'route', server: 'isp-fakeip' }],
      final: 'isp-doh', strategy: 'prefer_ipv4',
    };
    if (options.legacyTunPolicy !== true) {
      result.dns.servers.push({ type: 'hosts', tag: 'callback-hosts', predefined: { localhost: ['127.0.0.1', '::1'] } });
      result.dns.rules.unshift({ domain: ['localhost'], action: 'route', server: 'callback-hosts' });
    }
    result.route = {
      auto_detect_interface: true, final: 'isp-upstream',
      rules: [
        { inbound: ['system-tun'], port: 53, action: 'hijack-dns' },
        // Both supported provider protocols are TCP-only. Never fall back to
        // direct UDP; browsers may retry QUIC as HTTPS over TCP.
        { inbound: ['system-tun'], network: 'udp', action: 'reject' },
      ],
    };
    if (options.legacyTunPolicy !== true) {
      const policy = buildTunRoutingPolicy({ applicationPaths: options.applicationPaths, routingMode });
      result.route.rules = policy.rules;
      result.outbounds.push(...policy.outbounds.map(outbound => ({ ...outbound, domain_resolver: 'isp-doh' })));
      // 1.14.2 sniff actions expose HTTP/TLS metadata but cannot dynamically
      // replace the dial target with SNI. Do not add removed inbound fields or
      // promise that ECH / literal IPv6 is converted into domain CONNECT.
      result.route.rules.splice(3, 0, { inbound: ['system-tun'], network: 'tcp', action: 'sniff', sniffer: ['tls', 'http'], timeout: '300ms' });
    }
  } else if (!config.relay && !vpnProxy && !vpnNode && !isIP(up.host)) {
    result.dns = { servers: [{ type: 'local', tag: 'bootstrap' }] };
    outbound.domain_resolver = 'bootstrap';
  }
  if (options.trafficGate === true) {
    if (!options.coreApi || mode !== 'tun') throw new UserError('CORE_TRAFFIC_GATE_INVALID', 'The traffic gate requires an owned TUN and private core API');
    result.experimental.clash_api.default_mode = 'mc-active';
    result.route.rules.unshift({ clash_mode: 'mc-blocked', action: 'reject' });
    result.dns.rules.unshift({ clash_mode: 'mc-blocked', action: 'reject' });
  }
  return result;
}
