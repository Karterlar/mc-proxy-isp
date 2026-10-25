import path from 'node:path';

export const ROUTING_FAKE_IP_NETWORK = Object.freeze({ ipv4: '198.18.0.0/15', ipv6: 'fc00::/18' });
const protectedDomains = ['anthropic.com', 'claude.ai', 'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com'];
const loopback = ['127.0.0.0/8', '::1/128'];
const privateNetworks = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'];

// Paths come from trusted local application discovery, never from subscriptions.
export function validateRoutingApplicationPaths(values = []) {
  if (!Array.isArray(values) || values.length > 16 || values.some(value => typeof value !== 'string' || value.length > 1024
    || !/^[A-Za-z]:[\\/]/.test(value) || !path.win32.isAbsolute(value) || /[\x00-\x1f\x7f*?]/.test(value)
    || path.win32.extname(value).toLowerCase() !== '.exe' || value.slice(2).includes(':'))) {
    throw Object.assign(new Error('Trusted absolute application executable paths are required'), { code: 'ROUTING_POLICY_INVALID' });
  }
  const seen = new Set();
  return values.map(value => path.win32.normalize(value)).filter(value => {
    const key = value.toLowerCase(); if (seen.has(key)) return false; seen.add(key); return true;
  });
}

// Only traffic already captured by TUN uses these exceptions. Unknown public
// destinations always retain the caller's isp-upstream final route.
export function buildTunRoutingPolicy({ applicationPaths = [], routingMode = 'safe-rules' } = {}) {
  if (!['safe-rules', 'global'].includes(routingMode)) throw Object.assign(new Error('Unsupported TUN routing mode'), { code: 'ROUTING_POLICY_INVALID' });
  const paths = validateRoutingApplicationPaths(applicationPaths);
  const rules = [
    { inbound: ['system-tun'], port: 53, action: 'hijack-dns' },
    { inbound: ['system-tun'], network: 'udp', action: 'reject' },
    { inbound: ['system-tun'], network: 'tcp', ip_cidr: [...loopback], action: 'route', outbound: 'private-direct' },
    { inbound: ['system-tun'], domain_suffix: [...protectedDomains], action: 'route', outbound: 'isp-upstream' },
    ...(paths.length ? [{ inbound: ['system-tun'], process_path: paths, action: 'route', outbound: 'isp-upstream' }] : []),
    ...(routingMode === 'safe-rules' ? [{ type: 'logical', mode: 'and', rules: [
      { inbound: ['system-tun'], network: 'tcp', ip_cidr: [...privateNetworks] },
      { ip_cidr: Object.values(ROUTING_FAKE_IP_NETWORK), invert: true },
    ], action: 'route', outbound: 'private-direct' }] : []),
  ];
  return { rules, outbounds: [{ type: 'direct', tag: 'private-direct', domain_resolver: 'isp-doh' }], summary: {
    version: 1, mode: routingMode, defaultPublic: 'isp-upstream', udp: 'reject', localException: routingMode === 'global' ? 'loopback-tcp' : 'loopback-private-tcp',
    applicationCount: paths.length, protectedDomainCount: protectedDomains.length,
  } };
}
