// Configuration target, not a claim that each provider supports every feature.
export function proxyCapabilities() {
  return {
    engine: { name: 'sing-box', version: '1.14.2', multipleEngines: false },
    inputFormats: ['clash-yaml', 'sing-box', 'v2ray-json', 'share-uri', 'base64-subscription', 'surge-ini'],
    entryProtocols: ['shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria2', 'tuic', 'http', 'socks'],
    finalTransport: { tcp: true, dns: 'fake-ip-and-isp-doh', udp: 'reject-except-dns', ipv6Literal: 'provider-dependent' },
    tunRouting: ['safe-rules', 'global'],
    subscription: { manual: true, httpsOnly: true, redirects: false, directFallback: false, maxBytes: 1048576 },
    optionalFeatures: { pac: false, lanSharing: false, automaticUpdates: false, appContainerExemptions: false },
  };
}
