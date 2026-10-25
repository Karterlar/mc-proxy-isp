import { execFile as nodeExecFile } from 'node:child_process';
import { validateVpnProxy } from './config.mjs';

const PROXY_SETTINGS_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$settings = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
@{ enabled=($settings.ProxyEnable -eq 1); server=[string]$settings.ProxyServer; pacPresent=[bool]$settings.AutoConfigURL } | ConvertTo-Json -Compress
`;

export async function readWindowsProxySettings({ execFile = nodeExecFile, platform = process.platform } = {}) {
  if (platform !== 'win32') return {};
  try {
    const output = await new Promise((resolve, reject) => execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(PROXY_SETTINGS_SCRIPT, 'utf16le').toString('base64')],
      { windowsHide: true, encoding: 'utf8', timeout: 5000, maxBuffer: 8192 }, (cause, stdout) => cause ? reject(cause) : resolve(stdout)));
    const settings = JSON.parse(String(output).replace(/^\uFEFF/, '').trim());
    return { enabled: settings.enabled === true, server: typeof settings.server === 'string' ? settings.server.slice(0, 4096) : '', pacPresent: settings.pacPresent === true };
  } catch { return {}; }
}

function localProxy(value, defaultType, listenPort) {
  if (typeof value !== 'string' || value.length > 4096) return null;
  try {
    const url = new URL(value.includes('://') ? value : `${defaultType === 'socks' ? 'socks5' : 'http'}://${value}`);
    if (url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) return null;
    const type = ['socks:', 'socks5:', 'socks5h:'].includes(url.protocol) ? 'socks' : url.protocol === 'http:' ? 'http' : null;
    const host = url.hostname.replace(/^\[|\]$/g, '') === 'localhost' ? '127.0.0.1' : url.hostname.replace(/^\[|\]$/g, '');
    return validateVpnProxy({ type, host, port: Number(url.port) }, listenPort);
  } catch { return null; }
}

// Discovery reads configured local proxy addresses only. It never scans ports,
// evaluates PAC JavaScript, reads VPN credentials, or assumes an adapter name
// proves a usable path. The controller verifies each candidate through the ISP.
export async function compatibilityRoutes({ manualProxy, listenPort, environment = process.env, readSystemProxy = readWindowsProxySettings } = {}) {
  if (manualProxy !== undefined) return [{ strategy: `${validateVpnProxy(manualProxy, listenPort).type}-proxy`, source: 'manual', vpnProxy: { ...manualProxy } }];
  const candidates = [{ strategy: 'system', source: 'system-network' }];
  const seen = new Set();
  const add = (value, type, source) => {
    const vpnProxy = localProxy(value, type, listenPort);
    if (!vpnProxy || candidates.length >= 4) return;
    const key = JSON.stringify(vpnProxy);
    if (seen.has(key)) return;
    seen.add(key); candidates.push({ strategy: `${vpnProxy.type}-proxy`, source, vpnProxy });
  };
  const settings = await readSystemProxy();
  if (settings?.enabled) for (const entry of (settings.server || '').split(';')) {
    const match = /^(?:(https?|socks)=)?(.+)$/i.exec(entry.trim());
    if (match) add(match[2], match[1]?.toLowerCase() === 'socks' ? 'socks' : 'http', 'windows-proxy');
  }
  for (const key of ['HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'HTTP_PROXY', 'http_proxy']) add(environment[key], 'http', 'proxy-environment');
  return candidates;
}
