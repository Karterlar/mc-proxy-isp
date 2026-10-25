import { execFile as nodeExecFile } from 'node:child_process';
import { UserError, TUN_NETWORK } from './config.mjs';

const ADMIN_SCRIPT = '[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) | ConvertTo-Json -Compress';
const CLEAR_DNS_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
Clear-DnsClientCache -ErrorAction Stop
ConvertTo-Json -InputObject @{ cleared=$true } -Compress
`;
// Shared by the standalone inspection and the process/listener snapshot. This
// fixed function accepts only our internal TUN_NETWORK, never caller scripts.
export const TUN_STATE_FUNCTION = String.raw`
function Read-TunState($expected) {
$adapter = @(Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -ceq $expected.interfaceName })
if ($adapter.Count -eq 0) { return @{ exists=$false; ready=$false } }
if ($adapter.Count -ne 1) { throw 'Ambiguous TUN interface' }
$routes = @(Get-NetRoute -InterfaceIndex $adapter[0].ifIndex -ErrorAction Stop | Select-Object -ExpandProperty DestinationPrefix)
$dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter[0].ifIndex -ErrorAction Stop | ForEach-Object { $_.ServerAddresses })
$missingRoutes = @($expected.routes | Where-Object { $routes -notcontains $_ })
$missingDns = @($expected.dnsAddresses | Where-Object { $dns -notcontains $_ })
return @{ exists=$true; ready=($adapter[0].Status -eq 'Up' -and $missingRoutes.Count -eq 0 -and $missingDns.Count -eq 0) }
}
`;
const STATE_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$expected = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PROXYPILOT_TUN_CHECK)) | ConvertFrom-Json
${TUN_STATE_FUNCTION}
Read-TunState $expected | ConvertTo-Json -Compress
`;

const EXTERNAL_ADAPTERS_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object {
  @{ name=[string]$_.Name; description=[string]$_.InterfaceDescription; status=[string]$_.Status }
})
ConvertTo-Json -InputObject $adapters -Compress
`;

// Classify active VPN/TUN/TAP adapters without returning adapter names to logs.
export function classifyExternalVpnAdapters(adapters) {
  if (!Array.isArray(adapters) || adapters.length > 1024 || adapters.some(item => !item ||
    ['name', 'description', 'status'].some(key => typeof item[key] !== 'string' || item[key].length > 512))) {
    throw new UserError('VPN_INTERFACE_STATE_UNAVAILABLE', 'Windows VPN interface inspection returned an invalid result');
  }
  const count = adapters.filter(item => {
    if (item.status !== 'Up' || item.name === TUN_NETWORK.interfaceName) return false;
    if (/Hyper-V|Teredo|ISATAP|6to4|WAN Miniport/i.test(item.description)) return false;
    return /\b(?:tun|tap|vpn|wintun|wireguard|openvpn|xvpn|x-vpn)\b|TAP-Windows/i.test(`${item.name} ${item.description}`);
  }).length;
  return { active: count > 0, count };
}

// Inspections are read-only. The explicit startup hook clears only the local
// DNS cache; this module never changes DNS servers, routes or elevation.
export function createWindowsTunTools({ execFile = nodeExecFile, platform = process.platform } = {}) {
  async function inspect(script, code, env = {}) {
    if (platform !== 'win32') throw new UserError('PLATFORM_UNSUPPORTED', 'System TUN requires Windows');
    const output = await new Promise((resolve, reject) => execFile('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64'),
    ], { windowsHide: true, encoding: 'utf8', timeout: 15000, maxBuffer: 65536, env: { ...process.env, ...env } }, (error, stdout) => {
      if (error) reject(new UserError(code, 'Unable to inspect Windows TUN prerequisites'));
      else resolve(stdout);
    })).catch(() => { throw new UserError(code, code === 'DNS_CACHE_CLEAR_FAILED' ? 'Unable to clear Windows DNS cache' : 'Unable to inspect Windows TUN prerequisites'); });
    try { return JSON.parse(output.replace(/^\uFEFF/, '').trim()); }
    catch { throw new UserError(code, 'Windows TUN inspection returned an invalid result'); }
  }
  return {
    async isElevated() { return await inspect(ADMIN_SCRIPT, 'ADMIN_CHECK_FAILED') === true; },
    async inspectTun() {
      const state = await inspect(STATE_SCRIPT, 'TUN_STATE_UNAVAILABLE', {
        PROXYPILOT_TUN_CHECK: Buffer.from(JSON.stringify(TUN_NETWORK), 'utf8').toString('base64'),
      });
      if (typeof state?.exists !== 'boolean' || typeof state?.ready !== 'boolean') throw new UserError('TUN_STATE_UNAVAILABLE', 'Windows TUN inspection returned an invalid result');
      return state;
    },
    async inspectExternalVpnTun() {
      return classifyExternalVpnAdapters(await inspect(EXTERNAL_ADAPTERS_SCRIPT, 'VPN_INTERFACE_STATE_UNAVAILABLE'));
    },
    async clearDnsCache() {
      const result = await inspect(CLEAR_DNS_SCRIPT, 'DNS_CACHE_CLEAR_FAILED');
      if (result?.cleared !== true) throw new UserError('DNS_CACHE_CLEAR_FAILED', 'Windows DNS cache clearing was not confirmed');
      return { cleared: true };
    },
  };
}

const defaults = createWindowsTunTools();
export const isElevated = () => defaults.isElevated();
export const inspectTun = () => defaults.inspectTun();
export const inspectExternalVpnTun = () => defaults.inspectExternalVpnTun();
export const clearDnsCache = options => (options ? createWindowsTunTools(options) : defaults).clearDnsCache();
