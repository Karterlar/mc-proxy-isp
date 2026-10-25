import { execFile as nodeExecFile } from 'node:child_process';
import { UserError } from './config.mjs';
import { sanitizeWfpLockDiagnostic } from './windows-wfp-lock.mjs';

const INPUT = 'PROXYPILOT_NETWORK_LOCK_REQUEST';
const SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$request = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PROXYPILOT_NETWORK_LOCK_REQUEST)) | ConvertFrom-Json
$diagnosticRule = $null
function Strings($value) { return ,@($value | ForEach-Object { [string]$_ } | Sort-Object -Culture en-US) }
$configurationFields = @{}
function Read-Configuration($item, $skip = @()) {
  $result = [ordered]@{}
  $cacheKey = [string]$item.CimSystemProperties.ClassName + ':' + ($skip -join ',')
  if (-not $configurationFields.ContainsKey($cacheKey)) {
    $configurationFields[$cacheKey] = @($item.CimInstanceProperties | Where-Object {
      $_.Name -notin $skip -and $_.Name -notin @('InstanceID','Caption','CreationClassName','SystemCreationClassName','SystemName','PrimaryStatus','Status','StatusCode','PolicyStoreSource','PolicyStoreSourceType','EnforcementStatus','HealthState','OperationalStatus','CommunicationStatus','DetailedStatus','OperatingStatus')
    } | Sort-Object Name -Culture en-US | ForEach-Object { $_.Name })
  }
  foreach ($name in $configurationFields[$cacheKey]) {
    $value = $item.CimInstanceProperties[$name].Value
    $result[$name] = $(if ($null -eq $value) { $null }
      elseif ($value -is [Microsoft.Management.Infrastructure.CimInstance]) { Read-Configuration $value }
      elseif ($value -is [System.Array]) {
        # Most firewall properties are simple strings. Only IPsec proposals
        # require recursive CIM serialization; keep their priority ordering.
        if ($value.Count -gt 0 -and $value[0] -is [Microsoft.Management.Infrastructure.CimInstance]) { ,@($value | ForEach-Object { Read-Configuration $_ }) }
        else { Strings $value }
      } else { [string]$value })
  }
  return $result
}
function Profiles([string]$store) {
  return ,@(Get-NetFirewallProfile -PolicyStore $store | Sort-Object Name -Culture en-US | ForEach-Object {
    [ordered]@{name=[string]$_.Name;enabled=[string]$_.Enabled;defaultOutboundAction=[string]$_.DefaultOutboundAction;disabledInterfaceAliases=(Strings $_.DisabledInterfaceAliases);allowLocalFirewallRules=[string]$_.AllowLocalFirewallRules;details=(Read-Configuration $_ @('Name','Enabled','DefaultOutboundAction','DisabledInterfaceAliases','AllowLocalFirewallRules'))}
  })
}
function FilterMap([string]$command, [string]$store) {
  $map = @{}
  foreach ($item in @(& $command -PolicyStore $store)) {
    $key = [string]$item.InstanceID
    if ($map.ContainsKey($key)) { throw 'Duplicate firewall filter' }
    $map[$key] = $item
  }
  return $map
}
function Policy($snapshot) { return [ordered]@{profiles=$snapshot.profiles;rules=$snapshot.rules;settings=$snapshot.settings;ipsecRules=$snapshot.ipsecRules} }
function Digest($value) {
  # All dictionaries are constructed as [ordered] and source arrays are sorted
  # above. Avoid an expensive recursive PowerShell walk of hundreds of rules.
  $serialized = ConvertTo-Json -InputObject $value -Depth 30 -Compress
  $sha = [Security.Cryptography.SHA256]::Create()
  try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($serialized))).Replace('-','').ToLowerInvariant() }
  finally { $sha.Dispose() }
}
function Rules([string]$store, [bool]$onlyActiveAllow) {
  $rules = @(Get-NetFirewallRule -PolicyStore $store -TracePolicyStore | Sort-Object Name -Culture en-US)
  if ($onlyActiveAllow) { $rules = @($rules | Where-Object { $_.Direction -eq 'Outbound' -and $_.Action -eq 'Allow' -and $_.Enabled -eq 'True' }) }
  $maps = @{}
  $kinds = $(if ($onlyActiveAllow) { @('Address','Port','Application','Interface') } else { @('Address','Port','Application','Service','Interface','InterfaceType','Security') })
  foreach ($kind in $kinds) { $maps[$kind] = FilterMap ('Get-NetFirewall' + $kind + 'Filter') $store }
  return ,@($rules | ForEach-Object {
    $rule = $_
    $filters = [ordered]@{}
    foreach ($kind in $kinds) {
      $filter = $maps[$kind][[string]$rule.InstanceID]
      if ($null -eq $filter) { throw 'Missing firewall filter association' }
      if (-not $onlyActiveAllow) { $filters[$kind] = Read-Configuration $filter }
    }
    $port = $maps.Port[[string]$rule.InstanceID]
    $application = $maps.Application[[string]$rule.InstanceID]
    $address = $maps.Address[[string]$rule.InstanceID]
    $interface = $maps.Interface[[string]$rule.InstanceID]
    $protocol = [string]$port.Protocol
    if ($protocol -eq '6') { $protocol = 'TCP' }; if ($protocol -eq '17') { $protocol = 'UDP' }
    $result = [ordered]@{
      name=[string]$rule.Name;enabled=[string]$rule.Enabled;direction=[string]$rule.Direction;action=[string]$rule.Action;profile=[string]$rule.Profile;
      protocol=$protocol;program=[string]$application.Program;remoteAddress=(Strings $address.RemoteAddress);remotePort=(Strings $port.RemotePort);interfaceAlias=(Strings $interface.InterfaceAlias);
    }
    if ($onlyActiveAllow) { $result.source = [string]$rule.PolicyStoreSourceType }
    else { $result.details = [ordered]@{rule=(Read-Configuration $rule @('Name','Enabled','Direction','Action','Profile'));filters=$filters} }
    $result
  })
}
function Inspect {
  $governed = $false
  # Refuse configured machine policy rather than trying to override domain/MDM
  # controls. Effective policy is independently checked after every operation.
  $policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
  if (Test-Path -LiteralPath $policyRoot) {
    foreach ($key in @((Get-Item -LiteralPath $policyRoot)) + @(Get-ChildItem -LiteralPath $policyRoot -Recurse)) {
      if ($key.GetValueNames().Count -gt 0) { $governed = $true }
    }
  }
  $settings = [ordered]@{firewall=@(Get-NetFirewallSetting -PolicyStore PersistentStore | Sort-Object InstanceID -Culture en-US | ForEach-Object { Read-Configuration $_ });ipsec=[ordered]@{}}
  $persistentIpsecCount = 0
  foreach ($kind in @('Rule','MainModeRule','Phase1AuthSet','Phase2AuthSet','MainModeCryptoSet','QuickModeCryptoSet')) {
    $command = 'Get-NetIPsec' + $kind
    $items = @(& $command -PolicyStore PersistentStore | Sort-Object InstanceID -Culture en-US)
    $settings.ipsec[$kind] = @($items | ForEach-Object {
      # Keep object identity as well as configuration, so a renamed or replaced
      # auth/crypto set cannot be silently overwritten by full-policy import.
      # Auth proposals may contain sensitive material. Only fingerprints leave
      # this process; the private Windows .wfw export is the recovery artifact.
      [ordered]@{id=[string]$_.InstanceID;digest=(Digest (Read-Configuration $_))}
    })
    if ($kind -in @('Rule','MainModeRule')) { $persistentIpsecCount += $items.Count }
  }
  $ipsec = @(Get-NetIPsecRule -PolicyStore ActiveStore) + @(Get-NetIPsecMainModeRule -PolicyStore ActiveStore)
  $snapshot = @{
    admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    serviceRunning=((Get-Service -Name MpsSvc).Status -eq 'Running' -and (Get-Service -Name BFE).Status -eq 'Running')
    governed=$governed;ipsecRules=($ipsec.Count + $persistentIpsecCount);settings=$settings
    profiles=(Profiles 'PersistentStore');activeProfiles=(Profiles 'ActiveStore')
    rules=(Rules 'PersistentStore' $false);activeAllowRules=(Rules 'ActiveStore' $true)
  }
  $snapshot.policyDigest = Digest (Policy $snapshot)
  return $snapshot
}
try {
  $result = $null
  if ($request.operation -in @('export','import','profiles','disable','add') -and -not [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ADMIN_REQUIRED' }
  switch ($request.operation) {
    'inspect' { $result = Inspect }
    'inspect-orphans' {
      # A never-armed or fully restored manager only needs to detect this
      # product's residual rules. Full filter/IPsec snapshots are reserved for
      # arming, locked verification and restoration transactions.
      $result = @{ names=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { ([string]$_.Name).StartsWith('ProxyPilot-Lock-', [StringComparison]::Ordinal) } | ForEach-Object { [string]$_.Name }) }
    }
    'export' {
      if (Test-Path -LiteralPath $request.path) { throw 'Backup already exists' }
      & "$env:SystemRoot\System32\netsh.exe" advfirewall export ([string]$request.path) | Out-Null
      if ($LASTEXITCODE -ne 0) { throw 'NETWORK_LOCK_EXPORT_FAILED' }
      $result = $true
    }
    'import' {
      if ([string]$request.expectedPolicyDigest -notmatch '^[a-f0-9]{64}$') { throw 'Import requires a fresh expected policy' }
      $beforeImport = Inspect
      if ($beforeImport.policyDigest -cne $request.expectedPolicyDigest -or $beforeImport.governed) { throw 'NETWORK_LOCK_CONFLICT' }
      & "$env:SystemRoot\System32\netsh.exe" advfirewall import ([string]$request.path) | Out-Null
      if ($LASTEXITCODE -ne 0) { throw 'NETWORK_LOCK_IMPORT_FAILED' }
      $result = $true
    }
    'profiles' {
      foreach ($profile in $request.profiles) { Set-NetFirewallProfile -PolicyStore PersistentStore -Name ([string]$profile.name) -Enabled ([string]$profile.enabled) -DefaultOutboundAction ([string]$profile.defaultOutboundAction) }
      $result = $true
    }
    'disable' {
      foreach ($name in $request.names) {
        # -Name has no wildcard support. Recheck type before the sole mutation.
        $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name ([string]$name)
        if ($rule.Direction -ne 'Outbound' -or $rule.Action -ne 'Allow') { throw 'Rule changed before disable' }
        $rule | Set-NetFirewallRule -Enabled False
      }
      $result = $true
    }
    'add' {
      foreach ($rule in $request.rules) {
        if ([string]$rule.name -notmatch '^ProxyPilot-Lock-[0-9a-f-]{36}-(isp|loopback|tun-tcp|tun-dns)$') { throw 'Invalid rule identity' }
        $diagnosticRule = $Matches[1]
        $arguments = @{
          PolicyStore='PersistentStore';Name=[string]$rule.name;DisplayName=[string]$rule.name;Group='ProxyPilot persistent network lock';
          Direction='Outbound';Action='Allow';Enabled='True';Profile='Any';Protocol=[string]$rule.protocol;
          Program=[string]$rule.program;RemoteAddress=[string[]]$rule.remoteAddress;RemotePort=[string[]]$rule.remotePort;
          InterfaceAlias=[string[]]$rule.interfaceAlias;InterfaceType='Any';LocalAddress='Any';LocalPort='Any';
          Authentication='NotRequired';Encryption='NotRequired';OverrideBlockRules=$false;EdgeTraversalPolicy='Block'
        }
        New-NetFirewallRule @arguments | Out-Null
      }
      $result = $true
    }
    default { throw 'Unsupported operation' }
  }
  ConvertTo-Json -InputObject @{ok=$true;value=$result} -Depth 30 -Compress
} catch {
  $code = [string]$_.Exception.Message
  if ($code -cnotin @('ADMIN_REQUIRED','NETWORK_LOCK_CONFLICT','NETWORK_LOCK_EXPORT_FAILED','NETWORK_LOCK_IMPORT_FAILED')) { $code = 'NETWORK_LOCK_WINDOWS_FAILED' }
  # Native messages, source lines and target objects can contain private rule
  # names or paths. Keep only command/category and numeric native metadata.
  $diagnostic = @{command=[string]$_.InvocationInfo.MyCommand.Name;category=[string]$_.CategoryInfo.Category;
    hResult=$_.Exception.HResult;nativeCode=$_.Exception.NativeErrorCode;rule=$diagnosticRule}
  ConvertTo-Json -InputObject @{ok=$false;code=$code;diagnostic=$diagnostic} -Compress
}
`;

const operations = new Set(['inspect', 'inspect-orphans', 'export', 'import', 'profiles', 'disable', 'add']);
const commands = new Set(['powershell.exe', 'Get-Service', 'Get-Item', 'Get-ChildItem', 'Test-Path', 'ConvertFrom-Json', 'ConvertTo-Json',
  ...['Rule', 'Profile', 'Setting', 'AddressFilter', 'PortFilter', 'ApplicationFilter', 'ServiceFilter', 'InterfaceFilter', 'InterfaceTypeFilter', 'SecurityFilter'].map(name => `Get-NetFirewall${name}`),
  ...['Rule', 'MainModeRule', 'Phase1AuthSet', 'Phase2AuthSet', 'MainModeCryptoSet', 'QuickModeCryptoSet'].map(name => `Get-NetIPsec${name}`),
  'Set-NetFirewallProfile', 'Set-NetFirewallRule', 'New-NetFirewallRule']);
const categories = new Set(['NotSpecified', 'OpenError', 'CloseError', 'DeviceError', 'Deadlock', 'InvalidArgument', 'InvalidData', 'InvalidOperation', 'InvalidResult', 'InvalidType',
  'MetadataError', 'NotImplemented', 'NotInstalled', 'ObjectNotFound', 'OperationStopped', 'OperationTimeout', 'SyntaxError', 'ParserError', 'PermissionDenied', 'ResourceBusy',
  'ResourceExists', 'ResourceUnavailable', 'ReadError', 'WriteError', 'FromStdErr', 'SecurityError', 'ProtocolError', 'ConnectionError', 'AuthenticationError', 'LimitsExceeded', 'QuotaExceeded', 'NotEnabled']);
const ruleKinds = new Set(['isp', 'loopback', 'tun-tcp', 'tun-dns']);

export function sanitizeNetworkLockDiagnostic(value, operation = value?.operation) {
  if(value?.command==='MCProxy.NetworkLock.exe')return sanitizeWfpLockDiagnostic(value,operation);
  if (!operations.has(operation)) return undefined;
  const diagnostic = { operation };
  if (commands.has(value?.command)) diagnostic.command = value.command;
  if (categories.has(value?.category)) diagnostic.category = value.category;
  if (Number.isInteger(value?.nativeCode) && value.nativeCode >= -2147483648 && value.nativeCode <= 4294967295) diagnostic.nativeCode = value.nativeCode;
  if (Number.isInteger(value?.hResult) && value.hResult >= -2147483648 && value.hResult <= 2147483647) diagnostic.hResult = value.hResult;
  if (operation === 'add' && ruleKinds.has(value?.rule)) diagnostic.rule = value.rule;
  return diagnostic;
}

function windowsFailure(code, diagnostic, operation) {
  const cause = new UserError(code, 'Windows firewall operation failed; recovery journal retained');
  cause.diagnostic = sanitizeNetworkLockDiagnostic(diagnostic, operation);
  return cause;
}

// All mutations are reachable only through the manager's persisted transaction.
// Tests inject execFile and must never call this adapter against the host.
export function createWindowsNetworkLockAdapter({ execFile = nodeExecFile, platform = process.platform } = {}) {
  async function call(request) {
    if (platform !== 'win32') throw new UserError('PLATFORM_UNSUPPORTED', 'The persistent network lock requires Windows');
    const output = await new Promise((resolve, reject) => execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(SCRIPT, 'utf16le').toString('base64')], {
      windowsHide: true, encoding: 'utf8', timeout: 60000, maxBuffer: 16 * 1024 * 1024,
      env: { ...process.env, [INPUT]: Buffer.from(JSON.stringify(request)).toString('base64') },
    }, (error, stdout) => error ? reject(windowsFailure(error.killed ? 'NETWORK_LOCK_TIMEOUT' : 'NETWORK_LOCK_WINDOWS_FAILED',
      { command: 'powershell.exe', category: error.killed ? 'OperationTimeout' : 'OperationStopped' }, request.operation)) : resolve(stdout)));
    let result;
    try { result = JSON.parse(output.replace(/^\uFEFF/, '').trim()); } catch {}
    if (!result) throw windowsFailure('NETWORK_LOCK_RESPONSE_INVALID', {}, request.operation);
    if (!result.ok) {
      const code = ['ADMIN_REQUIRED', 'NETWORK_LOCK_CONFLICT', 'NETWORK_LOCK_EXPORT_FAILED', 'NETWORK_LOCK_IMPORT_FAILED'].includes(result.code) ? result.code : 'NETWORK_LOCK_WINDOWS_FAILED';
      throw windowsFailure(code, result.diagnostic, request.operation);
    }
    return result.value;
  }
  return {
    inspect: () => call({ operation: 'inspect' }),
    inspectOrphans: () => call({ operation: 'inspect-orphans' }),
    exportPolicy: path => call({ operation: 'export', path }),
    importPolicy: (path, expectedState) => {
      if (!/^[a-f0-9]{64}$/.test(expectedState?.policyDigest || '')) throw new UserError('NETWORK_LOCK_INPUT_INVALID', 'Firewall restoration requires a fresh policy fingerprint');
      return call({ operation: 'import', path, expectedPolicyDigest: expectedState.policyDigest });
    },
    setProfiles: profiles => call({ operation: 'profiles', profiles }),
    disableRules: async names => {
      // Windows limits a single environment variable to 32,767 characters.
      // Bound both encoded size and per-command native work. Each rule is still
      // re-read and checked before disabling; journal recovery spans batches.
      if (!Array.isArray(names) || names.some(name => typeof name !== 'string' || !name || name.length > 2048)) throw new UserError('NETWORK_LOCK_INPUT_INVALID', 'Invalid firewall rule identity');
      let batch = [];
      for (const name of names) {
        const next = [...batch, name];
        if ((next.length > 16 || Buffer.byteLength(JSON.stringify({ operation: 'disable', names: next }), 'utf8') > 12_000) && batch.length) {
          await call({ operation: 'disable', names: batch });
          batch = [name];
        } else batch = next;
      }
      if (batch.length) await call({ operation: 'disable', names: batch });
    },
    addRules: rules => call({ operation: 'add', rules }),
  };
}
