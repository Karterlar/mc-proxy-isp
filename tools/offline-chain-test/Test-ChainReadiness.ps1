[CmdletBinding()]
param(
    [string]$ManifestPath = '',
    [switch]$CheckConnectedTunnel,
    [switch]$NonInteractive,
    [switch]$Recovery,
    [switch]$LibraryOnly
)

# ASCII-only source: compatible with Windows PowerShell 5.1 without a BOM.
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
function Get-Field($Value, [string]$Name, $Default = $null) {
    if ($null -ne $Value -and $null -ne $Value.PSObject.Properties[$Name]) { return ,$Value.$Name }
    return $Default
}
function Test-AbsoluteFilePath($Value) {
    return ($Value -is [string] -and $Value.Length -gt 2 -and $Value -notmatch '[\x00-\x1f\x7f]' -and [IO.Path]::IsPathRooted($Value))
}
function Read-Manifest([string]$File) {
    if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { throw 'MANIFEST_MISSING' }
    if ((Get-Item -LiteralPath $File).Length -gt 65536) { throw 'MANIFEST_INVALID' }
    try { $value = Get-Content -LiteralPath $File -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'MANIFEST_INVALID' }
    if ((Get-Field $value 'version') -ne 1 -or (Get-Field $value 'brand') -cne 'MC Proxy') { throw 'MANIFEST_INVALID' }
    $connectionMode = Get-Field $value 'connectionMode' 'relay'
    if (@('relay', 'vpn-compat', 'vpn-import') -notcontains $connectionMode) { throw 'MANIFEST_INVALID' }
    $relay = Get-Field $value 'relay'
    if (@('vpn-compat', 'vpn-import') -contains $connectionMode -and $null -ne $relay) { throw 'MANIFEST_INVALID' }
    if ($null -ne $relay) {
        $address = $null
        if (-not [Net.IPAddress]::TryParse([string](Get-Field $relay 'host'), [ref]$address)) { throw 'MANIFEST_INVALID' }
        $port = Get-Field $relay 'port'
        if (($port -isnot [int] -and $port -isnot [long]) -or $port -lt 1 -or $port -gt 65535) { throw 'MANIFEST_INVALID' }
        if ([string](Get-Field $relay 'certificateSha256') -notmatch '^[a-fA-F0-9]{64}$') { throw 'MANIFEST_INVALID' }
        $serverName = [string](Get-Field $relay 'serverName'); $serverIp = $null
        if ($serverName -notmatch '^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$' -and -not [Net.IPAddress]::TryParse($serverName, [ref]$serverIp)) { throw 'MANIFEST_INVALID' }
    }
    $runtime = Get-Field $value 'runtime'
    foreach ($key in @('corePath', 'wintunPath', 'runtimeRoot')) {
        $entry = Get-Field $runtime $key
        if ($null -ne $entry -and -not (Test-AbsoluteFilePath $entry)) { throw 'MANIFEST_INVALID' }
    }
    $recoveryState = Get-Field $value 'recovery'
    foreach ($key in @('appPath', 'firewallDirectory')) {
        $entry = Get-Field $recoveryState $key
        if ($null -ne $entry -and -not (Test-AbsoluteFilePath $entry)) { throw 'MANIFEST_INVALID' }
    }
    $app = Get-Field $recoveryState 'appPath'
    if ($app -and [IO.Path]::GetExtension($app) -ine '.exe') { throw 'MANIFEST_INVALID' }
    $local = Get-Field $value 'localProxy'
    $port = Get-Field $local 'port'
    if ((Get-Field $local 'host') -cne '127.0.0.1' -or ($null -ne $port -and (($port -isnot [int] -and $port -isnot [long]) -or $port -lt 1024 -or $port -gt 65535))) { throw 'MANIFEST_INVALID' }
    $expected = Get-Field $value 'expectedExitIps'
    if ($expected -isnot [array] -or $expected.Count -gt 64) { throw 'MANIFEST_INVALID' }
    foreach ($ip in $expected) {
        $parsed = $null
        if ($ip -isnot [string] -or -not [Net.IPAddress]::TryParse($ip, [ref]$parsed)) { throw 'MANIFEST_INVALID' }
    }
    $isp = Get-Field $value 'isp'; $configured = Get-Field $isp 'configured'
    if ($configured -isnot [bool]) { throw 'MANIFEST_INVALID' }
    if ($configured) {
        $ispPort = Get-Field $isp 'port'
        if (@('http', 'socks') -notcontains (Get-Field $isp 'type') -or @('none', 'password') -notcontains (Get-Field $isp 'authentication') -or ($ispPort -isnot [int] -and $ispPort -isnot [long]) -or $ispPort -lt 1 -or $ispPort -gt 65535) { throw 'MANIFEST_INVALID' }
    }
    return $value
}
function Initialize-Transport {
    if (-not ('McProxyOffline.Transport' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'Transport.cs') }
}
function Test-CoreVersion([string]$File) {
    $process = New-Object Diagnostics.Process
    try {
        $process.StartInfo.FileName = $File
        $process.StartInfo.Arguments = 'version'
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $null = $process.Start()
        if (-not $process.WaitForExit(5000)) { $process.Kill(); return $false }
        $output = $process.StandardOutput.ReadToEnd()
        return ($process.ExitCode -eq 0 -and $output -match '^sing-box version 1\.14\.2(?:\s|$)')
    } catch { return $false }
    finally { $process.Dispose() }
}
function Get-NetworkEvidence([string]$RelayAddress) {
    $errors = @(); $adapters = @(); $bestRoute = $null
    try {
        foreach ($adapter in @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)) {
            $alias = [string]$adapter.Name
            $description = [string](Get-Field $adapter 'InterfaceDescription' '')
            $suspected = "$alias $description" -match '(?i)(^|[^a-z])(tun|tap|vpn)([^a-z]|$)|wintun|wireguard|xvpn|x-vpn|sing-box|singbox|clash|openvpn|tailscale|zerotier|protonvpn|nordvpn|utun'
            $adapters += [pscustomobject]@{ index = [int]$adapter.ifIndex; alias = $alias; up = ([string]$adapter.Status -eq 'Up'); physical = [bool](Get-Field $adapter 'HardwareInterface' $false); suspectedTunnel = [bool]$suspected; mcProxy = ($alias -ceq 'ProxyPilot') }
        }
    } catch { $errors += 'ADAPTER_INSPECTION_UNAVAILABLE' }
    if ($RelayAddress) {
        try {
            $found = @(Find-NetRoute -RemoteIPAddress $RelayAddress -ErrorAction Stop)
            $routes = @($found | Where-Object { $null -ne $_.PSObject.Properties['DestinationPrefix'] })
            $sources = @($found | Where-Object { $null -ne $_.PSObject.Properties['IPAddress'] })
            if ($routes.Count -ne 1 -or $sources.Count -ne 1) { throw 'ambiguous' }
            $route = $routes[0]; $match = @($adapters | Where-Object { $_.index -eq [int]$route.InterfaceIndex })
            $physical = $match.Count -eq 1 -and $match[0].physical -and $match[0].up -and -not $match[0].suspectedTunnel -and -not $match[0].mcProxy
            $bestRoute = [pscustomobject]@{ interfaceIndex = [int]$route.InterfaceIndex; nextHop = [string]$route.NextHop; destinationPrefix = [string]$route.DestinationPrefix; sourceAddress = [string]$sources[0].IPAddress; physicalAdapter = [bool]$physical }
        } catch { $errors += 'ROUTE_INSPECTION_UNAVAILABLE' }
    }
    $proxyVariables = @()
    foreach ($key in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY')) {
        if ([Environment]::GetEnvironmentVariable($key, 'Process')) { $proxyVariables += $key }
    }
    $admin = $false
    try { $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
    catch { $errors += 'ADMIN_INSPECTION_UNAVAILABLE' }
    return [pscustomobject]@{ admin = $admin; adapters = $adapters; bestRoute = $bestRoute; proxyVariableNames = $proxyVariables; errors = $errors }
}
function Compare-PhysicalRoute($Before, $After, [string]$SocketSource) {
    if (@($Before.errors).Count -or @($After.errors).Count) { return $false }
    if ($null -eq $Before.bestRoute -or $null -eq $After.bestRoute) { return $false }
    if (-not $Before.bestRoute.physicalAdapter -or -not $After.bestRoute.physicalAdapter) { return $false }
    $a = @($Before.bestRoute.interfaceIndex, $Before.bestRoute.nextHop, $Before.bestRoute.destinationPrefix, $Before.bestRoute.sourceAddress) -join '|'
    $b = @($After.bestRoute.interfaceIndex, $After.bestRoute.nextHop, $After.bestRoute.destinationPrefix, $After.bestRoute.sourceAddress) -join '|'
    return ($a -ceq $b -and $SocketSource -ceq $Before.bestRoute.sourceAddress)
}
function Read-ExitIp([string]$Source, [string]$Body) {
    $ip = ''
    if ($Source -eq 'ipify') { try { $ip = [string]((ConvertFrom-Json $Body).ip) } catch { return $null } }
    elseif ($Source -eq 'cloudflare') { foreach ($line in ($Body -split "`n")) { if ($line -match '^ip=(.+)$') { $ip = $matches[1].Trim(); break } } }
    $parsed = $null
    if ([Net.IPAddress]::TryParse($ip, [ref]$parsed)) { return $parsed.ToString() }
    return $null
}
function Get-ServiceAssessment([int]$StatusCode, [bool]$Reached) {
    if (-not $Reached) { return 'unreachable' }
    if ($StatusCode -eq 401) { return 'reachable-authentication-required' }
    if ($StatusCode -eq 403) { return 'reachable-access-restricted' }
    if ($StatusCode -eq 429) { return 'reachable-rate-or-quota-restricted' }
    if ($StatusCode -ge 500) { return 'reachable-service-error' }
    if ($StatusCode -ge 200 -and $StatusCode -lt 400) { return 'reachable-account-unverified' }
    return 'reachable-request-not-accepted'
}
function Start-RecoveryApp($Manifest) {
    $app = Get-Field (Get-Field $Manifest 'recovery') 'appPath'
    if (-not $app -or -not (Test-Path -LiteralPath $app -PathType Leaf)) { return $false }
    $runtimeRoot = Get-Field (Get-Field $Manifest 'runtime') 'runtimeRoot'
    if ($runtimeRoot -isnot [string] -or $runtimeRoot -notmatch '^[A-Za-z]:[\\/]' -or $runtimeRoot -match '[<>"|?*\x00-\x1f\x7f]' -or $runtimeRoot.Substring(2).Contains(':') -or -not (Test-Path -LiteralPath $runtimeRoot -PathType Container)) { throw 'RECOVERY_RUNTIME_INVALID' }
    # Start-Process joins ArgumentList without quoting. Double terminal slashes
    # inside the quoted Windows argument so even a drive root keeps its value.
    $runtimeArgument = '"' + ($runtimeRoot -replace '(\\+)$', '$1$1') + '"'
    $null = Start-Process -FilePath $app -ArgumentList @('--runtime-root', $runtimeArgument) -WindowStyle Normal
    return $true
}
if ($LibraryOnly) { return }
if (-not $ManifestPath) { $ManifestPath = Join-Path $PSScriptRoot 'manifest.json' }
if ($Recovery) {
    try {
        $manifest = Read-Manifest $ManifestPath
        Write-Host 'Manual recovery only. No firewall/routing changes are performed.'
        Write-Host ('Keep the original firewall journal/backups at: ' + (Get-Field $manifest.recovery 'firewallDirectory'))
        if (Start-RecoveryApp $manifest) {
            # Opening the visible recovery UI is the sole requested action.
            Write-Host 'MC Proxy opened. Stop the connection, then explicitly use its unlock control.'
        } else { Write-Host 'Open your original MC Proxy shortcut/portable app manually. See README.zh-CN.txt.' }
        exit 0
    } catch { Write-Host 'Cannot read a valid recovery manifest. Open MC Proxy manually. Keep runtime and logs.'; exit 30 }
}

$runDirectory = Join-Path $PSScriptRoot ('logs\' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + $PID)
$null = New-Item -ItemType Directory -Path $runDirectory -Force
$utf8 = New-Object Text.UTF8Encoding($false)
$summary = [ordered]@{ version = 1; startedAt = [DateTime]::UtcNow.ToString('o'); endedAt = $null; mode = $(if ($CheckConnectedTunnel) { 'connected' } else { 'preflight' }); connectionMode = $null; manifestCreatedAt = $null; exitCode = 30; status = 'running'; checks = @(); networkBefore = $null; networkAfter = $null; relay = $null; exits = @(); services = @(); userConfirmedOtherVpnDisabled = $false; fatalCode = $null; scope = 'Read-only checks. No direct fallback, auto-unlock, VPN changes, or account authentication. Service reachability does not prove account usability.' }
function Save-Summary { [IO.File]::WriteAllText((Join-Path $runDirectory 'summary.json'), ($summary | ConvertTo-Json -Depth 10), $utf8) }
function Write-Event([string]$Code, [string]$Level = 'info') {
    $line = '[' + [DateTime]::UtcNow.ToString('o') + '] ' + $Level.ToUpperInvariant() + ' ' + $Code
    [IO.File]::AppendAllText((Join-Path $runDirectory 'report.txt'), ($line + [Environment]::NewLine), $utf8)
    if ($Level -eq 'failure') { [IO.File]::AppendAllText((Join-Path $runDirectory 'errors.log'), ($line + [Environment]::NewLine), $utf8) }
    Write-Host $line
}
function Add-Check([string]$Code, [string]$Level = 'pass') {
    $summary.checks += [pscustomobject]@{ code = $Code; level = $Level }
    Write-Event $Code $Level; Save-Summary
}
try {
    [IO.File]::WriteAllText((Join-Path $runDirectory 'errors.log'), '', $utf8)
    Write-Event 'MC Proxy offline diagnostics. This program does not modify the network.'
    Write-Host ('Logs: ' + $runDirectory)
    Save-Summary
    $manifest = Read-Manifest $ManifestPath
    $summary.manifestCreatedAt = [string](Get-Field $manifest 'createdAt')
    $summary.connectionMode = [string](Get-Field $manifest 'connectionMode' 'relay')
    Add-Check 'MANIFEST_LOADED'
    if (@('vpn-compat', 'vpn-import') -contains $summary.connectionMode) {
        $summary.status = 'mode-not-applicable'; $summary.exitCode = 10
        if ($summary.connectionMode -eq 'vpn-import') {
            $summary.scope = 'Imported VPN to ISP remains unverified by this TUN-only tool. No external VPN is required. Use MC Proxy network detection. Only the local HTTP proxy path is covered.'
            Add-Check 'VPN_IMPORT_USE_APP_NETWORK_CHECK' 'warning'
            Write-Host 'Imported VPN to ISP mode: no external VPN is required. Run network detection in MC Proxy.'
        } else {
            $summary.scope = 'VPN compatibility remains unverified by this TUN-only tool. Keep the external VPN enabled and use MC Proxy network detection to verify the ISP path.'
            Add-Check 'VPN_COMPAT_USE_APP_NETWORK_CHECK' 'warning'
            Write-Host 'VPN compatibility mode: keep your external VPN enabled. Run network detection in MC Proxy.'
        }
        Write-Host 'This offline TUN preflight/connected test does not apply; no relay or network requests were made.'
        exit $summary.exitCode
    }
    if (-not (Get-Field (Get-Field $manifest 'isp') 'configured' $false)) { Add-Check 'PROVIDER_NOT_CONFIGURED' 'failure' }
    if ($null -eq $manifest.relay) { Add-Check 'RELAY_NOT_CONFIGURED' 'failure' }
    $coreFile = Get-Field $manifest.runtime 'corePath'
    if ($coreFile -and (Test-Path -LiteralPath $coreFile -PathType Leaf)) {
        Add-Check 'CORE_FILE_PRESENT'
        if (Test-CoreVersion $coreFile) { Add-Check 'PINNED_CORE_VERSION_VERIFIED'; Add-Check 'WINTUN_EMBEDDED_NATIVE_START_STILL_REQUIRED' 'info' }
        else { Add-Check 'CORE_VERSION_INVALID_OR_UNAVAILABLE' 'failure' }
    } else { Add-Check 'CORE_FILE_MISSING' 'failure' }
    if (-not $NonInteractive) {
        Write-Host 'Keep MC Proxy connected only in connected-test mode. Close OTHER VPN/TUN software yourself.'
        $answer = Read-Host 'Type OFF to confirm OTHER VPN/TUN software is disabled, or Enter for an unconfirmed test'
        $summary.userConfirmedOtherVpnDisabled = ($answer.Trim() -ceq 'OFF')
    }
    if (-not $summary.userConfirmedOtherVpnDisabled) { Add-Check 'OTHER_VPN_OFF_NOT_CONFIRMED' 'warning' }
    $relayHost = [string](Get-Field $manifest.relay 'host' '')
    $summary.networkBefore = Get-NetworkEvidence $relayHost
    if ($summary.networkBefore.admin) { Add-Check 'ADMIN_TOKEN_PRESENT' } else { Add-Check 'ADMIN_REQUIRED_FOR_TUN_START' 'warning' }
    $otherTunnels = @($summary.networkBefore.adapters | Where-Object { $_.up -and $_.suspectedTunnel -and -not $_.mcProxy })
    if ($otherTunnels.Count) { Add-Check 'VPN_CONFLICT' 'failure' } else { Add-Check 'NO_NAMED_OTHER_TUNNEL_OBSERVED' }
    if (@($summary.networkBefore.errors).Count) { Add-Check 'NETWORK_INSPECTION_INCOMPLETE' 'warning' }
    Initialize-Transport
    if (-not $CheckConnectedTunnel -and $null -ne $manifest.relay) {
        if (@($summary.networkBefore.adapters | Where-Object { $_.up -and $_.mcProxy }).Count) { Add-Check 'MC_PROXY_ALREADY_CONNECTED_USE_CONNECTED_TEST' 'warning' }
        Write-Event 'Checking the current relay leaf certificate, hostname, and validity period.'
        $relay = [McProxyOffline.Transport]::Relay($manifest.relay.host, $manifest.relay.port, $manifest.relay.serverName, $manifest.relay.certificateSha256, 7000)
        $summary.relay = [ordered]@{ success = $relay.success; code = $relay.code; elapsedMs = $relay.elapsedMs; localAddress = $relay.localAddress; certificateSha256 = $relay.certificateSha256; exceptionType = $relay.exceptionType }
        Add-Check $relay.code $(if ($relay.success) { 'pass' } else { 'failure' })
        $summary.networkAfter = Get-NetworkEvidence $relayHost
        if (Compare-PhysicalRoute $summary.networkBefore $summary.networkAfter $relay.localAddress) { Add-Check 'STABLE_PHYSICAL_ROUTE_OBSERVED' }
        else { Add-Check 'PHYSICAL_ROUTE_UNVERIFIED' 'warning' }
        if (@($summary.networkAfter.adapters | Where-Object { $_.up -and $_.suspectedTunnel -and -not $_.mcProxy }).Count) { Add-Check 'VPN_APPEARED_DURING_TEST' 'failure' }
        Add-Check 'ISP_AUTH_AND_FULL_CHAIN_NOT_TESTED_BY_PREFLIGHT' 'info'
    }
    if ($CheckConnectedTunnel) {
        $ownTun = @($summary.networkBefore.adapters | Where-Object { $_.up -and $_.mcProxy })
        if ($ownTun.Count -ne 1) { Add-Check 'MC_PROXY_TUN_NOT_OBSERVED' 'failure' }
        else { Add-Check 'MC_PROXY_TUN_ADAPTER_OBSERVED' }
        $localPort = Get-Field $manifest.localProxy 'port'
        if ($null -eq $localPort) { throw 'LOCAL_PROXY_NOT_CONFIGURED' }
        $sources = @(@{ id = 'ipify'; url = 'https://api.ipify.org?format=json' }, @{ id = 'cloudflare'; url = 'https://www.cloudflare.com/cdn-cgi/trace' })
        $allowed = @($manifest.expectedExitIps | ForEach-Object { ([Net.IPAddress]::Parse($_)).ToString() })
        foreach ($mode in @('local-proxy', 'system-route')) {
            foreach ($source in $sources) {
                Write-Event ('Checking exit: ' + $mode + '/' + $source.id)
                $probe = [McProxyOffline.Transport]::Https($source.url, $localPort, ($mode -eq 'system-route'), 'GET', 12000)
                $ip = if ($probe.success -and $probe.statusCode -eq 200) { Read-ExitIp $source.id $probe.body } else { $null }
                $summary.exits += [ordered]@{ mode = $mode; source = $source.id; ip = $ip; statusCode = $probe.statusCode; elapsedMs = $probe.elapsedMs; code = $probe.code }
                if (-not $ip) { Add-Check $(if (@(407, 502, 503) -contains $probe.statusCode) { 'CHAIN_CONNECT_REJECTED_UNKNOWN_STAGE' } elseif ($probe.success) { 'EXIT_RESPONSE_INVALID' } else { $probe.code }) 'failure' }
                elseif ($allowed.Count -eq 0) { Add-Check 'EXPECTED_EXIT_NOT_PINNED' 'warning' }
                elseif ($allowed -notcontains $ip) { Add-Check 'EXIT_IP_MISMATCH' 'failure' }
                else { Add-Check ($mode.ToUpperInvariant() + '_EXPECTED_EXIT_OBSERVED') }
            }
        }
        $observed = @($summary.exits | Where-Object { $_.ip } | Select-Object -ExpandProperty ip -Unique)
        if ($observed.Count -eq 1 -and @($summary.exits | Where-Object { -not $_.ip }).Count -eq 0) { Add-Check 'INDEPENDENT_EXIT_SOURCES_AGREE' }
        else { Add-Check 'EXIT_SOURCE_DISAGREEMENT_OR_INCOMPLETE' 'failure' }
        foreach ($service in @(@{ id = 'openai'; url = 'https://api.openai.com/v1/models' }, @{ id = 'anthropic'; url = 'https://api.anthropic.com/v1/messages' })) {
            Write-Event ('Checking service HTTPS without account credentials: ' + $service.id)
            $probe = [McProxyOffline.Transport]::Https($service.url, $localPort, $true, 'HEAD', 12000)
            $assessment = Get-ServiceAssessment $probe.statusCode $probe.success
            $summary.services += [ordered]@{ id = $service.id; mode = 'system-route'; statusCode = $probe.statusCode; elapsedMs = $probe.elapsedMs; assessment = $assessment; code = $probe.code; accountVerified = $false }
            Add-Check ($service.id.ToUpperInvariant() + '_' + $assessment.ToUpperInvariant()) $(if ($probe.success -and $probe.statusCode -ne 403 -and $probe.statusCode -ne 429 -and $probe.statusCode -lt 500) { 'pass' } else { 'warning' })
        }
        $summary.networkAfter = Get-NetworkEvidence $relayHost
        if (@($summary.networkAfter.adapters | Where-Object { $_.up -and $_.mcProxy }).Count -ne 1) { Add-Check 'MC_PROXY_TUN_DISAPPEARED' 'failure' }
        if (@($summary.networkAfter.adapters | Where-Object { $_.up -and $_.suspectedTunnel -and -not $_.mcProxy }).Count) { Add-Check 'VPN_APPEARED_DURING_TEST' 'failure' }
        if (@($summary.networkAfter.errors).Count) { Add-Check 'NETWORK_INSPECTION_INCOMPLETE' 'warning' }
    }
    if (@($summary.checks | Where-Object { $_.level -eq 'failure' }).Count) { $summary.status = 'checks-failed'; $summary.exitCode = 20 }
    elseif (@($summary.checks | Where-Object { $_.level -eq 'warning' }).Count) { $summary.status = 'verification-incomplete'; $summary.exitCode = 10 }
    else { $summary.status = 'requested-checks-passed'; $summary.exitCode = 0 }
} catch {
    # Never copy arbitrary exception messages, which can contain config material.
    $safeCodes = @('MANIFEST_MISSING', 'MANIFEST_INVALID', 'LOCAL_PROXY_NOT_CONFIGURED')
    $summary.fatalCode = if ($safeCodes -contains $_.Exception.Message) { $_.Exception.Message } else { 'DIAGNOSTIC_TOOL_ERROR' }
    $summary.status = 'configuration-or-tool-error'; $summary.exitCode = 30
    Write-Event $summary.fatalCode 'failure'
} finally {
    $summary.endedAt = [DateTime]::UtcNow.ToString('o'); Save-Summary
    Write-Event ('Finished: ' + $summary.status + '; exit=' + $summary.exitCode)
    Write-Host 'Recovery: Run-Recovery.cmd opens MC Proxy. Unlock only with its explicit manual control.'
}
exit $summary.exitCode
