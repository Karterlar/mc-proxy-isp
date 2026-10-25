[CmdletBinding()]
param(
    [string]$RuntimeRoot,
    [switch]$Confirmed,
    [int]$WaitForPid = 0,
    [switch]$ShowResult,
    [switch]$Elevated,
    [switch]$PreserveChangedRules,
    [string]$DesktopRequestId,
    [int]$DesktopPid = 0,
    [switch]$LibraryOnly
)

# Offline recovery deliberately edits only the fields changed by MC Proxy.
# It never resets/imports the whole firewall, changes DNS/routes or kills processes.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$configurationFields = @{}
$script:repairConflicts = @()
$script:repairStage = 'starting'

function Repair-Failure([string]$Code) { throw [InvalidOperationException]::new($Code) }
function Get-RepairErrorInfo($Record) {
    # Error messages, source lines and target objects may contain private rule
    # values. Record only the operation and bounded error metadata.
    $errorId = [string]$Record.FullyQualifiedErrorId
    if ($errorId -cnotmatch '^[A-Za-z0-9_,.\-]{1,200}$') { $errorId = 'OMITTED' }
    $command = [string]$Record.InvocationInfo.MyCommand.Name
    if ($command -cnotmatch '^[A-Za-z][A-Za-z0-9\-]{0,80}$') { $command = $null }
    $inner = $Record.Exception.InnerException
    return [pscustomobject]@{ stage=$script:repairStage; exceptionType=$Record.Exception.GetType().FullName;
        innerExceptionType=$(if ($inner) { $inner.GetType().FullName } else { $null });
        hResult=$Record.Exception.HResult; innerHResult=$(if ($inner) { $inner.HResult } else { $null });
        errorId=$errorId; command=$command; line=[int]$Record.InvocationInfo.ScriptLineNumber }
}
function Assert-RepairPath([string]$Path, [switch]$AllowMissing) {
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Contains('"')) { Repair-Failure 'UNSAFE_PATH' }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.Length -gt [IO.Path]::GetPathRoot($full).Length) { $full = $full.TrimEnd([char]'\',[char]'/') }
    $current = [IO.Path]::GetPathRoot($full)
    foreach ($part in $full.Substring($current.Length).Split([char]'\')) {
        if (-not $part) { continue }
        $current = Join-Path $current $part
        if (-not (Test-Path -LiteralPath $current)) {
            if ($AllowMissing) { continue }
            Repair-Failure 'RECOVERY_FILE_MISSING'
        }
        if (((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Repair-Failure 'UNSAFE_PATH' }
    }
    return $full
}
function Json-String([string]$Value) {
    # Match JSON.stringify, including its non-ASCII spelling, for the existing
    # journal's SHA-256 rule fingerprints. PowerShell's serializer escapes HTML.
    $escaped = [regex]::Replace($Value, '[\x00-\x1f\\"]', {
        param($match)
        switch ([int][char]$match.Value) {
            34 { '\"'; break }; 92 { '\\'; break }; 8 { '\b'; break }
            9 { '\t'; break }; 10 { '\n'; break }; 12 { '\f'; break }; 13 { '\r'; break }
            default { '\u{0:x4}' -f [int][char]$match.Value }
        }
    })
    return '"' + $escaped + '"'
}
function Canonical-Json($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string]) { return Json-String $Value }
    if ($Value -is [bool]) { return $Value.ToString().ToLowerInvariant() }
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [pscustomobject]) {
        [string[]]$keys = $(if ($Value -is [System.Collections.IDictionary]) { @($Value.Keys) } else { @($Value.PSObject.Properties.Name) })
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        $parts = foreach ($key in $keys) { (Json-String $key) + ':' + (Canonical-Json $Value.$key) }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = foreach ($item in $Value) { Canonical-Json $item }
        return '[' + ($parts -join ',') + ']'
    }
    return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
}
function Rule-Digest($Rule) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((Canonical-Json $Rule)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}
function Same-Value($Left, $Right) { return (Canonical-Json $Left) -ceq (Canonical-Json $Right) }
function Without-Fields($Value, [string[]]$Skip) {
    $result = [ordered]@{}
    foreach ($item in $Value.PSObject.Properties) { if ($item.Name -cnotin $Skip) { $result[$item.Name] = $item.Value } }
    return $result
}
function Strings($Value) { return ,@($Value | ForEach-Object { [string]$_ } | Sort-Object -Culture en-US) }
function Read-Configuration($Item, $Skip = @()) {
    $result = [ordered]@{}
    $key = [string]$Item.CimSystemProperties.ClassName + ':' + ($Skip -join ',')
    if (-not $configurationFields.ContainsKey($key)) {
        $configurationFields[$key] = @($Item.CimInstanceProperties | Where-Object {
            $_.Name -notin $Skip -and $_.Name -notin @('InstanceID','Caption','CreationClassName','SystemCreationClassName','SystemName','PrimaryStatus','Status','StatusCode','PolicyStoreSource','PolicyStoreSourceType','EnforcementStatus','HealthState','OperationalStatus','CommunicationStatus','DetailedStatus','OperatingStatus')
        } | Sort-Object Name -Culture en-US | ForEach-Object { $_.Name })
    }
    foreach ($name in $configurationFields[$key]) {
        $value = $Item.CimInstanceProperties[$name].Value
        $result[$name] = $(if ($null -eq $value) { $null }
            elseif ($value -is [Microsoft.Management.Infrastructure.CimInstance]) { Read-Configuration $value }
            elseif ($value -is [System.Array]) {
                if ($value.Count -gt 0 -and $value[0] -is [Microsoft.Management.Infrastructure.CimInstance]) { ,@($value | ForEach-Object { Read-Configuration $_ }) }
                else { Strings $value }
            } else { [string]$value })
    }
    return $result
}
function Profile-Snapshot($Profile) {
    return [pscustomobject][ordered]@{ name=[string]$Profile.Name; enabled=[string]$Profile.Enabled; defaultOutboundAction=[string]$Profile.DefaultOutboundAction;
        disabledInterfaceAliases=(Strings $Profile.DisabledInterfaceAliases); allowLocalFirewallRules=[string]$Profile.AllowLocalFirewallRules;
        details=(Read-Configuration $Profile @('Name','Enabled','DefaultOutboundAction','DisabledInterfaceAliases','AllowLocalFirewallRules')) }
}
function Rule-Snapshot($Rule, $Filters) {
    $details=[ordered]@{}
    foreach ($kind in @('Address','Port','Application','Service','Interface','InterfaceType','Security')) {
        if ($null -eq $Filters[$kind]) { Repair-Failure 'FIREWALL_FILTER_MISSING' }
        $details[$kind]=Read-Configuration $Filters[$kind]
    }
    $protocol=[string]$Filters.Port.Protocol
    if ($protocol -eq '6') { $protocol='TCP' }; if ($protocol -eq '17') { $protocol='UDP' }
    return [pscustomobject][ordered]@{ name=[string]$Rule.Name; enabled=[string]$Rule.Enabled; direction=[string]$Rule.Direction; action=[string]$Rule.Action; profile=[string]$Rule.Profile;
        protocol=$protocol; program=[string]$Filters.Application.Program; remoteAddress=(Strings $Filters.Address.RemoteAddress); remotePort=(Strings $Filters.Port.RemotePort); interfaceAlias=(Strings $Filters.Interface.InterfaceAlias);
        details=[pscustomobject][ordered]@{ rule=(Read-Configuration $Rule @('Name','Enabled','Direction','Action','Profile')); filters=$details } }
}
function Read-RepairNamedRule([string]$Name, [switch]$AllowMissing) {
    try { $found=@(Get-NetFirewallRule -PolicyStore PersistentStore -Name $Name -ErrorAction Stop) }
    catch {
        if ($AllowMissing -and $_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound_Name,*') { return $null }
        throw
    }
    if ($AllowMissing -and $found.Count -eq 0) { return $null }
    if ($found.Count -ne 1) { Repair-Failure 'AMBIGUOUS_FIREWALL_RULE' }
    $filters=@{}
    foreach ($kind in @('Address','Port','Application','Service','Interface','InterfaceType','Security')) {
        $items=@($found[0] | & ('Get-NetFirewall' + $kind + 'Filter') -ErrorAction Stop)
        if ($items.Count -ne 1) { Repair-Failure 'AMBIGUOUS_FIREWALL_FILTER' }
        $filters[$kind]=$items[0]
    }
    return [pscustomobject]@{ native=$found[0]; snapshot=(Rule-Snapshot $found[0] $filters) }
}
function Read-RepairNamedProfile([string]$Name) { return Profile-Snapshot (Get-NetFirewallProfile -PolicyStore PersistentStore -Name $Name -ErrorAction Stop) }
function Read-RepairPolicy {
    $profiles = @(Get-NetFirewallProfile -PolicyStore PersistentStore | Sort-Object Name -Culture en-US | ForEach-Object { Profile-Snapshot $_ })
    $maps = @{}
    foreach ($kind in @('Address','Port','Application','Service','Interface','InterfaceType','Security')) {
        $map = @{}
        foreach ($filter in @(& ('Get-NetFirewall' + $kind + 'Filter') -PolicyStore PersistentStore)) {
            $key = [string]$filter.InstanceID
            if ($map.ContainsKey($key)) { Repair-Failure 'AMBIGUOUS_FIREWALL_FILTER' }
            $map[$key] = $filter
        }
        $maps[$kind] = $map
    }
    $rules = @(Get-NetFirewallRule -PolicyStore PersistentStore -TracePolicyStore | Sort-Object Name -Culture en-US | ForEach-Object {
        $rule = $_; $key = [string]$rule.InstanceID; $filters = @{}
        foreach ($kind in @('Address','Port','Application','Service','Interface','InterfaceType','Security')) {
            if ($null -eq $maps[$kind][$key]) { Repair-Failure 'FIREWALL_FILTER_MISSING' }
            $filters[$kind] = $maps[$kind][$key]
        }
        Rule-Snapshot $rule $filters
    })
    return [pscustomobject]@{ profiles=$profiles; rules=$rules }
}
function Assert-RepairJournal($Journal) {
    if ($Journal.version -ne 1 -or $Journal.id -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or $Journal.binding -cnotmatch '^[0-9a-f]{64}$' -or $Journal.backupHash -cnotmatch '^[0-9a-f]{64}$' -or
        $Journal.phase -cnotin @('preparing','arming','armed','attaching','active','unlocking','repairing','unlocked') -or
        $Journal.corePath -notmatch '^[A-Za-z]:[\\/]' -or $Journal.corePath.Contains('"') -or
        $Journal.before.profiles -isnot [array] -or $Journal.before.profiles.Count -ne 3 -or
        $Journal.before.rules -isnot [array] -or $Journal.before.rules.Count -gt 10000 -or
        $Journal.rules -isnot [array] -or $Journal.rules.Count -ne 4) { Repair-Failure 'INVALID_RECOVERY_JOURNAL' }
    if ((@($Journal.before.profiles.name | Sort-Object) -join ',') -cne 'Domain,Private,Public') { Repair-Failure 'INVALID_RECOVERY_JOURNAL' }
    foreach ($profile in $Journal.before.profiles) {
        if ($profile.enabled -cnotin @('True','False','NotConfigured') -or $profile.defaultOutboundAction -cnotin @('Allow','Block','NotConfigured') -or $null -eq $profile.details) { Repair-Failure 'INVALID_RECOVERY_JOURNAL' }
    }
    $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($rule in $Journal.before.rules) {
        if ($rule.name -isnot [string] -or -not $rule.name -or $rule.name.Length -gt 2048 -or $rule.name.StartsWith('ProxyPilot-Lock-', [StringComparison]::Ordinal) -or
            -not $names.Add($rule.name) -or $rule.enabled -cnotin @('True','False') -or $rule.direction -cnotin @('Inbound','Outbound') -or $rule.action -cnotin @('Allow','Block') -or $null -eq $rule.details) { Repair-Failure 'INVALID_RECOVERY_JOURNAL' }
    }
    $address = $null
    if (-not [Net.IPAddress]::TryParse([string]$Journal.endpoint.ip, [ref]$address) -or ($Journal.endpoint.port -isnot [int] -and $Journal.endpoint.port -isnot [long]) -or $Journal.endpoint.port -lt 1 -or $Journal.endpoint.port -gt 65535) { Repair-Failure 'INVALID_RECOVERY_JOURNAL' }
    $endpointProtocol = 'TCP'
    if ($Journal.endpoint.PSObject.Properties.Name -ccontains 'protocol') {
        if ($Journal.endpoint.protocol -isnot [string] -or $Journal.endpoint.protocol -cnotin @('TCP','UDP')) { Repair-Failure 'INVALID_RECOVERY_JOURNAL' }
        $endpointProtocol = $Journal.endpoint.protocol
    }
    $expected = @(
        @{ suffix='isp'; protocol=$endpointProtocol; program=$Journal.corePath; addresses=@([string]$Journal.endpoint.ip); ports=@([string]$Journal.endpoint.port); interfaces=@('Any') },
        @{ suffix='loopback'; protocol='TCP'; program='Any'; addresses=@('127.0.0.1','::1'); ports=@('Any'); interfaces=@('Any') },
        @{ suffix='tun-tcp'; protocol='TCP'; program='Any'; addresses=@('Any'); ports=@('Any'); interfaces=@('ProxyPilot') },
        @{ suffix='tun-dns'; protocol='UDP'; program='Any'; addresses=@('Any'); ports=@('53'); interfaces=@('ProxyPilot') }
    )
    for ($index = 0; $index -lt 4; $index++) {
        $rule = $Journal.rules[$index]; $item = $expected[$index]
        if ($rule.name -cne ('ProxyPilot-Lock-' + $Journal.id + '-' + $item.suffix) -or $rule.enabled -cne 'True' -or $rule.direction -cne 'Outbound' -or $rule.action -cne 'Allow' -or $rule.profile -cne 'Any' -or
            $rule.protocol -cne $item.protocol -or $rule.program -ine $item.program -or
            -not (Same-Value $rule.remoteAddress $item.addresses) -or -not (Same-Value $rule.remotePort $item.ports) -or -not (Same-Value $rule.interfaceAlias $item.interfaces)) { Repair-Failure 'INVALID_RECOVERY_JOURNAL' }
    }
}
function Assert-RepairProfile($Original, $Live) {
    if (-not (Same-Value (Without-Fields $Live @('enabled','defaultOutboundAction')) (Without-Fields $Original @('enabled','defaultOutboundAction'))) -or
        $Live.enabled -cnotin @($Original.enabled,'True') -or $Live.defaultOutboundAction -cnotin @($Original.defaultOutboundAction,'Block')) { Repair-Failure 'PROFILE_CHANGED_OUTSIDE_MC_PROXY' }
}
function Assert-RepairAllowRule($Original, $Live) {
    if (-not (Same-Value (Without-Fields $Live @('enabled')) (Without-Fields $Original @('enabled'))) -or $Live.enabled -cnotin @('True','False')) { Repair-Failure 'ALLOW_RULE_CHANGED_OUTSIDE_MC_PROXY' }
}
function Changed-RepairFields($Original, $Live, [string]$Prefix = '') {
    if (Same-Value $Original $Live) { return }
    $originalObject = $Original -is [System.Collections.IDictionary] -or $Original -is [pscustomobject]
    $liveObject = $Live -is [System.Collections.IDictionary] -or $Live -is [pscustomobject]
    if ($originalObject -and $liveObject) {
        $originalKeys = $(if ($Original -is [System.Collections.IDictionary]) { @($Original.Keys) } else { @($Original.PSObject.Properties.Name) })
        $liveKeys = $(if ($Live -is [System.Collections.IDictionary]) { @($Live.Keys) } else { @($Live.PSObject.Properties.Name) })
        foreach ($key in @(@($originalKeys) + @($liveKeys) | Sort-Object -Unique)) {
            $field = $(if ($Prefix) { $Prefix + '.' + $key } else { $key })
            if ($originalKeys -cnotcontains $key -or $liveKeys -cnotcontains $key) { $field }
            else { Changed-RepairFields $Original.$key $Live.$key $field }
        }
    } else { $(if ($Prefix) { $Prefix } else { '$rule' }) }
}
function Get-RepairAllowConflict($Journal, $Original, $Live) {
    $code = $null; $fields = @()
    if ($null -eq $Live) { $code = 'ORIGINAL_ALLOW_RULE_MISSING'; $fields = @('$missing') }
    else {
        $fields = @(Changed-RepairFields (Without-Fields $Original @('enabled')) (Without-Fields $Live @('enabled')))
        if ($Live.enabled -cnotin @('True','False')) { $fields += 'enabled' }
        if ($fields.Count) { $code = 'ALLOW_RULE_CHANGED_OUTSIDE_MC_PROXY' }
    }
    if (-not $code) { return $null }
    $index = 0
    while ($index -lt $Journal.before.rules.Count -and $Journal.before.rules[$index].name -cne $Original.name) { $index++ }
    # Identify the backed-up rule without exposing its name, program, addresses
    # or other rule values in the portable repair report.
    return [pscustomobject]@{ originalRuleIndex=$index; identityHash=(Rule-Digest $Original.name); code=$code; changedFields=$fields }
}
function Assert-RepairOwnedRule($Journal, $Live) {
    $expected = @($Journal.rules | Where-Object { $_.name -ceq $Live.name })
    if ($expected.Count -ne 1 -or -not (Same-Value (Without-Fields $Live @('details')) $expected[0])) { Repair-Failure 'MANAGED_RULE_CHANGED_OR_OTHER_LOCK_EXISTS' }
    # Arming can fail after creating the base rules but before persisting
    # fingerprints. Still validate their exact journal identity and allow
    # filters above; removing these allow rules does not weaken other rules.
    $fingerprint = $Journal.ruleFingerprints.($Live.name)
    if ($fingerprint -and ($fingerprint -cnotmatch '^[0-9a-f]{64}$' -or (Rule-Digest $Live) -cne $fingerprint)) { Repair-Failure 'MANAGED_RULE_FINGERPRINT_MISMATCH' }
}
function New-RepairPlan($Journal, $Current, [switch]$PreserveChangedRules) {
    $script:repairConflicts = @()
    Assert-RepairJournal $Journal
    if ($Current.profiles.Count -ne 3 -or (@($Current.profiles.name | Sort-Object) -join ',') -cne 'Domain,Private,Public') { Repair-Failure 'FIREWALL_INSPECTION_FAILED' }
    $currentRules = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    foreach ($rule in $Current.rules) {
        if ($currentRules.ContainsKey($rule.name)) { Repair-Failure 'AMBIGUOUS_FIREWALL_RULE' }
        $currentRules.Add($rule.name, $rule)
    }
    $profiles = @(); $rules = @(); $remove = @(); $conflicts = @()
    foreach ($original in $Journal.before.profiles) {
        $live = @($Current.profiles | Where-Object { $_.name -ceq $original.name })[0]
        Assert-RepairProfile $original $live
        if ($live.enabled -cne $original.enabled -or $live.defaultOutboundAction -cne $original.defaultOutboundAction) { $profiles += $original }
    }
    foreach ($original in $Journal.before.rules | Where-Object { $_.enabled -ceq 'True' -and $_.direction -ceq 'Outbound' -and $_.action -ceq 'Allow' }) {
        $live = $(if ($currentRules.ContainsKey($original.name)) { $currentRules[$original.name] } else { $null })
        $conflict = Get-RepairAllowConflict $Journal $original $live
        if ($conflict) { $conflicts += $conflict; continue }
        if ($live.enabled -ceq 'False') { $rules += $original }
    }
    $script:repairConflicts = $conflicts
    if ($conflicts.Count -and -not $PreserveChangedRules) { Repair-Failure $conflicts[0].code }
    foreach ($live in $Current.rules | Where-Object { $_.name.StartsWith('ProxyPilot-Lock-', [StringComparison]::Ordinal) }) {
        Assert-RepairOwnedRule $Journal $live
        $remove += $live
    }
    return [pscustomobject]@{ profiles=$profiles; rules=$rules; remove=$remove; conflicts=$conflicts }
}
function Resolve-RepairRoot([string]$Requested) {
    if ($Requested) { return Assert-RepairPath $Requested }
    $candidates = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $folder = $PSScriptRoot
    if ([IO.Path]::GetFileName($folder) -eq 'offline-diagnostics') {
        $candidate = [IO.Path]::GetDirectoryName($folder)
        if (Test-Path -LiteralPath (Join-Path $candidate '.network-lock\journal.json')) { [void]$candidates.Add($candidate) }
    }
    for ($index = 0; $index -lt 5 -and $folder; $index++) {
        foreach ($suffix in @('MC Proxy Data\runtime','backend\runtime')) {
            $candidate = Join-Path $folder $suffix
            if (Test-Path -LiteralPath (Join-Path $candidate '.network-lock\journal.json')) { [void]$candidates.Add([IO.Path]::GetFullPath($candidate)) }
        }
        $folder = [IO.Path]::GetDirectoryName($folder)
    }
    if ($env:APPDATA) {
        $candidate = Join-Path $env:APPDATA 'MC Proxy\runtime'
        if (Test-Path -LiteralPath (Join-Path $candidate '.network-lock\journal.json')) { [void]$candidates.Add($candidate) }
    }
    $active = @($candidates | Where-Object { try { (Get-Content -LiteralPath (Join-Path $_ '.network-lock\journal.json') -Raw | ConvertFrom-Json).phase -cne 'unlocked' } catch { $true } })
    if ($active.Count -eq 1) { return Assert-RepairPath $active[0] }
    if ($active.Count -gt 1) { Repair-Failure 'MULTIPLE_RECOVERY_ROOTS_USE_RUNTIME_ROOT' }
    if ($candidates.Count -eq 1) { return Assert-RepairPath @($candidates)[0] }
    Repair-Failure 'RECOVERY_ROOT_NOT_FOUND_USE_RUNTIME_ROOT'
}
function Assert-RepairIdle([string]$CorePath) {
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        if ($process.ExecutablePath -and [string]$process.ExecutablePath -ieq $CorePath) { Repair-Failure 'MANAGED_CORE_STILL_RUNNING_CLOSE_MC_PROXY' }
        if ([string]$process.Name -ieq [IO.Path]::GetFileName($CorePath) -and -not $process.ExecutablePath) { Repair-Failure 'CORE_PROCESS_IDENTITY_UNAVAILABLE' }
    }
    if (@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { $_.Name -ceq 'ProxyPilot' }).Count) { Repair-Failure 'PROXYPILOT_TUN_STILL_EXISTS_CLOSE_MC_PROXY_OR_REBOOT' }
}
function Wait-DesktopRepair([string]$Root, [string]$RequestId, [int]$OwnerPid) {
    if ($RequestId -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' -or $OwnerPid -le 0 -or $OwnerPid -eq $PID) { Repair-Failure 'INVALID_DESKTOP_REQUEST' }
    $directory = Assert-RepairPath (Join-Path $Root 'network-repair') -AllowMissing
    [void][IO.Directory]::CreateDirectory($directory)
    $ready = Assert-RepairPath (Join-Path $directory ('desktop-' + $RequestId + '.ready')) -AllowMissing
    $temporary = Assert-RepairPath ($ready + '.tmp') -AllowMissing
    $continue = Assert-RepairPath (Join-Path $directory ('desktop-' + $RequestId + '.continue')) -AllowMissing
    $script:repairStage = 'wait-desktop-sessions'
    $stream = [IO.File]::Open($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $bytes=[Text.Encoding]::UTF8.GetBytes($RequestId); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    [IO.File]::Move($temporary,$ready)
    $deadline = [DateTime]::UtcNow.AddMinutes(5)
    while (-not (Test-Path -LiteralPath $continue)) {
        if (-not (Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue)) { Repair-Failure 'DESKTOP_REPAIR_CANCELED' }
        if ([DateTime]::UtcNow -ge $deadline) { Repair-Failure 'DESKTOP_SESSION_STOP_TIMEOUT' }
        Start-Sleep -Milliseconds 100
    }
    [void](Assert-RepairPath $continue)
    if ([IO.File]::ReadAllText($continue) -cne $RequestId) { Repair-Failure 'DESKTOP_REPAIR_CANCELED' }
}
function Save-RepairJournal($Journal, [string]$JournalPath) {
    [void](Assert-RepairPath $JournalPath)
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($JournalPath)) ([Guid]::NewGuid().ToString() + '.tmp')
    try {
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Journal | ConvertTo-Json -Depth 40 -Compress)); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        [void](Assert-RepairPath $JournalPath)
        # In Windows PowerShell 5.1, plain $null becomes an empty string for a
        # .NET string parameter. NullString passes the actual null backup path.
        [IO.File]::Replace($temporary,$JournalPath,[System.Management.Automation.Language.NullString]::Value)
    } finally { if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force } }
}
function Assert-WfpRepairJournal($Journal) {
    if (($Journal.version -isnot [int] -and $Journal.version -isnot [long]) -or $Journal.version -ne 2 -or $Journal.engine -isnot [string] -or $Journal.engine -cne 'wfp' -or
        $Journal.id -isnot [string] -or $Journal.binding -isnot [string] -or
        $Journal.id -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' -or
        $Journal.binding -cnotmatch '^[0-9a-f]{64}$' -or $Journal.phase -cnotin @('arming','armed','attaching','active','unlocking','unlocked') -or
        $Journal.corePath -isnot [string] -or $Journal.corePath -notmatch '^[A-Za-z]:[\\/]' -or
        $Journal.corePath -match '[\x00\r\n]' -or $Journal.corePath.Length -gt 1024 -or [IO.Path]::GetExtension($Journal.corePath) -ine '.exe' -or
        $Journal.includeTun -isnot [bool] -or ($null -ne $Journal.fingerprint -and ($Journal.fingerprint -isnot [string] -or $Journal.fingerprint -cnotmatch '^[0-9a-f]{64}$')) -or
        ($null -eq $Journal.fingerprint -and $Journal.phase -cnotin @('arming','unlocked'))) { Repair-Failure 'INVALID_WFP_RECOVERY_JOURNAL' }
    $address = $null
    if ($Journal.endpoint.protocol -isnot [string] -or $Journal.endpoint.protocol -cnotin @('TCP','UDP') -or $Journal.endpoint.ip -isnot [string] -or
        -not [Net.IPAddress]::TryParse([string]$Journal.endpoint.ip, [ref]$address) -or
        ($Journal.endpoint.port -isnot [int] -and $Journal.endpoint.port -isnot [long]) -or $Journal.endpoint.port -lt 1 -or $Journal.endpoint.port -gt 65535) { Repair-Failure 'INVALID_WFP_RECOVERY_JOURNAL' }
    if ($Journal.endpoint.PSObject.Properties.Name -ccontains 'host' -and
        ($Journal.endpoint.host -isnot [string] -or -not $Journal.endpoint.host -or $Journal.endpoint.host.Length -gt 253 -or $Journal.endpoint.host -match '[\s\x00]')) { Repair-Failure 'INVALID_WFP_RECOVERY_JOURNAL' }
}
function Get-ProtectedWfpHelper {
    # Never execute a path from a user-writable journal or imported VPN config.
    # The native helper independently verifies the protected copy and SCM state.
    $base = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    $directory = Assert-RepairPath (Join-Path $base 'MC Proxy\NetworkLock-v1')
    $helper = Assert-RepairPath (Join-Path $directory 'MCProxy.NetworkLock.exe')
    if (-not (Get-Item -LiteralPath $helper -Force).PSIsContainer -and [IO.Path]::GetExtension($helper) -ieq '.exe') {
        $privileged = @('S-1-5-18','S-1-5-32-544')
        $write = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Modify -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
            [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
        foreach ($target in @($directory,$helper)) {
            $acl = Get-Acl -LiteralPath $target
            if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cnotin $privileged) { Repair-Failure 'WFP_HELPER_UNTRUSTED' }
            foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                    $rule.IdentityReference.Value -cnotin $privileged -and ($rule.FileSystemRights -band $write)) { Repair-Failure 'WFP_HELPER_UNTRUSTED' }
            }
        }
        return $helper
    }
    Repair-Failure 'WFP_HELPER_UNAVAILABLE'
}
function Invoke-WfpHelper($Request) {
    if ($Request.operation -cnotin @('inspect','clear')) { Repair-Failure 'INVALID_WFP_REPAIR_OPERATION' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Get-ProtectedWfpHelper
    $start.Arguments = ''; $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true; $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $start.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $process = [Diagnostics.Process]::new(); $process.StartInfo = $start
    try {
        if (-not $process.Start()) { Repair-Failure 'WFP_HELPER_UNAVAILABLE' }
        $output = $process.StandardOutput.ReadToEndAsync(); $errors = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.Write(($Request | ConvertTo-Json -Depth 8 -Compress)); $process.StandardInput.Close()
        # An ambiguous timeout preserves the recovery journal. Never terminate a
        # helper that might already have committed its atomic rule removal.
        if (-not $process.WaitForExit(15000)) { Repair-Failure 'WFP_REPAIR_TIMEOUT' }
        $json = $output.GetAwaiter().GetResult(); [void]$errors.GetAwaiter().GetResult()
        if ($json.Length -gt 131072) { Repair-Failure 'WFP_HELPER_RESPONSE_INVALID' }
        try { $reply = $json.TrimStart([char]0xfeff).Trim() | ConvertFrom-Json } catch { Repair-Failure 'WFP_HELPER_RESPONSE_INVALID' }
        if ($reply.ok -isnot [bool]) { Repair-Failure 'WFP_HELPER_RESPONSE_INVALID' }
        if (-not $reply.ok) {
            $known = @('ADMIN_REQUIRED','NETWORK_LOCK_CONFLICT','NETWORK_LOCK_VERIFY_FAILED','NETWORK_LOCK_WFP_FAILED','NETWORK_LOCK_SERVICE_CONFLICT','NETWORK_LOCK_SERVICE_UNAVAILABLE')
            if ($reply.code -cin $known) { Repair-Failure $reply.code }
            Repair-Failure 'WFP_HELPER_OPERATION_FAILED'
        }
        if ($process.ExitCode -ne 0) { Repair-Failure 'WFP_HELPER_OPERATION_FAILED' }
        return $reply.value
    } finally { $process.Dispose() }
}
function Assert-WfpRepairObservation($Journal, $Observed) {
    if ($Observed.present -isnot [bool] -or $Observed.verified -isnot [bool] -or
        ($Observed.ownedFilterCount -isnot [int] -and $Observed.ownedFilterCount -isnot [long]) -or
        $Observed.ownedFilterCount -lt 0 -or $Observed.ownedFilterCount -gt 512) { Repair-Failure 'WFP_HELPER_RESPONSE_INVALID' }
    if (-not $Observed.present) {
        if (-not $Observed.verified -or $Observed.ownedFilterCount -ne 0) { Repair-Failure 'WFP_REPAIR_VERIFICATION_FAILED' }
        return
    }
    # A known partial/disabled policy can be removed on explicit confirmation.
    # Ownership, full immutable identity and actual fingerprint must still match.
    if ($Observed.id -isnot [string] -or $Observed.binding -isnot [string] -or $Observed.corePath -isnot [string] -or
        $Observed.endpoint.ip -isnot [string] -or $Observed.endpoint.protocol -isnot [string] -or $Observed.fingerprint -isnot [string] -or
        $Observed.id -cne $Journal.id -or $Observed.binding -cne $Journal.binding -or $Observed.corePath -ine $Journal.corePath -or
        $Observed.endpoint.ip -ine $Journal.endpoint.ip -or $Observed.endpoint.port -ne $Journal.endpoint.port -or
        $Observed.endpoint.protocol -cne $Journal.endpoint.protocol -or $Observed.fingerprint -cnotmatch '^[0-9a-f]{64}$') { Repair-Failure 'WFP_RECOVERY_POLICY_CONFLICT' }
    if ($Journal.phase -cnotin @('arming','attaching','unlocking') -and $Journal.fingerprint -cne $Observed.fingerprint) { Repair-Failure 'WFP_RECOVERY_POLICY_CONFLICT' }
}
function Invoke-WfpRepair($Journal, [string]$JournalPath) {
    Assert-WfpRepairJournal $Journal
    $script:repairStage = 'check-idle'; Assert-RepairIdle $Journal.corePath
    $script:repairStage = 'inspect-owned-wfp'
    $observed = Invoke-WfpHelper @{operation='inspect'}
    Assert-WfpRepairObservation $Journal $observed
    if ($observed.present) {
        $script:repairStage = 'check-idle'; Assert-RepairIdle $Journal.corePath
        $Journal.phase='unlocking'; $Journal.fingerprint=$observed.fingerprint
        $script:repairStage = 'save-wfp-unlocking-journal'; Save-RepairJournal $Journal $JournalPath
        $script:repairStage = 'clear-owned-wfp'; $script:repairMutationStarted=$true
        $request = @{operation='clear'; id=[string]$Journal.id; expectedFingerprint=[string]$observed.fingerprint}
        # Ignore a lost response only if a fresh observation confirms absence.
        $clearError=$null
        try { [void](Invoke-WfpHelper $request) } catch { $clearError=$_ }
        $script:repairStage = 'verify-owned-wfp-absence'
        $after = Invoke-WfpHelper @{operation='inspect'}
        if ($after.present -isnot [bool] -or $after.verified -isnot [bool] -or $after.present -or -not $after.verified -or $after.ownedFilterCount -ne 0) {
            if ($clearError) { throw $clearError }
            Repair-Failure 'WFP_REPAIR_VERIFICATION_FAILED'
        }
    }
    $Journal.phase='unlocked'; $Journal.fingerprint=$null; $Journal.includeTun=$false
    $Journal | Add-Member -NotePropertyName updatedAt -NotePropertyValue ([DateTime]::UtcNow.ToString('o')) -Force
    $Journal | Add-Member -NotePropertyName recovery -NotePropertyValue ([pscustomobject]@{engine='wfp'; lockReleased=$true; completedAt=[DateTime]::UtcNow.ToString('o')}) -Force
    $script:repairStage = 'save-wfp-unlocked-journal'; Save-RepairJournal $Journal $JournalPath
    $script:repairStage = 'complete'
    return [pscustomobject]@{engine='wfp'; managedRulesRemoved=$observed.ownedFilterCount; profilesRestored=0; allowRulesRestored=0;
        skippedAllowRules=0; preservedRules=@(); lockReleased=$true; managedBaselineRestored=$false; fullPolicyBaselineVerified=$false}
}
function Invoke-SelectiveRepair($Journal, [string]$JournalPath, [switch]$PreserveChangedRules) {
    $script:repairStage = 'check-idle'
    Assert-RepairIdle $Journal.corePath
    $script:repairStage = 'inspect-firewall-initial'
    $initial = Read-RepairPolicy
    $script:repairStage = 'validate-firewall-initial'
    [void](New-RepairPlan $Journal $initial -PreserveChangedRules:$PreserveChangedRules)
    # Reinspect immediately before the journal commit and sole mutations. A
    # conflict refuses the entire preflight instead of deleting unrelated rules.
    $script:repairStage = 'check-idle'
    Assert-RepairIdle $Journal.corePath
    $script:repairStage = 'inspect-firewall-final'
    $current = Read-RepairPolicy
    $script:repairStage = 'validate-firewall-final'
    $plan = New-RepairPlan $Journal $current -PreserveChangedRules:$PreserveChangedRules
    $script:repairStage = 'check-idle'
    Assert-RepairIdle $Journal.corePath
    $Journal.phase = 'repairing'
    $script:repairStage = 'save-repairing-journal'
    Save-RepairJournal $Journal $JournalPath
    $script:repairMutationStarted = $true
    $allowRulesRestored = 0
    foreach ($rule in $plan.rules) {
        $script:repairStage = 'restore-allow-rule'
        $live=Read-RepairNamedRule $rule.name -AllowMissing:$PreserveChangedRules
        $conflict=Get-RepairAllowConflict $Journal $rule $live.snapshot
        if ($conflict) {
            $script:repairConflicts = @($script:repairConflicts | Where-Object { $_.originalRuleIndex -ne $conflict.originalRuleIndex }) + @($conflict)
            if ($PreserveChangedRules) { continue }
            Repair-Failure $conflict.code
        }
        if ($live.snapshot.enabled -ceq 'False') { $live.native | Set-NetFirewallRule -Enabled True -ErrorAction Stop; $allowRulesRestored++ }
    }
    foreach ($profile in $plan.profiles) {
        $script:repairStage = 'restore-profile'
        Assert-RepairProfile $profile (Read-RepairNamedProfile $profile.name)
        Set-NetFirewallProfile -PolicyStore PersistentStore -Name $profile.name -Enabled $profile.enabled -DefaultOutboundAction $profile.defaultOutboundAction -ErrorAction Stop
    }
    foreach ($rule in $plan.remove) {
        $script:repairStage = 'remove-managed-rule'
        $live=Read-RepairNamedRule $rule.name
        Assert-RepairOwnedRule $Journal $live.snapshot
        $live.native | Remove-NetFirewallRule -ErrorAction Stop
    }
    $script:repairStage = 'verify-restored-policy'
    $after = New-RepairPlan $Journal (Read-RepairPolicy) -PreserveChangedRules:$PreserveChangedRules
    if ($after.profiles.Count -or $after.rules.Count -or $after.remove.Count) { Repair-Failure 'REPAIR_VERIFICATION_FAILED' }
    $Journal.phase = 'unlocked'
    $recovery = [pscustomobject]@{ mode=$(if ($PreserveChangedRules) { 'preserve-changed-rules' } else { 'strict' }); managedBaselineRestored=($after.conflicts.Count -eq 0); fullPolicyBaselineVerified=$false; preservedRules=$after.conflicts; completedAt=[DateTime]::UtcNow.ToString('o') }
    $Journal | Add-Member -NotePropertyName recovery -NotePropertyValue $recovery -Force
    $script:repairStage = 'save-unlocked-journal'
    Save-RepairJournal $Journal $JournalPath
    $script:repairStage = 'complete'
    return [pscustomobject]@{ profilesRestored=$plan.profiles.Count; allowRulesRestored=$allowRulesRestored; managedRulesRemoved=$plan.remove.Count; skippedAllowRules=$after.conflicts.Count; preservedRules=$after.conflicts; lockReleased=$true; managedBaselineRestored=$recovery.managedBaselineRestored; fullPolicyBaselineVerified=$false }
}
function Write-RepairResult($Result, [string]$Root) {
    $directory = Assert-RepairPath (Join-Path $Root 'network-repair') -AllowMissing
    [void][IO.Directory]::CreateDirectory($directory)
    [void](Assert-RepairPath $directory)
    $file = Join-Path $directory ('result-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff') + '-' + [Guid]::NewGuid().ToString() + '.json')
    $json = $Result | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($file,$json,[Text.UTF8Encoding]::new($false))
    $last = Assert-RepairPath (Join-Path $directory 'last-result.json') -AllowMissing
    [IO.File]::WriteAllText($last,$json,[Text.UTF8Encoding]::new($false))
    if ($Result.desktopRequestId -cmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$') {
        $request = Assert-RepairPath (Join-Path $directory ('desktop-' + $Result.desktopRequestId + '.result.json')) -AllowMissing
        [IO.File]::WriteAllText($request,$json,[Text.UTF8Encoding]::new($false))
    }
    Write-Host ('MC_PROXY_REPAIR_RESULT=' + $file)
    return $file
}
function Show-RepairResult($Result, [string]$ResultPath) {
    if (-not $ShowResult) { return }
    Add-Type -AssemblyName System.Windows.Forms
    $message = $(if ($Result.success -and $Result.skippedAllowRules -gt 0) { 'MC Proxy network lock removed; ' + $Result.skippedAllowRules + ' changed/missing allow rules kept unchanged. The complete original policy was not restored. Test normal connectivity.' }
        elseif ($Result.success -and $Result.code -ceq 'LOCAL_WFP_LOCK_RELEASED') { 'MC Proxy WFP network lock was removed. Other firewall settings were kept unchanged. Test your normal network.' }
        elseif ($Result.success) { 'MC Proxy firewall changes were restored. Reconnect Wi-Fi/Ethernet and test your normal network.' }
        else { 'Repair did not complete. No success is assumed. Code: ' + $Result.code })
    if (-not $Result.success) { $message += "`r`nStage: " + $Result.stage }
    if ($ResultPath) { $message += "`r`n`r`nReport: " + $ResultPath }
    [void][Windows.Forms.MessageBox]::Show($message,'MC Proxy network repair',[Windows.Forms.MessageBoxButtons]::OK)
}

if ($LibraryOnly) { return }
$exitCode = 3; $resultPath = $null; $delegated = $false; $script:repairMutationStarted = $false
$result = [ordered]@{ version=3; desktopRequestId=$DesktopRequestId; startedAt=[DateTime]::UtcNow.ToString('o'); completedAt=$null; success=$false; code='REPAIR_NOT_STARTED'; exitCode=3; stage='starting'; error=$null; preservedRecoveryRecords=$true; lockReleased=$false; managedBaselineRestored=$false; fullPolicyBaselineVerified=$false; internetConnectivityVerified=$false; skippedAllowRules=0; preservedRules=@(); conflicts=@(); details=$null }
try {
    $script:repairStage = 'resolve-runtime'
    $RuntimeRoot = Resolve-RepairRoot $RuntimeRoot
    if (($DesktopRequestId -or $DesktopPid) -and ($DesktopRequestId -cnotmatch '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' -or $DesktopPid -le 0 -or $DesktopPid -eq $PID -or $WaitForPid)) { Repair-Failure 'INVALID_DESKTOP_REQUEST' }
    if (-not $Confirmed) {
        $script:repairStage = 'user-confirmation'
        Write-Host 'Close MC Proxy completely from its tray first. This repair restores ordinary direct networking and may expose your local IP.'
        if ($PreserveChangedRules) { Write-Host 'Changed/missing existing allow rules will be kept as they are; only verified MC Proxy changes will be undone.' }
        Write-Host ('Recovery data: ' + $RuntimeRoot)
        if ((Read-Host 'Type REPAIR to continue; anything else cancels') -cne 'REPAIR') { $exitCode=2; Repair-Failure 'USER_CANCELED' }
    }
    $script:repairStage = 'wait-desktop-exit'
    if ($WaitForPid -lt 0 -or $WaitForPid -eq $PID) { Repair-Failure 'INVALID_WAIT_PROCESS' }
    if ($WaitForPid -gt 0) {
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (Get-Process -Id $WaitForPid -ErrorAction SilentlyContinue) {
            if ([DateTime]::UtcNow -ge $deadline) { Repair-Failure 'DESKTOP_STILL_RUNNING' }
            Start-Sleep -Milliseconds 200
        }
    }
    $script:repairStage = 'admin-elevation'
    $admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        if ($Elevated) { Repair-Failure 'ADMIN_ELEVATION_FAILED' }
        $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -RuntimeRoot "' + $RuntimeRoot + '" -Confirmed -Elevated'
        if ($ShowResult) { $arguments += ' -ShowResult' }
        if ($PreserveChangedRules) { $arguments += ' -PreserveChangedRules' }
        if ($DesktopRequestId) { $arguments += ' -DesktopRequestId ' + $DesktopRequestId + ' -DesktopPid ' + $DesktopPid }
        try {
            $child = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
            Write-Host ('Elevated repair exit code: ' + $child.ExitCode)
            Write-Host ('Report: ' + (Join-Path $RuntimeRoot 'network-repair\last-result.json'))
            $delegated = $true
            exit $child.ExitCode
        } catch { $exitCode=2; Repair-Failure 'UAC_CANCELED_OR_ELEVATION_FAILED' }
    }
    $script:repairStage = 'validate-journal'
    $journalPath = Assert-RepairPath (Join-Path $RuntimeRoot '.network-lock\journal.json')
    $journal = Get-Content -LiteralPath $journalPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $isWfp = $journal.version -eq 2 -and $journal.engine -ceq 'wfp'
    if ($isWfp) { Assert-WfpRepairJournal $journal }
    else {
        Assert-RepairJournal $journal
        $script:repairStage = 'verify-backup'
        $backupPath = Assert-RepairPath (Join-Path $RuntimeRoot ('.network-lock\' + $journal.id + '.wfw'))
        if ((Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $journal.backupHash) { Repair-Failure 'RECOVERY_BACKUP_HASH_MISMATCH' }
        $script:repairStage = 'check-managed-policy'
        $policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
        if (Test-Path -LiteralPath $policyRoot) {
            foreach ($key in @((Get-Item -LiteralPath $policyRoot)) + @(Get-ChildItem -LiteralPath $policyRoot -Recurse)) {
                if ($key.GetValueNames().Count) { Repair-Failure 'MANAGED_FIREWALL_POLICY_PRESENT' }
            }
        }
    }
    if ($DesktopRequestId) { Wait-DesktopRepair $RuntimeRoot $DesktopRequestId $DesktopPid }
    $script:repairStage = 'archive-journal'
    $archive = Assert-RepairPath (Join-Path $RuntimeRoot 'network-repair') -AllowMissing
    [void][IO.Directory]::CreateDirectory($archive)
    [void](Assert-RepairPath $archive)
    Copy-Item -LiteralPath $journalPath -Destination (Join-Path $archive ('journal-before-' + [Guid]::NewGuid().ToString() + '.json'))
    $result.details = $(if ($isWfp) { Invoke-WfpRepair $journal $journalPath } else { Invoke-SelectiveRepair $journal $journalPath -PreserveChangedRules:$PreserveChangedRules })
    $result.lockReleased=$result.details.lockReleased; $result.managedBaselineRestored=$result.details.managedBaselineRestored
    $result.success=$true; $result.code=$(if ($isWfp) { 'LOCAL_WFP_LOCK_RELEASED' } elseif ($result.details.skippedAllowRules) { 'LOCAL_LOCK_RELEASED_WITH_PRESERVED_RULES' } else { 'LOCAL_FIREWALL_RESTORED' }); $exitCode=0
} catch {
    $result.error=Get-RepairErrorInfo $_
    if ($script:repairMutationStarted) { $exitCode=4 }
    $code = [string]$_.Exception.Message
    if ($code -cnotmatch '^[A-Z][A-Z_]+$') { $code='WINDOWS_REPAIR_OPERATION_FAILED' }
    $result.code=$code
} finally {
    if (-not $delegated) {
        $result.stage=$script:repairStage
        $result.conflicts=@($script:repairConflicts)
        if ($PreserveChangedRules) { $result.preservedRules=@($script:repairConflicts); $result.skippedAllowRules=$result.preservedRules.Count }
        $result.completedAt=[DateTime]::UtcNow.ToString('o'); $result.exitCode=$exitCode
        if ($RuntimeRoot) { try { $resultPath=Write-RepairResult $result $RuntimeRoot } catch { Write-Host 'Repair report could not be saved. Preserve the original recovery files.' } }
        Write-Host ('MC Proxy repair: ' + $result.code)
        if (-not $result.success) { Write-Host ('Repair stage: ' + $result.stage) }
        try { Show-RepairResult $result $resultPath } catch {}
    }
}
exit $exitCode
