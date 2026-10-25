import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { tmpdir } from 'node:os';

const script = fileURLToPath(new URL('../../tools/offline-chain-test/Repair-Network.ps1', import.meta.url));
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const hash = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');

test('desktop repair handshake requires session release and writes a request-bound final report', { skip: process.platform !== 'win32' }, () => {
  const folder = mkdtempSync(path.join(tmpdir(), 'mc-proxy-repair-handshake-'));
  const requestId = '5523e83d-5f34-47ed-b137-6496716baec3';
  const source = String.raw`
$ErrorActionPreference='Stop'
. '${script.replaceAll("'", "''")}' -LibraryOnly
$root=$env:MC_PROXY_REPAIR_ROOT
$owner=[int]$env:MC_PROXY_DESKTOP_PID
$request='${requestId}'
$directory=Join-Path $root 'network-repair'
[void][IO.Directory]::CreateDirectory($directory)
$continue=Join-Path $directory ('desktop-' + $request + '.continue')
[IO.File]::WriteAllText($continue,$request)
Wait-DesktopRepair $root $request $owner
if ([IO.File]::ReadAllText((Join-Path $directory ('desktop-' + $request + '.ready'))) -cne $request) { throw 'READY_REQUEST_MISMATCH' }
$report=[ordered]@{desktopRequestId=$request;success=$true;code='LOCAL_FIREWALL_RESTORED';exitCode=0;lockReleased=$true}
[void](Write-RepairResult $report $root)
$saved=Get-Content -LiteralPath (Join-Path $directory ('desktop-' + $request + '.result.json')) -Raw | ConvertFrom-Json
if ($saved.desktopRequestId -cne $request -or -not $saved.success) { throw 'FINAL_REQUEST_MISMATCH' }
Remove-Item -LiteralPath (Join-Path $directory ('desktop-' + $request + '.ready'))
[IO.File]::WriteAllText($continue,'cancel')
$code=$null
try { Wait-DesktopRepair $root $request $owner } catch { $code=$_.Exception.Message }
if ($code -cne 'DESKTOP_REPAIR_CANCELED') { throw 'CANCELED_REQUEST_RELEASED' }
$code=$null
try { Wait-DesktopRepair $root '../invalid' $owner } catch { $code=$_.Exception.Message }
if ($code -cne 'INVALID_DESKTOP_REQUEST') { throw 'INVALID_REQUEST_ACCEPTED' }
'desktop handshake checks passed'
`;
  try {
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(source, 'utf16le').toString('base64')], {
      encoding: 'utf8', windowsHide: true, timeout: 10000, env: { ...process.env, MC_PROXY_REPAIR_ROOT: folder, MC_PROXY_DESKTOP_PID: String(process.pid) },
    });
    assert.equal(result.status, 0, result.stdout + result.stderr + (result.error?.message || ''));
    assert.match(result.stdout, /desktop handshake checks passed/);
  } finally {
    assert.ok(path.resolve(folder).startsWith(path.resolve(tmpdir()) + path.sep));
    rmSync(folder, { recursive: true, force: true });
  }
});

test('offline repair planner and mocked mutations restore only owned changes, fail safely and resume partial recovery', { skip: process.platform !== 'win32' }, () => {
  const id = 'f558ca91-e511-4076-b72e-e1afe7ab534b';
  const corePath = 'D:\\MC Proxy Data\\core\\sing-box.exe';
  const profile = name => ({ name, enabled: 'False', defaultOutboundAction: 'NotConfigured', disabledInterfaceAliases: ['NotConfigured'], allowLocalFirewallRules: 'NotConfigured', details: { inbound: 'Block' } });
  const rule = (name, values = {}) => ({ name, enabled: 'True', direction: 'Outbound', action: 'Allow', profile: 'Any', protocol: 'TCP', program: 'Any', remoteAddress: ['Any'], remotePort: ['Any'], interfaceAlias: ['Any'], ...values });
  const managed = [
    rule(`ProxyPilot-Lock-${id}-isp`, { program: corePath, remoteAddress: ['192.0.2.1'], remotePort: ['1080'] }),
    rule(`ProxyPilot-Lock-${id}-loopback`, { remoteAddress: ['127.0.0.1', '::1'] }),
    rule(`ProxyPilot-Lock-${id}-tun-tcp`, { interfaceAlias: ['ProxyPilot'] }),
    rule(`ProxyPilot-Lock-${id}-tun-dns`, { interfaceAlias: ['ProxyPilot'], protocol: 'UDP', remotePort: ['53'] }),
  ];
  const detail = { rule: { description: 'literal <tag> & 中文 "quote" \\ slash\nline', untouched: 'value' }, filters: { Security: { OverrideBlockRules: 'False' }, Service: { Service: 'Any' } } };
  const originalRule = { ...rule('existing-allow'), details: structuredClone(detail) };
  const untouched = { ...rule('existing-block', { action: 'Block', enabled: 'False' }), details: structuredClone(detail) };
  const owned = managed.map(rule => ({ ...structuredClone(rule), details: structuredClone(detail) }));
  const journal = { version: 1, id, binding: 'a'.repeat(64), backupHash: 'b'.repeat(64), endpoint: { ip: '192.0.2.1', port: 1080 }, corePath, phase: 'unlocking', before: { profiles: ['Domain', 'Private', 'Public'].map(profile), rules: [originalRule, untouched] }, rules: managed, ruleFingerprints: Object.fromEntries(owned.map(rule => [rule.name, hash(rule)])) };
  const current = { profiles: journal.before.profiles.map(profile => ({ ...structuredClone(profile), enabled: 'True', defaultOutboundAction: 'Block' })), rules: [{ ...structuredClone(originalRule), enabled: 'False' }, structuredClone(untouched), ...owned, { ...rule('foreign-new-allow'), details: structuredClone(detail) }, { ...rule('foreign-new-block', { action: 'Block' }), details: structuredClone(detail) }] };
  const payload = Buffer.from(JSON.stringify({ journal, current, fingerprint: hash(owned[0]), allowIdentityHash: hash(originalRule.name) })).toString('base64');
  const source = String.raw`
$ErrorActionPreference = 'Stop'
$repairSource = '${script.replaceAll("'", "''")}'
$tokens=$null; $errors=$null
[void][Management.Automation.Language.Parser]::ParseFile($repairSource,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | ForEach-Object Message | Out-String) }
. $repairSource -LibraryOnly
$fixture = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:MC_PROXY_REPAIR_FIXTURE)) | ConvertFrom-Json
function Check($condition,[string]$message) { if (-not $condition) { throw $message } }
function Clone($value) { return ($value | ConvertTo-Json -Depth 40 -Compress | ConvertFrom-Json) }
function Refuses([scriptblock]$work,[string]$code) {
    $seen=$null; try { & $work } catch { $seen=$_.Exception.Message }
    Check ($seen -ceq $code) ('Expected ' + $code + ', got ' + $seen)
}
$journal=Clone $fixture.journal; $current=Clone $fixture.current
Check ((Rule-Digest $current.rules[2]) -ceq $fixture.fingerprint) 'JS-compatible fingerprint including Unicode/HTML/escape characters'
$plan=New-RepairPlan $journal $current
Check ($plan.profiles.Count -eq 3 -and $plan.rules.Count -eq 1 -and $plan.remove.Count -eq 4) 'Owned changes planned'
Check ($plan.rules.name -cnotcontains 'foreign-new-allow') 'New foreign allow preserved'
$restored=Clone $current
$restored.profiles=Clone $journal.before.profiles
$restored.rules=@((Clone $journal.before.rules)) + @($current.rules | Where-Object { $_.name -like 'foreign-new-*' })
$done=New-RepairPlan $journal $restored
Check ($done.profiles.Count -eq 0 -and $done.rules.Count -eq 0 -and $done.remove.Count -eq 0) 'Repeated repair is idempotent'
$partial=Clone $journal; $partial.ruleFingerprints=[pscustomobject]@{}
$partialCurrent=Clone $current; $partialCurrent.rules=@($partialCurrent.rules | Where-Object { $_.name -notlike '*-tun-tcp' -and $_.name -notlike '*-tun-dns' })
Check ((New-RepairPlan $partial $partialCurrent).remove.Count -eq 2) 'Real incident partial arming without fingerprints is recoverable'
$changed=Clone $current; $changed.rules[2].remotePort=@('9999')
Refuses { New-RepairPlan $partial $changed } 'MANAGED_RULE_CHANGED_OR_OTHER_LOCK_EXISTS'
$changed=Clone $current; $changed.rules[2].details.rule.untouched='changed'
Refuses { New-RepairPlan $journal $changed } 'MANAGED_RULE_FINGERPRINT_MISMATCH'
$changed=Clone $current; $changed.profiles[0].details.inbound='Allow'
Refuses { New-RepairPlan $journal $changed } 'PROFILE_CHANGED_OUTSIDE_MC_PROXY'
$changed=Clone $current; $changed.rules=@($changed.rules | Where-Object { $_.name -cne 'existing-allow' })
Refuses { New-RepairPlan $journal $changed } 'ORIGINAL_ALLOW_RULE_MISSING'
$changed=Clone $current; $changed.rules[0].details.filters.Service.Service='unexpected'
Refuses { New-RepairPlan $journal $changed } 'ALLOW_RULE_CHANGED_OUTSIDE_MC_PROXY'
Check ($script:repairConflicts.Count -eq 1 -and $script:repairConflicts[0].originalRuleIndex -eq 0 -and $script:repairConflicts[0].identityHash -ceq $fixture.allowIdentityHash) 'Strict rejection identifies the backed-up rule without raw name'
Check ($script:repairConflicts[0].changedFields -ccontains 'details.filters.Service.Service') 'Strict rejection identifies changed nested field'
$diagnostics=$script:repairConflicts | ConvertTo-Json -Depth 10 -Compress
Check ($diagnostics -notmatch 'existing-allow|unexpected|literal|sing-box|192\.0\.2') 'Conflict diagnostics contain no raw rule values'
$preserved=New-RepairPlan $journal $changed -PreserveChangedRules
Check ($preserved.conflicts.Count -eq 1 -and $preserved.rules.Count -eq 0 -and $preserved.profiles.Count -eq 3 -and $preserved.remove.Count -eq 4) 'Opted-in changed rule stays outside all writes while lock release is planned'
$changed.rules[0].enabled='True'
Check ((New-RepairPlan $journal $changed -PreserveChangedRules).conflicts.Count -eq 1) 'Changed already-enabled allow is still preserved and disclosed'
$missing=Clone $current; $missing.rules=@($missing.rules | Where-Object { $_.name -cne 'existing-allow' })
$preserved=New-RepairPlan $journal $missing -PreserveChangedRules
Check ($preserved.conflicts.Count -eq 1 -and $preserved.conflicts[0].code -ceq 'ORIGINAL_ALLOW_RULE_MISSING' -and $preserved.rules.Count -eq 0) 'Opted-in missing rule is not recreated'
$changed=Clone $current; $changed.profiles[0].details.inbound='Allow'
Refuses { New-RepairPlan $journal $changed -PreserveChangedRules } 'PROFILE_CHANGED_OUTSIDE_MC_PROXY'
$changed=Clone $current; $changed.rules[2].remotePort=@('9999')
Refuses { New-RepairPlan $journal $changed -PreserveChangedRules } 'MANAGED_RULE_CHANGED_OR_OTHER_LOCK_EXISTS'
$changed=Clone $current; $changed.rules[2].details.rule.untouched='changed'
Refuses { New-RepairPlan $journal $changed -PreserveChangedRules } 'MANAGED_RULE_FINGERPRINT_MISMATCH'
$invalid=Clone $journal; $invalid.rules[0].action='Block'
Refuses { New-RepairPlan $invalid $current } 'INVALID_RECOVERY_JOURNAL'
Refuses { Assert-RepairPath '\\server\share\runtime' } 'UNSAFE_PATH'

# Old journals omit protocol. New imported-node journals must pin TCP or UDP
# exactly; the recovery planner never substitutes an unrestricted protocol.
$explicitTcp=Clone $journal; $explicitTcp.endpoint | Add-Member protocol 'TCP'
Check ((New-RepairPlan $explicitTcp $current).remove.Count -eq 4) 'Explicit TCP remains compatible with legacy rules'
$udpJournal=Clone $partial; $udpJournal.endpoint | Add-Member protocol 'UDP'; $udpJournal.rules[0].protocol='UDP'
$udpCurrent=Clone $current; $udpCurrent.rules[2].protocol='UDP'
Check ((New-RepairPlan $udpJournal $udpCurrent).remove.Count -eq 4) 'Pinned UDP recovery plans only the four owned rules'
foreach ($protocol in @('Any','udp','',17,$null,@('UDP','TCP'))) {
    $invalid=Clone $udpJournal; $invalid.endpoint.protocol=$protocol
    Refuses { New-RepairPlan $invalid $udpCurrent } 'INVALID_RECOVERY_JOURNAL'
}
$invalid=Clone $udpJournal; $invalid.rules[0].protocol='TCP'
Refuses { New-RepairPlan $invalid $udpCurrent } 'INVALID_RECOVERY_JOURNAL'
$invalid=Clone $journal; $invalid.rules[0].protocol='UDP'
Refuses { New-RepairPlan $invalid $udpCurrent } 'INVALID_RECOVERY_JOURNAL'
$changed=Clone $udpCurrent; $changed.rules[2].protocol='TCP'
Refuses { New-RepairPlan $udpJournal $changed } 'MANAGED_RULE_CHANGED_OR_OTHER_LOCK_EXISTS'

# Exercise the mutation driver with cmdlets replaced in this isolated process.
# No production Windows networking cmdlet can be reached by these fixtures.
$script:mockPolicy=Clone $current; $script:saves=@(); $script:operations=@(); $script:failOperation=$null; $script:lateRuleChange=$null
function Assert-RepairIdle($core) {}
function Read-RepairPolicy { return Clone $script:mockPolicy }
function Save-RepairJournal($value,$file) { $script:saves += $value.phase }
function Read-RepairNamedRule($name,[switch]$AllowMissing) {
    if ($name -ceq 'existing-allow' -and $script:lateRuleChange) {
        if ($script:lateRuleChange -ceq 'missing') { $script:mockPolicy.rules=@($script:mockPolicy.rules | Where-Object { $_.name -cne $name }) }
        else { ($script:mockPolicy.rules | Where-Object { $_.name -ceq $name }).details.filters.Service.Service='late-external-service' }
        $script:lateRuleChange=$null
    }
    $rule=@($script:mockPolicy.rules | Where-Object { $_.name -ceq $name })[0]
    if ($null -eq $rule) { return $null }
    return [pscustomobject]@{native=[pscustomobject]@{name=$name};snapshot=(Clone $rule)}
}
function Read-RepairNamedProfile($name) { return Clone @($script:mockPolicy.profiles | Where-Object { $_.name -ceq $name })[0] }
function Get-NetFirewallRule { param($PolicyStore,$Name,$ErrorAction) return [pscustomobject]@{ name=$Name } }
function Set-NetFirewallRule {
    param($Enabled,[Parameter(ValueFromPipeline=$true)]$InputObject)
    process {
        if ($script:failOperation -eq 'rule') { throw 'FIXTURE_RULE_FAILED' }
        ($script:mockPolicy.rules | Where-Object { $_.name -ceq $InputObject.name }).enabled=[string]$Enabled
        $script:operations += 'rule:' + $InputObject.name
    }
}
function Set-NetFirewallProfile {
    param($PolicyStore,$Name,$Enabled,$DefaultOutboundAction,$ErrorAction)
    if ($script:failOperation -eq 'profile') { throw 'FIXTURE_PROFILE_FAILED' }
    $profile=@($script:mockPolicy.profiles | Where-Object { $_.name -ceq $Name })[0]
    $profile.enabled=[string]$Enabled; $profile.defaultOutboundAction=[string]$DefaultOutboundAction
    $script:operations += 'profile:' + $Name
}
function Remove-NetFirewallRule {
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process {
        $script:mockPolicy.rules=@($script:mockPolicy.rules | Where-Object { $_.name -cne $InputObject.name })
        $script:operations += 'remove:' + $InputObject.name
    }
}
$script:mockPolicy=Clone $udpCurrent; $script:operations=@(); $script:saves=@(); $mutating=Clone $udpJournal
$result=Invoke-SelectiveRepair $mutating 'D:\fixture\journal.json'
Check ($mutating.phase -ceq 'unlocked' -and $result.lockReleased -and $result.managedBaselineRestored) 'UDP recovery verifies exact baseline before unlocking'
Check ($result.managedRulesRemoved -eq 4 -and $result.allowRulesRestored -eq 1 -and $result.profilesRestored -eq 3) 'UDP restoration counts match legacy restoration'
Check (@($script:mockPolicy.rules | Where-Object { $_.name -like 'ProxyPilot-Lock-*' }).Count -eq 0) 'UDP recovery removes all owned rules'
Check ((Same-Value $script:mockPolicy.profiles $udpJournal.before.profiles)) 'UDP recovery restores exact profile settings'
Check (@($script:mockPolicy.rules | Where-Object { $_.name -like 'foreign-new-*' }).Count -eq 2) 'UDP recovery preserves foreign rules'
$script:operations=@(); $invalid=Clone $udpJournal; $invalid.endpoint.protocol='Any'
Refuses { Invoke-SelectiveRepair $invalid 'D:\fixture\journal.json' } 'INVALID_RECOVERY_JOURNAL'
Check ($script:operations.Count -eq 0) 'Invalid protocol refuses before any mutation'
$script:mockPolicy=Clone $current; $script:operations=@(); $script:saves=@()
$mutating=Clone $journal
$result=Invoke-SelectiveRepair $mutating 'D:\fixture\journal.json'
Check ($mutating.phase -ceq 'unlocked' -and $script:saves[-1] -ceq 'unlocked') 'Only verified repair marks unlocked'
Check ($result.allowRulesRestored -eq 1 -and $result.profilesRestored -eq 3 -and $result.managedRulesRemoved -eq 4) 'Mutation report counts'
Check (@($script:mockPolicy.rules | Where-Object { $_.name -ceq 'foreign-new-allow' }).Count -eq 1) 'Foreign rule survives mutation driver'
Check (@($script:mockPolicy.rules | Where-Object { $_.name -ceq 'foreign-new-block' -and $_.action -ceq 'Block' -and $_.enabled -ceq 'True' }).Count -eq 1) 'New foreign block survives mutation driver'
Check (@($script:mockPolicy.profiles | Where-Object { $_.enabled -cne 'False' -or $_.defaultOutboundAction -cne 'NotConfigured' }).Count -eq 0) 'Exact disabled/NotConfigured original profile restored'
$script:mockPolicy=Clone $current; $script:saves=@(); $script:failOperation='profile'; $mutating=Clone $partial
Refuses { Invoke-SelectiveRepair $mutating 'D:\fixture\journal.json' } 'FIXTURE_PROFILE_FAILED'
Check ($mutating.phase -ceq 'repairing' -and $script:saves -cnotcontains 'unlocked') 'Partial mutation is never success'
$script:failOperation=$null
[void](Invoke-SelectiveRepair $mutating 'D:\fixture\journal.json')
Check ($mutating.phase -ceq 'unlocked') 'Partial repair resumes using retained baseline'
$script:mockPolicy=Clone $current; $script:mockPolicy.rules[0].details.rule.untouched='external'; $script:operations=@()
Refuses { Invoke-SelectiveRepair (Clone $journal) 'D:\fixture\journal.json' } 'ALLOW_RULE_CHANGED_OUTSIDE_MC_PROXY'
Check ($script:operations.Count -eq 0) 'Every conflict refuses before firewall writes'

# Explicit fallback only bypasses foreign allow conflicts, never ownership or
# profile validation. Its report distinguishes lock release from full restore.
$script:mockPolicy=Clone $current; $script:mockPolicy.rules[0].details.filters.Service.Service='external-secret-service'; $script:operations=@(); $script:saves=@()
$mutating=Clone $journal
$result=Invoke-SelectiveRepair $mutating 'D:\fixture\journal.json' -PreserveChangedRules
Check ($result.lockReleased -and -not $result.managedBaselineRestored -and $result.skippedAllowRules -eq 1 -and $result.allowRulesRestored -eq 0 -and -not $result.fullPolicyBaselineVerified) 'Fallback reports verified release with preserved external rule'
Check ($mutating.phase -ceq 'unlocked' -and -not $mutating.recovery.managedBaselineRestored -and $mutating.recovery.preservedRules.Count -eq 1 -and -not $mutating.recovery.fullPolicyBaselineVerified) 'Verified fallback marks only lock release complete and retains conflict metadata'
Check (($script:mockPolicy.rules | Where-Object { $_.name -ceq 'existing-allow' }).enabled -ceq 'False') 'Changed disabled rule is never reenabled'
Check (($script:mockPolicy.rules | Where-Object { $_.name -ceq 'existing-allow' }).details.filters.Service.Service -ceq 'external-secret-service') 'Changed service value is preserved'
Check (@($script:mockPolicy.rules | Where-Object { $_.name -like 'foreign-new-*' }).Count -eq 2) 'New foreign allow and block are preserved in fallback'
Check (@($script:mockPolicy.profiles | Where-Object { $_.enabled -cne 'False' -or $_.defaultOutboundAction -cne 'NotConfigured' }).Count -eq 0) 'Fallback restores the incident original disabled profiles exactly'
Check (($result | ConvertTo-Json -Depth 10 -Compress) -notmatch 'external-secret-service|existing-allow') 'Fallback report omits raw rule name and values'
$script:operations=@()
$result=Invoke-SelectiveRepair $mutating 'D:\fixture\journal.json' -PreserveChangedRules
Check ($script:operations.Count -eq 0 -and $result.skippedAllowRules -eq 1) 'Repeated fallback is idempotent and retains warning'
$script:mockPolicy=Clone $missing; $script:operations=@(); $mutating=Clone $journal
$result=Invoke-SelectiveRepair $mutating 'D:\fixture\journal.json' -PreserveChangedRules
Check ($result.skippedAllowRules -eq 1 -and $result.preservedRules[0].code -ceq 'ORIGINAL_ALLOW_RULE_MISSING' -and $result.allowRulesRestored -eq 0 -and $mutating.phase -ceq 'unlocked') 'Missing foreign rule stays absent while lock release is verified'

# Safe unchanged rules must still be restored when another rule conflicts.
$mixedJournal=Clone $journal; $mixedCurrent=Clone $current
$second=Clone $journal.before.rules[0]; $second.name='second-unchanged-allow'
$mixedJournal.before.rules=@($mixedJournal.before.rules) + @($second)
$disabledSecond=Clone $second; $disabledSecond.enabled='False'
$mixedCurrent.rules=@($mixedCurrent.rules) + @($disabledSecond)
$mixedCurrent.rules[0].program='external-program'; $mixedCurrent.rules[0].action='Block'
$script:mockPolicy=Clone $mixedCurrent; $script:operations=@()
$result=Invoke-SelectiveRepair $mixedJournal 'D:\fixture\journal.json' -PreserveChangedRules
Check ($result.allowRulesRestored -eq 1 -and $result.skippedAllowRules -eq 1) 'Fallback still restores unchanged disabled allows'
Check (($script:mockPolicy.rules | Where-Object { $_.name -ceq 'second-unchanged-allow' }).enabled -ceq 'True') 'Unchanged sibling reenabled'
Check (($script:mockPolicy.rules | Where-Object { $_.name -ceq 'existing-allow' }).action -ceq 'Block' -and ($script:mockPolicy.rules | Where-Object { $_.name -ceq 'existing-allow' }).enabled -ceq 'False') 'Externally replaced block stays untouched'

foreach ($late in @('changed','missing')) {
    $script:mockPolicy=Clone $current; $script:lateRuleChange=$late; $script:operations=@(); $mutating=Clone $journal
    $result=Invoke-SelectiveRepair $mutating 'D:\fixture\journal.json' -PreserveChangedRules
    Check ($result.allowRulesRestored -eq 0 -and $result.skippedAllowRules -eq 1 -and $mutating.phase -ceq 'unlocked') ('Late external ' + $late + ' is skipped and reported with actual mutation counts')
    Check ($script:operations -cnotcontains 'rule:existing-allow') 'Freshly conflicted rule never reaches mutation'
}
$script:mockPolicy=Clone $current; $script:lateRuleChange='changed'; $script:operations=@(); $script:saves=@(); $mutating=Clone $journal
Refuses { Invoke-SelectiveRepair $mutating 'D:\fixture\journal.json' } 'ALLOW_RULE_CHANGED_OUTSIDE_MC_PROXY'
Check ($mutating.phase -ceq 'repairing' -and $script:saves -cnotcontains 'unlocked' -and $script:operations.Count -eq 0) 'Strict mode still refuses late change and never falsely completes'
'repair fixture checks passed'
`;
  // Keep the expanded isolated fixture below Windows' command-line size limit.
  const folder = mkdtempSync(path.join(tmpdir(), 'mc-proxy-repair-driver-test-'));
  try {
    const fixtureScript = path.join(folder, 'fixture.ps1');
    writeFileSync(fixtureScript, source);
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', fixtureScript], { encoding: 'utf8', windowsHide: true, timeout: 30000, env: { ...process.env, MC_PROXY_REPAIR_FIXTURE: payload } });
    assert.equal(result.status, 0, (result.stdout || '') + (result.stderr || '') + (result.error?.message || ''));
    assert.match(result.stdout, /repair fixture checks passed/);
  } finally {
    assert.ok(path.resolve(folder).startsWith(path.resolve(tmpdir()) + path.sep));
    rmSync(folder, { recursive: true, force: true });
  }
});

test('offline repair contains no global firewall/network reset and self-elevation cannot overwrite the child report', () => {
  const source = readFileSync(script, 'utf8');
  assert.doesNotMatch(source, /advfirewall\s+(?:reset|import)|netsh\s+int|Reset-Net|Set-Dns|Remove-NetRoute|Stop-Process|taskkill/i);
  assert.match(source, /-Verb RunAs -WindowStyle Hidden -Wait -PassThru/);
  assert.match(source, /if \(-not \$delegated\)/);
  assert.match(source, /WaitForPid/);
  assert.match(source, /RECOVERY_BACKUP_HASH_MISMATCH/);
  assert.match(source, /if \(\$PreserveChangedRules\) \{ \$arguments \+= ' -PreserveChangedRules' \}/);
  assert.match(source, /LOCAL_LOCK_RELEASED_WITH_PRESERVED_RULES/);
  assert.match(source, /internetConnectivityVerified=\$false/);
  assert.match(source, /fullPolicyBaselineVerified=\$false/);
  assert.doesNotMatch(source, /[;.]\s*baselineRestored/);
  assert.match(source, /\$result = \[ordered\]@\{ version=3;/);
});

test('real Windows PowerShell journal saves twice, preserves fields and leaves the prior file intact on replacement failure', { skip: process.platform !== 'win32' }, () => {
  const folder = mkdtempSync(path.join(tmpdir(), 'mc-proxy-repair-journal-test-'));
  try {
    const journalPath = path.join(folder, 'journal.json');
    const original = { version: 1, phase: 'unlocking', id: 'retained-identity', before: { profiles: [{ name: 'Domain', enabled: 'False', defaultOutboundAction: 'NotConfigured' }], rules: [{ name: 'retained-rule', details: { description: 'literal <tag> & 中文 "quote" \\ slash\nline', nested: { arrays: ['first', 'second'], bool: false, nullable: null } } }] }, unknownField: { retained: true } };
    writeFileSync(journalPath, JSON.stringify(original));
    const source = String.raw`
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
. '${script.replaceAll("'", "''")}' -LibraryOnly
function Check($condition,[string]$message) { if (-not $condition) { throw $message } }
Check ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'Run the real save regression under Windows PowerShell 5.1'
$journalPath=$env:MC_PROXY_REPAIR_JOURNAL_PATH
$original=Get-Content -LiteralPath $journalPath -Raw -Encoding UTF8 | ConvertFrom-Json
$originalFields=Without-Fields $original @('phase')
$journal=Get-Content -LiteralPath $journalPath -Raw -Encoding UTF8 | ConvertFrom-Json
$journal.phase='repairing'
Save-RepairJournal $journal $journalPath
$saved=Get-Content -LiteralPath $journalPath -Raw -Encoding UTF8 | ConvertFrom-Json
Check ($saved.phase -ceq 'repairing' -and (Same-Value (Without-Fields $saved @('phase')) $originalFields)) 'First real journal replacement preserves all original fields'
$saved.phase='unlocked'
Save-RepairJournal $saved $journalPath
$saved=Get-Content -LiteralPath $journalPath -Raw -Encoding UTF8 | ConvertFrom-Json
Check ($saved.phase -ceq 'unlocked' -and (Same-Value (Without-Fields $saved @('phase')) $originalFields)) 'Second real journal replacement preserves all original fields'
Check (@(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($journalPath)) -Filter '*.tmp').Count -eq 0) 'Successful saves leave no temporary files'

# A real sharing violation prevents atomic replacement. No fake Save helper or
# networking cmdlet is involved, and the previous committed journal must survive.
$previous=[IO.File]::ReadAllText($journalPath)
$lock=[IO.File]::Open($journalPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
$failed=$false
try {
    $saved.phase='repairing'
    try { Save-RepairJournal $saved $journalPath } catch { $failed=$true }
} finally { $lock.Dispose() }
Check $failed 'Locked destination must cause a real replacement error'
Check ([IO.File]::ReadAllText($journalPath) -ceq $previous) 'Replacement failure does not damage the committed journal'
Check (@(Get-ChildItem -LiteralPath ([IO.Path]::GetDirectoryName($journalPath)) -Filter '*.tmp').Count -eq 0) 'Failed save cleans its temporary source'

# Error diagnostics may describe the operation and types, never messages,
# target objects or the source line containing those sensitive values.
$script:repairStage='fixture-diagnostics'
$secret='SENSITIVE secret=password-value; C:\PRIVATE\account.json'
$exception=[IO.IOException]::new($secret,[UnauthorizedAccessException]::new($secret))
$record=[Management.Automation.ErrorRecord]::new($exception,'Unsafe "SENSITIVE" target C:\PRIVATE',[Management.Automation.ErrorCategory]::WriteError,$secret)
$diagnostic=Get-RepairErrorInfo $record
Check ($diagnostic.stage -ceq 'fixture-diagnostics' -and $diagnostic.line -is [int]) 'Diagnostic retains fixed stage and numeric source line'
Check ($diagnostic.exceptionType -ceq 'System.IO.IOException' -and $diagnostic.innerExceptionType -ceq 'System.UnauthorizedAccessException') 'Diagnostic retains actionable outer and inner exception types'
Check ($diagnostic.hResult -is [int] -and $diagnostic.innerHResult -is [int]) 'Diagnostic retains numeric HRESULT values'
Check ($diagnostic.errorId -ceq 'OMITTED') 'Unsafe error identity is omitted'
Check (($diagnostic | ConvertTo-Json -Depth 10 -Compress) -notmatch 'SENSITIVE|PRIVATE|password-value|account\.json') 'Diagnostic excludes raw error messages and targets'
Check ($diagnostic.PSObject.Properties.Name -cnotcontains 'message' -and $diagnostic.PSObject.Properties.Name -cnotcontains 'target') 'Diagnostic contains no message or target fields'
$record=[Management.Automation.ErrorRecord]::new($exception,'ArgumentException',[Management.Automation.ErrorCategory]::WriteError,$secret)
Check ((Get-RepairErrorInfo $record).errorId -ceq 'ArgumentException') 'Safe error identity remains actionable'
'real journal fixture checks passed'
`;
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(source, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 10000, env: { ...process.env, MC_PROXY_REPAIR_JOURNAL_PATH: journalPath } });
    assert.equal(result.status, 0, (result.stdout || '') + (result.stderr || '') + (result.error?.message || ''));
    assert.match(result.stdout, /real journal fixture checks passed/);
    const saved = JSON.parse(readFileSync(journalPath, 'utf8'));
    assert.deepEqual(saved, { ...original, phase: 'unlocked' });
  } finally {
    assert.ok(path.resolve(folder).startsWith(path.resolve(tmpdir()) + path.sep));
    rmSync(folder, { recursive: true, force: true });
  }
});

const incident = fileURLToPath(new URL('../../dist/MC Proxy Data/runtime/.network-lock/journal.json', import.meta.url));
test('sanitized incident-size inventory plans all disabled allows and restores exact original profile defaults', { skip: process.platform !== 'win32' || !existsSync(incident) }, () => {
  const record = JSON.parse(readFileSync(incident, 'utf8'));
  const safeEnums = new Set(['True', 'False', 'NotConfigured', 'Allow', 'Block', 'Any', 'Inbound', 'Outbound', 'TCP', 'UDP', 'Domain', 'Private', 'Public']);
  const scrub = value => typeof value === 'string' ? safeEnums.has(value) ? value : 'SANITIZED' : Array.isArray(value) ? value.map(scrub) : value && typeof value === 'object' ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, scrub(item)])) : value;
  const before = scrub(record.before);
  before.rules.forEach((rule, index) => { rule.name = `sanitized-original-${index}`; });
  const corePath = 'D:\\Sanitized MC Proxy Data\\core\\sing-box.exe';
  const rules = record.rules.map(rule => ({ ...structuredClone(rule), program: rule.program === 'Any' ? 'Any' : corePath, remoteAddress: rule.name.endsWith('-isp') ? ['192.0.2.1'] : rule.remoteAddress, remotePort: rule.name.endsWith('-isp') ? ['1080'] : rule.remotePort }));
  const journal = { version: 1, id: record.id, binding: 'a'.repeat(64), backupHash: 'b'.repeat(64), phase: 'unlocking', corePath, endpoint: { ip: '192.0.2.1', port: 1080 }, before, rules, ruleFingerprints: {} };
  const disabled = before.rules.filter(rule => rule.enabled === 'True' && rule.direction === 'Outbound' && rule.action === 'Allow').length;
  const current = { profiles: before.profiles.map(profile => ({ ...structuredClone(profile), enabled: 'True', defaultOutboundAction: 'Block' })), rules: [...before.rules.map(rule => ({ ...structuredClone(rule), enabled: rule.enabled === 'True' && rule.direction === 'Outbound' && rule.action === 'Allow' ? 'False' : rule.enabled })), ...rules.slice(0, 2).map(rule => ({ ...structuredClone(rule), details: {} }))] };
  const folder = mkdtempSync(path.join(tmpdir(), 'mc-proxy-repair-test-'));
  try {
    const fixture = path.join(folder, 'sanitized.json');
    writeFileSync(fixture, JSON.stringify({ journal, current, disabled }));
    const source = String.raw`
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
. '${script.replaceAll("'", "''")}' -LibraryOnly
$fixture=Get-Content -LiteralPath $env:MC_PROXY_REPAIR_FIXTURE_PATH -Raw -Encoding UTF8 | ConvertFrom-Json
$plan=New-RepairPlan $fixture.journal $fixture.current
if ($plan.rules.Count -ne $fixture.disabled -or $plan.remove.Count -ne 2 -or $plan.profiles.Count -ne 3) { throw 'INCIDENT_SIZE_PLAN_MISMATCH' }
if (@($plan.profiles | Where-Object { $_.enabled -cne 'False' -or $_.defaultOutboundAction -cne 'NotConfigured' }).Count) { throw 'INCIDENT_PROFILE_RESTORE_MISMATCH' }
'sanitized incident fixture passed'
`;
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(source, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 45000, env: { ...process.env, MC_PROXY_REPAIR_FIXTURE_PATH: fixture } });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /sanitized incident fixture passed/);
  } finally {
    assert.ok(path.resolve(folder).startsWith(path.resolve(tmpdir()) + path.sep));
    rmSync(folder, { recursive: true, force: true });
  }
});
