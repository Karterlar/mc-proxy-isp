import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const script = fileURLToPath(new URL('../../tools/offline-chain-test/Repair-Network.ps1', import.meta.url));

test('offline WFP recovery runs only the protected fixed helper and never invokes legacy firewall restoration', () => {
  const source = readFileSync(script, 'utf8');
  const helper = source.split('function Get-ProtectedWfpHelper {')[1].split('function Assert-WfpRepairObservation')[0];
  assert.match(helper, /CommonApplicationData/); assert.match(helper, /MC Proxy\\NetworkLock-v1/);
  assert.match(helper, /MCProxy\.NetworkLock\.exe/); assert.match(helper, /GetAccessRules/);
  assert.match(helper, /\.FileName = Get-ProtectedWfpHelper/); assert.match(helper, /UseShellExecute = \$false/);
  assert.doesNotMatch(helper, /Journal.*\.exe|\.Arguments.*Journal|Start-Process|\.Kill\(/);
  const repair = source.split('function Invoke-WfpRepair(')[1].split('function Invoke-SelectiveRepair(')[0];
  assert.doesNotMatch(repair, /NetFirewall|Read-RepairPolicy|SelectiveRepair|backupHash|netsh|\.wfw/);
  assert.ok(repair.indexOf("$Journal.phase='unlocking'") < repair.indexOf("operation='clear'"));
  assert.ok(repair.indexOf("verify-owned-wfp-absence") < repair.indexOf("$Journal.phase='unlocked'"));
  assert.match(source, /if \(\$DesktopRequestId\) \{ Wait-DesktopRepair/);
  assert.match(source, /\$isWfp = \$journal\.version -eq 2 -and \$journal\.engine -ceq 'wfp'/);
  assert.match(source, /if \(\$isWfp\) \{ Invoke-WfpRepair \$journal \$journalPath \} else \{ Invoke-SelectiveRepair/);
  assert.doesNotMatch(helper, /operation='apply'|--service|CreateService|Start-Service/);
  assert.match(source, /LOCAL_WFP_LOCK_RELEASED/);
});

test('isolated PowerShell WFP repair covers pending, partial, lost response, failed commit and identity conflicts', { skip: process.platform !== 'win32' }, () => {
  const cache = fileURLToPath(new URL('../../.cache/', import.meta.url));
  mkdirSync(cache, { recursive: true });
  const directory = mkdtempSync(path.join(cache, 'wfp-repair-fixture-'));
  try {
    const fixturePath = path.join(directory, 'fixture.ps1');
    const source = String.raw`
$ErrorActionPreference='Stop'
. '${script.replaceAll("'", "''")}' -LibraryOnly
function Check($condition,[string]$message) { if (-not $condition) { throw $message } }
function Clone($value) { return ($value | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json) }
function Refuses($work,[string]$code) { $actual=$null; try { & $work } catch { $actual=$_.Exception.Message }; Check ($actual -ceq $code) ('Expected ' + $code + ', got ' + $actual) }
function Assert-RepairIdle([string]$CorePath) { $script:idleChecks++ }
function Save-RepairJournal($Journal,[string]$Path) { $script:saves+=@((Clone $Journal)) }
function Read-RepairPolicy { throw 'FOREIGN_FIREWALL_SCAN_FORBIDDEN' }
function Get-NetFirewallRule { throw 'FOREIGN_FIREWALL_SCAN_FORBIDDEN' }
function Set-NetFirewallProfile { throw 'FOREIGN_FIREWALL_MUTATION_FORBIDDEN' }
function Set-NetFirewallRule { throw 'FOREIGN_FIREWALL_MUTATION_FORBIDDEN' }
function Remove-NetFirewallRule { throw 'FOREIGN_FIREWALL_MUTATION_FORBIDDEN' }
function Get-ProtectedWfpHelper { throw 'REAL_HELPER_EXECUTION_FORBIDDEN' }
function Invoke-WfpHelper($Request) {
    $script:calls+=@((Clone $Request))
    if ($Request.operation -ceq 'inspect') { if ($script:mode -ceq 'inspection-failed') { throw 'FIXTURE_INSPECTION_FAILED' }; return Clone $script:observed }
    Check ($Request.operation -ceq 'clear') 'Only clear may mutate'
    Check ($script:saves[-1].phase -ceq 'unlocking') 'Journal must be persisted before native clear'
    Check ($Request.id -ceq $script:observed.id -and $Request.expectedFingerprint -ceq $script:observed.fingerprint) 'Native clear must carry the fresh CAS identity'
    if ($script:mode -ceq 'before-commit') { throw 'FIXTURE_CLEAR_FAILED' }
    $script:observed=[pscustomobject]@{present=$false;verified=$true;ownedFilterCount=0}
    if ($script:mode -ceq 'lost-response') { throw 'FIXTURE_RESPONSE_LOST' }
    return Clone $script:observed
}
$journal=[pscustomobject]@{version=2;engine='wfp';id='dcf6b070-78c7-4b7a-9186-4785fc414383';binding=('a'*64);corePath='D:\fixture\sing-box.exe';endpoint=[pscustomobject]@{host='pinned.example';ip='192.0.2.9';port=443;protocol='TCP'};phase='active';fingerprint=('b'*64);includeTun=$true;createdAt='2026-10-06T00:00:00.000Z'}
$base=[pscustomobject]@{present=$true;verified=$true;serviceReady=$true;bootProtected=$false;ownedFilterCount=12;id=$journal.id;binding=$journal.binding;corePath=$journal.corePath;endpoint=$journal.endpoint;fingerprint=$journal.fingerprint}
foreach ($mode in @('success','lost-response','partial')) {
    $script:mode=$mode; $script:observed=Clone $base; $script:saves=@(); $script:calls=@(); $script:idleChecks=0
    if ($mode -ceq 'partial') { $script:observed.verified=$false; $script:observed.serviceReady=$false }
    $working=Clone $journal
    $result=Invoke-WfpRepair $working 'D:\fixture\journal.json'
    Check ($result.lockReleased -and -not $result.managedBaselineRestored -and -not $result.fullPolicyBaselineVerified) 'WFP report claims only owned lock removal'
    Check ($working.phase -ceq 'unlocked' -and $null -eq $working.fingerprint -and -not $working.includeTun) 'Only verified absence marks journal unlocked'
    Check ($script:calls.Count -eq 3 -and $script:calls[1].operation -ceq 'clear') 'Exactly inspect, clear, inspect'
    Check ($script:idleChecks -eq 2) 'Sessions are checked idle before removal'
}
$script:mode='success'; $script:observed=Clone $base; $script:saves=@(); $script:calls=@(); $working=Clone $journal
$working.phase='arming'; $working.fingerprint=$null
[void](Invoke-WfpRepair $working 'D:\fixture\journal.json')
Check ($script:calls[1].expectedFingerprint -ceq $base.fingerprint) 'Interrupted initial activation uses actual observed fingerprint'
$script:observed=Clone $base; $script:mode='before-commit'; $script:saves=@(); $script:calls=@(); $working=Clone $journal
Refuses { Invoke-WfpRepair $working 'D:\fixture\journal.json' } 'FIXTURE_CLEAR_FAILED'
Check ($working.phase -ceq 'unlocking' -and $script:saves[-1].phase -ceq 'unlocking' -and $script:observed.present) 'Failed clear preserves active policy and recovery record'
foreach ($field in @('id','binding','corePath','fingerprint')) {
    $script:mode='success'; $script:observed=Clone $base; $script:observed.$field='different'; $script:saves=@(); $script:calls=@()
    Refuses { Invoke-WfpRepair (Clone $journal) 'D:\fixture\journal.json' } 'WFP_RECOVERY_POLICY_CONFLICT'
    Check ($script:calls.Count -eq 1 -and $script:saves.Count -eq 0) 'Identity conflict refuses before mutation'
}
$script:mode='inspection-failed'; $script:observed=Clone $base; $script:saves=@(); $script:calls=@()
Refuses { Invoke-WfpRepair (Clone $journal) 'D:\fixture\journal.json' } 'FIXTURE_INSPECTION_FAILED'
Check ($script:saves.Count -eq 0) 'Unreadable inspection does not mutate journal or rules'
$script:mode='success'; $script:observed=[pscustomobject]@{present=$false;verified=$true;ownedFilterCount=0}; $script:saves=@(); $script:calls=@()
$working=Clone $journal
[void](Invoke-WfpRepair $working 'D:\fixture\journal.json')
Check ($script:calls.Count -eq 1 -and $working.phase -ceq 'unlocked') 'Already absent policy needs no native clear'
foreach ($invalid in @('version','engine','id','binding','corePath','includeTun','fingerprint')) {
    $working=Clone $journal; $working.$invalid=@('invalid'); $script:calls=@(); $script:saves=@()
    Refuses { Invoke-WfpRepair $working 'D:\fixture\journal.json' } 'INVALID_WFP_RECOVERY_JOURNAL'
    Check ($script:calls.Count -eq 0) 'Invalid journal refuses before helper access'
}
'isolated WFP recovery checks passed'
`;
    writeFileSync(fixturePath, source);
    const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', fixturePath],
      { encoding: 'utf8', windowsHide: true, timeout: 30000 });
    assert.equal(result.status, 0, (result.stdout || '') + (result.stderr || '') + (result.error?.message || ''));
    assert.match(result.stdout, /isolated WFP recovery checks passed/);
  } finally {
    assert.ok(path.resolve(directory).startsWith(path.resolve(cache) + path.sep));
    rmSync(directory, { recursive: true, force: true });
  }
});
