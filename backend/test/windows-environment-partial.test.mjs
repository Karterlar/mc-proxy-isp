import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { createWindowsEnvironmentAdapter } from '../src/windows-environment.mjs';

const before = {
  timeZoneId: 'China Standard Time', daylightSavingDisabled: false, homeGeoId: 45,
  culture: 'zh-CN', uiLanguageOverride: null, languages: [{ languageTag: 'zh-CN', inputMethodTips: ['0804:00000804'], handwriting: false }],
  defaultInputMethod: null, cultureFromLanguageListOptOut: false,
};
const target = {
  ...before, timeZoneId: 'Tokyo Standard Time', homeGeoId: 122, culture: 'zh-SG', uiLanguageOverride: 'ja-JP',
  languages: [{ languageTag: 'ja-JP', inputMethodTips: ['0411:00000411'], handwriting: false }, ...before.languages],
  defaultInputMethod: '0411:00000411', cultureFromLanguageListOptOut: true,
};

// Every setter and settings read is shadowed. New-WinUserLanguageList and .NET
// identity parsing only construct in-memory values; these tests never set the OS.
const fixture = String.raw`
$script:State=$env:MC_ENVIRONMENT_FIXTURE_STATE | ConvertFrom-Json
$script:Faults=$env:MC_ENVIRONMENT_FIXTURE_FAULTS | ConvertFrom-Json
$script:Writes=New-Object 'Collections.Generic.List[string]'
function WriteStep($field) {
  $script:Writes.Add($field)
  if ($field -in $script:Faults) { throw (New-Object UnauthorizedAccessException('fixture denial; must not escape to client')) }
}
function Get-WinUserLanguageList {
  $list=New-WinUserLanguageList -Language $script:State.languages[0].languageTag
  $list.Clear()
  foreach ($language in $script:State.languages) {
    $entry=(New-WinUserLanguageList -Language $language.languageTag)[0]
    $entry.InputMethodTips.Clear()
    foreach ($tip in $language.inputMethodTips) { $entry.InputMethodTips.Add($tip) }
    $entry.Handwriting=$language.handwriting; $list.Add($entry)
  }
  Write-Output -NoEnumerate $list
}
function Get-WinUILanguageOverride { if ($script:State.uiLanguageOverride) { return [Globalization.CultureInfo]::GetCultureInfo($script:State.uiLanguageOverride) } }
function Get-WinDefaultInputMethodOverride { if ($script:State.defaultInputMethod) { return [pscustomobject]@{InputMethodTip=$script:State.defaultInputMethod} } }
function Get-TimeZone { return [pscustomobject]@{Id=$script:State.timeZoneId} }
function Get-WinHomeLocation { return [pscustomobject]@{GeoId=$script:State.homeGeoId} }
function Get-Culture { return [Globalization.CultureInfo]::GetCultureInfo($script:State.culture) }
function Get-WinCultureFromLanguageListOptOut { return $script:State.cultureFromLanguageListOptOut }
function Get-ItemProperty {
  param($LiteralPath,$Name)
  if ($LiteralPath -ceq 'HKCU:\Control Panel\International') { return [pscustomobject]@{LocaleName=$script:State.culture;Locale=([Globalization.CultureInfo]::GetCultureInfo($script:State.culture).LCID.ToString('x8'))} }
  if ($LiteralPath -ceq 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts') { return [pscustomobject]@{'Segoe UI (TrueType)'='fixture'} }
  if ($LiteralPath -ceq 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation') { return [pscustomobject]@{DynamicDaylightTimeDisabled=$script:State.daylightSavingDisabled} }
  throw 'Unexpected real registry read'
}
function Get-ChildItem {
  param($LiteralPath)
  if ($LiteralPath -cne 'HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages') { throw 'Unexpected real registry read' }
  return @([pscustomobject]@{PSChildName='zh-CN'},[pscustomobject]@{PSChildName='ja-JP'})
}
function Set-WinUserLanguageList {
  param($LanguageList,[switch]$Force)
  WriteStep 'languages'
  $script:State.languages=@(foreach ($language in $LanguageList) { Language $language })
  $script:State.defaultInputMethod='0409:00000409'
}
function Set-WinUILanguageOverride { param($Language); WriteStep 'uiLanguageOverride'; $script:State.uiLanguageOverride=$(if ($Language) { $Language } else { $null }) }
function Set-WinHomeLocation { param($GeoId); WriteStep 'homeGeoId'; $script:State.homeGeoId=$GeoId }
function Set-WinCultureFromLanguageListOptOut { param($OptOut); WriteStep 'cultureFromLanguageListOptOut'; $script:State.cultureFromLanguageListOptOut=$OptOut }
function Set-Culture { param($CultureInfo); WriteStep 'culture'; $script:State.culture=$CultureInfo }
function Set-WinDefaultInputMethodOverride { param($InputTip); WriteStep 'defaultInputMethod'; $script:State.defaultInputMethod=$InputTip }
function Remove-ItemProperty { throw 'Unexpected registry mutation' }
function Remove-Item { throw 'Unexpected registry deletion' }
function Set-ItemProperty { throw 'Unexpected registry mutation' }
function tzutil.exe { param($Option,$Zone); if ($Option -cne '/s') { throw 'Unexpected timezone command' }; WriteStep 'timeZoneId'; $script:State.timeZoneId=$Zone; $global:LASTEXITCODE=0 }
`;

async function captureScript() {
  let script;
  const adapter = createWindowsEnvironmentAdapter({ platform: 'win32', execFile: (_file, args, _options, callback) => {
    assert.ok(args.join(' ').length < 30000, 'encoded production script must stay below Windows command-line limit');
    script = Buffer.from(args.at(-1), 'base64').toString('utf16le'); callback(null, JSON.stringify({ ok: true, value: null }));
  } });
  await adapter.apply(before);
  return script;
}

async function runner(t) {
  const directory = await mkdtemp(path.resolve(import.meta.dirname, '.environment-partial-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const scriptFile = path.join(directory, 'fixture.ps1');
  const script = await captureScript();
  const marker = 'ConvertTo-Json -InputObject @{ok=$true;value=$value} -Depth 12 -Compress';
  assert.ok(script.includes(marker));
  await writeFile(scriptFile, fixture + script.replace(marker, "ConvertTo-Json -InputObject @{ok=$true;value=$value;snapshot=(Snapshot);writes=@($script:Writes)} -Depth 12 -Compress"));
  return (request, state = before, faults = []) => {
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptFile], {
      encoding: 'utf8', windowsHide: true, timeout: 15000,
      env: { ...process.env, MC_ENVIRONMENT_FIXTURE_STATE: JSON.stringify(state), MC_ENVIRONMENT_FIXTURE_FAULTS: JSON.stringify(faults),
        PROXYPILOT_ENVIRONMENT_INPUT: Buffer.from(JSON.stringify(request)).toString('base64') },
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    return JSON.parse(result.stdout.trim());
  };
}

test('best-effort Windows apply retains independent successes after language or timezone errors; strict mode remains fail-fast', { skip: process.platform !== 'win32' }, async t => {
  const run = await runner(t);
  const result = run({ operation: 'apply', target, bestEffort: true }, before, ['languages']);
  assert.equal(result.ok, true); assert.equal(result.value.applied, false);
  assert.deepEqual(result.value.failures, [{ field: 'languages', code: 'ENVIRONMENT_PERMISSION_DENIED', environmentStage: 'apply-language-list' }]);
  for (const key of ['timeZoneId', 'homeGeoId', 'culture', 'uiLanguageOverride', 'defaultInputMethod', 'cultureFromLanguageListOptOut']) assert.deepEqual(result.snapshot[key], target[key], key);
  assert.equal(result.snapshot.homeCountryCode, 'JP');
  assert.deepEqual(result.snapshot.languages, before.languages); assert.equal(result.writes.at(-1), 'culture');
  assert.ok(!JSON.stringify(result).includes('fixture denial'));

  const invalidZone = run({ operation: 'apply', target: { ...target, timeZoneId: 'Not A Windows Time Zone' }, bestEffort: true });
  assert.equal(invalidZone.ok, true); assert.equal(invalidZone.snapshot.timeZoneId, before.timeZoneId);
  assert.equal(invalidZone.snapshot.homeGeoId, target.homeGeoId); assert.equal(invalidZone.snapshot.culture, 'zh-SG');
  assert.equal(invalidZone.value.failures[0].field, 'timeZoneId');

  const strict = run({ operation: 'apply', target }, before, ['languages']);
  assert.equal(strict.ok, false); assert.equal(strict.code, 'ENVIRONMENT_PERMISSION_DENIED');
  assert.equal(strict.diagnostic.environmentStage, 'apply-language-list');
});

test('language identity treats harmless spelling and TIP ordering as equal without ignoring language order or missing inputs', { skip: process.platform !== 'win32' }, async t => {
  const run = await runner(t);
  const state = { ...before, languages: [{ languageTag: 'zh-Hans-CN', inputMethodTips: ['0804:abcdef01', '0804:00000804'], handwriting: false }, { languageTag: 'en-US', inputMethodTips: ['0409:00000409'], handwriting: false }] };
  const equivalent = { ...state, languages: [{ languageTag: 'zh-CN', inputMethodTips: ['0804:00000804', '0804:ABCDEF01', '0804:ABCDEF01'], handwriting: false }, state.languages[1]] };
  const same = run({ operation: 'apply', target: equivalent, bestEffort: true }, state);
  assert.equal(same.ok, true); assert.equal(same.value.applied, true); assert.deepEqual(same.writes, []);
  for (const languages of [[...state.languages].reverse(), [{ ...state.languages[0], inputMethodTips: ['0804:00000804'] }, state.languages[1]]]) {
    const changed = run({ operation: 'apply', target: { ...state, languages }, bestEffort: true }, state);
    assert.equal(changed.ok, true); assert.ok(changed.writes.includes('languages'));
  }
});

test('Windows home region maps country independently of regional format and legacy target omits home mutation', { skip: process.platform !== 'win32' }, async t => {
  const run = await runner(t);
  for (const [countryCode, expected] of [['US', 244], ['JP', 122], ['SG', 215], ['HK', 104], ['TW', 237]]) {
    const result = run({ operation: 'mapHomeRegion', countryCode });
    assert.equal(result.ok, true); assert.equal(result.value, expected); assert.deepEqual(result.writes, []);
  }
  const legacy = { ...target }; delete legacy.homeGeoId;
  const result = run({ operation: 'apply', target: legacy, bestEffort: true });
  assert.equal(result.snapshot.homeGeoId, before.homeGeoId); assert.ok(!result.writes.includes('homeGeoId'));
  assert.equal(result.snapshot.homeCountryCode, 'CN');
});

test('adapter validates and limits partial failure responses and country mappings', async () => {
  let response; let request; let calls = 0;
  const adapter = createWindowsEnvironmentAdapter({ platform: 'win32', execFile: (_file, _args, options, callback) => {
    calls++;
    request = JSON.parse(Buffer.from(options.env.PROXYPILOT_ENVIRONMENT_INPUT, 'base64'));
    callback(null, JSON.stringify({ ok: true, value: response }));
  } });
  response = { applied: false, failures: [{ field: 'languages', code: 'ENVIRONMENT_PERMISSION_DENIED', environmentStage: 'apply-language-list', secret: 'never return' }] };
  assert.deepEqual(await adapter.apply(target, { bestEffort: true }), { applied: false, failures: [{ field: 'languages', code: 'ENVIRONMENT_PERMISSION_DENIED', environmentStage: 'apply-language-list' }] });
  assert.equal(request.bestEffort, true);
  for (const bad of [null, {}, { applied: true, failures: [{ field: 'languages', code: 'ENVIRONMENT_WINDOWS_FAILED', environmentStage: 'apply-language-list' }] }, { applied: false, failures: [{ field: 'private-setting', code: 'private message', environmentStage: 'script' }] }]) {
    response = bad; await assert.rejects(adapter.apply(target, { bestEffort: true }), { code: 'ENVIRONMENT_WINDOWS_FAILED' });
  }
  response = 122; assert.equal(await adapter.mapHomeRegion('JP'), 122); assert.equal(request.operation, 'mapHomeRegion');
  for (const value of [null, 0, -1, 1.5, '122']) { response = value; await assert.rejects(adapter.mapHomeRegion('JP'), { code: 'ENVIRONMENT_WINDOWS_FAILED' }); }
  await assert.rejects(adapter.mapHomeRegion('JP;anything'), { code: 'ENVIRONMENT_WINDOWS_FAILED' });
  const previousCalls = calls;
  for (const bad of [null, {}, [], { ...target, languages: [] }, { ...target, homeGeoId: -1 }, { ...target, cultureFromLanguageListOptOut: undefined }, { ...target, defaultInputMethod: 'bad;script' }]) {
    await assert.rejects(adapter.apply(bad, { bestEffort: true }), { code: 'ENVIRONMENT_WINDOWS_FAILED' });
  }
  assert.equal(calls, previousCalls, 'malformed target must not launch a process or clear missing settings');
});
