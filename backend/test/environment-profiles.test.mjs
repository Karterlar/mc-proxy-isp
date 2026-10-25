import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile, rm, readdir, mkdir, symlink } from 'node:fs/promises';
import { ENVIRONMENT_PRESETS, ENVIRONMENT_TIME_ZONES, defaultEnvironmentPreferences, profileFromSnapshot, validateEnvironmentPreferences, createEnvironmentProfiles } from '../src/environment-profiles.mjs';

const scopeHash = async () => 'a'.repeat(64);
const daily = { countryCode: 'CN', timeZoneId: 'China Standard Time', preferredLanguage: 'zh-CN', culture: 'zh-CN' };
const preferences = () => ({ ...defaultEnvironmentPreferences(), daily: { ...daily } });
async function fixture(t) {
  const stateDir = await mkdtemp(path.resolve(import.meta.dirname, '.environment-profiles-test-'));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  return { stateDir, file: path.join(stateDir, 'envprefs.json'), store: createEnvironmentProfiles({ stateDir, scopeHash }) };
}

test('presets provide editable regional defaults, fixed work format and no invented daily settings', () => {
  assert.deepEqual(ENVIRONMENT_PRESETS.map(item => item.id), ['US', 'JP', 'KR', 'HK', 'SG', 'TW', 'GB', 'DE', 'CA', 'AU', 'CN']);
  assert.equal(defaultEnvironmentPreferences().daily, null);
  for (const { id, label, ...preset } of ENVIRONMENT_PRESETS) {
    assert.ok(id && label);
    assert.ok(ENVIRONMENT_TIME_ZONES.includes(preset.timeZoneId));
    assert.equal(validateEnvironmentPreferences({ work: { mode: 'custom', ...preset }, daily: null }).work.culture, 'zh-SG');
  }
  const first = defaultEnvironmentPreferences(); first.work.countryCode = 'JP';
  assert.equal(defaultEnvironmentPreferences().work.countryCode, 'US');
});

test('manual daily settings are independent from work settings and canonicalize language tags', () => {
  const value = preferences(); value.daily.preferredLanguage = 'ZH-cn'; value.daily.culture = 'EN-us';
  const result = validateEnvironmentPreferences(value);
  assert.equal(result.daily.preferredLanguage, 'zh-CN'); assert.equal(result.daily.culture, 'en-US');
  assert.equal(result.work.culture, 'zh-SG');
  result.daily.countryCode = 'SG'; assert.equal(value.daily.countryCode, 'CN');
  assert.equal(validateEnvironmentPreferences({ ...preferences(), daily: { ...daily, countryCode: 'FR' } }).daily.countryCode, 'FR');
});

test('profile validation rejects unknown fields, invalid regions, unrecognized timezones and command-like tags', () => {
  const invalid = [
    null, [], {}, { ...preferences(), unexpected: true }, { work: preferences().work },
    { ...preferences(), work: { ...preferences().work, mode: 'silent' } },
    { ...preferences(), work: { ...preferences().work, culture: 'ja-JP' } },
    ...['ZZ', 'EU', 'us', 'US;Write-Host x'].map(countryCode => ({ ...preferences(), daily: { ...daily, countryCode } })),
    ...['UTC;echo x', 'Unrecognized Standard Time', 'Asia/Tokyo'].map(timeZoneId => ({ ...preferences(), daily: { ...daily, timeZoneId } })),
    ...['zh_CN', 'en-US;Write-Host x', '$($env:USER)', 'x-private', ''].map(preferredLanguage => ({ ...preferences(), daily: { ...daily, preferredLanguage } })),
    { ...preferences(), daily: { ...daily, languages: ['en-US'] } },
  ];
  for (const value of invalid) assert.throws(() => validateEnvironmentPreferences(value), { code: 'ENVIRONMENT_PROFILE_INVALID' });
});

test('capture uses the observed country and first preferred language, never guesses from timezone', () => {
  const snapshot = { homeCountryCode: 'JP', homeGeoId: 45, timeZoneId: 'Tokyo Standard Time', culture: 'zh-SG', languages: [{ languageTag: 'ja-JP' }, { languageTag: 'zh-CN' }] };
  assert.deepEqual(profileFromSnapshot(snapshot), { countryCode: 'JP', timeZoneId: 'Tokyo Standard Time', preferredLanguage: 'ja-JP', culture: 'zh-SG' });
  assert.equal(profileFromSnapshot({ ...snapshot, homeCountryCode: null, homeGeoId: 45 }).countryCode, 'CN');
  assert.equal(profileFromSnapshot({ ...snapshot, homeCountryCode: null, homeGeoId: 99999 }), null);
  assert.equal(profileFromSnapshot({ ...snapshot, languages: [] }), null);
  assert.equal(profileFromSnapshot(null), null);
});

test('save and reload retain only explicit preferences without touching the recovery journal', async t => {
  const { store, stateDir, file } = await fixture(t);
  assert.equal(await store.load(), null);
  const original = '{"originalSnapshot":"preserved"}\n';
  await writeFile(path.join(stateDir, 'state.json'), original);
  assert.deepEqual(await store.save(preferences()), preferences());
  const record = JSON.parse(await readFile(file, 'utf8'));
  assert.equal(record.scopeHash, await scopeHash()); assert.equal(record.version, 1);
  assert.deepEqual(await createEnvironmentProfiles({ stateDir, scopeHash }).load(), preferences());
  assert.equal(await readFile(path.join(stateDir, 'state.json'), 'utf8'), original);
  assert.deepEqual((await readdir(stateDir)).sort(), ['envprefs.json', 'state.json']);
});

test('foreign, invalid and oversized preference files stay intact on attempted save', async t => {
  const { stateDir, file } = await fixture(t);
  const cases = [
    [JSON.stringify({ version: 1, scopeHash: 'b'.repeat(64), preferences: preferences() }), 'ENVIRONMENT_PROFILE_FOREIGN'],
    ['{broken-json', 'ENVIRONMENT_PROFILE_INVALID'],
    [JSON.stringify({ version: 1, scopeHash: await scopeHash(), preferences: { ...preferences(), daily: { ...daily, culture: 'bad_tag' } } }), 'ENVIRONMENT_PROFILE_INVALID'],
    [' '.repeat(16385), 'ENVIRONMENT_PROFILE_INVALID'],
  ];
  for (const [bytes, code] of cases) {
    await writeFile(file, bytes);
    const store = createEnvironmentProfiles({ stateDir, scopeHash });
    await assert.rejects(store.load(), { code });
    await assert.rejects(store.save(preferences()), { code });
    assert.equal(await readFile(file, 'utf8'), bytes);
  }
});

test('stale preference saves cannot replace another window changes or recreate deleted settings', async t => {
  const { store, stateDir, file } = await fixture(t);
  await store.save(preferences());
  const stale = createEnvironmentProfiles({ stateDir, scopeHash }); await stale.load();
  const changed = preferences(); changed.work.mode = 'custom'; changed.work.countryCode = 'JP';
  await store.save(changed); const bytes = await readFile(file);
  await assert.rejects(stale.save(preferences()), { code: 'ENVIRONMENT_PROFILE_CONFLICT' });
  assert.deepEqual(await readFile(file), bytes);
  assert.deepEqual(await stale.load(), changed); await stale.save(preferences());
  await rm(file);
  await assert.rejects(stale.save(changed), { code: 'ENVIRONMENT_PROFILE_CONFLICT' });
  assert.equal(await createEnvironmentProfiles({ stateDir, scopeHash }).load(), null);
  assert.deepEqual(await readdir(stateDir), []);
});

test('storage refuses invalid or changed machine identity and returns detached mock values', async t => {
  const { stateDir, file } = await fixture(t);
  await assert.rejects(createEnvironmentProfiles({ stateDir, scopeHash: async () => null }).save(preferences()), { code: 'ENVIRONMENT_IDENTITY_UNAVAILABLE' });
  let identity = 'a'.repeat(64);
  const store = createEnvironmentProfiles({ stateDir, scopeHash: async () => identity });
  await store.save(preferences()); const before = await readFile(file);
  identity = 'b'.repeat(64);
  await assert.rejects(store.save(preferences()), { code: 'ENVIRONMENT_PROFILE_FOREIGN' });
  assert.deepEqual(await readFile(file), before);
  const mock = createEnvironmentProfiles({ mock: true, scopeHash });
  assert.equal(await mock.load(), null); await mock.save(preferences());
  const copy = await mock.load(); copy.work.mode = 'custom';
  assert.equal((await mock.load()).work.mode, 'exit');
});

test('preference storage rejects linked paths and directory-valued files', async t => {
  const { stateDir } = await fixture(t);
  const target = path.join(stateDir, 'target'), linked = path.join(stateDir, 'linked');
  await mkdir(target); await symlink(target, linked, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(createEnvironmentProfiles({ stateDir: linked, scopeHash }).save(preferences()), { code: 'ENVIRONMENT_PATH_INVALID' });
  await mkdir(path.join(target, 'envprefs.json'));
  await assert.rejects(createEnvironmentProfiles({ stateDir: target, scopeHash }).load(), { code: 'ENVIRONMENT_PROFILE_INVALID' });
});
