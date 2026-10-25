import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { createEnvironmentManager, createMockEnvironmentAdapter } from '../src/environment-manager.mjs';
import { defaultEnvironmentPreferences } from '../src/environment-profiles.mjs';

const geo = { verified: true, ip: '203.0.113.8', countryCode: 'JP', city: 'Tokyo', timezone: 'Asia/Tokyo' };
const daily = { countryCode: 'JP', timeZoneId: 'Tokyo Standard Time', preferredLanguage: 'ja-JP', culture: 'zh-CN' };
async function fixture(t) {
  const stateDir = await mkdtemp(path.resolve(import.meta.dirname, '.environment-profile-recovery-test-'));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const adapter = createMockEnvironmentAdapter();
  return { stateDir, adapter, manager: createEnvironmentManager({ stateDir, adapter }), stateFile: path.join(stateDir, 'state.json') };
}

test('legacy region migration preserves original backup bytes and rejects supplemental fields replacing original settings', async t => {
  const { stateDir, adapter, manager, stateFile } = await fixture(t);
  const snapshot = adapter.snapshot;
  adapter.snapshot = async () => { const value = await snapshot(); delete value.homeGeoId; delete value.homeCountryCode; return value; };
  const initial = await manager.check(), backupBytes = await readFile(initial.backup.path);
  adapter.snapshot = snapshot;
  const original = await snapshot();
  const applied = await manager.optimize({ geo, force: true });
  assert.equal(applied.current.homeGeoId, 122);
  const migrated = JSON.parse(await readFile(stateFile, 'utf8'));
  assert.equal(migrated.backup.snapshot.homeGeoId, undefined);
  assert.deepEqual(migrated.supplementalOriginalSettings, { homeGeoId: original.homeGeoId });
  assert.deepEqual(await readFile(initial.backup.path), backupBytes);
  const restored = await createEnvironmentManager({ stateDir, adapter }).restore({ original: true });
  assert.equal(restored.current.homeGeoId, original.homeGeoId); assert.equal(restored.current.culture, original.culture);
  assert.deepEqual(await readFile(initial.backup.path), backupBytes);

  const malformed = JSON.parse(await readFile(stateFile, 'utf8'));
  malformed.supplementalOriginalSettings.culture = 'fr-FR';
  const malformedBytes = Buffer.from(JSON.stringify(malformed)); await writeFile(stateFile, malformedBytes);
  let writes = 0; adapter.apply = async () => { writes++; };
  await assert.rejects(createEnvironmentManager({ stateDir, adapter }).restore({ original: true }), { code: 'ENVIRONMENT_STATE_INVALID' });
  assert.equal(writes, 0); assert.deepEqual(await readFile(stateFile), malformedBytes);
  assert.deepEqual(await readFile(initial.backup.path), backupBytes); assert.deepEqual(await snapshot(), original);
});

test('denied daily restore remains actionable across restart even at original state, then clears after retry and tracks changed daily goal', async t => {
  const { stateDir, adapter, manager, stateFile } = await fixture(t);
  const initial = await manager.check(), original = await adapter.snapshot(), backupBytes = await readFile(initial.backup.path);
  const preferences = { ...defaultEnvironmentPreferences(), daily };
  await manager.savePreferences(preferences);
  const apply = adapter.apply; let writes = 0;
  adapter.apply = async () => { writes++; throw Object.assign(new Error('mock permission denial'), { code: 'ENVIRONMENT_PERMISSION_DENIED' }); };
  const partial = await manager.restore();
  assert.equal(writes, 1); assert.equal(partial.restored, false); assert.equal(partial.optimization.status, 'partial');
  assert.equal(partial.optimization.restoreSource, 'daily'); assert.equal(partial.backup.restoreNeeded, true);
  assert.deepEqual(partial.current, original); assert.ok(partial.optimization.differingFields.includes('timeZoneId'));
  const saved = JSON.parse(await readFile(stateFile, 'utf8'));
  assert.equal(saved.lastApplied, null); assert.equal(saved.pending, null);
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const inspected = await restarted.inspectSaved();
  assert.equal(inspected.backup.restoreNeeded, true); assert.equal(inspected.optimization.status, 'partial');
  assert.equal(writes, 1, 'reading a partial result must never retry OS setters');
  adapter.apply = apply;
  const completed = await restarted.restore();
  assert.equal(completed.restored, true); assert.equal(completed.backup.restoreNeeded, false);
  assert.equal(completed.current.homeGeoId, 122); assert.equal(completed.current.timeZoneId, daily.timeZoneId);
  const changed = await restarted.savePreferences({ ...preferences, daily: { countryCode: 'US', timeZoneId: 'Eastern Standard Time', preferredLanguage: 'en-US', culture: 'zh-CN' } });
  assert.equal(changed.backup.restoreNeeded, true); assert.equal(changed.current.homeGeoId, 122, 'saving a new daily goal must not apply it');
  assert.deepEqual(await readFile(initial.backup.path), backupBytes);
});
