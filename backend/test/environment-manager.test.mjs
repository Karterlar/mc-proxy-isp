import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, writeFile, rm, readdir } from 'node:fs/promises';
import { createEnvironmentManager, createMockEnvironmentAdapter } from '../src/environment-manager.mjs';
import { createWindowsEnvironmentAdapter, sanitizeEnvironmentDiagnostic } from '../src/windows-environment.mjs';
import { WINDOWS_TIME_ZONES, localeForGeo } from '../src/environment-regions.mjs';
import { defaultEnvironmentPreferences } from '../src/environment-profiles.mjs';

const geo = { verified: true, ip: '203.0.113.8', countryCode: 'JP', city: 'Tokyo', timezone: 'Asia/Tokyo' };
async function fixture(t, options = {}) {
  const directory = await mkdtemp(path.resolve(import.meta.dirname, '.environment-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const adapter = createMockEnvironmentAdapter();
  const stateDir = path.join(directory, '.environment');
  const manager = createEnvironmentManager({ stateDir, adapter, ...options });
  return { manager, adapter, stateDir };
}

test('stale environment readers cannot overwrite a newer recovery journal or recreate a deleted journal', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  await manager.check();
  const stale = createEnvironmentManager({ stateDir, adapter }); await stale.inspectSaved();
  await manager.optimize({ geo });
  const file = path.join(stateDir, 'state.json'); const latest = await readFile(file);
  let mutations = 0; const apply = adapter.apply; adapter.apply = async target => { mutations++; return apply(target); };
  for (const action of [() => stale.check(), () => stale.optimize({ geo }), () => stale.optimize({ geo, force: true }), () => stale.restore({ original: true })]) {
    await assert.rejects(action(), { code: 'ENVIRONMENT_CONFLICT' });
    assert.deepEqual(await readFile(file), latest);
  }
  assert.equal(mutations, 0);
  await rm(file);
  await assert.rejects(manager.check(), { code: 'ENVIRONMENT_CONFLICT' });
  await assert.rejects(readFile(file), { code: 'ENOENT' });
});

test('a mismatched setting remains visible while successfully applied fields are retained', async t => {
  const { manager, adapter, stateDir } = await fixture(t); await manager.check();
  const apply = adapter.apply; let applies = 0;
  adapter.apply = async target => { applies++; await apply({ ...target, culture: 'fr-FR' }); };
  const result = await manager.optimize({ geo });
  assert.equal(result.optimization.status, 'partial');
  assert.deepEqual(result.optimization.differingFields, ['culture']);
  assert.equal(result.current.timeZoneId, 'Tokyo Standard Time');
  assert.equal(result.current.homeGeoId, 122);
  assert.equal(applies, 1, 'a mismatch must not roll back the working settings');
  assert.equal((await adapter.snapshot()).culture, 'fr-FR');
  const record = JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8'));
  assert.equal(record.pending, null); assert.equal(record.optimization.status, 'partial');
  assert.ok(record.optimization.matchedFields.includes('timeZoneId'));
});

test('journal conflict after apply never overwrites the other record or rolls Windows back', async t => {
  const { manager, adapter, stateDir } = await fixture(t); await manager.check();
  const file = path.join(stateDir, 'state.json'); const apply = adapter.apply; let applies = 0; let changed;
  adapter.apply = async target => {
    applies++; await apply(target);
    changed = Buffer.from(JSON.stringify({ ...JSON.parse(await readFile(file, 'utf8')), externalMarker: 'retain-new-record' }));
    await writeFile(file, changed);
  };
  await assert.rejects(manager.optimize({ geo }), { code: 'ENVIRONMENT_CONFLICT' });
  assert.equal(applies, 1); assert.deepEqual(await readFile(file), changed);
  assert.equal((await adapter.snapshot()).culture, 'zh-SG');
  assert.equal(manager.status().optimization.persisted, false);
});

test('startup snapshots settings and durable backup without OS mutation', async t => {
  const { manager, adapter } = await fixture(t);
  let writes = 0; adapter.apply = async () => { writes++; };
  const checked = await manager.check();
  assert.equal(checked.status, 'ready');
  assert.equal(checked.backup.canRestore, true);
  assert.equal(checked.backup.restoreNeeded, false);
  const saved = JSON.parse(await readFile(checked.backup.path, 'utf8'));
  assert.deepEqual(saved.snapshot, checked.current);
  assert.equal(writes, 0);
  assert.deepEqual(manager.status(), checked);
  assert.equal((await manager.check()).backup.id, checked.backup.id);
});

test('global geo selects exact timezone, country and preferred language with fixed Singapore Chinese format', async t => {
  const { manager, adapter } = await fixture(t);
  const before = await adapter.snapshot();
  const result = await manager.optimize({ geo });
  assert.equal(result.current.timeZoneId, 'Tokyo Standard Time');
  assert.equal(result.current.culture, 'zh-SG');
  assert.equal(result.current.homeGeoId, 122);
  assert.equal(result.current.uiLanguageOverride, 'ja-JP');
  assert.deepEqual(result.current.languages[1], before.languages[0]);
  assert.deepEqual(result.current.fonts, before.fonts);
  assert.equal(result.backup.canRestore, true);
  assert.equal(result.needsSignOut, true);
  const restored = await manager.restore({ original: true });
  assert.deepEqual(restored.current, before);
  assert.equal(restored.backup.canRestore, true);
  assert.equal(restored.backup.restoreNeeded, false);
});

test('US Central, Mountain, Arizona and global offsets never collapse into east/west', () => {
  assert.equal(WINDOWS_TIME_ZONES['America/Chicago'], 'Central Standard Time');
  assert.equal(WINDOWS_TIME_ZONES['America/Denver'], 'Mountain Standard Time');
  assert.equal(WINDOWS_TIME_ZONES['America/Phoenix'], 'US Mountain Standard Time');
  assert.equal(WINDOWS_TIME_ZONES['America/Indiana/Indianapolis'], 'US Eastern Standard Time');
  assert.equal(WINDOWS_TIME_ZONES['Australia/Adelaide'], 'Cen. Australia Standard Time');
  assert.equal(WINDOWS_TIME_ZONES['Asia/Kathmandu'], 'Nepal Standard Time');
  assert.equal(localeForGeo({ countryCode: 'CA', city: 'Montréal' }), 'fr-CA');
  assert.equal(localeForGeo({ countryCode: 'CA', city: 'Toronto' }), 'en-CA');
  assert.equal(localeForGeo({ countryCode: 'CH', city: 'Geneva' }), 'fr-CH');
  assert.equal(localeForGeo({ countryCode: 'BE', city: 'Brussels' }), null);
});

test('ambiguous multilingual location preserves language and gives clear warning', async t => {
  const { manager, adapter } = await fixture(t);
  const before = await adapter.snapshot();
  adapter.mapHomeRegion = async () => 21;
  const result = await manager.optimize({ geo: { ...geo, countryCode: 'BE', city: 'Brussels', timezone: 'Europe/Brussels' } });
  assert.equal(result.current.timeZoneId, 'Romance Standard Time');
  assert.equal(result.current.homeGeoId, 21);
  assert.deepEqual(result.current.languages, before.languages);
  assert.equal(result.current.culture, 'zh-SG');
  assert.equal(result.appliedRegion.locale ?? null, null);
  assert.match(result.warnings.join(''), /首选语言映射/);
  assert.equal(result.optimization.status, 'partial');
  assert.deepEqual(result.optimization.differingFields, ['languages']);
});

test('missing display language pack changes preferences but never claims display language installed', async t => {
  const { manager } = await fixture(t);
  const result = await manager.optimize({ geo: { ...geo, countryCode: 'KR', city: 'Seoul', timezone: 'Asia/Seoul' } });
  assert.equal(result.current.culture, 'zh-SG');
  assert.equal(result.current.uiLanguageOverride, null);
  assert.equal(result.current.languages[0].languageTag, 'ko-KR');
  assert.match(result.warnings.join(''), /未安装对应显示语言包/);
});

test('Windows script-qualified Chinese language aliases retain existing input methods without duplicates', async t => {
  const { manager, adapter } = await fixture(t);
  const original = await adapter.snapshot();
  const result = await manager.optimize({ geo: { ...geo, countryCode: 'CN', city: 'Shanghai', timezone: 'Asia/Shanghai' } });
  assert.equal(result.current.culture, 'zh-SG');
  assert.deepEqual(result.current.languages, original.languages);
  assert.equal(result.current.languages.length, 1);
});

test('timezone optimization restores the original disabled daylight-saving preference', async t => {
  const { manager, adapter } = await fixture(t);
  await adapter.apply({ ...await adapter.snapshot(), timeZoneId: 'Pacific Standard Time', daylightSavingDisabled: true });
  const original = await adapter.snapshot();
  assert.equal((await manager.optimize({ geo })).current.daylightSavingDisabled, false);
  assert.deepEqual((await manager.restore({ original: true })).current, original);
});

test('unverified geography never writes; unsupported timezone does not prevent other verified settings', async t => {
  const { manager, adapter } = await fixture(t);
  let writes = 0; const apply = adapter.apply; adapter.apply = async target => { writes++; return apply(target); };
  for (const invalid of [{ ...geo, verified: false }, { ...geo, ip: 'invalid' }, { ...geo, timezone: "x'; calc" }]) await assert.rejects(manager.optimize({ geo: invalid }), { code: 'EXIT_GEO_UNVERIFIED' });
  assert.equal(writes, 0);
  const result = await manager.optimize({ geo: { ...geo, timezone: 'Unknown/City' } });
  assert.equal(writes, 1); assert.equal(result.current.timeZoneId, 'Taipei Standard Time');
  assert.equal(result.current.homeGeoId, 122); assert.equal(result.current.culture, 'zh-SG');
  assert.deepEqual(result.optimization.differingFields, ['timeZoneId']);
  assert.equal(result.optimization.failures[0].code, 'TIMEZONE_UNSUPPORTED');
});

test('restoration survives process restart and preserves the first original snapshot', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const original = await adapter.snapshot();
  await manager.optimize({ geo });
  await manager.optimize({ geo: { ...geo, countryCode: 'US', city: 'New York', timezone: 'America/New_York' } });
  const restarted = createEnvironmentManager({ stateDir, adapter });
  assert.equal((await restarted.check()).status, 'optimized');
  assert.deepEqual((await restarted.restore({ original: true })).current, original);
});

test('background optimization detects drift but explicit apply and restore converge without replacing the original backup', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const original = await adapter.snapshot();
  await manager.optimize({ geo });
  const backup = manager.status().backup;
  const backupBytes = await readFile(backup.path);
  const changed = { ...await adapter.snapshot(), timeZoneId: 'Pacific Standard Time' };
  await adapter.apply(changed);
  await assert.rejects(manager.optimize({ geo }), cause => {
      assert.equal(cause.code, 'ENVIRONMENT_CONFLICT');
      assert.deepEqual(cause.diagnostic, { environmentFields: ['timeZoneId'] });
      assert.ok(!JSON.stringify(cause.diagnostic).includes('Pacific Standard Time')); return true;
  });
  assert.deepEqual(await adapter.snapshot(), changed);
  const saved = await createEnvironmentManager({ stateDir, adapter }).inspectSaved();
  assert.deepEqual(saved.optimization.differingFields, ['timeZoneId']);
  assert.ok(!JSON.stringify(saved.optimization).includes('Pacific Standard Time'));
  assert.equal((await manager.optimize({ geo, force: true })).current.timeZoneId, 'Tokyo Standard Time');
  await adapter.apply({ ...changed, culture: 'fr-FR' });
  assert.deepEqual((await manager.restore({ original: true })).current, original);
  assert.equal(manager.status().backup.id, backup.id);
  assert.deepEqual(await readFile(backup.path), backupBytes);
});

test('a native error after a partial mutation retains successful settings and untouched original details', async t => {
  const { manager, adapter } = await fixture(t);
  const original = await adapter.snapshot();
  const apply = adapter.apply; let calls = 0;
  adapter.apply = async value => {
    if (++calls === 1) { await apply({ ...original, timeZoneId: value.timeZoneId }); throw Object.assign(new Error('failure'), { code: 'TEST_FAILURE' }); }
    return apply(value);
  };
  const result = await manager.optimize({ geo });
  assert.equal(result.optimization.status, 'partial'); assert.equal(calls, 1);
  assert.deepEqual(await adapter.snapshot(), { ...original, timeZoneId: 'Tokyo Standard Time' });
  assert.ok(result.optimization.matchedFields.includes('timeZoneId'));
  assert.ok(result.optimization.differingFields.includes('culture'));
  assert.equal(result.current.defaultInputMethod, null); assert.deepEqual(result.current.languages, original.languages);
});

test('a denied apply reports per-field errors without another setter or false pending recovery', async t => {
  const { manager, adapter, stateDir } = await fixture(t); await manager.check();
  const original = await adapter.snapshot(); let writes = 0;
  adapter.apply = async () => { writes++; throw Object.assign(new Error('private native message'), { code: 'ENVIRONMENT_PERMISSION_DENIED', diagnostic: { environmentStage: 'apply-timezone', raw: 'private native message' } }); };
  const result = await manager.optimize({ geo }); assert.equal(result.optimization.status, 'partial');
  assert.equal(writes, 1);
  assert.deepEqual(await adapter.snapshot(), original);
  const state = JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8'));
  assert.equal(state.pending, null); assert.equal(state.lastApplied, null);
  assert.equal(state.optimization.status, 'partial');
  assert.ok(state.optimization.failures.length > 0);
  assert.ok(state.optimization.failures.every(item => item.code === 'ENVIRONMENT_PERMISSION_DENIED' && item.environmentStage === 'apply-timezone'));
  assert.ok(!JSON.stringify(state.optimization).includes('private native message'));
  const saved = await createEnvironmentManager({ stateDir, adapter }).inspectSaved();
  assert.equal(saved.status, 'ready'); assert.equal(saved.backup.canRestore, true); assert.equal(saved.backup.restoreNeeded, false);
  assert.equal(saved.optimization.code, 'ENVIRONMENT_PARTIAL');
});

test('restore timeout without a mutation retains its applied baseline and per-field failure across restart', async t => {
  const { manager, adapter, stateDir } = await fixture(t); await manager.optimize({ geo });
  const applied = await adapter.snapshot(); let writes = 0;
  adapter.apply = async () => { writes++; throw Object.assign(new Error('private timeout'), { code: 'ENVIRONMENT_TIMEOUT', diagnostic: { environmentStage: 'apply-language-list' } }); };
  const result = await manager.restore({ original: true }); assert.equal(result.optimization.status, 'partial'); assert.equal(result.restored, false);
  assert.equal(writes, 1); assert.deepEqual(await adapter.snapshot(), applied);
  const saved = await createEnvironmentManager({ stateDir, adapter }).inspectSaved();
  assert.equal(saved.status, 'optimized'); assert.equal(saved.backup.canRestore, true);
  assert.equal(saved.optimization.status, 'partial'); assert.equal(saved.optimization.code, 'ENVIRONMENT_PARTIAL');
  assert.ok(saved.optimization.failures.every(item => item.code === 'ENVIRONMENT_TIMEOUT' && item.environmentStage === 'apply-language-list'));
  assert.equal(JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8')).pending, null);
});

test('an unreadable final snapshot leaves durable intent and restores after restart without blind rollback', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const original = await adapter.snapshot();
  const apply = adapter.apply, snapshot = adapter.snapshot;
  let writes = 0;
  adapter.apply = async value => { writes++; await apply({ ...original, timeZoneId: value.timeZoneId }); adapter.snapshot = async () => { throw Object.assign(new Error('snapshot unavailable'), { code: 'ENVIRONMENT_WINDOWS_FAILED' }); }; };
  await assert.rejects(manager.optimize({ geo }), { code: 'ENVIRONMENT_WINDOWS_FAILED' });
  assert.equal(writes, 1);
  const persisted = JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8'));
  assert.ok(persisted.pending);
  adapter.apply = apply; adapter.snapshot = snapshot;
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const recovered = await restarted.check();
  assert.equal(recovered.status, 'recovery-required');
  assert.equal(recovered.optimization.status, 'recovery-required');
  assert.deepEqual((await restarted.restore({ original: true })).current, original);
});

test('partial restoration retains completed fields and reports only unmatched field names across restart', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  await manager.optimize({ geo });
  const apply = adapter.apply;
  let applies = 0;
  adapter.apply = value => { applies++; return apply({ ...value, defaultInputMethod: '0409:00000409' }); };
  const result = await manager.restore({ original: true });
  assert.equal(result.optimization.status, 'partial'); assert.equal(result.restored, false);
  assert.deepEqual(result.optimization.differingFields, ['defaultInputMethod']);
  assert.ok(!JSON.stringify(result.optimization.fieldResults).includes('0409:00000409'));
  assert.equal(applies, 1, 'the mismatched input method must not undo other successful restoration');
  const state = JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8'));
  assert.equal(state.pending, null);
  assert.deepEqual(state.optimization.differingFields, ['defaultInputMethod']);
  assert.equal(state.optimization.rollbackDifferingFields, undefined);
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const saved = await restarted.inspectSaved();
  assert.deepEqual(saved.optimization.differingFields, ['defaultInputMethod']);
  assert.equal(saved.optimization.rollbackDifferingFields, undefined);
  assert.match(saved.warnings.join(''), /已恢复的设置保留/);
  adapter.apply = apply;
  assert.equal((await restarted.restore({ original: true })).current.defaultInputMethod, null);
});

test('partial verification identifies the failed field and legacy failure notes still sanitize diagnostics', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const apply = adapter.apply; let calls = 0;
  const baseline = await adapter.snapshot();
  adapter.apply = target => apply(++calls === 1 ? { ...target, culture: baseline.culture } : target);
  const result = await manager.optimize({ geo });
  assert.equal(result.optimization.status, 'partial'); assert.equal(calls, 1);
  assert.deepEqual(result.optimization.differingFields, ['culture']);
  assert.equal(result.current.timeZoneId, 'Tokyo Standard Time');
  assert.equal(manager.status().current.defaultInputMethod, null);
  const state = JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8'));
  assert.equal(state.pending, null); assert.deepEqual(state.optimization.differingFields, ['culture']);
  assert.equal(state.optimization.rollbackDifferingFields, undefined);
  await manager.noteOptimizationFailure({ code: 'ENVIRONMENT_VERIFY_FAILED', diagnostic: {
    environmentFields: ['notAField', 'private-actual-value', 'culture', 'culture'], rollbackEnvironmentFields: ['secret', 'defaultInputMethod'], raw: 'secret'
  } });
  assert.deepEqual(manager.status().optimization.differingFields, ['culture']);
  assert.deepEqual(manager.status().optimization.rollbackDifferingFields, ['defaultInputMethod']);
  assert.ok(!JSON.stringify(manager.status().optimization).includes('secret'));
});

test('external changes during target preparation are refused before the transaction writes', async t => {
  const { manager, adapter } = await fixture(t);
  const baseline = await manager.check();
  const apply = adapter.apply;
  let writes = 0;
  adapter.apply = async value => { writes++; await apply(value); };
  adapter.defaultLanguage = async languageTag => {
    await apply({ ...await adapter.snapshot(), culture: 'zh-TW' });
    return { languageTag, inputMethodTips: [], handwriting: false };
  };
  await assert.rejects(manager.optimize({ geo }), { code: 'ENVIRONMENT_CONFLICT' });
  assert.equal(writes, 0);
  assert.equal((await adapter.snapshot()).culture, 'zh-TW');
  assert.equal(manager.status().backup.id, baseline.backup.id);
  assert.equal(manager.status().optimization.code, 'ENVIRONMENT_CONFLICT');
});

test('explicit apply tolerates preparation drift and preserves completed writes even if one field fails', async t => {
  for (const fails of [false, true]) {
    const { manager, adapter, stateDir } = await fixture(t);
    const initial = await manager.check(), backupBytes = await readFile(initial.backup.path);
    const apply = adapter.apply;
    let writes = 0;
    adapter.defaultLanguage = async languageTag => {
      await apply({ ...await adapter.snapshot(), culture: 'fr-FR', uiLanguageOverride: 'fr-FR' });
      return { languageTag, inputMethodTips: [], handwriting: false };
    };
    adapter.apply = async target => {
      writes++;
      if (fails && writes === 1) {
        await apply({ ...target, culture: 'de-DE' });
        throw Object.assign(new Error('denied'), { code: 'ENVIRONMENT_PERMISSION_DENIED' });
      }
      return apply(target);
    };
    if (fails) {
      const result = await manager.optimize({ geo, force: true });
      assert.equal(result.optimization.status, 'partial');
      assert.deepEqual(result.optimization.differingFields, ['culture']);
      assert.equal(result.current.culture, 'de-DE'); assert.equal(result.current.timeZoneId, 'Tokyo Standard Time');
      assert.equal(writes, 1);
    } else {
      assert.equal((await manager.optimize({ geo, force: true })).current.culture, 'zh-SG');
      assert.equal(writes, 1);
    }
    assert.deepEqual(await readFile(initial.backup.path), backupBytes);
    assert.equal(JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8')).backup.id, initial.backup.id);
  }
});

test('pending recovery with third values supports explicit reapply after restart and retains the original backup', async t => {
  for (const retryFails of [false, true]) {
    const { manager, adapter, stateDir } = await fixture(t);
    const original = await adapter.snapshot(), first = await manager.check();
    const apply = adapter.apply, snapshot = adapter.snapshot;
    adapter.apply = async target => {
      await apply({ ...target, culture: 'fr-FR' });
      adapter.snapshot = async () => { throw Object.assign(new Error('read unavailable'), { code: 'ENVIRONMENT_WINDOWS_FAILED' }); };
    };
    await assert.rejects(manager.optimize({ geo }), { code: 'ENVIRONMENT_WINDOWS_FAILED' });
    adapter.snapshot = snapshot;
    const prior = JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8'));
    assert.ok(prior.pending);
    const restarted = createEnvironmentManager({ stateDir, adapter });
    let writes = 0;
    adapter.apply = async target => {
      if (++writes === 1 && retryFails) {
        await apply({ ...target, timeZoneId: 'Pacific Standard Time' });
        throw Object.assign(new Error('denied'), { code: 'ENVIRONMENT_PERMISSION_DENIED' });
      }
      await apply(target);
    };
    if (retryFails) {
      const result = await restarted.optimize({ geo, force: true });
      assert.equal(result.optimization.status, 'partial');
      assert.deepEqual(result.optimization.differingFields, ['timeZoneId']);
      const saved = JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8'));
      assert.equal(saved.pending, null);
      assert.equal((await adapter.snapshot()).timeZoneId, 'Pacific Standard Time');
      assert.equal((await adapter.snapshot()).culture, 'zh-SG');
    } else {
      assert.equal((await restarted.optimize({ geo, force: true })).optimization.status, 'applied');
      assert.equal(JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8')).pending, null);
    }
    assert.equal(writes, 1);
    adapter.apply = apply;
    assert.deepEqual((await restarted.restore({ original: true })).current, original);
    assert.equal(restarted.status().backup.id, first.backup.id);
    assert.deepEqual(JSON.parse(await readFile(first.backup.path, 'utf8')).snapshot, original);
  }
});

test('explicit restoration resets all managed fields including country despite unrelated values and survives restart', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const original = await adapter.snapshot(), first = await manager.check();
  await adapter.apply({ timeZoneId: 'Pacific Standard Time', daylightSavingDisabled: true,
    culture: 'fr-FR', uiLanguageOverride: 'fr-FR', languages: [{ languageTag: 'fr-FR', inputMethodTips: ['040C:0000040C'], handwriting: true }],
    defaultInputMethod: '040C:0000040C', cultureFromLanguageListOptOut: true, homeGeoId: 244 });
  const restarted = createEnvironmentManager({ stateDir, adapter });
  assert.deepEqual((await restarted.restore({ original: true })).current, original);
  const again = createEnvironmentManager({ stateDir, adapter });
  const restored = await again.restore({ original: true });
  assert.equal(restored.noChange, true); assert.equal(restored.backup.id, first.backup.id);
  assert.equal(restored.backup.canRestore, true); assert.equal(restored.backup.restoreNeeded, false);
});

test('inactive baseline drift can be force-restored repeatedly without replacing the initial snapshot', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const first = await manager.check();
  const updated = { ...await adapter.snapshot(), culture: 'zh-TW' };
  await adapter.apply(updated);
  let mutations = 0;
  const apply = adapter.apply;
  adapter.apply = async value => { mutations++; await apply(value); };
  await assert.rejects(manager.optimize({ geo }), { code: 'ENVIRONMENT_BACKUP_DRIFT' });
  assert.equal(manager.status().backup.id, first.backup.id);
  assert.equal(manager.status().backup.drifted, true);
  assert.deepEqual(manager.status().backup.driftedFields, ['culture']);
  assert.equal(mutations, 0);
  assert.equal(manager.status().backup.canRestore, true);
  assert.equal(manager.status().backup.restoreNeeded, true);
  assert.deepEqual((await manager.restore({ original: true })).current, first.current);
  assert.equal(mutations, 1);
  assert.equal(manager.status().backup.restoreNeeded, false);
  await apply(updated);
  const restarted = createEnvironmentManager({ stateDir, adapter });
  assert.equal((await restarted.inspectSaved()).backup.canRestore, true, 'saved status never disables explicit restore');
  assert.equal((await restarted.check()).backup.id, first.backup.id);
  assert.deepEqual((await restarted.restore({ original: true })).current, first.current);
  await apply(updated);
  const refreshed = await restarted.check({ refreshBackup: true });
  assert.notEqual(refreshed.backup.id, first.backup.id);
  assert.equal(refreshed.optimization.status, 'not-requested');
  await restarted.optimize({ geo });
  assert.deepEqual((await restarted.restore({ original: true })).current, updated);
  assert.deepEqual(JSON.parse(await readFile(first.backup.path, 'utf8')).snapshot, first.current);
});

test('restoring an unchanged baseline clears an earlier failure without a Windows mutation', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  await manager.check();
  let writes = 0;
  adapter.apply = async () => { writes++; };
  await assert.rejects(manager.optimize({ geo: { ...geo, verified: false } }), { code: 'EXIT_GEO_UNVERIFIED' });
  const restored = await manager.restore({ original: true });
  assert.equal(restored.restored, true);
  assert.equal(restored.noChange, true);
  assert.equal(restored.optimization.status, 'restored');
  assert.equal(restored.optimization.code, undefined);
  assert.equal(writes, 0);
  const saved = await createEnvironmentManager({ stateDir, adapter }).inspectSaved();
  assert.equal(saved.optimization.status, 'restored');
});

test('restore overwrites both partially restored fields and third values with the initial snapshot', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const original = await adapter.snapshot();
  await manager.optimize({ geo });
  const applied = await adapter.snapshot();
  const apply = adapter.apply;
  await apply({ ...applied, culture: original.culture, uiLanguageOverride: original.uiLanguageOverride });
  let writes = 0; adapter.apply = async target => { writes++; return apply(target); };
  const restored = await manager.restore({ original: true });
  assert.equal(writes, 1); assert.deepEqual(restored.current, original);
  assert.equal(restored.optimization.status, 'restored'); assert.equal(restored.backup.canRestore, true); assert.equal(restored.backup.restoreNeeded, false);
  await manager.optimize({ geo });
  await apply({ ...await adapter.snapshot(), culture: 'fr-FR' });
  const beforeWrites = writes;
  assert.deepEqual((await manager.restore({ original: true })).current, original);
  assert.equal(writes, beforeWrites + 1);
  const saved = await createEnvironmentManager({ stateDir, adapter }).inspectSaved();
  assert.equal(saved.optimization.status, 'restored'); assert.equal(saved.backup.id, restored.backup.id);
});

test('already restored active or interrupted settings complete the journal without retrying any Windows setter', async t => {
  for (const interrupted of [false, true]) {
    const { manager, adapter, stateDir } = await fixture(t);
    const original = await adapter.snapshot();
    await manager.optimize({ geo });
    if (interrupted) {
      const file = path.join(stateDir, 'state.json'), record = JSON.parse(await readFile(file, 'utf8'));
      record.pending = { before: record.lastApplied, target: { ...record.lastApplied, culture: 'en-US', timeZoneId: 'Eastern Standard Time' }, startedAt: new Date().toISOString() };
      await writeFile(file, JSON.stringify(record));
    }
    await adapter.apply(original);
    let writes = 0; adapter.apply = async () => { writes++; throw new Error('an unchanged setting must not require a writable setter'); };
    const restarted = createEnvironmentManager({ stateDir, adapter });
    const result = await restarted.restore({ original: true });
    assert.equal(writes, 0); assert.equal(result.noChange, true); assert.deepEqual(result.current, original);
    assert.equal(result.backup.canRestore, true); assert.equal(result.backup.restoreNeeded, false); assert.equal(result.optimization.status, 'restored');
    assert.equal(result.needsSignOut, true, 'verified saved values do not prove existing language sessions have refreshed');
    const record = JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8'));
    assert.equal(record.lastApplied, null); assert.equal(record.pending, null);
    const repeated = await restarted.restore({ original: true }); assert.equal(writes, 0); assert.equal(repeated.needsSignOut, true);
  }
});

test('timezone-only apply and restore do not claim a language sign-out is required', async t => {
  const { manager } = await fixture(t);
  const optimized = await manager.optimize({ geo, localize: false });
  assert.equal(optimized.needsSignOut, false);
  const restored = await manager.restore({ original: true });
  assert.equal(restored.needsSignOut, false); assert.equal(restored.restored, true);
});

test('restore rechecks a previously matching snapshot and force-writes if it changes during preparation', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const original = await adapter.snapshot(); await manager.optimize({ geo }); await adapter.apply(original);
  const snapshot = adapter.snapshot; let reads = 0, writes = 0;
  adapter.snapshot = async () => ++reads === 3 ? { ...await snapshot(), culture: 'fr-FR' } : snapshot();
  const apply = adapter.apply; adapter.apply = async target => { writes++; await apply(target); };
  assert.deepEqual((await manager.restore({ original: true })).current, original);
  assert.equal(reads, 4); assert.equal(writes, 1);
  const record = JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8'));
  assert.equal(record.lastApplied, null); assert.equal(record.optimization.status, 'restored');
  assert.equal(manager.status().current.culture, original.culture); assert.equal(manager.status().backup.canRestore, true);
});

test('environment diagnostics expose only fixed stages and deduplicated managed field names', () => {
  assert.deepEqual(sanitizeEnvironmentDiagnostic({ environmentStage: 'apply-culture', environmentFields: ['secret', 'culture', 'culture', 'timeZoneId'], rollbackEnvironmentFields: ['defaultInputMethod', 'private-value'], raw: 'private-value' }), {
    environmentStage: 'apply-culture', environmentFields: ['timeZoneId', 'culture'], rollbackEnvironmentFields: ['defaultInputMethod'],
  });
  assert.deepEqual(sanitizeEnvironmentDiagnostic({ environmentStage: 'private-stage', environmentFields: ['culture'] }), { environmentFields: ['culture'] });
  assert.equal(sanitizeEnvironmentDiagnostic({ environmentStage: 'private-stage', environmentFields: ['secret'], raw: 'secret' }), null);
  assert.equal(sanitizeEnvironmentDiagnostic(null), null);
});

test('invalid language preparation is isolated while timezone, home region and culture apply and survive restart', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const before = await manager.check();
  let mutations = 0; const apply = adapter.apply;
  adapter.apply = async target => { mutations++; return apply(target); };
  adapter.defaultLanguage = async () => ({ languageTag: 'ja-JP', inputMethodTips: null, handwriting: false });
  const result = await manager.optimize({ geo });
  assert.equal(mutations, 1);
  assert.equal(result.optimization.status, 'partial');
  assert.deepEqual(result.optimization.differingFields, ['languages']);
  assert.equal(result.optimization.failures[0].code, 'ENVIRONMENT_STATE_INVALID');
  assert.equal((await manager.check()).optimization.code, 'ENVIRONMENT_PARTIAL');
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const saved = await restarted.inspectSaved();
  assert.equal(saved.optimization.status, 'partial');
  assert.equal(saved.optimization.code, 'ENVIRONMENT_PARTIAL');
  assert.deepEqual(saved.current.languages, before.current.languages);
  assert.equal(saved.current.timeZoneId, 'Tokyo Standard Time'); assert.equal(saved.current.homeGeoId, 122); assert.equal(saved.current.culture, 'zh-SG');
  assert.equal(saved.backup.id, before.backup.id);
  assert.equal(saved.appliedRegion.countryCode, 'JP');
});

test('Windows TSF input identities remain intact through application and restoration', async t => {
  const { manager, adapter } = await fixture(t);
  const before = await adapter.snapshot();
  const tip = '0411:{03B5835F-F03C-411B-9CE2-AA23E1171E36}{A76C93D9-5523-4E90-AAFA-4DB112F9AC76}';
  assert.equal(tip.length, 81);
  adapter.defaultLanguage = async languageTag => ({ languageTag, inputMethodTips: [tip], handwriting: false });
  const result = await manager.optimize({ geo });
  assert.equal(result.current.defaultInputMethod, tip);
  assert.deepEqual(result.current.languages[0].inputMethodTips, [tip]);
  assert.equal(result.optimization.status, 'applied');
  assert.deepEqual((await manager.restore({ original: true })).current, before);
  assert.equal(manager.status().optimization.status, 'restored');
  assert.equal(manager.status().appliedRegion, undefined);
});

test('a later partial optimization preserves actual timezone and its unmatched result after restart', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  await manager.optimize({ geo });
  assert.equal((await manager.optimize({ geo: { ...geo, timezone: 'Unknown/City' } })).optimization.status, 'partial');
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const saved = await restarted.inspectSaved();
  assert.equal(saved.status, 'optimized');
  assert.equal(saved.current.timeZoneId, 'Tokyo Standard Time');
  assert.equal(saved.optimization.status, 'partial');
  assert.equal(saved.optimization.code, 'ENVIRONMENT_PARTIAL');
  assert.equal(saved.optimization.failures[0].code, 'TIMEZONE_UNSUPPORTED');
  assert.equal((await restarted.check()).optimization.status, 'partial');
});

test('mock manager never touches disk or an injected host adapter', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'proxypilot-mock-environment-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const adapter = { snapshot() { throw new Error('host access'); }, apply() { throw new Error('host mutation'); } };
  const manager = createEnvironmentManager({ mock: true, stateDir: path.join(directory, 'never-created'), adapter });
  assert.equal((await manager.check()).mock, true);
  assert.equal((await manager.optimize({ geo })).current.culture, 'zh-SG');
  await manager.restore({ original: true });
  assert.deepEqual(await readdir(directory), []);
});

test('encoded Windows requests keep user values out of shell source and redact failures', async () => {
  const calls = [];
  const adapter = createWindowsEnvironmentAdapter({ platform: 'win32', execFile: (file, args, options, callback) => { calls.push({ file, args, options }); callback(null, JSON.stringify({ ok: true, value: null })); } });
  const literal = "Asia/Tokyo'; $(Get-Secret)";
  await adapter.mapTimeZone(literal);
  assert.equal(calls[0].file, 'powershell.exe');
  assert.equal(calls[0].options.windowsHide, true);
  const source = Buffer.from(calls[0].args.at(-1), 'base64').toString('utf16le');
  assert.ok(!source.includes(literal));
  const payload = JSON.parse(Buffer.from(calls[0].options.env.PROXYPILOT_ENVIRONMENT_INPUT, 'base64'));
  assert.equal(payload.iana, literal);
  const broken = createWindowsEnvironmentAdapter({ platform: 'win32', execFile: (_f, _a, _o, cb) => cb(new Error('secret-token')) });
  await assert.rejects(broken.snapshot(), e => e.code === 'ENVIRONMENT_WINDOWS_FAILED' && !e.message.includes('secret-token'));
});

test('Windows operation failures classify access and timeout errors without retaining native details or trusting child codes', async () => {
  for (const [native, expected] of [[{ code: 'EACCES' }, 'ENVIRONMENT_PERMISSION_DENIED'], [{ killed: true }, 'ENVIRONMENT_TIMEOUT'], [{ code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER', killed: true }, 'ENVIRONMENT_WINDOWS_FAILED']]) {
    const adapter = createWindowsEnvironmentAdapter({ platform: 'win32', execFile: (_f, _a, _o, callback) => callback(Object.assign(new Error('credential-private-data'), native)) });
    await assert.rejects(adapter.snapshot(), cause => cause.code === expected && cause.diagnostic.environmentStage === 'invoke' && !JSON.stringify(cause).includes('credential-private-data'));
  }
  for (const payload of [{ ok: 'true', value: 'untrusted' }, { ok: false, code: 'credential-private-data', diagnostic: { environmentStage: 'credential-private-data', raw: 'credential-private-data' } }]) {
    const adapter = createWindowsEnvironmentAdapter({ platform: 'win32', execFile: (_f, _a, _o, callback) => callback(null, JSON.stringify(payload)) });
    await assert.rejects(adapter.apply({}), cause => cause.code === 'ENVIRONMENT_WINDOWS_FAILED' && cause.diagnostic.environmentStage === 'invoke' && !JSON.stringify(cause).includes('credential-private-data'));
  }
});

test('later startup loads saved snapshots without touching the host and marks them as saved', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const first = await manager.check();
  adapter.snapshot = async () => { throw new Error('no host check during startup'); };
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const saved = await restarted.initialize({ checkIfMissing: true });
  assert.equal(saved.snapshotSource, 'saved'); assert.equal(saved.needsCheck, true);
  assert.deepEqual(saved.current, first.current); assert.equal(saved.backup.id, first.backup.id);
  assert.deepEqual(await restarted.inspectSaved(), saved);
});

test('inspect saved on first run creates no backup or host inspection', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  adapter.snapshot = async () => { throw new Error('unexpected host check'); };
  assert.equal((await manager.inspectSaved()).status, 'unchecked');
  assert.equal((await manager.initialize({ checkIfMissing: false })).status, 'unchecked');
  assert.deepEqual(await readdir(path.dirname(stateDir)), []);
});

test('explicit recheck and rebackup replaces baseline while normal check preserves it', async t => {
  const { manager, adapter } = await fixture(t);
  const first = await manager.initialize();
  const changed = { ...await adapter.snapshot(), culture: 'zh-TW' };
  await adapter.apply(changed);
  assert.equal((await manager.check()).backup.id, first.backup.id);
  const refreshed = await manager.check({ refreshBackup: true });
  assert.notEqual(refreshed.backup.id, first.backup.id);
  assert.equal(refreshed.backupRefreshed, true); assert.equal(refreshed.snapshotSource, 'live');
  assert.deepEqual(JSON.parse(await readFile(refreshed.backup.path, 'utf8')).snapshot, changed);
  assert.equal(JSON.parse(await readFile(first.backup.path, 'utf8')).id, first.backup.id);
});

test('rebackup refuses optimized and pending state until restoration completes', async t => {
  const { manager, adapter } = await fixture(t);
  const first = await manager.check(); await manager.optimize({ geo });
  await assert.rejects(manager.check({ refreshBackup: true }), { code: 'ENVIRONMENT_BACKUP_ACTIVE' });
  assert.equal(manager.status().backup.id, first.backup.id);
  await manager.restore({ original: true });
  assert.notEqual((await manager.check({ refreshBackup: true })).backup.id, first.backup.id);
  const apply = adapter.apply, snapshot = adapter.snapshot;
  adapter.apply = async value => { await apply(value); adapter.snapshot = async () => { throw Object.assign(new Error('final read unavailable'), { code: 'ENVIRONMENT_WINDOWS_FAILED' }); }; };
  await assert.rejects(manager.optimize({ geo }), { code: 'ENVIRONMENT_WINDOWS_FAILED' });
  adapter.snapshot = snapshot;
  await assert.rejects(manager.check({ refreshBackup: true }), { code: 'ENVIRONMENT_BACKUP_ACTIVE' });
});

test('explicit rebuild bypasses invalid JSON and schema only after validating a live snapshot and archives exact bytes', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const first = await manager.check();
  const firstBackup = await readFile(first.backup.path);
  let applies = 0; adapter.apply = async () => { applies++; };
  for (const raw of [Buffer.from('\ufeff{broken json\r\n'), Buffer.from(JSON.stringify({ version: 1, backup: { id: 'broken-id' }, pending: { secret: 'preserve-me' } })), Buffer.from('null')]) {
    await writeFile(path.join(stateDir, 'state.json'), raw);
    const restarted = createEnvironmentManager({ stateDir, adapter });
    await assert.rejects(restarted.check({ refreshBackup: true }), { code: 'ENVIRONMENT_STATE_INVALID' });
    assert.equal(restarted.status().ownership, 'invalid');
    assert.equal(restarted.status().status, 'error');
    assert.equal(restarted.status().canRefresh, true);
    const rebuilt = await restarted.check({ refreshBackup: true, rebuildBackup: true });
    assert.equal(rebuilt.backupRebuilt, true);
    assert.equal(rebuilt.ownership, 'matched');
    assert.equal(rebuilt.needsCheck, false);
    assert.equal(rebuilt.backup.canRestore, true); assert.equal(rebuilt.backup.restoreNeeded, false);
    assert.deepEqual(await readFile(rebuilt.archivedStatePath), raw);
    const saved = JSON.parse(await readFile(path.join(stateDir, 'state.json'), 'utf8'));
    assert.equal(saved.version, 2); assert.equal(saved.scopeHash, 'a'.repeat(64));
    assert.equal(saved.lastApplied, null); assert.equal(saved.pending, null);
    assert.deepEqual(saved.backup.snapshot, await adapter.snapshot());
    assert.deepEqual(await readFile(first.backup.path), firstBackup);
  }
  assert.equal(applies, 0);
});

test('foreign optimized or pending state never restores to this device and explicit rebuild preserves its complete old record', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  await manager.optimize({ geo });
  const stateFile = path.join(stateDir, 'state.json');
  const prior = JSON.parse(await readFile(stateFile, 'utf8'));
  const apply = adapter.apply;
  await apply({ ...await adapter.snapshot(), culture: 'zh-TW', timeZoneId: 'Pacific Standard Time' });
  const current = await adapter.snapshot();
  adapter.scopeHash = async () => 'b'.repeat(64);
  let applies = 0; adapter.apply = async () => { applies++; };
  for (const pending of [false, true]) {
    const imported = structuredClone(prior);
    if (pending) imported.pending = { before: prior.backup.snapshot, target: prior.lastApplied, startedAt: new Date().toISOString() };
    const raw = Buffer.from(JSON.stringify(imported, null, 2));
    await writeFile(stateFile, raw);
    const restarted = createEnvironmentManager({ stateDir, adapter });
    const savedView = await restarted.inspectSaved();
    assert.ok(!savedView.warnings.join('').includes('请先使用一键复原'));
    const checked = await restarted.check();
    assert.equal(checked.status, 'foreign'); assert.equal(checked.ownership, 'foreign');
    assert.equal(checked.backup.canRestore, false); assert.equal(checked.canRefresh, true); assert.equal(checked.needsCheck, true);
    assert.deepEqual(checked.current, current);
    await assert.rejects(restarted.restore({ original: true }), { code: 'ENVIRONMENT_BACKUP_FOREIGN' });
    await assert.rejects(restarted.optimize({ geo }), { code: 'ENVIRONMENT_BACKUP_FOREIGN' });
    await assert.rejects(restarted.optimize({ geo, force: true }), { code: 'ENVIRONMENT_BACKUP_FOREIGN' });
    await assert.rejects(restarted.check({ refreshBackup: true }), { code: 'ENVIRONMENT_REBUILD_REQUIRED' });
    assert.deepEqual(await readFile(stateFile), raw);
    const rebuilt = await restarted.check({ refreshBackup: true, rebuildBackup: true });
    assert.deepEqual(await readFile(rebuilt.archivedStatePath), raw);
    assert.equal(rebuilt.status, 'ready'); assert.equal(rebuilt.ownership, 'matched');
    assert.deepEqual(rebuilt.current, current);
    const saved = JSON.parse(await readFile(stateFile, 'utf8'));
    assert.equal(saved.scopeHash, 'b'.repeat(64)); assert.equal(saved.lastApplied, null); assert.equal(saved.pending, null);
    assert.deepEqual(saved.backup.snapshot, current);
  }
  assert.equal(applies, 0);
});

test('legacy unbound state may be viewed but cannot optimize or restore even if current settings match the old applied values', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  await manager.optimize({ geo });
  const stateFile = path.join(stateDir, 'state.json');
  const prior = JSON.parse(await readFile(stateFile, 'utf8')); prior.version = 1; delete prior.scopeHash;
  const raw = Buffer.from(JSON.stringify(prior)); await writeFile(stateFile, raw);
  let applies = 0; adapter.apply = async () => { applies++; };
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const saved = await restarted.inspectSaved();
  assert.equal(saved.status, 'unbound'); assert.equal(saved.ownership, 'unbound');
  assert.equal(saved.backup.canRestore, false); assert.equal(saved.canRefresh, true); assert.equal(saved.needsCheck, true);
  await assert.rejects(restarted.restore({ original: true }), { code: 'ENVIRONMENT_BACKUP_UNBOUND' });
  await assert.rejects(restarted.optimize({ geo }), { code: 'ENVIRONMENT_BACKUP_UNBOUND' });
  await assert.rejects(restarted.optimize({ geo, force: true }), { code: 'ENVIRONMENT_BACKUP_UNBOUND' });
  assert.equal(applies, 0); assert.deepEqual(await readFile(stateFile), raw);
  const rebuilt = await restarted.check({ refreshBackup: true, rebuildBackup: true });
  assert.equal(rebuilt.ownership, 'matched'); assert.deepEqual(await readFile(rebuilt.archivedStatePath), raw);
});

test('same-device optimized and pending recovery records refuse explicit rebuild without dropping their recovery baseline', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  await manager.optimize({ geo });
  const stateFile = path.join(stateDir, 'state.json');
  for (const pending of [false, true]) {
    const state = JSON.parse(await readFile(stateFile, 'utf8'));
    if (pending) state.pending = { before: state.backup.snapshot, target: state.lastApplied, startedAt: new Date().toISOString() };
    const raw = Buffer.from(JSON.stringify(state)); await writeFile(stateFile, raw);
    let snapshots = 0; const snapshot = adapter.snapshot; adapter.snapshot = async () => { snapshots++; return snapshot(); };
    const restarted = createEnvironmentManager({ stateDir, adapter });
    await assert.rejects(restarted.check({ refreshBackup: true, rebuildBackup: true }), { code: 'ENVIRONMENT_BACKUP_ACTIVE' });
    assert.equal(snapshots, 0); assert.deepEqual(await readFile(stateFile), raw);
    assert.equal((await readdir(stateDir)).filter(name => name.startsWith('state-archive-')).length, 0);
    adapter.snapshot = snapshot;
  }
});

test('adopting manually repaired pending settings archives recovery bytes without applying Windows and survives restart', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const original = await manager.check();
  const originalBackup = await readFile(original.backup.path);
  await manager.optimize({ geo });
  const stateFile = path.join(stateDir, 'state.json');
  const pending = JSON.parse(await readFile(stateFile, 'utf8'));
  pending.pending = { before: pending.backup.snapshot, target: pending.lastApplied, startedAt: new Date().toISOString() };
  pending.optimization = { status: 'recovery-required', code: 'ENVIRONMENT_RESTORE_REQUIRED', oldResult: true };
  const manual = { ...await adapter.snapshot(), timeZoneId: 'Pacific Standard Time', culture: 'zh-TW' };
  const apply = adapter.apply; await apply(manual);
  let applies = 0; adapter.apply = async target => { applies++; await apply(target); };
  const raw = Buffer.from(`${JSON.stringify(pending, null, 2)}\r\n`); await writeFile(stateFile, raw);
  const priorArchive = path.join(stateDir, 'state-archive-prior.json');
  const priorArchiveBytes = Buffer.from('older recovery evidence'); await writeFile(priorArchive, priorArchiveBytes);
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const saved = await restarted.inspectSaved();
  assert.equal(saved.status, 'recovery-required'); assert.equal(saved.canAdoptCurrent, true);
  await assert.rejects(restarted.check({ refreshBackup: true }), { code: 'ENVIRONMENT_BACKUP_ACTIVE' });
  await assert.rejects(restarted.check({ refreshBackup: true, rebuildBackup: true }), { code: 'ENVIRONMENT_BACKUP_ACTIVE' });
  assert.deepEqual(await readFile(stateFile), raw);
  const adopted = await restarted.adoptCurrent();
  assert.equal(applies, 0); assert.equal(adopted.status, 'ready'); assert.equal(adopted.ownership, 'matched');
  assert.equal(adopted.canAdoptCurrent, true); assert.equal(adopted.canRefresh, true); assert.equal(adopted.needsCheck, false);
  assert.equal(adopted.snapshotSource, 'live'); assert.equal(adopted.adoptedCurrent, true);
  assert.equal(adopted.needsSignOut, false); assert.equal(adopted.appliedRegion, undefined);
  assert.equal(adopted.backup.canRestore, true); assert.equal(adopted.backup.restoreNeeded, false); assert.equal(adopted.backup.drifted, false);
  assert.deepEqual(adopted.optimization, { status: 'not-requested' }); assert.deepEqual(adopted.current, manual);
  assert.deepEqual(await readFile(adopted.archivedStatePath), raw);
  assert.deepEqual(await readFile(priorArchive), priorArchiveBytes);
  assert.deepEqual(await readFile(original.backup.path), originalBackup);
  const newRecord = JSON.parse(await readFile(stateFile, 'utf8'));
  assert.equal(newRecord.lastApplied, null); assert.equal(newRecord.pending, null);
  assert.equal(newRecord.appliedRegion, null); assert.equal(newRecord.needsSignOut, false);
  assert.deepEqual(newRecord.optimization, { status: 'not-requested' });
  assert.deepEqual(newRecord.backup.snapshot, manual); assert.deepEqual(newRecord.lastObserved, manual);
  let snapshots = 0; const snapshot = adapter.snapshot;
  adapter.snapshot = async () => { snapshots++; return snapshot(); };
  const fresh = createEnvironmentManager({ stateDir, adapter });
  const persisted = await fresh.initialize();
  assert.equal(snapshots, 0); assert.equal(persisted.status, 'ready'); assert.deepEqual(persisted.current, manual);
  assert.equal(persisted.backup.id, adopted.backup.id); assert.deepEqual(persisted.optimization, { status: 'not-requested' });
  await fresh.optimize({ geo }); assert.equal(applies, 1);
  const restored = await fresh.restore({ original: true });
  assert.equal(applies, 2); assert.deepEqual(restored.current, manual);
  assert.deepEqual(await readFile(adopted.archivedStatePath), raw);
  assert.deepEqual(await readFile(original.backup.path), originalBackup);
});

test('explicit adoption permits matched active conflict and inactive drift while ordinary refresh retains its guard', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  await manager.optimize({ geo });
  const apply = adapter.apply;
  await apply({ ...await adapter.snapshot(), culture: 'zh-TW' });
  const conflict = await manager.check();
  assert.equal(conflict.status, 'conflict'); assert.equal(conflict.canAdoptCurrent, true); assert.equal(conflict.canRefresh, false);
  const stateFile = path.join(stateDir, 'state.json'); const raw = await readFile(stateFile);
  await assert.rejects(manager.check({ refreshBackup: true }), { code: 'ENVIRONMENT_BACKUP_ACTIVE' });
  await assert.rejects(manager.check({ refreshBackup: true, rebuildBackup: true }), { code: 'ENVIRONMENT_BACKUP_ACTIVE' });
  assert.deepEqual(await readFile(stateFile), raw);
  let applies = 0; adapter.apply = async () => { applies++; };
  const adopted = await manager.adoptCurrent();
  assert.equal(adopted.status, 'ready'); assert.deepEqual(await readFile(adopted.archivedStatePath), raw);
  await apply({ ...await adapter.snapshot(), timeZoneId: 'Taipei Standard Time' });
  const drift = await manager.check();
  assert.equal(drift.backup.drifted, true); assert.equal(drift.canAdoptCurrent, true);
  const second = await manager.adoptCurrent();
  assert.equal(second.backup.drifted, false); assert.notEqual(second.backup.id, adopted.backup.id);
  assert.deepEqual(await readFile(adopted.archivedStatePath), raw); assert.equal(applies, 0);
});

test('adoption creates a current-user baseline from foreign, unbound and invalid records without applying their settings', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const first = await manager.check(); await manager.optimize({ geo });
  const stateFile = path.join(stateDir, 'state.json');
  const prior = JSON.parse(await readFile(stateFile, 'utf8'));
  const originals = [
    ['foreign', JSON.stringify({ ...prior, scopeHash: 'b'.repeat(64) })],
    ['unbound', JSON.stringify({ ...prior, version: 1, scopeHash: undefined })],
    ['invalid', '{retain broken imported recovery record'],
  ];
  let applies = 0; adapter.apply = async () => { applies++; };
  for (const [ownership, text] of originals) {
    const raw = Buffer.from(text); await writeFile(stateFile, raw);
    const restarted = createEnvironmentManager({ stateDir, adapter });
    if (ownership === 'invalid') await assert.rejects(restarted.inspectSaved(), { code: 'ENVIRONMENT_STATE_INVALID' });
    else assert.equal((await restarted.inspectSaved()).ownership, ownership);
    assert.equal(restarted.status().canAdoptCurrent, true);
    const adopted = await restarted.adoptCurrent();
    assert.equal(adopted.ownership, 'matched'); assert.equal(adopted.status, 'ready');
    assert.deepEqual(adopted.current, await adapter.snapshot());
    assert.deepEqual(await readFile(adopted.archivedStatePath), raw);
    assert.ok(await readFile(first.backup.path));
  }
  assert.equal(applies, 0);
});

test('adoption refuses changing live settings and retains the prior record, backups and completed archive', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const original = await manager.check(); await manager.optimize({ geo });
  const stateFile = path.join(stateDir, 'state.json'); const raw = await readFile(stateFile);
  const originalBackup = await readFile(original.backup.path);
  let snapshots = 0; const snapshot = adapter.snapshot;
  adapter.snapshot = async () => {
    const value = await snapshot();
    return ++snapshots === 2 ? { ...value, culture: 'zh-TW' } : value;
  };
  let applies = 0; adapter.apply = async () => { applies++; };
  await assert.rejects(manager.adoptCurrent(), { code: 'ENVIRONMENT_CONFLICT' });
  assert.equal(snapshots, 2); assert.equal(applies, 0); assert.deepEqual(await readFile(stateFile), raw);
  assert.deepEqual(await readFile(original.backup.path), originalBackup);
  const archives = (await readdir(stateDir)).filter(name => name.startsWith('state-archive-'));
  assert.equal(archives.length, 1); assert.deepEqual(await readFile(path.join(stateDir, archives[0])), raw);
  assert.equal(manager.status().backup.id, original.backup.id);
});

test('adoption refuses record bytes changed during archive preparation without dropping either recovery record', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const original = await manager.check(); await manager.optimize({ geo });
  const stateFile = path.join(stateDir, 'state.json'); const raw = await readFile(stateFile);
  const changed = Buffer.concat([raw, Buffer.from('\n')]);
  let archive;
  const restarted = createEnvironmentManager({ stateDir, adapter, writeArchive: async (file, bytes) => {
    archive = file; await writeFile(file, bytes); await writeFile(stateFile, changed);
  } });
  let applies = 0; adapter.apply = async () => { applies++; };
  await assert.rejects(restarted.adoptCurrent(), { code: 'ENVIRONMENT_CONFLICT' });
  assert.deepEqual(await readFile(stateFile), changed); assert.deepEqual(await readFile(archive), raw);
  assert.ok(await readFile(original.backup.path)); assert.equal(applies, 0);
});

test('failed adoption archive preserves active recovery state and every existing backup', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const original = await manager.check(); await manager.optimize({ geo });
  const stateFile = path.join(stateDir, 'state.json'); const raw = await readFile(stateFile);
  const originalBackup = await readFile(original.backup.path); const files = await readdir(stateDir);
  let applies = 0; adapter.apply = async () => { applies++; };
  const restarted = createEnvironmentManager({ stateDir, adapter, writeArchive: async () => {
    throw Object.assign(new Error('fixture archive denied'), { code: 'EACCES' });
  } });
  await assert.rejects(restarted.adoptCurrent(), { code: 'EACCES' });
  assert.deepEqual(await readFile(stateFile), raw); assert.deepEqual(await readFile(original.backup.path), originalBackup);
  assert.deepEqual(await readdir(stateDir), files); assert.equal(applies, 0);
});

test('failed archive write and invalid live snapshot never replace the old invalid recovery file', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const first = await manager.check();
  const stateFile = path.join(stateDir, 'state.json');
  const raw = Buffer.from('{retain old broken record byte-for-byte'); await writeFile(stateFile, raw);
  const beforeFiles = await readdir(stateDir);
  let applies = 0; adapter.apply = async () => { applies++; };
  const archiveFailure = createEnvironmentManager({ stateDir, adapter, writeArchive: async () => { throw Object.assign(new Error('fixture archive failure'), { code: 'EACCES' }); } });
  await assert.rejects(archiveFailure.check({ refreshBackup: true, rebuildBackup: true }), { code: 'EACCES' });
  assert.deepEqual(await readFile(stateFile), raw); assert.deepEqual(await readdir(stateDir), beforeFiles);
  const snapshot = adapter.snapshot;
  adapter.snapshot = async () => ({ ...await snapshot(), languages: [] });
  const invalidSnapshot = createEnvironmentManager({ stateDir, adapter });
  await assert.rejects(invalidSnapshot.check({ refreshBackup: true, rebuildBackup: true }), { code: 'ENVIRONMENT_SNAPSHOT_INVALID' });
  assert.deepEqual(await readFile(stateFile), raw); assert.deepEqual(await readdir(stateDir), beforeFiles);
  assert.ok(await readFile(first.backup.path)); assert.equal(applies, 0);
});

test('missing or invalid device identity fails closed before reading snapshots or replacing recovery state', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  await manager.check();
  const stateFile = path.join(stateDir, 'state.json'); const raw = await readFile(stateFile);
  let snapshots = 0; adapter.snapshot = async () => { snapshots++; throw new Error('unexpected snapshot'); };
  for (const scopeHash of [undefined, async () => 'not-a-hash', async () => { throw new Error('private machine identifier'); }]) {
    adapter.scopeHash = scopeHash;
    const restarted = createEnvironmentManager({ stateDir, adapter });
    await assert.rejects(restarted.check({ refreshBackup: true, rebuildBackup: true }), e => e.code === 'ENVIRONMENT_IDENTITY_UNAVAILABLE' && !e.message.includes('private machine identifier'));
    await assert.rejects(restarted.adoptCurrent(), { code: 'ENVIRONMENT_IDENTITY_UNAVAILABLE' });
    assert.equal(restarted.status().canRefresh, false); assert.equal(restarted.status().canAdoptCurrent, false); assert.deepEqual(await readFile(stateFile), raw);
  }
  assert.equal(snapshots, 0);
});

test('new environment records bind only hashed identity and still optimize and restore the matched device', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const checked = await manager.check();
  assert.equal(checked.ownership, 'matched'); assert.equal(checked.backup.ownership, 'matched');
  assert.equal(checked.canRefresh, true);
  const stateFile = path.join(stateDir, 'state.json');
  const record = JSON.parse(await readFile(stateFile, 'utf8'));
  assert.equal(record.version, 2); assert.equal(record.scopeHash, await adapter.scopeHash());
  assert.equal(record.backup.scopeHash, record.scopeHash);
  await manager.optimize({ geo });
  assert.equal(manager.status().canRefresh, false); assert.equal(manager.status().backup.canRestore, true);
  const restored = await createEnvironmentManager({ stateDir, adapter }).restore({ original: true });
  assert.deepEqual(restored.current, checked.current); assert.equal(restored.ownership, 'matched');
  assert.equal(restored.canRefresh, true);
});

test('Windows PowerShell scope identity branch hashes fixture machine and user values without inspecting real host settings', { skip: process.platform !== 'win32' }, async () => {
  let captured;
  const adapter = createWindowsEnvironmentAdapter({ platform: 'win32', execFile: (_file, args, options, callback) => { captured = { args, options }; callback(null, JSON.stringify({ ok: true, value: 'fixture' })); } });
  await adapter.scopeHash();
  assert.equal(JSON.parse(Buffer.from(captured.options.env.PROXYPILOT_ENVIRONMENT_INPUT, 'base64')).operation, 'scopeHash');
  const machine = 'FIXTURE-MACHINE-GUID'; const user = 'S-1-5-21-111-222-333-1000';
  const windowsSource = Buffer.from(captured.args.at(-1), 'base64').toString('utf16le');
  const source = String.raw`
function Get-ItemProperty {
  param($LiteralPath,$Name)
  if ($LiteralPath -cne 'HKLM:\SOFTWARE\Microsoft\Cryptography' -or $Name -cne 'MachineGuid') { throw 'Unexpected real registry access' }
  return [pscustomobject]@{ MachineGuid=$env:MC_ENVIRONMENT_FIXTURE_MACHINE }
}
` + windowsSource.replaceAll('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value', '$env:MC_ENVIRONMENT_FIXTURE_USER');
  assert.ok(!source.includes('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value'));
  const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(source, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 10000, env: { ...process.env, PROXYPILOT_ENVIRONMENT_INPUT: captured.options.env.PROXYPILOT_ENVIRONMENT_INPUT, MC_ENVIRONMENT_FIXTURE_MACHINE: machine, MC_ENVIRONMENT_FIXTURE_USER: user } });
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const output = JSON.parse(result.stdout.trim());
  assert.equal(output.ok, true);
  assert.equal(output.value, createHash('sha256').update(`${machine.toLowerCase()}:${user}`).digest('hex'));
  assert.ok(!result.stdout.includes(machine)); assert.ok(!result.stdout.includes(user));
});

test('Windows snapshot enumerates a single pipeline List of two languages without merging tags, input methods or handwriting', { skip: process.platform !== 'win32' }, async t => {
  let captured;
  const adapter = createWindowsEnvironmentAdapter({ platform: 'win32', execFile: (_file, args, options, callback) => { captured = { args, options }; callback(null, JSON.stringify({ ok: true, value: null })); } });
  await adapter.snapshot();
  const windowsSource = Buffer.from(captured.args.at(-1), 'base64').toString('utf16le');
  const fixtureSource = String.raw`
function Get-WinUserLanguageList {
  # Build the real WinUserLanguage List<T> in memory. The native getter emits
  # this whole list as one pipeline object, rather than emitting its entries.
  $list=New-WinUserLanguageList -Language 'zh-Hans-CN'
  $list.Clear()
  $zh=(New-WinUserLanguageList -Language 'zh-Hans-CN')[0]
  $zh.InputMethodTips.Clear(); $zh.InputMethodTips.Add('0804:00000804'); $zh.InputMethodTips.Add('0804:00000804')
  $zh.Handwriting=$true; $list.Add($zh)
  $en=(New-WinUserLanguageList -Language 'en-US')[0]
  $en.InputMethodTips.Clear(); $en.InputMethodTips.Add('0409:00000409')
  $en.Handwriting=$false; $list.Add($en)
  Write-Output -NoEnumerate $list
}
function Get-WinUILanguageOverride { return $null }
function Get-WinDefaultInputMethodOverride {
  if ($env:MC_ENVIRONMENT_FIXTURE_INPUT -ceq 'null') { return $null }
  return [pscustomobject]@{ InputMethodTip=$env:MC_ENVIRONMENT_FIXTURE_INPUT }
}
function Get-TimeZone { return [pscustomobject]@{ Id='China Standard Time' } }
function Get-Culture { return [Globalization.CultureInfo]::GetCultureInfo('zh-CN') }
function Get-WinCultureFromLanguageListOptOut { return $false }
function Get-ItemProperty {
  param($LiteralPath,$Name)
  if ($LiteralPath -ceq 'HKCU:\Control Panel\International') { return [pscustomobject]@{LocaleName='zh-CN';Locale='00000804'} }
  if ($LiteralPath -ceq 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts') { return [pscustomobject]@{'Segoe UI (TrueType)'='fixture'; 'Microsoft YaHei (TrueType)'='fixture'; 'SimSun (TrueType)'='fixture'} }
  if ($LiteralPath -ceq 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation') { return [pscustomobject]@{DynamicDaylightTimeDisabled=0} }
  throw 'Unexpected real registry access'
}
function Get-ChildItem {
  param($LiteralPath)
  if ($LiteralPath -cne 'HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages') { throw 'Unexpected real registry access' }
  return @([pscustomobject]@{PSChildName='zh-CN'},[pscustomobject]@{PSChildName='en-US'})
}
`;
  function run(source, defaultInput) {
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(fixtureSource + source, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 10000, env: { ...process.env, PROXYPILOT_ENVIRONMENT_INPUT: captured.options.env.PROXYPILOT_ENVIRONMENT_INPUT, MC_ENVIRONMENT_FIXTURE_INPUT: defaultInput } });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const output = JSON.parse(result.stdout.trim()); assert.equal(output.ok, true);
    return output.value;
  }
  const snapshot = run(windowsSource, 'null');
  assert.deepEqual(snapshot.languages, [
    { languageTag: 'zh-Hans-CN', inputMethodTips: ['0804:00000804', '0804:00000804'], handwriting: true },
    { languageTag: 'en-US', inputMethodTips: ['0409:00000409'], handwriting: false },
  ]);
  assert.equal(snapshot.defaultInputMethod, null);
  assert.equal(run(windowsSource, '0409:00000409').defaultInputMethod, '0409:00000409');
  const brokenSource = windowsSource.replace('languages=@(foreach ($language in $languageList) { Language $language })', 'languages=@(Get-WinUserLanguageList | ForEach-Object { Language $_ })');
  assert.notEqual(brokenSource, windowsSource);
  const broken = run(brokenSource, 'null');
  assert.equal(broken.languages.length, 1); assert.equal(broken.languages[0].languageTag, 'zh-Hans-CN en-US');

  const { stateDir } = await fixture(t);
  const manager = createEnvironmentManager({ stateDir, adapter: { scopeHash: async () => 'a'.repeat(64), snapshot: async () => snapshot, apply: async () => { throw new Error('unexpected system mutation'); } } });
  const checked = await manager.check();
  assert.equal(checked.status, 'ready'); assert.deepEqual(checked.current.languages, snapshot.languages);
  assert.deepEqual(JSON.parse(await readFile(checked.backup.path, 'utf8')).snapshot.languages, snapshot.languages);
  assert.deepEqual((await createEnvironmentManager({ stateDir, adapter: { scopeHash: async () => 'a'.repeat(64) } }).inspectSaved()).current.languages, snapshot.languages);
});

test('Windows saved culture resolves stale names by persisted standard locale and never resolves custom or cached placeholders numerically', { skip: process.platform !== 'win32' }, async () => {
  let captured;
  const adapter = createWindowsEnvironmentAdapter({ execFile: (_file, args, _options, callback) => { captured = args; callback(null, JSON.stringify({ ok: true, value: null })); } });
  await adapter.snapshot();
  const script = Buffer.from(captured.at(-1), 'base64').toString('utf16le');
  const helper = script.slice(script.indexOf('function SavedCulture {'), script.indexOf('function Snapshot {'));
  const fixtures = [
    { Locale: '00000804', LocaleName: 'fr-FR', expected: 'zh-CN' },
    { Locale: '0000040c', LocaleName: 'zh-CN', expected: 'fr-FR' },
    { Locale: '00000411', LocaleName: null, expected: 'ja-JP' },
    { Locale: '00000409', LocaleName: 'invalid&&', expected: 'en-US' },
    { Locale: '00000409', LocaleName: 'en-US', expected: 'en-US' },
    ...['00001000', '00000c00', '00001400'].flatMap(Locale => [
      { Locale, LocaleName: 'en-DE', expected: 'en-DE' }, { Locale, LocaleName: null, expected: 'REJECTED' }, { Locale, LocaleName: 'fr-FR', expected: 'REJECTED' },
    ]),
    ...['00000000', '0000007f', '00000400', '00000800', 'nothex', 'ffffffff'].map(Locale => ({ Locale, LocaleName: 'zh-CN', expected: 'REJECTED' })),
  ];
  const fixtureScript = String.raw`
function Get-ItemProperty { param($LiteralPath) if ($LiteralPath -cne 'HKCU:\Control Panel\International') { throw 'Unexpected registry access' }; return $script:fixture }
function Get-Culture { throw 'Cached process culture cannot prove persistence' }
$results = @(foreach ($item in (ConvertFrom-Json $env:MC_ENV_CULTURE_FIXTURES)) {
  $script:fixture = $item
  try { SavedCulture } catch { 'REJECTED' }
})
ConvertTo-Json -InputObject $results -Compress
`;
  const run = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(helper + fixtureScript, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 10000, env: { ...process.env, MC_ENV_CULTURE_FIXTURES: JSON.stringify(fixtures) } });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout.trim()), fixtures.map(item => item.expected));
});

test('Windows apply clears only a remaining InputMethodOverride property and keeps non-null setters native', { skip: process.platform !== 'win32' }, async t => {
  let captured;
  const adapter = createWindowsEnvironmentAdapter({ platform: 'win32', execFile: (_file, args, options, callback) => {
    captured = { args, options }; callback(null, JSON.stringify({ ok: true, value: null }));
  } });
  const target = await createMockEnvironmentAdapter().snapshot();
  await adapter.apply(target);
  const source = Buffer.from(captured.args.at(-1), 'base64').toString('utf16le');
  const fixtureSource = String.raw`
$script:InputTip='0409:00000409'; $script:Removes=0; $script:SetterCalls=0
$script:Languages=New-WinUserLanguageList -Language 'zh-Hans-CN'
$script:Culture='zh-CN'; $script:Ui=$null; $script:OptOut=$false
function Get-WinUserLanguageList { Write-Output -NoEnumerate $script:Languages }
function Get-WinUILanguageOverride { return $script:Ui }
function Get-WinDefaultInputMethodOverride {
  if ($null -eq $script:InputTip) { return $null }
  return [pscustomobject]@{InputMethodTip=$script:InputTip}
}
function Get-TimeZone { return [pscustomobject]@{Id='Taipei Standard Time'} }
function Get-WinHomeLocation { return [pscustomobject]@{GeoId=45} }
function Set-WinHomeLocation { throw 'Unexpected home region mutation' }
function Get-Culture { return [Globalization.CultureInfo]::GetCultureInfo($script:Culture) }
function Get-WinCultureFromLanguageListOptOut { return $script:OptOut }
function Get-ItemProperty {
  param($LiteralPath,$Name)
  if ($LiteralPath -ceq 'HKCU:\Control Panel\International') { return [pscustomobject]@{LocaleName=$script:Culture;Locale=([Globalization.CultureInfo]::GetCultureInfo($script:Culture).LCID.ToString('x8'))} }
  if ($LiteralPath -ceq 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts') { return [pscustomobject]@{'Segoe UI (TrueType)'='fixture'} }
  if ($LiteralPath -ceq 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation') { return [pscustomobject]@{DynamicDaylightTimeDisabled=0} }
  throw 'Unexpected registry read'
}
function Get-ChildItem {
  param($LiteralPath)
  if ($LiteralPath -cne 'HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages') { throw 'Unexpected registry read' }
  return [pscustomobject]@{PSChildName='zh-CN'}
}
function Set-WinUserLanguageList { param($LanguageList,[switch]$Force); $script:Languages=$LanguageList }
function Set-Culture { param($CultureInfo); $script:Culture=$CultureInfo }
function Set-WinUILanguageOverride { param($Language); $script:Ui=$(if ($Language) { [Globalization.CultureInfo]::GetCultureInfo($Language) } else { $null }) }
function Set-WinCultureFromLanguageListOptOut { param($OptOut); $script:OptOut=$OptOut }
function Set-WinDefaultInputMethodOverride {
  param($InputTip)
  $script:SetterCalls++
  if ($PSBoundParameters.ContainsKey('InputTip')) { $script:InputTip=$InputTip }
  elseif ($env:MC_ENVIRONMENT_FIXTURE_CLEAR -ceq '1') { $script:InputTip=$null }
}
function Remove-ItemProperty {
  param($LiteralPath,$Name,$ErrorAction)
  if ($LiteralPath -cne 'HKCU:\Control Panel\International\User Profile' -or $Name -cne 'InputMethodOverride' -or $ErrorAction -cne 'Stop') { throw 'Unexpected registry mutation' }
  $script:Removes++
  if ($env:MC_ENVIRONMENT_FIXTURE_DENY -ceq '1') { throw 'fixture private registry failure' }
  if ($env:MC_ENVIRONMENT_FIXTURE_DENY -ceq '2') { throw (New-Object System.UnauthorizedAccessException 'fixture private registry failure') }
  $script:InputTip=$null
}
function Remove-Item { throw 'Registry key deletion forbidden' }
function Set-ItemProperty { throw 'Registry property writes forbidden' }
function tzutil.exe { throw 'Unexpected timezone mutation' }
`;
  const inspected = source.replace('$value = @{applied=$true}', '$value = @{applied=$true; snapshot=(Snapshot); removes=$script:Removes; setterCalls=$script:SetterCalls}');
  assert.notEqual(inspected, source);
  const directory = await mkdtemp(path.resolve(import.meta.dirname, '.environment-script-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const scriptFile = path.join(directory, 'fixture.ps1');
  await writeFile(scriptFile, fixtureSource + inspected);
  function run(defaultInputMethod, clear = '0', deny = '0') {
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptFile], {
      encoding: 'utf8', windowsHide: true, timeout: 10000,
      env: { ...process.env, PROXYPILOT_ENVIRONMENT_INPUT: Buffer.from(JSON.stringify({ operation: 'apply', target: { ...target, defaultInputMethod } })).toString('base64'), MC_ENVIRONMENT_FIXTURE_CLEAR: clear, MC_ENVIRONMENT_FIXTURE_DENY: deny }
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.ok(!result.stdout.includes('fixture private registry failure'));
    return JSON.parse(result.stdout.trim());
  }
  const fallback = run(null);
  assert.equal(fallback.ok, true); assert.equal(fallback.value.snapshot.defaultInputMethod, null);
  assert.equal(fallback.value.removes, 1); assert.equal(fallback.value.setterCalls, 1);
  const native = run(null, '1');
  assert.equal(native.ok, true); assert.equal(native.value.snapshot.defaultInputMethod, null); assert.equal(native.value.removes, 0);
  const nonNull = run('0804:00000804');
  assert.equal(nonNull.ok, true); assert.equal(nonNull.value.snapshot.defaultInputMethod, '0804:00000804'); assert.equal(nonNull.value.removes, 0);
  assert.deepEqual(run(null, '0', '1'), { ok: false, code: 'ENVIRONMENT_WINDOWS_FAILED', diagnostic: { environmentStage: 'apply-input-method' } });
  assert.deepEqual(run(null, '0', '2'), { ok: false, code: 'ENVIRONMENT_PERMISSION_DENIED', diagnostic: { environmentStage: 'apply-input-method' } });
});

test('Windows apply shields coupled language changes, writes explicit Culture last and leaves timezone-only language settings untouched', { skip: process.platform !== 'win32' }, async t => {
  let captured;
  const adapter = createWindowsEnvironmentAdapter({ platform: 'win32', execFile: (_file, args, options, callback) => { captured = { args, options }; callback(null, JSON.stringify({ ok: true, value: null })); } });
  const original = await createMockEnvironmentAdapter().snapshot();
  await adapter.apply(original);
  const source = Buffer.from(captured.args.at(-1), 'base64').toString('utf16le');
  const fixtureSource = String.raw`
$script:State=$env:MC_ENVIRONMENT_FIXTURE_STATE | ConvertFrom-Json
$script:Writes=New-Object 'System.Collections.Generic.List[string]'
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
function Set-WinHomeLocation { param($GeoId); $script:Writes.Add('home-region'); $script:State.homeGeoId=$GeoId }
function Get-Culture { return [Globalization.CultureInfo]::GetCultureInfo($(if ($script:State.activeCulture) { $script:State.activeCulture } else { $script:State.culture })) }
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
  if (-not $script:State.cultureFromLanguageListOptOut) { throw 'The language transition was not shielded' }
  $script:Writes.Add('languages')
  $script:State.languages=@(foreach ($language in $LanguageList) { Language $language })
  $script:State.defaultInputMethod='0409:00000409'
}
function Set-WinUILanguageOverride {
  param($Language)
  if (-not $script:State.cultureFromLanguageListOptOut) { throw 'The UI language transition was not shielded' }
  $script:Writes.Add('uiLanguageOverride'); $script:State.uiLanguageOverride=$(if ($Language) { $Language } else { $null })
}
function Set-WinCultureFromLanguageListOptOut {
  param($OptOut)
  $script:Writes.Add('opt-out:' + [string]$OptOut); $script:State.cultureFromLanguageListOptOut=$OptOut
  # Model Windows restoring automatic display-language/region coupling. An
  # explicit Culture written before this transition must not count as restored.
  if (-not $OptOut) { $script:State.culture='en-US' }
}
function Set-Culture { param($CultureInfo); $script:Writes.Add('culture'); $script:State.culture=$CultureInfo }
function Set-WinDefaultInputMethodOverride { param($InputTip); $script:Writes.Add('input'); $script:State.defaultInputMethod=$InputTip }
function Remove-ItemProperty { throw 'Unexpected registry mutation' }
function Remove-Item { throw 'Unexpected registry deletion' }
function Set-ItemProperty { throw 'Unexpected registry mutation' }
function tzutil.exe { param($Option,$Zone); if ($Option -cne '/s') { throw 'Unexpected timezone command' }; $script:Writes.Add('timezone'); $script:State.timeZoneId=$Zone; $global:LASTEXITCODE=0 }
`;
  const inspected = source.replace('$value = @{applied=$true}', '$value = @{applied=$true; snapshot=(Snapshot); writes=@($script:Writes)}');
  const directory = await mkdtemp(path.resolve(import.meta.dirname, '.environment-script-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const scriptFile = path.join(directory, 'fixture.ps1');
  await writeFile(scriptFile, fixtureSource + inspected);
  function run(before, target) {
    const result = spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptFile], {
      encoding: 'utf8', windowsHide: true, timeout: 10000,
      env: { ...process.env, MC_ENVIRONMENT_FIXTURE_STATE: JSON.stringify(before), PROXYPILOT_ENVIRONMENT_INPUT: Buffer.from(JSON.stringify({ operation: 'apply', target })).toString('base64') },
    });
    assert.equal(result.status, 0, result.stdout + result.stderr); return JSON.parse(result.stdout.trim());
  }
  const localized = { ...original, timeZoneId: 'Tokyo Standard Time', culture: 'ja-JP', uiLanguageOverride: 'ja-JP', languages: [{ languageTag: 'ja-JP', inputMethodTips: ['0411:00000411'], handwriting: false }, ...original.languages], defaultInputMethod: '0411:00000411', cultureFromLanguageListOptOut: true };
  const applied = run(original, localized);
  assert.equal(applied.ok, true); assert.equal(applied.value.snapshot.culture, 'ja-JP'); assert.equal(applied.value.snapshot.cultureFromLanguageListOptOut, true);
  assert.equal(applied.value.writes[0], 'timezone'); assert.ok(applied.value.writes.indexOf('opt-out:True') < applied.value.writes.indexOf('languages'));
  assert.equal(applied.value.writes.at(-1), 'culture'); assert.equal(applied.value.snapshot.defaultInputMethod, localized.defaultInputMethod);
  const restored = run(localized, original);
  assert.equal(restored.ok, true); assert.equal(restored.value.snapshot.culture, original.culture); assert.equal(restored.value.snapshot.cultureFromLanguageListOptOut, false);
  assert.ok(restored.value.writes.indexOf('opt-out:False') < restored.value.writes.indexOf('culture'));
  assert.equal(restored.value.snapshot.defaultInputMethod, null); assert.deepEqual(restored.value.snapshot.languages, original.languages);
  const timezoneOnly = run(original, { ...original, timeZoneId: 'Tokyo Standard Time' });
  assert.equal(timezoneOnly.ok, true); assert.deepEqual(timezoneOnly.value.writes, ['timezone']);
  const unchanged = run(original, original);
  assert.equal(unchanged.ok, true); assert.deepEqual(unchanged.value.writes, []);
  const cachedCulture = run({ ...original, activeCulture: 'en-US' }, original);
  assert.equal(cachedCulture.ok, true); assert.equal(cachedCulture.value.snapshot.culture, 'zh-CN');
  assert.equal(cachedCulture.value.snapshot.activeCulture, 'en-US'); assert.deepEqual(cachedCulture.value.writes, []);
});

test('persisted Culture is verified exactly while cached process Culture remains visible as activation pending', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const snapshot = adapter.snapshot;
  adapter.snapshot = async () => ({ ...await snapshot(), activeCulture: 'en-US' });
  const original = (await manager.check()).current;
  const applied = await manager.optimize({ geo });
  assert.equal(applied.current.culture, 'zh-SG'); assert.equal(applied.current.activeCulture, 'en-US');
  assert.equal(applied.needsApplicationRestart, true); assert.match(applied.warnings.join(''), /保存的区域格式与检测进程/);
  const restored = await manager.restore({ original: true });
  assert.equal(restored.current.culture, original.culture); assert.equal(restored.current.activeCulture, 'en-US');
  assert.equal(restored.optimization.status, 'restored'); assert.equal(restored.backup.canRestore, true); assert.equal(restored.backup.restoreNeeded, false);
  assert.equal(restored.needsApplicationRestart, true);
  const saved = await createEnvironmentManager({ stateDir, adapter }).inspectSaved(); assert.equal(saved.needsApplicationRestart, true);
  const apply = adapter.apply; let writes = 0;
  adapter.apply = async target => { writes++; return apply({ ...target, culture: 'fr-FR' }); };
  const partial = await manager.optimize({ geo });
  assert.equal(partial.optimization.status, 'partial'); assert.deepEqual(partial.optimization.differingFields, ['culture']);
  assert.equal(writes, 1); assert.equal(manager.status().backup.canRestore, true, 'an incorrect persisted Culture must never be excused by an activation delay');
});

test('invalid live snapshot is distinct from invalid saved state and neither creates a recovery baseline', async t => {
  const { adapter, stateDir } = await fixture(t);
  const snapshot = await adapter.snapshot();
  adapter.snapshot = async () => ({ ...snapshot, languages: [{ ...snapshot.languages[0], languageTag: 'zh-Hans-CN en-US' }] });
  const manager = createEnvironmentManager({ stateDir, adapter });
  await assert.rejects(manager.check(), { code: 'ENVIRONMENT_SNAPSHOT_INVALID' });
  assert.deepEqual(await readdir(path.dirname(stateDir)), []);
  await assert.rejects(manager.check({ refreshBackup: true, rebuildBackup: true }), { code: 'ENVIRONMENT_SNAPSHOT_INVALID' });
  assert.deepEqual(await readdir(path.dirname(stateDir)), []);
  await assert.rejects(manager.optimize({ geo }), { code: 'ENVIRONMENT_SNAPSHOT_INVALID' });
  assert.equal(manager.status().optimization.code, 'ENVIRONMENT_SNAPSHOT_INVALID');
});

test('saving work and daily profiles performs no Windows inspection or mutation and survives startup', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  let reads = 0, writes = 0;
  adapter.snapshot = async () => { reads++; throw new Error('saving preferences must not inspect Windows'); };
  adapter.apply = async () => { writes++; throw new Error('saving preferences must not mutate Windows'); };
  const preferences = defaultEnvironmentPreferences();
  preferences.work = { mode: 'custom', countryCode: 'US', timeZoneId: 'Pacific Standard Time', preferredLanguage: 'en-US', culture: 'zh-SG' };
  preferences.daily = { countryCode: 'CN', timeZoneId: 'China Standard Time', preferredLanguage: 'zh-CN', culture: 'zh-CN' };
  const saved = await manager.savePreferences(preferences);
  assert.deepEqual(saved.preferences, preferences);
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const loaded = await restarted.inspectSaved();
  assert.deepEqual(loaded.preferences, preferences);
  assert.equal(reads, 0); assert.equal(writes, 0);
  assert.ok(loaded.profileCatalog.presets.some(item => item.countryCode === 'JP'));
  assert.ok(loaded.profileCatalog.timeZones.includes('Pacific Standard Time'));
  await assert.rejects(readFile(path.join(stateDir, 'state.json')), { code: 'ENOENT' });
});

test('a manually selected work profile applies offline and retains the original snapshot', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const baseline = await manager.check(), bytes = await readFile(baseline.backup.path);
  const preferences = defaultEnvironmentPreferences();
  preferences.work = { mode: 'custom', countryCode: 'US', timeZoneId: 'Pacific Standard Time', preferredLanguage: 'en-US', culture: 'zh-SG' };
  await manager.savePreferences(preferences);
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const applied = await restarted.optimize({ force: true });
  assert.equal(applied.optimization.status, 'applied');
  assert.equal(applied.current.timeZoneId, 'Pacific Standard Time');
  assert.equal(applied.current.homeGeoId, 244); assert.equal(applied.current.culture, 'zh-SG');
  assert.equal(applied.current.languages[0].languageTag, 'en-US');
  assert.equal(applied.appliedRegion.mode, 'custom');
  assert.equal(applied.backup.id, baseline.backup.id); assert.deepEqual(await readFile(baseline.backup.path), bytes);
});

test('daily restore force-overwrites current settings from saved choices after restart while original restore stays separate', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const initial = await manager.check(), backupBytes = await readFile(initial.backup.path);
  const preferences = defaultEnvironmentPreferences();
  preferences.daily = { countryCode: 'CN', timeZoneId: 'China Standard Time', preferredLanguage: 'zh-CN', culture: 'zh-CN' };
  await manager.savePreferences(preferences); await manager.optimize({ geo });
  await adapter.apply({ ...await adapter.snapshot(), timeZoneId: 'Eastern Standard Time', culture: 'fr-FR', homeGeoId: 244 });
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const daily = await restarted.restore();
  assert.equal(daily.restored, true); assert.equal(daily.optimization.restoreSource, 'daily');
  assert.equal(daily.current.timeZoneId, preferences.daily.timeZoneId);
  assert.equal(daily.current.homeGeoId, 45); assert.equal(daily.current.culture, 'zh-CN');
  assert.match(daily.current.languages[0].languageTag, /^zh-(?:Hans-)?CN$/);
  assert.equal(daily.backup.restoreNeeded, false);
  const repeat = await createEnvironmentManager({ stateDir, adapter }).restore();
  assert.equal(repeat.noChange, true); assert.equal(repeat.backup.restoreNeeded, false);
  const original = await createEnvironmentManager({ stateDir, adapter }).restore({ original: true });
  assert.equal(original.optimization.restoreSource, 'original'); assert.deepEqual(original.current, initial.current);
  assert.deepEqual(await readFile(initial.backup.path), backupBytes);
});

test('daily restoration requires an explicit saved daily plan and never silently substitutes the original snapshot', async t => {
  const { manager, adapter } = await fixture(t);
  const initial = await manager.check(); await manager.optimize({ geo });
  let writes = 0; const apply = adapter.apply;
  adapter.apply = async target => { writes++; return apply(target); };
  await assert.rejects(manager.restore(), { code: 'ENVIRONMENT_DAILY_REQUIRED' });
  assert.equal(writes, 0);
  assert.deepEqual((await manager.restore({ original: true })).current, initial.current);
  assert.equal(writes, 1);
});

test('corrupt profile settings do not prevent explicit recovery using the valid original snapshot', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const initial = await manager.check(); await manager.optimize({ geo });
  const corrupt = '{broken profile preferences';
  await writeFile(path.join(stateDir, 'envprefs.json'), corrupt);
  const restarted = createEnvironmentManager({ stateDir, adapter });
  const result = await restarted.restore({ original: true });
  assert.equal(result.restored, true); assert.deepEqual(result.current, initial.current);
  assert.equal(await readFile(path.join(stateDir, 'envprefs.json'), 'utf8'), corrupt);
});

test('old snapshots gain a separate home-region recovery value before the first new write without changing original backup bytes', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const initial = await manager.check(), stateFile = path.join(stateDir, 'state.json');
  const legacyState = JSON.parse(await readFile(stateFile, 'utf8'));
  delete legacyState.backup.snapshot.homeGeoId; delete legacyState.backup.snapshot.homeCountryCode;
  delete legacyState.lastObserved.homeGeoId; delete legacyState.lastObserved.homeCountryCode;
  const legacyBackup = JSON.parse(await readFile(initial.backup.path, 'utf8'));
  delete legacyBackup.snapshot.homeGeoId; delete legacyBackup.snapshot.homeCountryCode;
  await writeFile(stateFile, JSON.stringify(legacyState));
  await writeFile(initial.backup.path, JSON.stringify(legacyBackup));
  const backupBytes = await readFile(initial.backup.path);
  const restarted = createEnvironmentManager({ stateDir, adapter });
  assert.equal((await restarted.optimize({ geo, force: true })).current.homeGeoId, 122);
  const state = JSON.parse(await readFile(stateFile, 'utf8'));
  assert.deepEqual(state.supplementalOriginalSettings, { homeGeoId: 45 });
  assert.equal(state.backup.snapshot.homeGeoId, undefined);
  await adapter.apply({ ...await adapter.snapshot(), homeGeoId: 244 });
  const restored = await createEnvironmentManager({ stateDir, adapter }).restore({ original: true });
  assert.equal(restored.current.homeGeoId, 45);
  assert.deepEqual(await readFile(initial.backup.path), backupBytes);
});

test('Windows language aliases and case or order normalization of input methods do not cause false partial failures', async t => {
  const { manager, adapter } = await fixture(t);
  const apply = adapter.apply;
  const original = { ...await adapter.snapshot(), languages: [{ languageTag: 'zh-Hans-CN', inputMethodTips: ['0804:00000804', '0804:00000abc'], handwriting: false }] };
  await apply(original);
  adapter.apply = async target => apply({ ...target,
    culture: target.culture === 'zh-SG' ? 'zh-Hans-SG' : target.culture,
    languages: target.languages.map(item => ({ ...item, languageTag: item.languageTag.replace(/^zh-Hans-CN$/, 'zh-CN'), inputMethodTips: [...item.inputMethodTips].reverse().map(tip => tip.toUpperCase()) })),
    defaultInputMethod: target.defaultInputMethod?.toLowerCase() ?? null,
  });
  const result = await manager.optimize({ geo: { ...geo, countryCode: 'CN', city: 'Shanghai', timezone: 'Asia/Shanghai' } });
  assert.equal(result.optimization.status, 'applied'); assert.deepEqual(result.optimization.differingFields, []);
  assert.equal((await manager.check()).status, 'optimized');
  const restored = await manager.restore({ original: true });
  assert.equal(restored.restored, true); assert.deepEqual(restored.optimization.differingFields, []);
});

test('a stale preferences editor rejects overwriting new choices and refresh reloads the newer saved plan', async t => {
  const { manager, adapter, stateDir } = await fixture(t);
  const initial = defaultEnvironmentPreferences();
  await manager.savePreferences(initial); await manager.check();
  const other = createEnvironmentManager({ stateDir, adapter }); await other.inspectSaved();
  const newer = { ...initial, work: { ...initial.work, mode: 'custom', countryCode: 'JP', timeZoneId: 'Tokyo Standard Time', preferredLanguage: 'ja-JP' } };
  await manager.savePreferences(newer);
  await assert.rejects(other.savePreferences(initial), { code: 'ENVIRONMENT_PROFILE_CONFLICT' });
  assert.deepEqual((await other.check()).preferences, newer);
  assert.deepEqual((await other.savePreferences(initial)).preferences, initial);
});
