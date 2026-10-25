import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { createEnvironmentManager, createMockEnvironmentAdapter } from '../src/environment-manager.mjs';
import { defaultEnvironmentPreferences } from '../src/environment-profiles.mjs';

const geo = { verified: true, ip: '203.0.113.8', countryCode: 'JP', city: 'Tokyo', timezone: 'Asia/Tokyo' };
const languageResult = value => value.verification.fieldResults.find(item => item.field === 'languages');
async function fixture(t) {
  const stateDir = await mkdtemp(path.resolve(import.meta.dirname, '.environment-verification-'));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const adapter = createMockEnvironmentAdapter();
  let tick = Date.parse('2026-10-14T10:00:00.000Z');
  const now = () => tick += 1000;
  const manager = createEnvironmentManager({ stateDir, adapter, now });
  const file = path.join(stateDir, 'state.json');
  const readState = async () => JSON.parse(await readFile(file, 'utf8'));
  return { stateDir, adapter, manager, now, file, readState };
}
async function partialLanguage(fixture) {
  const { adapter, manager } = fixture;
  const apply = adapter.apply;
  adapter.apply = async target => {
    await apply({ ...target, languages: (await adapter.snapshot()).languages });
    return { applied: false, failures: [{ field: 'languages', code: 'ENVIRONMENT_WINDOWS_FAILED', environmentStage: 'apply-language-list' }] };
  };
  const partial = await manager.optimize({ geo, force: true });
  adapter.apply = apply;
  return partial;
}

test('checking externally repaired settings refreshes verification without rewriting failed operation or mutation baseline', async t => {
  const fixtureValue = await fixture(t);
  const { manager, adapter, readState } = fixtureValue;
  const partial = await partialLanguage(fixtureValue), saved = await readState();
  assert.equal(partial.optimization.failures[0].phase, 'apply');
  assert.equal(partial.verification.status, 'partial');
  assert.equal(languageResult(partial).status, 'unmatched');
  await adapter.apply(partial.optimization.target);
  const repaired = await manager.check(), checkedState = await readState();
  assert.equal(repaired.verification.status, 'matched');
  assert.equal(languageResult(repaired).status, 'matched');
  assert.deepEqual(repaired.verification.differingFields, []);
  assert.equal(repaired.verification.source, 'live');
  assert.equal(repaired.verification.checkedAt, repaired.checkedAt);
  assert.notEqual(repaired.checkedAt, partial.checkedAt);
  assert.deepEqual(repaired.optimization, partial.optimization);
  assert.deepEqual(checkedState.optimization, saved.optimization);
  assert.deepEqual(checkedState.lastApplied, saved.lastApplied);
  assert.equal(checkedState.pending, saved.pending);
  assert.equal(repaired.status, 'conflict', 'external repair must not silently rewrite the managed baseline');
});

test('checking detects damage after successful apply and saving preferences retains the last observation source and time', async t => {
  const { manager, adapter } = await fixture(t);
  const applied = await manager.optimize({ geo });
  assert.equal(applied.verification.status, 'matched');
  await adapter.apply({ ...await adapter.snapshot(), culture: 'fr-FR' });
  const changed = await manager.check();
  assert.equal(changed.verification.status, 'partial');
  assert.deepEqual(changed.verification.differingFields, ['culture']);
  assert.deepEqual(changed.optimization, applied.optimization);
  adapter.snapshot = async () => { throw new Error('preference save must not inspect Windows'); };
  const saved = await manager.savePreferences(defaultEnvironmentPreferences());
  assert.deepEqual(saved.verification, changed.verification);
  assert.equal(saved.snapshotSource, 'live');
  assert.equal(saved.checkedAt, changed.checkedAt);
});

test('failed target preparation cannot treat the previous language placeholder as a matched request', async t => {
  const { manager, adapter } = await fixture(t);
  adapter.defaultLanguage = async () => { throw Object.assign(new Error('fixture failure'), { code: 'ENVIRONMENT_WINDOWS_FAILED' }); };
  const partial = await manager.optimize({ geo });
  assert.equal(partial.optimization.failures[0].phase, 'preparation');
  assert.deepEqual(partial.current.languages, partial.optimization.target.languages);
  assert.equal(partial.verification.status, 'unverified');
  assert.equal(languageResult(partial).status, 'unknown');
  assert.deepEqual(partial.verification.differingFields, []);
  const rechecked = await manager.check();
  assert.equal(languageResult(rechecked).status, 'unknown');
  assert.deepEqual(rechecked.optimization, partial.optimization);
});

test('legacy failures stay unknown even after matching the saved placeholder and saved startup never claims a new live read', async t => {
  const fixtureValue = await fixture(t);
  const { adapter, file, readState, stateDir, now } = fixtureValue;
  const partial = await partialLanguage(fixtureValue);
  await adapter.apply(partial.optimization.target);
  const legacy = await readState(); delete legacy.optimization.failures[0].phase;
  legacy.lastObserved = await adapter.snapshot();
  await writeFile(file, JSON.stringify(legacy));
  const restarted = createEnvironmentManager({ stateDir, adapter, now });
  const checked = await restarted.check();
  assert.equal(checked.verification.status, 'unverified');
  assert.equal(languageResult(checked).status, 'unknown');
  assert.deepEqual(checked.optimization, legacy.optimization);
  adapter.snapshot = async () => { throw new Error('saved startup must not inspect Windows'); };
  adapter.apply = async () => { throw new Error('saved startup must not mutate Windows'); };
  const savedManager = createEnvironmentManager({ stateDir, adapter, now });
  const saved = await savedManager.inspectSaved();
  assert.equal(saved.verification.source, 'saved');
  assert.equal(saved.verification.checkedAt, checked.checkedAt);
  assert.equal(languageResult(saved).status, 'unknown');
  const updated = await savedManager.savePreferences(defaultEnvironmentPreferences());
  assert.deepEqual(updated.verification, saved.verification);
  assert.equal(updated.snapshotSource, 'saved');
  assert.equal(updated.checkedAt, saved.checkedAt);
});

test('no target, interrupted transactions, unknown failures and foreign or unbound records never produce matched verification', async t => {
  const { manager, adapter, file, readState, stateDir, now } = await fixture(t);
  assert.equal((await manager.check()).verification.status, 'unverified');
  const applied = await manager.optimize({ geo }), baseline = await readState();
  assert.equal(applied.verification.status, 'matched');
  const pending = { ...baseline, pending: { before: baseline.lastObserved, target: baseline.lastObserved, startedAt: baseline.checkedAt } };
  for (const record of [pending, { ...baseline, optimization: { ...baseline.optimization, failures: [null] } }, { ...baseline, scopeHash: 'b'.repeat(64) }, { ...baseline, version: 1 }]) {
    await writeFile(file, JSON.stringify(record));
    const saved = await createEnvironmentManager({ stateDir, adapter, now }).inspectSaved();
    assert.equal(saved.verification.status, 'unverified');
    assert.ok(saved.verification.fieldResults.every(item => item.status === 'unknown'));
  }
});
