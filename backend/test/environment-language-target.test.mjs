import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createEnvironmentManager, createMockEnvironmentAdapter } from '../src/environment-manager.mjs';
import { defaultEnvironmentPreferences } from '../src/environment-profiles.mjs';

const wubi = '0804:{81D4E9C9-1D3B-41BC-9E6C-4B40BF79E35E}{FA550B04-5AD7-411F-A5AC-CA038EC515D7}';
const pinyin = '0804:{E7EA138E-69F8-11D7-A6EA-00065B844310}{E7EA138F-69F8-11D7-A6EA-00065B844311}';
const english = { languageTag: 'en-US', inputMethodTips: ['0409:00000409'], handwriting: false };
const traditional = { languageTag: 'zh-Hant-TW', inputMethodTips: ['0404:00000404'], handwriting: false };
const tipSet = language => language.inputMethodTips.map(tip => tip.toLowerCase()).sort();
const preferences = () => ({ ...defaultEnvironmentPreferences(),
  work: { mode: 'custom', countryCode: 'SG', timeZoneId: 'Singapore Standard Time', preferredLanguage: 'zh-SG', culture: 'zh-SG' },
  daily: { countryCode: 'CN', timeZoneId: 'China Standard Time', preferredLanguage: 'zh-CN', culture: 'zh-CN' },
});

async function fixture(t, languages) {
  const stateDir = await mkdtemp(path.resolve(import.meta.dirname, '.environment-language-target-'));
  t.after(() => rm(stateDir, { recursive: true, force: true }));
  const adapter = createMockEnvironmentAdapter();
  await adapter.apply({ ...await adapter.snapshot(), languages: languages || [
    { languageTag: 'zh-Hans-CN', inputMethodTips: [pinyin, wubi], handwriting: true }, english, traditional,
  ] });
  adapter.defaultLanguage = async languageTag => ({ languageTag, inputMethodTips: [wubi.toLowerCase()], handwriting: false });
  const manager = createEnvironmentManager({ stateDir, adapter });
  await manager.savePreferences(preferences());
  return { manager, adapter };
}

test('CN to SG work and back to CN daily uses one regional Chinese entry retaining every existing keyboard and original backup', async t => {
  const { manager, adapter } = await fixture(t);
  const before = await manager.check(), backupBytes = await readFile(before.backup.path);
  const apply = adapter.apply; const targets = [];
  adapter.apply = async target => {
    targets.push(structuredClone(target));
    await apply({ ...target, languages: target.languages.map(item => ({ ...item,
      languageTag: item.languageTag.replace(/^zh-(CN|SG)$/, 'zh-Hans-$1'),
      inputMethodTips: [...item.inputMethodTips].reverse().map(tip => tip.toUpperCase()),
    })) });
  };
  const work = await manager.optimize({ force: true });
  assert.equal(work.optimization.status, 'applied');
  assert.deepEqual(targets[0].languages.map(item => item.languageTag), ['zh-SG', 'en-US', 'zh-Hant-TW']);
  assert.deepEqual(tipSet(targets[0].languages[0]), [pinyin, wubi].map(tip => tip.toLowerCase()).sort());
  assert.equal(targets[0].languages[0].handwriting, true);
  assert.equal(work.current.languages[0].languageTag, 'zh-Hans-SG');
  assert.deepEqual(work.optimization.differingFields, []);

  const daily = await manager.restore();
  assert.equal(daily.restored, true);
  assert.deepEqual(targets[1].languages.map(item => item.languageTag), ['zh-CN', 'en-US', 'zh-Hant-TW']);
  assert.deepEqual(tipSet(targets[1].languages[0]), tipSet(targets[0].languages[0]));
  assert.equal(targets[1].languages[0].handwriting, true);
  assert.equal(daily.current.languages[0].languageTag, 'zh-Hans-CN');
  assert.equal(daily.backup.restoreNeeded, false);
  assert.deepEqual(await readFile(before.backup.path), backupBytes);
});

test('existing CN and SG variants merge their keyboards without merging Traditional Chinese or other regions', async t => {
  const british = { languageTag: 'en-GB', inputMethodTips: ['0809:00000809'], handwriting: false };
  const { manager } = await fixture(t, [
    { languageTag: 'zh-Hans-SG', inputMethodTips: [wubi], handwriting: false },
    { languageTag: 'zh-CN', inputMethodTips: [wubi.toLowerCase(), pinyin], handwriting: true },
    english, british, traditional,
  ]);
  const applied = await manager.optimize({ force: true });
  assert.equal(applied.optimization.status, 'applied');
  assert.deepEqual(applied.current.languages.map(item => item.languageTag), ['zh-Hans-SG', 'en-US', 'en-GB', 'zh-Hant-TW']);
  assert.deepEqual(tipSet(applied.current.languages[0]), [pinyin, wubi].map(tip => tip.toLowerCase()).sort());
  assert.equal(applied.current.languages[0].handwriting, true);
  assert.deepEqual(applied.current.languages.slice(1), [english, british, traditional]);
});

for (const [name, change] of [
  ['a retained language is missing', languages => languages.filter(item => item.languageTag !== 'en-US')],
  ['an existing keyboard is missing', languages => languages.map((item, index) => index ? item : { ...item, inputMethodTips: item.inputMethodTips.filter(tip => tip.toLowerCase() !== pinyin.toLowerCase()) })],
  ['CN persisted instead of requested SG', languages => languages.map((item, index) => index ? item : { ...item, languageTag: 'zh-Hans-CN' })],
  ['the preferred language is not first', languages => [languages[1], languages[0], ...languages.slice(2)]],
]) {
  test(`Chinese planning still reports partial when ${name}`, async t => {
    const { manager, adapter } = await fixture(t);
    const apply = adapter.apply;
    adapter.apply = async target => apply({ ...target, languages: change(structuredClone(target.languages)) });
    const result = await manager.optimize({ force: true });
    assert.equal(result.optimization.status, 'partial');
    assert.deepEqual(result.optimization.differingFields, ['languages']);
    assert.equal(result.optimization.fieldResults.find(item => item.field === 'languages').status, 'unmatched');
    assert.equal(result.current.homeGeoId, 215);
    assert.equal(result.current.culture, 'zh-SG');
  });
}
