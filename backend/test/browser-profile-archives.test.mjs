import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdtemp, mkdir, readFile, writeFile, access, rename, rm } from 'node:fs/promises';
import { createBrowserProfileArchives } from '../src/browser-profile-archives.mjs';

async function fixture(t, values = {}) {
  await mkdir(fileURLToPath(new URL('../../.cache/', import.meta.url)), { recursive: true });
  const root = await mkdtemp(fileURLToPath(new URL('../../.cache/profile-archive-fault-', import.meta.url)));
  t.after(() => rm(root, { recursive: true, force: true }));
  const profileRoot = path.join(root, 'browser-profiles'), current = path.join(profileRoot, 'chrome'), journal = path.join(profileRoot, '.profile-change.json');
  const safePath = async file => { const relative = path.relative(root, path.resolve(file)); assert.ok(!relative.startsWith('..') && !path.isAbsolute(relative)); };
  const readJson = async file => { try { return JSON.parse(await readFile(file, 'utf8')); } catch (cause) { if (cause.code === 'ENOENT') return null; throw cause; } };
  const writeJson = async (file, data) => { await mkdir(path.dirname(file), { recursive: true }); await writeFile(file, JSON.stringify(data)); };
  const options = { profileRoot, browsers: ['chrome'], safePath, readJson, writeJson, assertClosed: async () => {}, ...values };
  return { root, profileRoot, current, journal, options, store: createBrowserProfileArchives(options) };
}
async function put(file, value) { await mkdir(path.dirname(file), { recursive: true }); await writeFile(file, value); }
const missing = file => assert.rejects(access(file), { code: 'ENOENT' });

test('a failed first rename leaves the current profile intact and does not publish empty history', async t => {
  const f = await fixture(t, { move: async () => { throw Object.assign(new Error('private local path'), { code: 'EPERM' }); } });
  await put(path.join(f.current, 'Cookies'), 'original');
  await assert.rejects(f.store.refresh({ confirm: true }), cause => cause.code === 'BROWSER_PROFILE_UPDATE_FAILED' && !cause.message.includes('private'));
  assert.equal(await readFile(path.join(f.current, 'Cookies'), 'utf8'), 'original');
  assert.deepEqual((await f.store.list()).archives, []); await missing(f.journal);
});

test('a failed selected-history rename rolls back the displaced current profile and can be retried', async t => {
  const f = await fixture(t); await put(path.join(f.current, 'Cookies'), 'old-login');
  const { archiveId } = await f.store.refresh({ confirm: true }); await put(path.join(f.current, 'Cookies'), 'current-login');
  let failed = false;
  const broken = createBrowserProfileArchives({ ...f.options, move: async (from, to) => {
    if (!failed && from.includes(archiveId)) { failed = true; throw Object.assign(new Error('denied'), { code: 'EACCES' }); }
    return rename(from, to);
  } });
  await assert.rejects(broken.restore({ confirm: true, archiveId }), { code: 'BROWSER_PROFILE_UPDATE_FAILED' });
  assert.equal(await readFile(path.join(f.current, 'Cookies'), 'utf8'), 'current-login');
  assert.equal(await readFile(path.join(f.profileRoot, 'archive', 'chrome', archiveId, 'profile', 'Cookies'), 'utf8'), 'old-login');
  await missing(f.journal); assert.deepEqual((await broken.list()).archives.map(item => item.id), [archiveId]);
  await broken.restore({ confirm: true, archiveId });
  assert.equal(await readFile(path.join(f.current, 'Cookies'), 'utf8'), 'old-login');
});

test('a failed restore and failed rollback retain intent so restart completes before a new profile is created', async t => {
  const f = await fixture(t); await put(path.join(f.current, 'Cookies'), 'old-login');
  const { archiveId } = await f.store.refresh({ confirm: true }); await put(path.join(f.current, 'Cookies'), 'current-login');
  let moves = 0;
  const broken = createBrowserProfileArchives({ ...f.options, move: async (from, to) => {
    moves++;
    if (moves >= 2) throw Object.assign(new Error('locked'), { code: 'EPERM' });
    return rename(from, to);
  } });
  await assert.rejects(broken.restore({ confirm: true, archiveId }), { code: 'BROWSER_PROFILE_UPDATE_FAILED' });
  await access(f.journal); await missing(f.current);
  const restarted = createBrowserProfileArchives(f.options), state = await restarted.list();
  assert.equal(state.currentAvailable, true); assert.equal(state.archives.length, 1);
  assert.equal(await readFile(path.join(f.current, 'Cookies'), 'utf8'), 'old-login');
  assert.equal(await readFile(path.join(f.profileRoot, 'archive', 'chrome', state.archives[0].id, 'profile', 'Cookies'), 'utf8'), 'current-login');
  await missing(f.journal);
});

test('metadata failure occurs before a move and recovery never replaces a conflicting canonical profile', async t => {
  const f = await fixture(t); await put(path.join(f.current, 'Cookies'), 'original');
  let moves = 0;
  const broken = createBrowserProfileArchives({ ...f.options, writeJson: async (file, value) => {
    if (file.endsWith('archive.json')) throw Object.assign(new Error('metadata disk full'), { code: 'ENOSPC' });
    return f.options.writeJson(file, value);
  }, move: async (from, to) => { moves++; return rename(from, to); } });
  await assert.rejects(broken.refresh({ confirm: true }), { code: 'BROWSER_PROFILE_UPDATE_FAILED' });
  assert.equal(moves, 0); assert.equal(await readFile(path.join(f.current, 'Cookies'), 'utf8'), 'original'); await missing(f.journal);
  const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', createdAt = '2026-10-16T12:00:00.000Z';
  await f.options.writeJson(path.join(f.profileRoot, 'archive', 'chrome', id, 'archive.json'), { version: 1, browser: 'chrome', id, createdAt });
  await put(path.join(f.profileRoot, 'archive', 'chrome', id, 'profile', 'Cookies'), 'conflicting-history');
  await f.options.writeJson(f.journal, { version: 1, browser: 'chrome', operation: 'refresh', currentId: id, createdAt });
  await assert.rejects(f.store.recover(), { code: 'BROWSER_STATE_INVALID' });
  assert.equal(await readFile(path.join(f.current, 'Cookies'), 'utf8'), 'original');
  assert.equal(await readFile(path.join(f.profileRoot, 'archive', 'chrome', id, 'profile', 'Cookies'), 'utf8'), 'conflicting-history'); await access(f.journal);
});
