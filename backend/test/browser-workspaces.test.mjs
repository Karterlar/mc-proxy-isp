import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, writeFile, readFile, rm, access, symlink } from 'node:fs/promises';
import { createBrowserWorkspaceManager, validateWorkspaceIdentity, workspaceBrowser } from '../src/browser-workspaces.mjs';

const binding = 'a'.repeat(64);
const identity = { version: 1, language: 'en-US', timezone: 'America/New_York', nativeGraphics: false };
async function fixture(t, extra = {}) {
  await mkdir(path.resolve('.cache'), { recursive: true });
  const root = await mkdtemp(path.resolve('.cache/workspaces-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const dependencies = { createPrivateDirectory: directory => mkdir(directory, { mode: 0o700 }), ...extra.dependencies };
  return { root, manager: createBrowserWorkspaceManager({ runtimeRoot: root, ...extra, dependencies }) };
}

test('workspace metadata persists independently, binds exact ISP and deletion retains all browser data', async t => {
  const { root, manager } = await fixture(t, { now: () => Date.parse('2026-10-13T00:00:00Z') });
  assert.deepEqual(await manager.list(), { version: 1, items: [] });
  await assert.rejects(access(path.join(root, '.browser-workspaces')), { code: 'ENOENT' });
  const item = await manager.create({ name: ' 工作 ', services: ['chatgpt', 'claude'], binding });
  assert.equal(item.name, '工作'); assert.equal(item.lastOpenedAt, null); assert.equal(item.browser, 'chrome');
  const profile = path.join(root, 'browser-profiles', 'workspaces', item.id, 'chrome');
  await mkdir(profile, { recursive: true }); await writeFile(path.join(profile, 'Cookies'), 'existing-login');
  await writeFile(path.join(root, 'config.json'), 'existing-config');
  await manager.update(item.id, { name: '客户工作', services: ['claude'] }); await manager.touch(item.id);
  assert.equal((await createBrowserWorkspaceManager({ runtimeRoot: root }).get(item.id)).lastOpenedAt, '2026-10-13T00:00:00.000Z');
  assert.equal((await manager.assertBinding(item.id, binding)).name, '客户工作');
  await assert.rejects(manager.assertBinding(item.id, 'b'.repeat(64)), { code: 'WORKSPACE_BINDING_MISMATCH' });
  await manager.remove(item.id);
  assert.equal(await readFile(path.join(profile, 'Cookies'), 'utf8'), 'existing-login');
  assert.equal(await readFile(path.join(root, 'config.json'), 'utf8'), 'existing-config');
  assert.deepEqual((await manager.list()).items, []);
});

test('workspace inputs reject path/URL/secret fields, invalid IDs and stale records without mutating saved state', async t => {
  const { root, manager } = await fixture(t);
  for (const bad of [{ name: '' }, { name: 'x\n' }, { services: [] }, { services: ['https://evil.test'] }, { services: ['claude', 'claude'] }, { binding: 'password' }, { browser: 'firefox' }, { browser: null }, { profile: '../elsewhere' }, { password: 'secret' }]) await assert.rejects(manager.create({ name: 'Test', services: ['claude'], binding, ...bad }));
  const item = await manager.create({ name: 'Test', services: ['claude'], binding });
  await assert.rejects(manager.get('../config.json'), { code: 'WORKSPACE_ID_INVALID' });
  const file = path.join(root, '.browser-workspaces', 'workspaces.json'), before = await readFile(file, 'utf8');
  await assert.rejects(manager.update(item.id, { id: '../bad' })); assert.equal(await readFile(file, 'utf8'), before);
  await writeFile(file, '{malformed');
  await assert.rejects(manager.create({ name: 'Test2', services: ['claude'], binding }), { code: 'WORKSPACE_STATE_INVALID' });
  assert.equal(await readFile(file, 'utf8'), '{malformed');
});

test('browser choice is immutable and replacement inherits Chrome, Edge and legacy fingerprint without migrating reads', async t => {
  const { root, manager } = await fixture(t);
  const file = path.join(root, '.browser-workspaces', 'workspaces.json');
  for (const browser of ['chrome', 'edge', 'fingerprint']) {
    const item = await manager.create({ name: browser, services: ['claude'], binding, browser });
    assert.equal(workspaceBrowser(item), browser);
    const before = await readFile(file, 'utf8');
    await assert.rejects(manager.update(item.id, { browser: browser === 'chrome' ? 'fingerprint' : 'chrome' }), { code: 'WORKSPACE_BROWSER_IMMUTABLE' });
    assert.equal(await readFile(file, 'utf8'), before);
    const replacement = await manager.replace(item.id);
    assert.equal(replacement.item.browser, browser);
  }
  const legacy = await manager.create({ name: 'Legacy', services: ['claude'], binding, browser: 'fingerprint' });
  const state = JSON.parse(await readFile(file, 'utf8')); delete state.items.find(item => item.id === legacy.id).browser;
  const bytes = JSON.stringify(state); await writeFile(file, bytes);
  assert.equal(workspaceBrowser(await manager.get(legacy.id)), 'fingerprint');
  assert.equal(await readFile(file, 'utf8'), bytes);
  await assert.rejects(manager.update(legacy.id, { browser: 'chrome' }), { code: 'WORKSPACE_BROWSER_IMMUTABLE' });
  assert.equal(await readFile(file, 'utf8'), bytes);
  await manager.update(legacy.id, { browser: 'fingerprint', name: 'Retained legacy' });
  assert.equal(Object.hasOwn(await manager.get(legacy.id), 'browser'), false);
  assert.equal((await manager.replace(legacy.id)).item.browser, 'fingerprint');
  const malformed = JSON.parse(await readFile(file, 'utf8')); malformed.items[0].browser = 'arbitrary';
  await writeFile(file, JSON.stringify(malformed));
  await assert.rejects(manager.list(), { code: 'WORKSPACE_STATE_INVALID' });
});

test('workspace writes serialize and an interrupted atomic replacement preserves the previous list', async t => {
  let rejectRename = false;
  const { renamePrivate } = await import('../src/private-files.mjs');
  const { root, manager } = await fixture(t, { dependencies: { renamePrivate: (from, to) => rejectRename ? Promise.reject(Object.assign(new Error('sharing lock'), { code: 'EPERM' })) : renamePrivate(from, to) } });
  await Promise.all(['A', 'B', 'C'].map(name => manager.create({ name, services: ['claude'], binding })));
  assert.equal((await manager.list()).items.length, 3);
  rejectRename = true;
  await assert.rejects(manager.create({ name: 'D', services: ['claude'], binding }), { code: 'EPERM' });
  assert.equal((await manager.list()).items.length, 3);
  const { readdir } = await import('node:fs/promises');
  assert.deepEqual((await readdir(path.join(root, '.browser-workspaces'))), ['workspaces.json']);
});

test('workspace storage refuses directory junctions and mock never writes files', async t => {
  const { root } = await fixture(t);
  const other = path.join(root, 'other'); await mkdir(other);
  await symlink(other, path.join(root, '.browser-workspaces'), process.platform === 'win32' ? 'junction' : 'dir');
  const live = createBrowserWorkspaceManager({ runtimeRoot: root });
  await assert.rejects(live.list(), { code: 'WORKSPACE_PATH_INVALID' });
  const manager = createBrowserWorkspaceManager({ runtimeRoot: root, mock: true });
  const item = await manager.create({ name: 'Mock', services: ['claude'], binding });
  assert.equal((await manager.get(item.id)).name, 'Mock');
  await assert.rejects(access(path.join(other, 'workspaces.json')), { code: 'ENOENT' });
});

test('legacy records migrate identity once without changing IDs, browser seed, login data or read-only file bytes', async t => {
  const { root, manager } = await fixture(t);
  const created = await manager.create({ name: 'Existing customer', services: ['claude'], binding });
  const file = path.join(root, '.browser-workspaces', 'workspaces.json');
  const oldState = JSON.parse(await readFile(file, 'utf8'));
  for (const field of ['identity', 'archivedAt', 'replacesId', 'browser']) delete oldState.items[0][field];
  const legacyBytes = `${JSON.stringify(oldState)}\n`; await writeFile(file, legacyBytes);
  const profile = path.join(root, 'browser-profiles', 'workspaces', created.id, 'fingerprint');
  await mkdir(profile, { recursive: true });
  await writeFile(path.join(profile, '.fingerprint-seed'), '119237'); await writeFile(path.join(profile, 'Cookies'), 'retained-login');
  const old = await manager.get(created.id);
  assert.equal(old.archivedAt, null); assert.equal(old.replacesId, null); assert.equal(Object.hasOwn(old, 'identity'), false);
  assert.equal(Object.hasOwn(old, 'browser'), false); assert.equal(workspaceBrowser(old), 'fingerprint');
  assert.equal(await readFile(file, 'utf8'), legacyBytes);
  const backup = path.join(root, '.browser-workspaces', 'workspaces.pre-fingerprint-p0.json');
  await assert.rejects(access(backup), { code: 'ENOENT' });
  const first = { version: 1, language: 'zh-sg', timezone: 'Asia/Singapore', nativeGraphics: true };
  const migrated = await Promise.all([manager.ensureIdentity(created.id, first), manager.ensureIdentity(created.id, identity)]);
  assert.deepEqual(migrated[0].identity, { ...first, language: 'zh-SG' });
  assert.deepEqual(migrated[1].identity, migrated[0].identity);
  assert.equal(migrated[0].id, created.id); assert.equal(migrated[0].lastOpenedAt, null);
  assert.equal((await createBrowserWorkspaceManager({ runtimeRoot: root }).get(created.id)).identity.language, 'zh-SG');
  assert.equal(await readFile(backup, 'utf8'), legacyBytes);
  await manager.update(created.id, { name: 'Updated customer' });
  assert.equal(await readFile(backup, 'utf8'), legacyBytes);
  assert.equal(await readFile(path.join(profile, '.fingerprint-seed'), 'utf8'), '119237');
  assert.equal(await readFile(path.join(profile, 'Cookies'), 'utf8'), 'retained-login');
});

test('replacement atomically archives the previous identity and gives a distinct clean profile path while restoration retains old data', async t => {
  const { root, manager } = await fixture(t);
  const original = await manager.create({ name: 'Customer', services: ['chatgpt', 'claude'], binding, identity, browser: 'fingerprint' });
  await manager.touch(original.id);
  const profile = path.join(root, 'browser-profiles', 'workspaces', original.id, 'fingerprint');
  await mkdir(profile, { recursive: true }); await writeFile(path.join(profile, 'Cookies'), 'old-cookie');
  const replaced = await manager.replace(original.id, { name: 'Customer replacement' });
  assert.equal(replaced.previous.id, original.id); assert.ok(replaced.previous.archivedAt);
  assert.notEqual(replaced.item.id, original.id); assert.equal(replaced.item.replacesId, original.id);
  assert.equal(replaced.item.name, 'Customer replacement'); assert.equal(replaced.item.lastOpenedAt, null);
  assert.equal(replaced.item.archivedAt, null); assert.deepEqual(replaced.item.identity, identity);
  assert.equal(replaced.item.browser, 'fingerprint');
  assert.deepEqual(replaced.item.services, original.services); assert.equal(replaced.item.binding, binding);
  await assert.rejects(access(path.join(root, 'browser-profiles', 'workspaces', replaced.item.id)), { code: 'ENOENT' });
  await assert.rejects(manager.touch(original.id), { code: 'WORKSPACE_ARCHIVED' });
  await assert.rejects(manager.assertBinding(original.id, binding), { code: 'WORKSPACE_ARCHIVED' });
  await assert.rejects(manager.replace(original.id), { code: 'WORKSPACE_ARCHIVED' });
  assert.equal((await manager.restore(original.id)).archivedAt, null);
  assert.equal((await manager.assertBinding(original.id, binding)).id, original.id);
  assert.equal(await readFile(path.join(profile, 'Cookies'), 'utf8'), 'old-cookie');
  assert.equal((await manager.list()).items.length, 2);
});

test('identity and replacement inputs reject unknown fields and malformed locale/timezone without altering saved records', async t => {
  const { root, manager } = await fixture(t);
  const item = await manager.create({ name: 'Customer', services: ['claude'], binding });
  assert.deepEqual(item.identity, { version: 1, language: 'auto', timezone: 'auto', nativeGraphics: false });
  const file = path.join(root, '.browser-workspaces', 'workspaces.json'), before = await readFile(file, 'utf8');
  for (const bad of [null, {}, { ...identity, version: 2 }, { ...identity, timezone: 'Not/A_Timezone' }, { ...identity, timezone: '../UTC' }, { ...identity, language: 'en US' }, { ...identity, language: '' }, { ...identity, nativeGraphics: 'false' }, { ...identity, seed: 123 }, { ...identity, timezone: 'auto', language: 'a'.repeat(86) }]) {
    assert.throws(() => validateWorkspaceIdentity(bad), { code: 'WORKSPACE_IDENTITY_INVALID' });
    await assert.rejects(manager.update(item.id, { identity: bad }), { code: 'WORKSPACE_IDENTITY_INVALID' });
  }
  await assert.rejects(manager.replace(item.id, { identity }), { code: 'WORKSPACE_INPUT_INVALID' });
  await assert.rejects(manager.replace(item.id, { name: '' }), { code: 'WORKSPACE_NAME_INVALID' });
  assert.equal(await readFile(file, 'utf8'), before);
  const malformed = JSON.parse(before); malformed.items[0].identity.secret = 'unsupported';
  await writeFile(file, JSON.stringify(malformed));
  await assert.rejects(manager.list(), { code: 'WORKSPACE_STATE_INVALID' });
  assert.equal(await readFile(file, 'utf8'), JSON.stringify(malformed));
});

test('archived workspaces do not consume active capacity and replacement works at the active limit', async t => {
  const { manager } = await fixture(t, { mock: true });
  const items = await Promise.all(Array.from({ length: 24 }, (_, index) => manager.create({ name: `User ${index}`, services: ['claude'], binding })));
  await assert.rejects(manager.create({ name: 'Too many active', services: ['claude'], binding }), { code: 'WORKSPACE_LIMIT_REACHED' });
  const replacement = await manager.replace(items[0].id);
  assert.equal((await manager.list()).items.filter(item => !item.archivedAt).length, 24);
  await assert.rejects(manager.restore(items[0].id), { code: 'WORKSPACE_LIMIT_REACHED' });
  await manager.archive(replacement.item.id); await manager.restore(items[0].id);
  await Promise.all(items.map(item => manager.archive(item.id)));
  for (let index = 25; index < 96; index++) {
    const item = await manager.create({ name: `Archived ${index}`, services: ['claude'], binding });
    await manager.archive(item.id);
  }
  assert.equal((await manager.list()).items.length, 96);
  await assert.rejects(manager.create({ name: 'Too many total', services: ['claude'], binding }), { code: 'WORKSPACE_LIMIT_REACHED' });
  await manager.restore(items[0].id);
  await assert.rejects(manager.replace(items[0].id), { code: 'WORKSPACE_LIMIT_REACHED' });
  assert.equal((await manager.get(items[0].id)).archivedAt, null);
});

test('concurrent replacement produces one successor and failed disk publication leaves the original active', async t => {
  let rejectRename = false;
  const { renamePrivate } = await import('../src/private-files.mjs');
  const { root, manager } = await fixture(t, { dependencies: { renamePrivate: (from, to) => rejectRename ? Promise.reject(Object.assign(new Error('sharing lock'), { code: 'EPERM' })) : renamePrivate(from, to) } });
  const item = await manager.create({ name: 'Original', services: ['claude'], binding, identity });
  const file = path.join(root, '.browser-workspaces', 'workspaces.json'), before = await readFile(file, 'utf8');
  rejectRename = true;
  await assert.rejects(manager.replace(item.id), { code: 'EPERM' });
  assert.equal(await readFile(file, 'utf8'), before);
  assert.equal((await manager.get(item.id)).archivedAt, null);
  rejectRename = false;
  const outcomes = await Promise.allSettled([manager.replace(item.id), manager.replace(item.id)]);
  assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(outcomes.find(result => result.status === 'rejected').reason.code, 'WORKSPACE_ARCHIVED');
  const saved = (await manager.list()).items;
  assert.equal(saved.length, 2); assert.equal(saved.filter(record => !record.archivedAt).length, 1);
  const { readdir } = await import('node:fs/promises');
  assert.deepEqual(await readdir(path.dirname(file)), ['workspaces.json']);
});

test('oversized workspace storage is preserved and rejected before parsing', async t => {
  const { root, manager } = await fixture(t);
  await manager.create({ name: 'Original', services: ['claude'], binding });
  const file = path.join(root, '.browser-workspaces', 'workspaces.json'), oversized = ' '.repeat(262145);
  await writeFile(file, oversized);
  await assert.rejects(manager.list(), { code: 'WORKSPACE_STATE_INVALID' });
  assert.equal(await readFile(file, 'utf8'), oversized);
});

async function legacyRecord(root, manager) {
  const item = await manager.create({ name: 'Legacy customer', services: ['claude'], binding });
  const file = path.join(root, '.browser-workspaces', 'workspaces.json'), state = JSON.parse(await readFile(file, 'utf8'));
  for (const record of state.items) for (const field of ['identity', 'archivedAt', 'replacesId', 'browser']) delete record[field];
  const bytes = Buffer.from(`{\r\n  "version": 1, "items": ${JSON.stringify(state.items)}\r\n}\r\n`, 'utf8');
  await writeFile(file, bytes);
  return { item, file, bytes, backup: path.join(path.dirname(file), 'workspaces.pre-fingerprint-p0.json') };
}

test('legacy backup is byte-exact, private exclusive creation and never overwritten even when the source remains old schema', async t => {
  const { writePrivate } = await import('../src/private-files.mjs');
  let backupWrites = 0;
  const { root, manager } = await fixture(t, { dependencies: { writePrivate: async (target, bytes) => { if (target.endsWith('workspaces.pre-fingerprint-p0.json')) backupWrites++; return writePrivate(target, bytes); } } });
  const { item, file, bytes, backup } = await legacyRecord(root, manager);
  await manager.list(); await manager.get(item.id);
  assert.equal(backupWrites, 0); await assert.rejects(access(backup), { code: 'ENOENT' });
  await manager.touch(item.id);
  assert.deepEqual(await readFile(backup), bytes); assert.equal(backupWrites, 1);
  // A later old-version run may change its metadata. Keep the first rollback
  // snapshot; a valid existing backup is never replaced by that newer source.
  const different = JSON.parse(bytes); different.items[0].name = 'Later old-version change';
  await writeFile(file, JSON.stringify(different));
  await manager.ensureIdentity(item.id, identity);
  assert.deepEqual(await readFile(backup), bytes); assert.equal(backupWrites, 1);
  assert.equal((await manager.get(item.id)).name, 'Later old-version change');
});

test('backup write failure blocks migration without changing original metadata', async t => {
  const { writePrivate } = await import('../src/private-files.mjs');
  const { root, manager } = await fixture(t, { dependencies: { writePrivate: (target, bytes) => target.endsWith('workspaces.pre-fingerprint-p0.json') ? Promise.reject(Object.assign(new Error('backup access denied'), { code: 'EACCES' })) : writePrivate(target, bytes) } });
  const { item, file, bytes, backup } = await legacyRecord(root, manager);
  await assert.rejects(manager.ensureIdentity(item.id, identity), { code: 'EACCES' });
  assert.deepEqual(await readFile(file), bytes); await assert.rejects(access(backup), { code: 'ENOENT' });
  assert.equal(Object.hasOwn(await manager.get(item.id), 'identity'), false);
});

test('unsafe or incomplete preexisting backups never allow a legacy metadata migration', async t => {
  for (const type of ['directory', 'junction', 'partial']) {
    const { root, manager } = await fixture(t), { item, file, bytes, backup } = await legacyRecord(root, manager);
    if (type === 'directory') await mkdir(backup);
    else if (type === 'junction') { const target = path.join(root, 'unrelated'); await mkdir(target); await symlink(target, backup, process.platform === 'win32' ? 'junction' : 'dir'); }
    else await writeFile(backup, '{partial');
    await assert.rejects(manager.ensureIdentity(item.id, identity), { code: type === 'partial' ? 'WORKSPACE_BACKUP_INVALID' : 'WORKSPACE_PATH_INVALID' });
    assert.deepEqual(await readFile(file), bytes);
    if (type === 'partial') assert.equal(await readFile(backup, 'utf8'), '{partial');
  }
});
