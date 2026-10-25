import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { EventEmitter } from 'node:events';
import { mkdtemp, mkdir, readFile, writeFile, rm, access, symlink, link, rename } from 'node:fs/promises';
import { createBrowserManager, commandUsesProfile, splitWindowsCommandLine, discoverWindowsBrowserCandidates } from '../src/browser-session.mjs';
const temporaryRoot = fileURLToPath(new URL('../../.cache/', import.meta.url));

async function fixture(t, overrides = {}) {
  await mkdir(temporaryRoot, { recursive: true });
  const root = await mkdtemp(path.join(temporaryRoot, 'proxypilot-browser-'));
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  const executable = path.join(root, 'chrome.exe');
  await writeFile(executable, 'test executable marker');
  const profile = path.join(root, 'browser-profiles', 'chrome');
  let running = []; let launches = 0; let closeCalls = 0;
  const processApi = {
    listProcesses: async name => running.filter(item => path.basename(item.executable) === name),
    inspectProcess: async pid => running.find(item => item.pid === pid) || null,
    sameProcess: (a, b) => !!a && !!b && ['pid', 'createdAt', 'executable', 'commandLine'].every(key => a[key] === b[key]),
    closeBrowser: async identity => { closeCalls += 1; running = running.filter(item => item.pid !== identity.pid); },
    ...overrides.processApi,
  };
  const spawnProcess = (file, args, options) => {
    launches += 1;
    const child = Object.assign(new EventEmitter(), { pid: 1122, unref() {} });
    queueMicrotask(() => {
      running.push({ pid: child.pid, parentPid: 1, createdAt: new Date().toISOString(), executable: file, commandLine: [file, ...args].map(arg => `"${arg}"`).join(' ') });
      child.emit('spawn');
    });
    return child;
  };
  const options = { runtimeRoot: root, processApi, candidates: [{ id: 'chrome', executable }], spawnProcess, wait: async () => {}, ...overrides, processApi };
  const manager = createBrowserManager(options);
  return { manager, options, root, profile, executable, get running() { return running; }, set running(value) { running = value; }, get launches() { return launches; }, get closeCalls() { return closeCalls; } };
}

async function put(file, value) { await mkdir(path.dirname(file), { recursive: true }); await writeFile(file, typeof value === 'string' ? value : JSON.stringify(value)); }
async function missing(file) { await assert.rejects(access(file), { code: 'ENOENT' }); }
const afterRoot = (f, seconds = 1) => new Date(Date.parse(f.running.find(item => item.pid === 1122).createdAt) + seconds * 1000).toISOString();

test('profile ownership parses full Windows arguments and rejects prefixes or duplicates', () => {
  const profile = 'C:\\test folder\\chrome';
  assert.equal(commandUsesProfile(`chrome.exe --user-data-dir="${profile}"`, profile), true);
  assert.equal(commandUsesProfile(`chrome.exe "--user-data-dir=${profile}"`, profile), true);
  assert.equal(commandUsesProfile(`chrome.exe --user-data-dir "${profile}"`, profile), true);
  assert.equal(commandUsesProfile(`chrome.exe --user-data-dir="${profile}-other"`, profile), false);
  assert.equal(commandUsesProfile(`chrome.exe --test="--user-data-dir=${profile}"`, profile), false);
  assert.equal(commandUsesProfile(`chrome.exe --user-data-dir="${profile}" --user-data-dir=other`, profile), false);
  assert.deepEqual(splitWindowsCommandLine('one "two three" four'), ['one', 'two three', 'four']);
});

test('empty installation status skips unrelated process scans but a created profile still detects orphan browsers', async t => {
  let scans = 0;
  const f = await fixture(t, { processApi: { listProcesses: async () => { scans++; return [{ pid: 33, executable: 'chrome.exe', commandLine: `chrome.exe --user-data-dir="${f.profile}"` }]; } } });
  assert.equal((await f.manager.status()).running, false); assert.equal(scans, 0);
  assert.equal((await f.manager.close()).closed, true); assert.equal(scans, 0);
  await mkdir(f.profile, { recursive: true });
  const observed = await f.manager.status();
  assert.equal(observed.running, true); assert.equal(observed.managed, false); assert.equal(scans, 2);
});

const candidateSnapshot = f => async name => f.running.filter(item => (item.name || path.basename(item.executable)) === name);

test('unreadable foreign Chrome children do not block closing the fully verified managed root', async t => {
  const f = await fixture(t);
  f.options.processApi.listProcessCandidates = candidateSnapshot(f);
  await put(path.join(f.profile, 'Default', 'Preferences'), { intl: { accept_languages: 'ja' }, untouched: true });
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  f.running.push({ pid: 10, parentPid: 1, createdAt: '2026-10-05T12:00:00Z', executable: f.executable, commandLine: 'chrome.exe --user-data-dir="C:\\foreign-profile"' });
  f.running.push({ pid: 11, parentPid: 10, createdAt: '2026-10-05T12:00:01Z', executable: '', commandLine: '', name: 'chrome.exe', unreadable: true });
  assert.equal((await f.manager.status()).managed, true);
  assert.equal((await f.manager.close()).closed, true);
  assert.equal(f.closeCalls, 1); assert.deepEqual(f.running.map(item => item.pid), [10, 11]);
  assert.equal(JSON.parse(await readFile(path.join(f.profile, 'Default', 'Preferences'), 'utf8')).intl.accept_languages, 'ja');
  await missing(path.join(f.root, 'browser-session.json'));
});

test('unreadable managed root or descendant preserves recovery state and never invokes close', async t => {
  for (const partialRoot of [true, false]) {
    const f = await fixture(t);
    f.options.processApi.listProcessCandidates = candidateSnapshot(f);
    await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
    if (partialRoot) f.running[0] = { ...f.running[0], name: 'chrome.exe', executable: '', commandLine: '', unreadable: true };
    else f.running.push({ pid: 3344, parentPid: 1122, createdAt: '2026-10-05T12:00:01Z', executable: '', commandLine: '', name: 'chrome.exe', unreadable: true });
    const restarted = createBrowserManager(f.options);
    await assert.rejects(restarted.status(), { code: 'PROCESS_UNREADABLE' });
    await assert.rejects(restarted.close(), { code: 'PROCESS_UNREADABLE' });
    assert.equal(f.closeCalls, 0);
    const manifest = JSON.parse(await readFile(path.join(f.root, 'browser-session.json'), 'utf8'));
    assert.ok(manifest.identity.commandLine); assert.ok(!(manifest.ownedProcesses || []).some(item => item.unreadable));
    assert.equal(JSON.parse(await readFile(path.join(f.profile, 'Default', 'Preferences'), 'utf8')).intl.accept_languages, 'en-US,en');
    f.running = [];
    assert.equal((await restarted.close()).closed, true);
  }
});

test('unreadable orphan or recycled parent cannot be used as proof that a session has exited', async t => {
  for (const parent of [null, { pid: 10, parentPid: 1, createdAt: '2026-10-05T12:00:02Z', commandLine: 'chrome.exe' }, { pid: 10, parentPid: 1, createdAt: '2026-10-05T12:00:01.0000001Z', commandLine: 'chrome.exe' }]) {
    const f = await fixture(t);
    f.options.processApi.listProcessCandidates = candidateSnapshot(f);
    await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
    f.running = [{ pid: 11, parentPid: 10, createdAt: '2026-10-05T12:00:01Z', executable: '', commandLine: '', name: 'chrome.exe', unreadable: true }, ...(parent ? [{ ...parent, executable: f.executable }] : [])];
    await assert.rejects(f.manager.close(), { code: 'PROCESS_UNREADABLE' });
    assert.equal(f.closeCalls, 0); await access(path.join(f.root, 'browser-session.json'));
    await access(path.join(f.profile, '.proxypilot-language.json'));
  }
});

test('identity failures during native close keep their safe error code and recovery state', async t => {
  const f = await fixture(t, { processApi: { closeBrowser: async () => { throw Object.assign(new Error('PRIVATE_SECRET'), { code: 'PROCESS_IDENTITY_MISMATCH' }); } } });
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  await assert.rejects(f.manager.close(), cause => cause.code === 'PROCESS_IDENTITY_MISMATCH' && !cause.message.includes('PRIVATE_SECRET'));
  await access(path.join(f.root, 'browser-session.json'));
  assert.equal((await f.manager.status()).running, true);
});

test('a PID reused between Chrome-name snapshots cannot hide an unreadable managed candidate', async t => {
  const f = await fixture(t);
  f.options.processApi.listProcessCandidates = candidateSnapshot(f);
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  f.running.push({ pid: 10, parentPid: 1, createdAt: '2026-10-05T12:00:00Z', executable: f.executable, commandLine: 'chrome.exe' });
  f.running.push({ pid: 11, parentPid: 10, createdAt: '2026-10-05T12:00:01Z', executable: '', commandLine: '', name: 'chrome.exe', unreadable: true });
  f.running.push({ pid: 11, parentPid: 1122, createdAt: '2026-10-05T12:00:02Z', executable: '', commandLine: '', name: 'Google Chrome.exe', unreadable: true });
  await assert.rejects(f.manager.close(), { code: 'PROCESS_UNREADABLE' });
  assert.equal(f.closeCalls, 0); await access(path.join(f.root, 'browser-session.json'));
  await access(path.join(f.profile, '.proxypilot-language.json'));
});

test('fresh sessions isolate previous login data, recover ownership and accept exit locale', async t => {
  const f = await fixture(t);
  await put(path.join(f.profile, 'Default', 'Cookies'), 'existing-login');
  const plan = await f.manager.plan({ browser: 'chrome', port: 17890, fresh: true, language: 'ja-JP' });
  assert.notEqual(plan.profile, f.profile);
  assert.ok(plan.args.includes('--lang=ja-JP'));
  await f.manager.launch(plan);
  await missing(path.join(plan.profile, 'Default', 'Cookies'));
  const prefs = JSON.parse(await readFile(path.join(plan.profile, 'Default', 'Preferences'), 'utf8'));
  assert.equal(prefs.intl.accept_languages, 'ja-JP,ja');
  assert.equal(prefs.webrtc.ip_handling_policy, 'disable_non_proxied_udp');
  const recovered = createBrowserManager(f.options);
  assert.equal((await recovered.status()).running, true);
  assert.equal((await recovered.status()).fresh, true);
  await recovered.close();
  assert.equal(await readFile(path.join(f.profile, 'Default', 'Cookies'), 'utf8'), 'existing-login');
  await assert.rejects(recovered.launch(plan), { code: 'BROWSER_PLAN_INVALID' });
  const next = await recovered.plan({ browser: 'chrome', port: 17890, fresh: true });
  assert.notEqual(next.profile, plan.profile);
  await assert.rejects(recovered.plan({ browser: 'chrome', port: 17890, fresh: true, freshId: '../other' }), { code: 'BROWSER_PLAN_INVALID' });
});

test('missing session manifest reports each orphaned fresh browser as untracked and blocks close and a second launch', async t => {
  for (const browser of ['chrome', 'edge', 'fingerprint']) {
    const f = await fixture(t);
    const options = { ...f.options, fingerprintRoot: path.join(f.root, 'engine') };
    const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', profile = path.join(f.root, 'browser-profiles', 'fresh', browser, id);
    const cookie = path.join(profile, 'Default', 'Cookies'), preferences = path.join(profile, 'Default', 'Preferences');
    await put(cookie, 'synthetic-fresh-login'); await put(preferences, { intl: { accept_languages: 'ja-JP' } });
    await put(path.join(profile, '.proxypilot-language.json'), { version: 2, preferences: [] });
    const command = `"${f.executable}" "--user-data-dir=${profile}"`;
    f.running = [{ pid: 1001, parentPid: 1, createdAt: '2026-10-18T00:00:00.000Z', executable: browser === 'edge' ? path.join(f.root, 'msedge.exe') : f.executable, commandLine: command }];
    const orphan = createBrowserManager(options), status = await orphan.status();
    assert.equal(status.running, true); assert.equal(status.browser, browser); assert.equal(status.fresh, true);
    assert.equal(status.managed, false); assert.equal(status.restorePending, true);
    assert.equal(JSON.stringify(status).includes(profile), false);
    await assert.rejects(orphan.close(), { code: 'BROWSER_SESSION_UNTRACKED' });
    await assert.rejects(orphan.launch(await orphan.plan({ browser: 'chrome', port: 17890 })), { code: 'BROWSER_ALREADY_RUNNING' });
    assert.equal(f.closeCalls, 0); assert.equal(f.launches, 0); assert.equal(f.running.length, 1);
    assert.equal(await readFile(cookie, 'utf8'), 'synthetic-fresh-login');
    assert.deepEqual(JSON.parse(await readFile(preferences, 'utf8')), { intl: { accept_languages: 'ja-JP' } });
    await missing(path.join(f.root, 'browser-session.json'));
    f.running = [];
    assert.equal((await orphan.close()).closed, true);
    assert.equal(await readFile(cookie, 'utf8'), 'synthetic-fresh-login');
  }
});

test('fresh orphan scans match exact UUID profiles and reject linked or malformed managed directories', async t => {
  const f = await fixture(t), base = path.join(f.root, 'browser-profiles', 'fresh', 'chrome'), id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const profile = path.join(base, id); await mkdir(profile, { recursive: true });
  f.running = [{ pid: 42, parentPid: 1, createdAt: '2026-10-18T00:00:00.000Z', executable: f.executable, commandLine: `"${f.executable}" "--user-data-dir=${profile}-other"` }];
  assert.equal((await f.manager.status()).running, false);
  await mkdir(path.join(base, 'malformed-profile')); 
  await assert.rejects(f.manager.status(), { code: 'BROWSER_PATH_UNSAFE' });
  await rm(path.join(base, 'malformed-profile'), { recursive: true });
  await rm(profile, { recursive: true });
  const external = path.join(f.root, 'external-profile'); await mkdir(external);
  await symlink(external, profile, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(f.manager.status(), { code: 'BROWSER_PATH_UNSAFE' });
  assert.equal(f.closeCalls, 0); assert.equal(f.launches, 0);
});

test('plans have fixed website, proxy, language, isolated profile and redact status', async t => {
  const f = await fixture(t);
  assert.deepEqual(await f.manager.listBrowsers(), [{ id: 'chrome', label: 'Google Chrome', available: true }, { id: 'edge', label: 'Microsoft Edge', available: false }]);
  const plan = await f.manager.plan({ browser: 'chrome', port: 17890 });
  assert.equal(plan.url, 'https://api.ipify.org/');
  assert.equal(plan.profile, f.profile);
  assert.ok(plan.args.includes('--lang=en-US'));
  assert.ok(plan.args.includes('--proxy-server=http://127.0.0.1:17890'));
  await assert.rejects(f.manager.plan({ browser: 'chrome', port: 17890, service: 'arbitrary' }), { code: 'SERVICE_INVALID' });
  await assert.rejects(f.manager.launch({ ...plan, args: [...plan.args, '--incognito'] }), { code: 'BROWSER_PLAN_INVALID' });
  assert.equal((await f.manager.launch(plan)).launched, true);
  assert.equal(JSON.stringify(await f.manager.status()).includes(f.root), false);
  await assert.rejects(f.manager.launch(plan), { code: 'BROWSER_ALREADY_RUNNING' });
  assert.equal(f.launches, 1);
});

test('existing same-profile process is rejected but sibling profile is not mistaken for ownership', async t => {
  const f = await fixture(t);
  const plan = await f.manager.plan({ browser: 'chrome', port: 17890 });
  f.running = [{ pid: 55, executable: f.executable, createdAt: 'old', commandLine: `chrome.exe "--user-data-dir=${f.profile}"` }];
  await assert.rejects(f.manager.launch(plan), { code: 'BROWSER_ALREADY_RUNNING' });
  assert.equal(f.launches, 0);
  // A real browser creates its selected profile. Without a profile or manifest,
  // first-install close deliberately avoids unrelated process enumeration.
  await mkdir(f.profile, { recursive: true });
  await assert.rejects(f.manager.close(), { code: 'BROWSER_SESSION_UNTRACKED' });
  f.running = [{ ...f.running[0], commandLine: `chrome.exe "--user-data-dir=${f.profile}-sibling"` }];
  await f.manager.launch(plan);
  await f.manager.close();
  assert.equal(f.running.length, 1);
});

test('asynchronous spawn failure is reported and language edits are rolled back', async t => {
  const f = await fixture(t, { spawnProcess: () => {
    const child = Object.assign(new EventEmitter(), { unref() {} });
    queueMicrotask(() => child.emit('error', Object.assign(new Error('private path unavailable'), { code: 'ENOENT' })));
    return child;
  } });
  const prefs = path.join(f.profile, 'Default', 'Preferences');
  await put(prefs, { intl: { accept_languages: 'zh-TW,zh' }, secretAccount: { unchanged: true } });
  await assert.rejects(f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 })), { code: 'BROWSER_LAUNCH_FAILED' });
  assert.deepEqual(JSON.parse(await readFile(prefs, 'utf8')), { intl: { accept_languages: 'zh-TW,zh' }, secretAccount: { unchanged: true } });
  assert.equal((await f.manager.status()).running, false);
  await missing(path.join(f.root, 'browser-session.json'));
});

test('language change and restoration merge Preferences and survive manager restart', async t => {
  const f = await fixture(t);
  const prefs = path.join(f.profile, 'Default', 'Preferences');
  const secondPrefs = path.join(f.profile, 'Profile 1', 'Preferences');
  await put(prefs, { intl: { accept_languages: 'zh-TW', selected_languages: 'zh-TW', keep: 'yes' }, bookmark_bar: { show_on_all_tabs: true } });
  await put(secondPrefs, { other: 4 });
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  const current = JSON.parse(await readFile(prefs, 'utf8'));
  assert.equal(current.intl.accept_languages, 'en-US,en');
  assert.equal(current.webrtc.ip_handling_policy, 'disable_non_proxied_udp');
  assert.equal(current.bookmark_bar.show_on_all_tabs, true);
  current.browserChangedThis = 'keep me'; current.intl.newUnrelatedField = 'keep too';
  await put(prefs, current);
  const restarted = createBrowserManager(f.options);
  assert.equal((await restarted.status()).running, true);
  assert.equal((await restarted.status()).managed, true);
  assert.equal((await restarted.close()).languageRestored, true);
  assert.equal(f.closeCalls, 1);
  const restored = JSON.parse(await readFile(prefs, 'utf8'));
  assert.deepEqual(restored.intl, { accept_languages: 'zh-TW', selected_languages: 'zh-TW', keep: 'yes', newUnrelatedField: 'keep too' });
  assert.equal(restored.webrtc, undefined);
  assert.equal(restored.browserChangedThis, 'keep me');
  assert.deepEqual(JSON.parse(await readFile(secondPrefs, 'utf8')), { other: 4 });
  await missing(path.join(f.profile, '.proxypilot-language.json'));
});

test('close timeout preserves live process, manifest and temporary language', async t => {
  const f = await fixture(t, { processApi: { closeBrowser: async () => { throw new Error('unsaved dialog'); } } });
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  await assert.rejects(f.manager.close(), { code: 'BROWSER_CLOSE_TIMEOUT' });
  assert.equal((await f.manager.status()).running, true);
  assert.equal(JSON.parse(await readFile(path.join(f.profile, 'Default', 'Preferences'), 'utf8')).intl.accept_languages, 'en-US,en');
  await access(path.join(f.root, 'browser-session.json'));
});

test('WebRTC native preference is enforced before spawn, restored after restart and preserves unrelated data', async t => {
  const f = await fixture(t);
  const file = path.join(f.profile, 'Default', 'Preferences');
  await put(file, { webrtc: { ip_handling_policy: 'default', other: 7 }, account: { untouched: true } });
  const originalSpawn = f.options.spawnProcess;
  let seenAtSpawn;
  const manager = createBrowserManager({ ...f.options, spawnProcess: (...args) => {
    seenAtSpawn = import('node:fs').then(fs => JSON.parse(fs.readFileSync(file, 'utf8')).webrtc.ip_handling_policy);
    return originalSpawn(...args);
  } });
  await manager.launch(await manager.plan({ browser: 'chrome', port: 17890 }));
  assert.equal(await seenAtSpawn, 'disable_non_proxied_udp');
  const live = JSON.parse(await readFile(file, 'utf8'));
  live.webrtc.newBrowserField = 'preserve'; await put(file, live);
  const recovered = createBrowserManager(f.options);
  assert.deepEqual((await recovered.status()).webrtc, { policy: 'disable_non_proxied_udp', configured: true, verification: 'unverified', restartRequired: false });
  await recovered.close();
  const restored = JSON.parse(await readFile(file, 'utf8'));
  assert.deepEqual(restored.webrtc, { ip_handling_policy: 'default', other: 7, newBrowserField: 'preserve' });
  assert.deepEqual(restored.account, { untouched: true });
});

test('legacy language snapshots remain recoverable without overwriting WebRTC preferences', async t => {
  const f = await fixture(t);
  const file = path.join(f.profile, 'Default', 'Preferences');
  await put(file, { intl: { accept_languages: 'en-US,en', selected_languages: 'en-US,en' }, webrtc: { ip_handling_policy: 'default_public_interface_only' } });
  await put(path.join(f.profile, '.proxypilot-language.json'), { version: 1, preferences: [{ directory: 'Default', hadIntl: true, fields: { accept_languages: { present: true, value: 'zh-TW' }, selected_languages: { present: false } } }] });
  assert.equal((await f.manager.status()).running, false);
  assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), { intl: { accept_languages: 'zh-TW' }, webrtc: { ip_handling_policy: 'default_public_interface_only' } });
});

test('close waits for owned children even without a profile argument', async t => {
  const f = await fixture(t);
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  f.running.push({ pid: 3344, parentPid: 1122, createdAt: afterRoot(f), executable: f.executable, commandLine: 'chrome.exe --type=utility' });
  await assert.rejects(f.manager.close(), { code: 'BROWSER_CLOSE_TIMEOUT' });
  assert.equal(f.running[0].pid, 3344);
  await access(path.join(f.root, 'browser-session.json'));
  const restarted = createBrowserManager(f.options);
  assert.equal((await restarted.status()).running, true);
  await assert.rejects(restarted.close(), { code: 'BROWSER_CLOSE_TIMEOUT' });
  await assert.rejects(restarted.cleanupPreview({ browser: 'chrome', items: ['browserCookies'] }), { code: 'BROWSER_ALREADY_RUNNING' });
  f.running = [];
  assert.equal((await restarted.close()).closed, true);
});

test('status combines both Chrome filenames once and retains children after their intermediate parent exits', async t => {
  const f = await fixture(t);
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  f.running.push({ pid: 3344, parentPid: 1122, createdAt: afterRoot(f), executable: f.executable, commandLine: 'chrome.exe --type=utility' });
  f.running.push({ pid: 3345, parentPid: 3344, createdAt: afterRoot(f, 2), executable: f.executable, commandLine: 'chrome.exe --type=renderer' });
  let snapshots = 0;
  const readSnapshot = f.options.processApi.listProcesses;
  f.options.processApi.listProcesses = async name => { snapshots++; return readSnapshot(name); };
  f.options.processApi.inspectProcess = async () => assert.fail('status must verify all identities in one snapshot');
  assert.equal((await f.manager.status()).running, true);
  assert.equal(snapshots, 2);
  f.running = f.running.filter(item => item.pid !== 3344);
  assert.equal((await f.manager.status()).running, true);
  const manifest = JSON.parse(await readFile(path.join(f.root, 'browser-session.json'), 'utf8'));
  assert.ok(manifest.ownedProcesses.some(item => item.pid === 3345));
  await assert.rejects(f.manager.close(), { code: 'BROWSER_CLOSE_TIMEOUT' });
  assert.equal(f.running[0].pid, 3345);
});

test('windowless recorded children can finish after root exit and retry without closing another browser', async t => {
  let f; const ended = []; let refuse = true;
  f = await fixture(t, { processApi: { stopBackgroundBrowser: async identity => {
    if (refuse) throw Object.assign(new Error('visible browser prompt'), { code: 'BROWSER_CLOSE_TIMEOUT' });
    ended.push(identity.pid); f.running = f.running.filter(item => item.pid !== identity.pid);
  } } });
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  f.running.push({ pid: 3344, parentPid: 1122, createdAt: afterRoot(f), executable: f.executable, commandLine: 'chrome.exe --type=utility' });
  f.running.push({ pid: 5566, parentPid: 1, createdAt: '2026-10-05T12:00:01Z', executable: f.executable, commandLine: 'chrome.exe --user-data-dir="C:\\foreign"' });
  await put(path.join(f.profile, 'Default', 'Cookies'), 'preserved customer login');
  await assert.rejects(f.manager.close(), { code: 'BROWSER_CLOSE_TIMEOUT' });
  await access(path.join(f.root, 'browser-session.json'));
  assert.equal(f.closeCalls, 1); assert.deepEqual(ended, []);
  refuse = false;
  const recovered = createBrowserManager(f.options);
  assert.equal((await recovered.close()).closed, true);
  assert.equal(f.closeCalls, 1); assert.deepEqual(ended, [3344]);
  assert.deepEqual(f.running.map(item => item.pid), [5566]);
  assert.equal(await readFile(path.join(f.profile, 'Default', 'Cookies'), 'utf8'), 'preserved customer login');
  await missing(path.join(f.root, 'browser-session.json'));
});

test('recycled descendant PID and a child born before its current parent are never stopped', async t => {
  let f; const ended = [];
  f = await fixture(t, { processApi: { stopBackgroundBrowser: async identity => {
    ended.push(identity.pid); f.running = f.running.filter(item => item.pid !== identity.pid);
  } } });
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  f.running.push({ pid: 3344, parentPid: 1122, createdAt: afterRoot(f), executable: f.executable, commandLine: 'chrome.exe --type=utility' });
  f.running.push({ pid: 4455, parentPid: 1122, createdAt: afterRoot(f, -1), executable: f.executable, commandLine: 'chrome.exe --user-data-dir="C:\\other"' });
  await f.manager.status();
  f.running = f.running.filter(item => item.pid !== 1122);
  f.running = f.running.map(item => item.pid === 3344 ? { ...item, createdAt: '2026-10-05T12:00:09Z' } : item);
  assert.equal((await f.manager.close()).closed, true);
  assert.deepEqual(ended, []); assert.equal(f.closeCalls, 0);
  assert.deepEqual(f.running.map(item => item.pid), [3344, 4455]);
});

test('root exiting between close status and final identity snapshot is a successful no-op', async t => {
  const f = await fixture(t);
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  const list = f.options.processApi.listProcesses; let reads = 0;
  f.options.processApi.listProcesses = async name => { if (++reads === 3) f.running = []; return list(name); };
  assert.equal((await f.manager.close()).closed, true);
  assert.equal(f.closeCalls, 0); await missing(path.join(f.root, 'browser-session.json'));
});

test('transient unreadable teardown snapshot is retried but persistent unknown identity remains blocked', async t => {
  const f = await fixture(t);
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  const list = f.options.processApi.listProcesses; let unreadable = 1;
  f.options.processApi.listProcessCandidates = async name => {
    if (name === 'chrome.exe' && unreadable-- > 0) throw Object.assign(new Error('CIM teardown race'), { code: 'PROCESS_UNREADABLE' });
    return list(name);
  };
  assert.equal((await f.manager.close()).closed, true);
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  unreadable = 5;
  await assert.rejects(f.manager.close(), { code: 'PROCESS_UNREADABLE' });
  assert.equal(f.closeCalls, 1); await access(path.join(f.root, 'browser-session.json'));
});

test('reused PID after restart is never treated as the owned browser', async t => {
  const f = await fixture(t);
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  f.running[0].createdAt = 'recycled-process-id';
  const restarted = createBrowserManager(f.options);
  const status = await restarted.status();
  assert.equal(status.running, true);
  assert.equal(status.managed, false);
  await assert.rejects(restarted.close(), { code: 'BROWSER_SESSION_UNTRACKED' });
  assert.equal(f.closeCalls, 0);
});

test('unverified launch keeps recovery state and temporary preferences until browser is closed', async t => {
  const f = await fixture(t, { processApi: { inspectProcess: async () => null } });
  const list = f.options.processApi.listProcesses;
  f.options.processApi.listProcesses = async name => (await list(name)).map(item => ({ ...item, commandLine: item.commandLine + ' --unplanned-browser-command' }));
  await assert.rejects(f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 })), { code: 'BROWSER_IDENTITY_UNVERIFIED' });
  assert.equal((await f.manager.status()).running, true);
  assert.equal((await f.manager.status()).managed, false);
  await assert.rejects(f.manager.close(), { code: 'BROWSER_SESSION_UNTRACKED' });
  await access(path.join(f.root, 'browser-session.json'));
  f.running = [];
  assert.equal((await f.manager.status()).running, false);
  await missing(path.join(f.root, 'browser-session.json'));
});

test('launcher PID handoff verifies the exact new root and survives pending-launch manager recovery', async t => {
  const f = await fixture(t, { processApi: { inspectProcess: async () => null } });
  const manager = createBrowserManager({ ...f.options, spawnProcess: (...args) => {
    const child = f.options.spawnProcess(...args);
    queueMicrotask(() => { f.running = f.running.map(item => ({ ...item, pid: 2233, parentPid: child.pid })); });
    return child;
  } });
  assert.equal((await manager.launch(await manager.plan({ browser: 'chrome', port: 17890 }))).launched, true);
  const file = path.join(f.root, 'browser-session.json');
  const manifest = JSON.parse(await readFile(file, 'utf8'));
  assert.equal(manifest.identity.pid, 2233); assert.equal(manifest.launch.pid, 1122);
  assert.equal(manifest.launch.baselineEmpty, true);
  // Simulate the desktop exiting after storing its launcher receipt, before
  // writing the successfully observed new-root identity.
  manifest.identity = null; delete manifest.ownedProcesses; await put(file, manifest);
  const recovered = createBrowserManager(f.options);
  assert.equal((await recovered.status()).managed, true);
  assert.equal((await recovered.close()).closed, true); assert.equal(f.closeCalls, 1);
  await missing(file);
});

test('old unverified records and roots created outside this launch window are never adopted', async t => {
  const f = await fixture(t);
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  const file = path.join(f.root, 'browser-session.json');
  const receipt = JSON.parse(await readFile(file, 'utf8'));
  for (const legacy of [false, true]) {
    const manifest = structuredClone(receipt); manifest.identity = null; delete manifest.ownedProcesses;
    if (legacy) delete manifest.launch;
    else manifest.launch.startedAt = '2000-01-01T00:00:00Z';
    await put(file, manifest);
    const recovered = createBrowserManager(f.options);
    assert.equal((await recovered.status()).managed, false);
    await assert.rejects(recovered.close(), { code: 'BROWSER_SESSION_UNTRACKED' });
    assert.equal(f.closeCalls, 0);
  }
});

test('launcher recovery refuses ambiguous new roots even when executable and full profile arguments match', async t => {
  const f = await fixture(t, { processApi: { inspectProcess: async () => null } });
  const manager = createBrowserManager({ ...f.options, spawnProcess: (...args) => {
    const child = f.options.spawnProcess(...args);
    queueMicrotask(() => { f.running.push({ ...f.running[0], pid: 2233 }); });
    return child;
  } });
  await assert.rejects(manager.launch(await manager.plan({ browser: 'chrome', port: 17890 })), { code: 'BROWSER_SESSION_UNTRACKED' });
  assert.equal(f.closeCalls, 0); await access(path.join(f.root, 'browser-session.json'));
});

test('corrupt root/owned recovery identities never close an external Chrome profile', async t => {
  const f = await fixture(t);
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  const file = path.join(f.root, 'browser-session.json');
  const saved = JSON.parse(await readFile(file, 'utf8'));
  const foreign = { pid: 2233, parentPid: 1, createdAt: afterRoot(f), executable: f.executable, commandLine: 'chrome.exe --user-data-dir="C:\\Daily-Browser-Profile"' };
  f.running.push(foreign);
  for (const corrupt of [
    { ...saved, identity: foreign, ownedProcesses: [foreign] },
    { ...saved, ownedProcesses: [saved.identity, foreign] },
    { ...saved, ownedProcesses: [saved.identity, { ...foreign, parentPid: 1122 }] },
  ]) {
    await put(file, corrupt);
    const restarted = createBrowserManager(f.options);
    await assert.rejects(restarted.close(), { code: 'BROWSER_STATE_INVALID' });
    assert.equal(f.closeCalls, 0); assert.deepEqual(f.running.map(item => item.pid), [1122, 2233]);
    await access(path.join(f.profile, '.proxypilot-language.json'));
  }
});

test('late children born while graceful close runs block restore/status and are never force-stopped', async t => {
  let f; let backgroundStops = 0;
  f = await fixture(t, { processApi: {
    closeBrowser: async identity => {
      f.running.push({ pid: 3344, parentPid: identity.pid, createdAt: afterRoot(f), executable: f.executable, commandLine: 'chrome.exe --type=utility' });
      f.running = f.running.filter(item => item.pid !== identity.pid);
    },
    stopBackgroundBrowser: async () => { backgroundStops++; assert.fail('an uncertain late child must not be stopped'); },
  } });
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  await assert.rejects(f.manager.close(), { code: 'BROWSER_CLOSE_TIMEOUT' });
  assert.equal(backgroundStops, 0); await access(path.join(f.profile, '.proxypilot-language.json'));
  const recovered = createBrowserManager(f.options);
  assert.equal((await recovered.status()).running, true);
  await assert.rejects(recovered.cleanupPreview({ browser: 'chrome', items: ['browserCookies'] }), { code: 'BROWSER_ALREADY_RUNNING' });
  await assert.rejects(recovered.close(), { code: 'BROWSER_CLOSE_TIMEOUT' });
  const late = f.running[0];
  f.running.push({ pid: 3345, parentPid: late.pid, createdAt: new Date(Date.parse(late.createdAt) + 1000).toISOString(), executable: f.executable, commandLine: 'chrome.exe --type=renderer' });
  assert.equal((await recovered.status()).running, true);
  f.running = f.running.filter(item => item.pid !== 3344);
  const third = createBrowserManager(f.options);
  assert.equal((await third.status()).running, true);
  await assert.rejects(third.close(), { code: 'BROWSER_CLOSE_TIMEOUT' });
  assert.equal(backgroundStops, 0);
  f.running = [];
  assert.equal((await third.close()).closed, true);
  await missing(path.join(f.root, 'browser-session.json')); await missing(path.join(f.profile, '.proxypilot-language.json'));
});

test('CIM sub-millisecond and equal creation timestamps retain late children without treating an older process as owned', async t => {
  for (const timing of ['later', 'equal', 'older']) {
    let f;
    f = await fixture(t, { processApi: { closeBrowser: async identity => {
      const rootTime = identity.createdAt.replace(/\.(\d{3})Z$/, '.$15000Z');
      const childTime = timing === 'later' ? rootTime.replace(/5000Z$/, '6000Z')
        : timing === 'older' ? rootTime.replace(/5000Z$/, '4000Z') : rootTime;
      f.running.push({ pid: 3344, parentPid: identity.pid, createdAt: childTime, executable: f.executable, commandLine: 'chrome.exe --type=utility' });
      f.running = f.running.filter(item => item.pid !== identity.pid);
    }, stopBackgroundBrowser: async () => assert.fail('an uncertain same-tick child must not be stopped') } });
    await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
    // Both times use the same millisecond; retain the native fractional part.
    const nativeTime = f.running[0].createdAt.replace(/\.(\d{3})Z$/, '.$15000Z');
    f.running = f.running.map(item => ({ ...item, createdAt: nativeTime }));
    const file = path.join(f.root, 'browser-session.json');
    const manifest = JSON.parse(await readFile(file, 'utf8'));
    manifest.identity.createdAt = nativeTime; await put(file, manifest);
    const recovered = createBrowserManager(f.options);
    if (timing === 'older') {
      assert.equal((await recovered.close()).closed, true);
    } else {
      await assert.rejects(recovered.close(), { code: 'BROWSER_CLOSE_TIMEOUT' });
      await access(path.join(f.profile, '.proxypilot-language.json'));
      assert.equal((await createBrowserManager(f.options).status()).running, true);
      f.running = [];
      assert.equal((await recovered.close()).closed, true);
    }
  }
});

test('browser exit observed after restart restores language without closing unrelated process', async t => {
  const f = await fixture(t);
  const prefs = path.join(f.profile, 'Default', 'Preferences');
  await put(prefs, { intl: { accept_languages: 'ja' }, untouched: 1 });
  await f.manager.launch(await f.manager.plan({ browser: 'chrome', port: 17890 }));
  f.running = [];
  const restarted = createBrowserManager(f.options);
  assert.equal((await restarted.status()).running, false);
  assert.equal(JSON.parse(await readFile(prefs, 'utf8')).intl.accept_languages, 'ja');
  assert.equal(f.closeCalls, 0);
});

test('precise cleanup deletes cache and cookie databases in real profiles, preserves other data', async t => {
  const f = await fixture(t);
  for (const directory of ['Default', 'Profile 2']) {
    for (const relative of ['Cache/cache-data', 'Code Cache/cache-data', 'Network/Cookies', 'Network/Cookies-wal', 'Cookies-journal']) await put(path.join(f.profile, directory, relative), 'remove');
    for (const relative of ['Bookmarks', 'Login Data', 'Local Storage/data', 'Preferences', 'Network/TransportSecurity']) await put(path.join(f.profile, directory, relative), 'preserve');
  }
  await put(path.join(f.profile, 'Not A Profile', 'Network', 'Cookies'), 'preserve');
  await put(path.join(f.root, 'browser-profiles', 'edge', 'Default', 'Network', 'Cookies'), 'preserve');
  const preview = await f.manager.cleanupPreview({ browser: 'chrome', items: ['browserCache', 'browserCookies'] });
  assert.equal(preview.targets.some(target => target.path === f.profile), false);
  assert.equal((await f.manager.cleanupApply(preview)).deleted, 10);
  for (const directory of ['Default', 'Profile 2']) {
    await missing(path.join(f.profile, directory, 'Cache'));
    await missing(path.join(f.profile, directory, 'Network', 'Cookies'));
    for (const relative of ['Bookmarks', 'Login Data', 'Local Storage/data', 'Preferences', 'Network/TransportSecurity']) assert.equal(await readFile(path.join(f.profile, directory, relative), 'utf8'), 'preserve');
  }
  await access(path.join(f.root, 'browser-profiles', 'edge', 'Default', 'Network', 'Cookies'));
  await access(path.join(f.profile, 'Not A Profile', 'Network', 'Cookies'));
  await assert.rejects(f.manager.cleanupPreview({ browser: 'chrome', items: ['claudeData'] }), { code: 'CLEANUP_SCOPE_INVALID' });
});

test('cleanup refuses tampered targets, a running profile, and symlink ancestors or descendants', async t => {
  const f = await fixture(t);
  await put(path.join(f.profile, 'Default', 'Cache', 'good'), 'cache');
  const preview = await f.manager.cleanupPreview({ browser: 'chrome', items: ['browserCache'] });
  const tampered = structuredClone(preview); tampered.targets[0].path = path.join(f.root, 'secret');
  await assert.rejects(f.manager.cleanupApply(tampered), { code: 'CLEANUP_PLAN_INVALID' });
  f.running = [{ pid: 55, executable: f.executable, commandLine: `chrome.exe "--user-data-dir=${f.profile}"` }];
  await assert.rejects(f.manager.cleanupApply(preview), { code: 'BROWSER_ALREADY_RUNNING' });
  f.running = [];
  const elsewhere = path.join(f.root, 'untouched'); await put(path.join(elsewhere, 'keep'), 'safe');
  await symlink(elsewhere, path.join(f.profile, 'Default', 'Cache', 'link'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(f.manager.cleanupApply(preview), { code: 'BROWSER_PATH_UNSAFE' });
  assert.equal(await readFile(path.join(elsewhere, 'keep'), 'utf8'), 'safe');
  await access(path.join(f.profile, 'Default', 'Cache', 'good'));
  await rm(path.join(f.profile, 'Default', 'Cache', 'link'));
  await mkdir(path.join(f.profile, 'Default', 'Network'), { recursive: true });
  await rm(path.join(f.profile, 'Default', 'Network'), { recursive: true });
  await symlink(elsewhere, path.join(f.profile, 'Default', 'Network'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(f.manager.cleanupPreview({ browser: 'chrome', items: ['browserCookies'] }), { code: 'BROWSER_PATH_UNSAFE' });
});

test('mock operations neither inspect processes nor create filesystem state', async t => {
  await mkdir(temporaryRoot, { recursive: true });
  const root = await mkdtemp(path.join(temporaryRoot, 'proxypilot-browser-mock-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const runtimeRoot = path.join(root, 'must-not-exist');
  const manager = createBrowserManager({ runtimeRoot, mock: true, discoverCandidates: () => { throw new Error('mock inspected installations'); }, processApi: new Proxy({}, { get() { throw new Error('mock touched processes'); } }), spawnProcess: () => { throw new Error('mock spawned'); } });
  await manager.listBrowsers();
  assert.equal((await manager.launch(await manager.plan({ port: 17890 }))).launched, false);
  await manager.status(); await manager.close();
  await manager.cleanupApply(await manager.cleanupPreview({ items: ['browserCache', 'browserCookies'] }));
  await missing(runtimeRoot);
});

test('native discovery reads bounded installation metadata and running browser executable paths without profiles', async () => {
  let script;
  const found = await discoverWindowsBrowserCandidates({ platform: 'win32', execFile: (file, args, options, callback) => {
    assert.equal(file, 'powershell.exe'); assert.equal(options.windowsHide, true); assert.equal(options.timeout, 15000);
    assert.ok(args.includes('-NonInteractive'));
    script = Buffer.from(args.at(-1), 'base64').toString('utf16le');
    callback(null, '\uFEFF' + JSON.stringify([
      { id: 'chrome', executable: '"D:\\Custom Chrome\\chrome.exe"' },
      { id: 'chrome', executable: 'd:\\custom chrome\\CHROME.EXE' },
      { id: 'edge', executable: 'E:\\Browser Apps\\msedge.exe' },
      { id: 'edge', executable: 'E:\\Other Browser\\msedge.exe' },
      { id: 'chrome', executable: 'D:\\Chrome\\chrome.exe --user-data-dir=private' },
      { id: 'edge', executable: 'D:\\Edge\\wrong.exe' },
      { id: 'opera', executable: 'D:\\Opera\\opera.exe' },
      { id: 'chrome', executable: 'chrome.exe' },
      { id: 'chrome', executable: 'D:\\Alias\\Google Chrome.exe', verifiedAlias: true },
      { id: 'chrome', executable: 'D:\\Unverified\\Google Chrome.exe' },
      { id: 'chrome', executable: '\\\\remote\\Chrome\\chrome.exe' },
      { id: 'chrome', executable: 'D:\\Chrome\\chrome.exe:payload' },
      null,
    ]));
  } });
  assert.deepEqual(found, [
    { id: 'chrome', executable: 'D:\\Custom Chrome\\chrome.exe' },
    { id: 'edge', executable: 'E:\\Browser Apps\\msedge.exe' },
    { id: 'edge', executable: 'E:\\Other Browser\\msedge.exe' },
    { id: 'chrome', executable: 'D:\\Alias\\Google Chrome.exe' },
  ]);
  for (const name of ['CurrentUser', 'LocalMachine', 'Registry64', 'Registry32', 'App Paths', 'ExecutablePath', 'Uninstall', 'InstallLocation', 'Google Chrome.exe', 'Select-Object -First 512', 'OriginalFilename']) assert.ok(script.includes(name));
  assert.ok(script.indexOf("$executable -notmatch '^[A-Za-z]:") < script.indexOf('Test-Path -LiteralPath $canonical'), 'native discovery rejects remote paths before inspecting their files');
  assert.doesNotMatch(script, /\.CommandLine|Cookies|Preferences|User Data/);
});

test('fixed website services default to browser-observed IP and cannot carry an arbitrary URL', async t => {
  const f = await fixture(t);
  const services = { exit: 'https://api.ipify.org/', google: 'https://www.google.com/', wikipedia: 'https://www.wikipedia.org/', github: 'https://github.com/', youtube: 'https://www.youtube.com/', chatgpt: 'https://chatgpt.com/', claude: 'https://claude.ai/', tiktok: 'https://www.tiktok.com/' };
  assert.equal((await f.manager.plan({ port: 17890 })).service, 'exit');
  for (const [service, url] of Object.entries(services)) {
    const plan = await f.manager.plan({ port: 17890, service });
    assert.equal(plan.url, url); assert.equal(plan.args.at(-1), url); assert.ok(plan.args.includes('--proxy-server=http://127.0.0.1:17890'));
  }
  for (const service of ['https://evil.invalid/', '__proto__', 'exit?url=https://evil.invalid']) await assert.rejects(f.manager.plan({ port: 17890, service }), { code: 'SERVICE_INVALID' });
  assert.equal(f.launches, 0);
});

test('explicit rescan refreshes stale discovery while ordinary browser reads remain cached', async t => {
  const f = await fixture(t); let calls = 0, visible = false;
  const manager = createBrowserManager({ ...f.options, candidates: undefined, discoverCandidates: async () => { calls++; return visible ? [{ id: 'chrome', executable: f.executable }] : []; } });
  // The injected installation appears after the initial scan.
  await manager.listBrowsers(); visible = true; await manager.listBrowsers(); assert.equal(calls, 1);
  await manager.rescan(); assert.equal(calls, 2);
  assert.equal((await manager.plan({ port: 17890 })).executable, f.executable); await manager.listBrowsers(); assert.equal(calls, 2);
  assert.equal(f.launches, 0);
});

test('manual executable selection accepts only local regular canonical browser files and does not persist settings', async t => {
  const f = await fixture(t); const selected = path.join(f.root, 'Custom Installation', 'chrome.exe'); await put(selected, 'fixture');
  const options = await f.manager.setExecutable({ browser: 'chrome', executable: path.join(path.dirname(selected), 'Google Chrome.exe') });
  assert.equal(options[0].available, true); assert.equal((await f.manager.plan({ port: 17890 })).executable, selected);
  assert.doesNotMatch(JSON.stringify(options), /Custom Installation/);
  for (const executable of ['chrome.exe', 'C:\\Chrome\\chrome.exe --private', '\\\\server\\share\\chrome.exe', '\\\\?\\C:\\Chrome\\chrome.exe', 'C:\\Chrome\\chrome.exe:payload', path.join(f.root, 'wrong.exe'), path.dirname(selected), selected + '\n']) await assert.rejects(f.manager.setExecutable({ executable }), { code: 'BROWSER_EXECUTABLE_INVALID' });
  const linked = path.join(f.root, 'Linked', 'chrome.exe');
  await symlink(path.dirname(selected), path.dirname(linked), 'junction'); await assert.rejects(f.manager.setExecutable({ executable: linked }), { code: 'BROWSER_EXECUTABLE_INVALID' });
  assert.equal((await f.manager.plan({ port: 17890 })).executable, selected, 'failed path validation preserves the previous choice');
  assert.equal((await createBrowserManager(f.options).plan({ port: 17890 })).executable, f.executable, 'manual selection is scoped to this manager');
  await f.manager.setExecutable({ executable: null }); assert.equal((await f.manager.plan({ port: 17890 })).executable, f.executable);
  assert.equal(f.launches, 0); await missing(path.join(f.root, 'browser-session.json'));
});

test('renamed Chrome processes retain exact profile and creation ownership guards', async t => {
  const f = await fixture(t); const alias = path.join(f.root, 'Google Chrome.exe'); await put(alias, 'fixture');
  const manager = createBrowserManager({ ...f.options, candidates: [{ id: 'chrome', executable: alias }] });
  await manager.launch(await manager.plan({ port: 17890 }));
  assert.equal((await manager.status()).managed, true);
  await assert.rejects(manager.setExecutable({ executable: f.executable }), { code: 'BROWSER_ALREADY_RUNNING' });
  const recovered = createBrowserManager({ ...f.options, candidates: [{ id: 'chrome', executable: alias }] });
  assert.equal((await recovered.status()).managed, true); await recovered.close(); assert.equal(f.closeCalls, 1);
  assert.equal(f.running.length, 0);
});

test('a manual installation replaced by a junction invalidates the saved launch plan before spawning', async t => {
  const f = await fixture(t);
  const selected = path.join(f.root, 'Selected', 'chrome.exe'); await put(selected, 'fixture');
  await f.manager.setExecutable({ executable: selected });
  const plan = await f.manager.plan({ port: 17890 });
  await rename(path.dirname(selected), path.join(f.root, 'Original'));
  const replacement = path.join(f.root, 'Replacement', 'chrome.exe'); await put(replacement, 'untrusted replacement');
  await symlink(path.dirname(replacement), path.dirname(selected), 'junction');
  await assert.rejects(f.manager.launch(plan), { code: 'BROWSER_PLAN_INVALID' });
  assert.equal(f.launches, 0); await missing(path.join(f.root, 'browser-session.json'));
  assert.equal((await f.manager.plan({ port: 17890 })).executable, f.executable);
});

test('native discovery safely falls back when unavailable, malformed or too large', async () => {
  const forbidden = () => assert.fail('non-Windows discovery must not launch a command');
  assert.deepEqual(await discoverWindowsBrowserCandidates({ platform: 'linux', execFile: forbidden }), []);
  for (const raw of ['invalid json', '{"executable":"D:\\\\chrome.exe"}', JSON.stringify(Array.from({ length: 65 }, () => ({ id: 'chrome', executable: 'D:\\chrome.exe' })))]) {
    assert.deepEqual(await discoverWindowsBrowserCandidates({ platform: 'win32', execFile: (_file, _args, _options, callback) => callback(null, raw) }), []);
  }
  assert.deepEqual(await discoverWindowsBrowserCandidates({ platform: 'win32', execFile: (_file, _args, _options, callback) => callback(new Error('registry query denied private path')) }), []);
});

test('discovered custom installations are verified once and availability exposes no program paths', async t => {
  const f = await fixture(t);
  const edge = path.join(f.root, 'Custom Edge', 'msedge.exe');
  await put(edge, 'test executable marker');
  let discoveries = 0;
  const manager = createBrowserManager({ ...f.options, candidates: undefined, discoverCandidates: async () => {
    discoveries++; return [{ id: 'chrome', executable: f.executable }, { id: 'edge', executable: edge }];
  } });
  const browsers = await manager.listBrowsers();
  assert.deepEqual(browsers, [{ id: 'chrome', label: 'Google Chrome', available: true }, { id: 'edge', label: 'Microsoft Edge', available: true }]);
  assert.equal(JSON.stringify(browsers).includes(f.root), false);
  assert.equal((await manager.plan({ browser: 'chrome', port: 17890 })).executable, f.executable);
  assert.equal((await manager.plan({ browser: 'edge', port: 17890 })).executable, edge);
  assert.equal(discoveries, 1);
  assert.equal(f.launches, 0);
});

test('explicit candidates bypass native discovery and a directory cannot count as an installed executable', async t => {
  const f = await fixture(t, { discoverCandidates: () => assert.fail('explicit candidates must not inspect the host') });
  assert.equal((await f.manager.listBrowsers())[0].available, true);
  await rm(f.executable); await mkdir(f.executable);
  assert.equal((await f.manager.listBrowsers())[0].available, false);
  await assert.rejects(f.manager.plan({ browser: 'chrome', port: 17890 }), { code: 'BROWSER_UNAVAILABLE' });
  assert.equal(f.launches, 0);
});

async function fingerprintFixture(t, runtimeOverrides = {}) {
  const f = await fixture(t);
  const calls = [];
  const options = { ...f.options, readPlatformVersion: async () => ({ version: '19.0.0', source: 'windows-universal-api-contract' }), readHardwareConcurrency: () => 8, fingerprintRoot: path.join(f.root, 'component'), readFingerprintRuntime: async (_root, { full }) => {
    calls.push(full);
    return { state: 'ready', version: '150.0.7871.186', architecture: 'x64', verified: true, integrity: full ? 'full' : 'executable', executable: f.executable, ...runtimeOverrides };
  } };
  return { ...f, f, options, manager: createBrowserManager(options), calls, profile: path.join(f.root, 'browser-profiles', 'fingerprint') };
}

test('optional fingerprint runtime is visible without paths and missing components cannot fall back to Chrome', async t => {
  const x = await fingerprintFixture(t, { state: 'missing', errorCode: 'BROWSER_FINGERPRINT_NOT_INSTALLED' });
  const list = await x.manager.listBrowsers();
  assert.equal(list.length, 3); assert.equal(list[2].id, 'fingerprint'); assert.equal(list[2].available, false);
  assert.equal(JSON.stringify(list).includes(x.root), false);
  await assert.rejects(x.manager.plan({ browser: 'fingerprint', port: 17890 }), { code: 'BROWSER_FINGERPRINT_NOT_INSTALLED' });
  await assert.rejects(x.manager.setExecutable({ browser: 'fingerprint', executable: x.executable }), { code: 'BROWSER_FINGERPRINT_PATH_MANAGED' });
  assert.equal(x.f.launches, 0);
});

test('stable fingerprint seeds are read-only during planning and persist across manager restarts and proxy changes', async t => {
  const x = await fingerprintFixture(t);
  const first = await x.manager.plan({ browser: 'fingerprint', port: 17890, language: 'ja', timezone: 'Asia/Tokyo', nativeGraphics: true });
  const again = await x.manager.plan({ browser: 'fingerprint', port: 17891, language: 'ja', timezone: 'Asia/Tokyo', nativeGraphics: true });
  assert.equal(first.fingerprint.seed, again.fingerprint.seed);
  await missing(x.profile);
  assert.ok(first.args.includes('--proxy-server=http://127.0.0.1:17890'));
  assert.ok(first.args.includes('--timezone=Asia/Tokyo'));
  assert.ok(first.args.includes('--disable-spoofing=font,audio,gpu,canvas,clientrects'));
  assert.equal(first.args.includes('--disable-accelerated-2d-canvas'), false);
  await x.manager.launch(first);
  assert.deepEqual(JSON.parse(await readFile(path.join(x.profile, '.mc-fingerprint.json'), 'utf8')), { version: 1, seed: first.fingerprint.seed, cores: 8 });
  assert.ok(x.calls.includes(true), 'full component validation runs before spawning');
  assert.equal((await x.manager.status()).managed, true);
  await x.manager.close();
  const restarted = createBrowserManager(x.options);
  assert.equal((await restarted.plan({ browser: 'fingerprint', port: 17892 })).fingerprint.seed, first.fingerprint.seed);
  await assert.rejects(restarted.plan({ browser: 'fingerprint', port: 17890, seed: first.fingerprint.seed === 1 ? 2 : 1 }), { code: 'BROWSER_FINGERPRINT_SEED_CHANGED' });
});

test('explicit stable seed rotation safely closes only its managed profile and preserves cookies and existing preferences', async t => {
  const x = await fingerprintFixture(t);
  const prefs = path.join(x.profile, 'Default', 'Preferences');
  const cookies = path.join(x.profile, 'Default', 'Network', 'Cookies');
  await put(prefs, { intl: { accept_languages: 'zh-CN' }, keep: true }); await put(cookies, 'signed-in fixture');
  const first = await x.manager.plan({ browser: 'fingerprint', port: 17890, timezone: 'Asia/Tokyo' });
  await x.manager.launch(first);
  await assert.rejects(x.manager.rotateFingerprint(), { code: 'CONFIRMATION_REQUIRED' });
  assert.equal(x.f.closeCalls, 0);
  const rotated = await x.manager.rotateFingerprint({ confirm: true });
  assert.notEqual(rotated.seed, first.fingerprint.seed); assert.equal(x.f.closeCalls, 1);
  assert.deepEqual(JSON.parse(await readFile(path.join(x.profile, '.mc-fingerprint.json'), 'utf8')), { version: 1, seed: rotated.seed, cores: 8 });
  assert.equal(await readFile(cookies, 'utf8'), 'signed-in fixture');
  assert.deepEqual(JSON.parse(await readFile(prefs, 'utf8')), { intl: { accept_languages: 'zh-CN' }, keep: true });
  const next = await x.manager.plan({ browser: 'fingerprint', port: 17890, timezone: 'Asia/Tokyo' });
  assert.equal(next.fingerprint.seed, rotated.seed); assert.ok(next.args.includes('--proxy-server=http://127.0.0.1:17890'));
});

test('fresh fingerprint spaces get new profile identities and rotation never silently closes a fresh window', async t => {
  const x = await fingerprintFixture(t);
  const first = await x.manager.plan({ browser: 'fingerprint', port: 17890, fresh: true });
  const next = await x.manager.plan({ browser: 'fingerprint', port: 17890, fresh: true });
  assert.notEqual(first.profile, next.profile); assert.notEqual(first.fingerprint.seed, next.fingerprint.seed);
  await x.manager.launch(first);
  await assert.rejects(x.manager.rotateFingerprint({ confirm: true }), { code: 'BROWSER_FINGERPRINT_FRESH_ROTATION_UNSUPPORTED' });
  assert.equal(x.f.closeCalls, 0); assert.equal((await x.manager.status()).running, true);
  await x.manager.close();
  await assert.rejects(x.manager.launch(first), { code: 'BROWSER_PLAN_INVALID' });
});

test('fingerprint argument validation and launch-time component drift prevent spawning or profile mutation', async t => {
  const x = await fingerprintFixture(t);
  for (const values of [{ seed: 0 }, { seed: 4294967296 }, { timezone: 'Asia/Tokyo\n--disable-web-security' }, { nativeGraphics: 'false' }]) await assert.rejects(x.manager.plan({ browser: 'fingerprint', port: 17890, ...values }));
  const planned = await x.manager.plan({ browser: 'fingerprint', port: 17890 });
  await assert.rejects(x.manager.launch({ ...planned, args: [...planned.args, '--disable-web-security'] }), { code: 'BROWSER_PLAN_INVALID' });
  const blocked = createBrowserManager({ ...x.options, readFingerprintRuntime: async (_root, { full }) => full ? { state: 'invalid', errorCode: 'BROWSER_FINGERPRINT_FILES_CHANGED' } : x.options.readFingerprintRuntime(_root, { full }) });
  await assert.rejects(blocked.launch(planned), { code: 'BROWSER_FINGERPRINT_FILES_CHANGED' });
  assert.equal(x.f.launches, 0); await missing(x.profile); await missing(path.join(x.root, 'browser-session.json'));
});

test('Canvas software readback workaround is limited to fingerprint seeded graphics and ordinary browsers keep their arguments', async t => {
  const x = await fingerprintFixture(t);
  const seeded = await x.manager.plan({ browser: 'fingerprint', port: 17890, nativeGraphics: false });
  const defaultSeeded = await x.manager.plan({ browser: 'fingerprint', port: 17890 });
  assert.equal(defaultSeeded.fingerprint.nativeGraphics, false); assert.ok(defaultSeeded.args.includes('--disable-accelerated-2d-canvas'));
  assert.ok(seeded.args.includes('--disable-accelerated-2d-canvas')); assert.ok(seeded.args.includes('--disable-spoofing=font,audio,gpu'));
  const native = await x.manager.plan({ browser: 'fingerprint', port: 17890, nativeGraphics: true });
  const chrome = await x.manager.plan({ browser: 'chrome', port: 17890 });
  const edge = await createBrowserManager({ ...x.options, mock: true }).plan({ browser: 'edge', port: 17890 });
  for (const planned of [native, chrome, edge]) assert.equal(planned.args.includes('--disable-accelerated-2d-canvas'), false);
  assert.equal(seeded.args.includes('--disable-gpu'), false); assert.equal(seeded.args.includes('--no-sandbox'), false);
});

test('browser observation service bypasses only its validated loopback port while HTTPS keeps the ISP proxy', async t => {
  const x = await fingerprintFixture(t);
  const observationUrl = 'http://127.0.0.1:23456/s/' + 'a'.repeat(32) + '/';
  for (const browser of ['chrome', 'fingerprint']) {
    const planned = await x.manager.plan({ browser, service: 'observation', observationUrl, port: 17890 });
    assert.equal(planned.args.at(-1), observationUrl);
    assert.ok(planned.args.includes('--proxy-bypass-list=<-loopback>;127.0.0.1:23456'));
    assert.ok(planned.args.includes('--proxy-server=http://127.0.0.1:17890'));
  }
  for (const invalid of [observationUrl.replace('127.0.0.1', 'localhost'), observationUrl.replace('http:', 'https:'), observationUrl + '?target=https://evil.invalid', observationUrl + '#x', observationUrl.replace('/s/', '/files/'), observationUrl.replace(':23456', ':80'), observationUrl.replace('127.0.0.1', 'user:pass@127.0.0.1'), observationUrl.replace('a'.repeat(32), 'a'.repeat(31))]) await assert.rejects(x.manager.plan({ browser: 'chrome', service: 'observation', observationUrl: invalid, port: 17890 }), { code: 'SERVICE_INVALID' });
  await assert.rejects(x.manager.plan({ port: 17890, service: 'exit', observationUrl }), { code: 'SERVICE_INVALID' });
  assert.equal(x.f.launches, 0);
});

test('named workspaces retain independent stable identities and cookies without moving the legacy profile', async t => {
  const x = await fingerprintFixture(t), firstId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', secondId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  await put(path.join(x.profile, 'Default', 'Cookies'), 'legacy-login');
  const first = await x.manager.plan({ browser: 'fingerprint', workspaceId: firstId, services: ['chatgpt', 'claude'], port: 17890 });
  const second = await x.manager.plan({ browser: 'fingerprint', workspaceId: secondId, services: ['google'], port: 17890 });
  assert.equal(first.profile, path.join(x.root, 'browser-profiles', 'workspaces', firstId, 'fingerprint'));
  assert.deepEqual(first.args.slice(-2), ['https://chatgpt.com/', 'https://claude.ai/']);
  assert.notEqual(first.fingerprint.seed, second.fingerprint.seed);
  await x.manager.launch(first); await put(path.join(first.profile, 'Default', 'Cookies'), 'workspace-login');
  assert.equal((await x.manager.status()).workspaceId, firstId);
  await assert.rejects(x.manager.launch(second), { code: 'BROWSER_ALREADY_RUNNING' });
  const restarted = createBrowserManager(x.options); assert.equal((await restarted.status()).workspaceId, firstId);
  await restarted.close(); await restarted.launch(second); await restarted.close();
  const reopened = await restarted.plan({ browser: 'fingerprint', workspaceId: firstId, services: ['claude'], port: 17890 });
  assert.equal(reopened.fingerprint.seed, first.fingerprint.seed);
  assert.equal(await readFile(path.join(first.profile, 'Default', 'Cookies'), 'utf8'), 'workspace-login');
  assert.equal(await readFile(path.join(x.profile, 'Default', 'Cookies'), 'utf8'), 'legacy-login');
});

test('Chrome and Edge named workspaces reopen the same login profile without fingerprint arguments or old configuration changes', async t => {
  for (const browser of ['chrome', 'edge']) {
    const f = await fixture(t), workspaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    const executable = browser === 'chrome' ? f.executable : path.join(f.root, 'msedge.exe');
    if (browser === 'edge') await put(executable, 'Edge executable fixture');
    const options = { ...f.options, candidates: [{ id: browser, executable }] }, manager = createBrowserManager(options);
    const config = path.join(f.root, 'config.json'), license = path.join(f.root, 'license.json');
    await put(config, 'existing connection'); await put(license, 'existing authorization');
    await put(path.join(f.root, 'browser-profiles', browser, 'Default', 'Cookies'), 'old global browser login');
    const first = await manager.plan({ browser, workspaceId, services: ['chatgpt', 'claude'], port: 17890, observationPort: 23456 });
    assert.equal(first.profile, path.join(f.root, 'browser-profiles', 'workspaces', workspaceId, browser));
    assert.deepEqual(first.args.slice(-2), ['https://chatgpt.com/', 'https://claude.ai/']);
    assert.equal(first.args.some(arg => /^--(?:fingerprint|disable-spoofing|timezone|disable-accelerated-2d-canvas)/.test(arg)), false);
    assert.equal(Object.hasOwn(first, 'fingerprint'), false);
    await manager.launch(first);
    const cookies = path.join(first.profile, 'Default', 'Network', 'Cookies'); await put(cookies, 'retained workspace login');
    await assert.rejects(manager.rotateFingerprint({ confirm: true, workspaceId }), { code: 'BROWSER_INVALID' });
    const recovered = createBrowserManager(options), status = await recovered.status();
    assert.equal(status.browser, browser); assert.equal(status.workspaceId, workspaceId); assert.equal(status.managed, true);
    await recovered.close();
    assert.equal(await readFile(cookies, 'utf8'), 'retained workspace login');
    const reopened = await recovered.plan({ browser, workspaceId, services: ['claude'], port: 17890 });
    assert.equal(reopened.profile, first.profile); await recovered.launch(reopened); await recovered.close();
    await missing(path.join(first.profile, '.mc-fingerprint.json'));
    assert.equal(await readFile(config, 'utf8'), 'existing connection'); assert.equal(await readFile(license, 'utf8'), 'existing authorization');
    assert.equal(await readFile(path.join(f.root, 'browser-profiles', browser, 'Default', 'Cookies'), 'utf8'), 'old global browser login');
  }
});

test('Chrome workspace appends approved tabs and observation only to the exact owned session and detects orphan profiles', async t => {
  const f = await fixture(t), workspaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  let count = 0;
  const options = { ...f.options, spawnProcess: (...args) => {
    if (count++ === 0) return f.options.spawnProcess(...args);
    const child = Object.assign(new EventEmitter(), { pid: 2244, unref() {} }); queueMicrotask(() => child.emit('spawn')); return child;
  } };
  const manager = createBrowserManager(options);
  await manager.launch(await manager.plan({ browser: 'chrome', workspaceId, services: ['chatgpt'], port: 17890, observationPort: 23456 }));
  const before = JSON.parse(await readFile(path.join(f.root, 'browser-session.json'), 'utf8'));
  const next = await manager.plan({ browser: 'chrome', workspaceId, services: ['claude', 'google'], port: 17890, observationPort: 23456 });
  assert.equal((await manager.launch(next)).reused, true);
  assert.equal((await manager.openObservation({ workspaceId, port: 17890, observationUrl: `http://127.0.0.1:23456/s/${'a'.repeat(32)}/` })).reused, true);
  assert.deepEqual(JSON.parse(await readFile(path.join(f.root, 'browser-session.json'), 'utf8')).identity, before.identity);
  await assert.rejects(manager.launch(await manager.plan({ browser: 'chrome', workspaceId, services: ['claude'], port: 17891, observationPort: 23456 })), { code: 'BROWSER_WORKSPACE_SESSION_CHANGED' });
  await rm(path.join(f.root, 'browser-session.json'));
  const orphan = createBrowserManager(options), status = await orphan.status();
  assert.equal(status.browser, 'chrome'); assert.equal(status.workspaceId, workspaceId); assert.equal(status.managed, false);
  await assert.rejects(orphan.launch(next), { code: 'BROWSER_ALREADY_RUNNING' });
  assert.equal(count, 3); assert.equal(f.closeCalls, 0);
});

test('same-workspace approved tabs reuse the owned session while changed proxy/environment and orphan sessions are refused', async t => {
  const x = await fingerprintFixture(t), workspaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  let count = 0;
  const original = x.options.spawnProcess;
  x.options.spawnProcess = (...args) => {
    if (count++ === 0) return original(...args);
    const child = Object.assign(new EventEmitter(), { pid: 2244, unref() {} }); queueMicrotask(() => child.emit('spawn')); return child;
  };
  const manager = createBrowserManager(x.options);
  const first = await manager.plan({ browser: 'fingerprint', workspaceId, services: ['chatgpt'], port: 17890 }); await manager.launch(first);
  const before = JSON.parse(await readFile(path.join(x.root, 'browser-session.json'), 'utf8'));
  const next = await manager.plan({ browser: 'fingerprint', workspaceId, services: ['claude', 'google'], port: 17890 });
  assert.equal((await manager.launch(next)).reused, true);
  assert.deepEqual(JSON.parse(await readFile(path.join(x.root, 'browser-session.json'), 'utf8')).identity, before.identity);
  await assert.rejects(manager.launch(await manager.plan({ browser: 'fingerprint', workspaceId, services: ['claude'], port: 17891 })), { code: 'BROWSER_WORKSPACE_SESSION_CHANGED' });
  await rm(path.join(x.root, 'browser-session.json'));
  const lostManifest = createBrowserManager(x.options);
  assert.equal((await lostManifest.status()).managed, false);
  await assert.rejects(lostManifest.launch(next), { code: 'BROWSER_ALREADY_RUNNING' });
  assert.equal(count, 2);
});

test('workspace plans reject untrusted paths, fresh combinations, arbitrary browser/URL arrays and junction profiles', async t => {
  const x = await fingerprintFixture(t), workspaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  for (const input of [{ workspaceId: '../bad' }, { workspaceId, browser: 'firefox' }, { workspaceId, fresh: true }, { workspaceId, freshId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }, { workspaceId, services: ['https://bad.test'] }, { workspaceId, services: ['claude', '--no-sandbox'] }, { workspaceId, services: [] }]) await assert.rejects(x.manager.plan({ browser: 'fingerprint', port: 17890, ...input }));
  const profileParent = path.join(x.root, 'browser-profiles', 'workspaces'); await mkdir(profileParent, { recursive: true });
  await symlink(x.profile, path.join(profileParent, workspaceId), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(x.manager.plan({ browser: 'fingerprint', workspaceId, port: 17890 }), { code: 'BROWSER_PATH_UNSAFE' });
  assert.equal(x.f.launches, 0);
});

test('UA-CH contract version is independent of NT build and a failed read never generates an invented identity', async t => {
  const x = await fingerprintFixture(t);
  const planned = await x.manager.plan({ browser: 'fingerprint', port: 17890 });
  assert.equal(planned.fingerprint.platformVersion, '19.0.0');
  assert.ok(planned.args.includes('--fingerprint-platform-version=19.0.0'));
  assert.ok(!planned.args.some(value => value.includes('10.0.26200')));
  const unavailable = createBrowserManager({ ...x.options, readPlatformVersion: async () => { throw Object.assign(new Error('contract unavailable'), { code: 'BROWSER_FINGERPRINT_PLATFORM_UNAVAILABLE' }); } });
  await assert.rejects(unavailable.plan({ browser: 'fingerprint', port: 17890 }), { code: 'BROWSER_FINGERPRINT_PLATFORM_UNAVAILABLE' });
  assert.equal(x.f.launches, 0); await missing(x.profile);
});

test('legacy seeds migrate without rotation and persisted CPU identity remains stable when host scheduling changes', async t => {
  const x = await fingerprintFixture(t);
  const marker = path.join(x.profile, '.mc-fingerprint.json');
  await put(marker, { version: 1, seed: 12345 });
  const first = await x.manager.plan({ browser: 'fingerprint', port: 17890 });
  assert.equal(first.fingerprint.seed, 12345); assert.equal(first.fingerprint.cores, 8);
  assert.deepEqual(JSON.parse(await readFile(marker, 'utf8')), { version: 1, seed: 12345 }, 'planning never rewrites migration data');
  await x.manager.launch(first); await x.manager.close();
  const persisted = JSON.parse(await readFile(marker, 'utf8'));
  assert.deepEqual(persisted, { version: 1, seed: 12345, cores: 8 });
  // Contract captured from the rollback reader: it accepts version 1 plus a
  // valid seed, and intentionally does not interpret new extension fields.
  const legacySeed = record => {
    if (record.version !== 1 || !Number.isInteger(record.seed) || record.seed < 1 || record.seed > 4294967295) throw new Error('legacy fingerprint state invalid');
    return record.seed;
  };
  assert.equal(legacySeed(persisted), 12345);
  assert.equal(legacySeed({ ...persisted, cores: 'unknown-to-old-reader' }), 12345);
  const restarted = createBrowserManager({ ...x.options, readHardwareConcurrency: () => 2 });
  const next = await restarted.plan({ browser: 'fingerprint', port: 17891 });
  assert.equal(next.fingerprint.seed, 12345); assert.equal(next.fingerprint.cores, 8);
  assert.ok(next.args.includes('--fingerprint-hardware-concurrency=8'));
  await put(marker, { version: 2, seed: 12345, cores: 8 });
  const preview = await restarted.plan({ browser: 'fingerprint', port: 17891 });
  assert.equal(preview.fingerprint.seed, 12345); assert.equal(preview.fingerprint.cores, 8, 'preview v2 records remain readable');
  await restarted.launch(preview); await restarted.close();
  assert.deepEqual(JSON.parse(await readFile(marker, 'utf8')), { version: 1, seed: 12345, cores: 8 }, 'next launch restores rollback-compatible serialization');
  for (const cores of [0, null, 'unknown-to-old-reader']) {
    await put(marker, { version: 1, seed: 12345, cores });
    await assert.rejects(restarted.plan({ browser: 'fingerprint', port: 17890 }), { code: 'BROWSER_FINGERPRINT_STATE_INVALID' });
    assert.deepEqual(JSON.parse(await readFile(marker, 'utf8')), { version: 1, seed: 12345, cores }, 'invalid extension data is never overwritten');
  }
  await put(marker, { version: 2, seed: 12345, cores: 0 });
  await assert.rejects(restarted.plan({ browser: 'fingerprint', port: 17890 }), { code: 'BROWSER_FINGERPRINT_STATE_INVALID' });
});

function appendingManager(x) {
  let calls = 0; const original = x.options.spawnProcess, args = [];
  return { args, manager: createBrowserManager({ ...x.options, spawnProcess: (file, input, options) => {
    args.push(input);
    if (calls++ === 0) return original(file, input, options);
    const child = Object.assign(new EventEmitter(), { pid: 2244, unref() {} }); queueMicrotask(() => child.emit('spawn')); return child;
  } }) };
}

test('current-workspace observation appends inside its owned profile without rewriting identity or changing proxy arguments', async t => {
  const x = await fingerprintFixture(t), workspaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const { manager, args } = appendingManager(x);
  const first = await manager.plan({ browser: 'fingerprint', workspaceId, services: ['chatgpt', 'claude'], port: 17890, observationPort: 23456, language: 'ja', timezone: 'Asia/Tokyo' });
  await manager.launch(first);
  const marker = path.join(first.profile, '.mc-fingerprint.json'), before = await readFile(marker, 'utf8');
  const observed = await manager.openObservation({ observationUrl: `http://127.0.0.1:23456/s/${'a'.repeat(32)}/`, workspaceId, port: 17890 });
  assert.equal(observed.mode, 'appended'); assert.equal(observed.workspaceId, workspaceId);
  assert.deepEqual(observed.fingerprint, first.fingerprint);
  assert.equal(await readFile(marker, 'utf8'), before);
  assert.deepEqual(args[1].slice(0, -1), args[0].slice(0, -2));
  assert.equal(args[1].at(-1), observed.observationUrl);
  assert.ok(args[1].includes('--proxy-bypass-list=<-loopback>;127.0.0.1:23456'));
  const status = await manager.status();
  assert.equal(status.managed, true); assert.equal(status.observationPort, 23456); assert.deepEqual(status.fingerprint, first.fingerprint);
  assert.equal(x.f.closeCalls, 0); assert.equal(x.f.running.length, 1);
});

test('observation refuses foreign targets, unreserved ports and orphan profiles without opening or closing any window', async t => {
  const x = await fingerprintFixture(t), workspaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const { manager, args } = appendingManager(x);
  const first = await manager.plan({ browser: 'fingerprint', workspaceId, port: 17890, observationPort: 23456 }); await manager.launch(first);
  const good = { observationUrl: `http://127.0.0.1:23456/s/${'a'.repeat(32)}/`, workspaceId, port: 17890 };
  await assert.rejects(manager.openObservation({ ...good, workspaceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }), { code: 'BROWSER_OBSERVATION_SESSION_CHANGED' });
  await assert.rejects(manager.openObservation({ ...good, workspaceId: undefined }), { code: 'BROWSER_OBSERVATION_SESSION_CHANGED' });
  await assert.rejects(manager.openObservation({ ...good, port: 17891 }), { code: 'BROWSER_OBSERVATION_SESSION_CHANGED' });
  await assert.rejects(manager.openObservation({ ...good, observationUrl: good.observationUrl.replace('23456', '23457') }), { code: 'BROWSER_OBSERVATION_RESTART_REQUIRED' });
  for (const url of [good.observationUrl + '?url=https://bad.test', good.observationUrl.replace('127.0.0.1', 'localhost'), good.observationUrl.replace('/s/', '/file/')]) await assert.rejects(manager.openObservation({ ...good, observationUrl: url }), { code: 'SERVICE_INVALID' });
  await rm(path.join(x.root, 'browser-session.json'));
  const orphan = createBrowserManager(x.options);
  await assert.rejects(orphan.openObservation(good), { code: 'BROWSER_SESSION_UNTRACKED' });
  assert.equal(args.length, 1); assert.equal(x.f.closeCalls, 0);
});

test('pre-P0 running profiles require an explicit close and reopen before observation', async t => {
  const x = await fingerprintFixture(t), workspaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  await x.manager.launch(await x.manager.plan({ browser: 'fingerprint', workspaceId, port: 17890 }));
  await assert.rejects(x.manager.openObservation({ observationUrl: `http://127.0.0.1:23456/s/${'a'.repeat(32)}/`, workspaceId, port: 17890 }), { code: 'BROWSER_OBSERVATION_RESTART_REQUIRED' });
  assert.equal(x.f.closeCalls, 0); assert.equal(x.f.launches, 1);
});

test('explicit inactive-workspace rotation changes only that identity and never closes another active environment', async t => {
  const x = await fingerprintFixture(t), workspaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', otherId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const first = await x.manager.plan({ browser: 'fingerprint', workspaceId, port: 17890 }); await x.manager.launch(first); await x.manager.close();
  await put(path.join(first.profile, 'Default', 'Cookies'), 'keep-this-login');
  const rotated = await x.manager.rotateFingerprint({ confirm: true, workspaceId });
  assert.notEqual(rotated.seed, first.fingerprint.seed); assert.equal(rotated.workspaceId, workspaceId);
  assert.equal((await x.manager.plan({ browser: 'fingerprint', workspaceId, port: 17890 })).fingerprint.seed, rotated.seed);
  assert.equal(await readFile(path.join(first.profile, 'Default', 'Cookies'), 'utf8'), 'keep-this-login');
  await x.manager.launch(await x.manager.plan({ browser: 'fingerprint', workspaceId: otherId, port: 17890 }));
  await assert.rejects(x.manager.rotateFingerprint({ confirm: true, workspaceId }), { code: 'BROWSER_ALREADY_RUNNING' });
  assert.equal((await x.manager.status()).workspaceId, otherId); assert.equal(x.f.closeCalls, 1);
});

test('tampered identity and observer recovery fields are rejected before any process is controlled', async t => {
  const x = await fingerprintFixture(t), workspaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  await x.manager.launch(await x.manager.plan({ browser: 'fingerprint', workspaceId, port: 17890, observationPort: 23456 }));
  const marker = path.join(x.root, 'browser-session.json'), original = JSON.parse(await readFile(marker, 'utf8'));
  for (const fields of [{ observationPort: 22 }, { observationPort: 17890 }, { browserArgs: [null] }, { fingerprint: { ...original.fingerprint, cores: 0 } }, { fingerprint: { ...original.fingerprint, platformVersion: '10.0.26200' } }]) {
    await put(marker, { ...original, ...fields });
    await assert.rejects(createBrowserManager(x.options).status(), { code: 'BROWSER_STATE_INVALID' });
  }
  assert.equal(x.f.closeCalls, 0); assert.equal(x.f.launches, 1);
});

test('refreshing a retained profile archives exact login data and restores it without changing canonical paths', async t => {
  const f = await fixture(t), cookie = path.join(f.profile, 'Default', 'Network', 'Cookies');
  const preferences = { intl: { accept_languages: 'zh-CN' }, keep: 'original' };
  const bytes = Buffer.from([0, 255, 10, 128, 42]);
  await mkdir(path.dirname(cookie), { recursive: true }); await writeFile(cookie, bytes); await put(path.join(f.profile, 'Default', 'Preferences'), preferences);
  const first = await f.manager.plan({ port: 17890 });
  await f.manager.launch(first); await f.manager.close();
  const before = await f.manager.profileArchives({ browser: 'chrome' });
  assert.deepEqual(before, { browser: 'chrome', currentAvailable: true, archives: [] });
  const refreshed = await f.manager.refreshProfile({ browser: 'chrome', confirm: true });
  assert.equal(refreshed.changed, true); assert.equal(refreshed.archives.length, 1);
  const archived = path.join(f.root, 'browser-profiles', 'archive', 'chrome', refreshed.archiveId, 'profile');
  assert.deepEqual(await readFile(path.join(archived, 'Default', 'Network', 'Cookies')), bytes);
  assert.deepEqual(JSON.parse(await readFile(path.join(archived, 'Default', 'Preferences'), 'utf8')), preferences);
  await missing(f.profile);
  assert.equal((await f.manager.plan({ port: 17891 })).profile, first.profile);
  await f.manager.launch(await f.manager.plan({ port: 17891 }));
  await missing(cookie); await put(cookie, 'new-login'); await f.manager.close();
  await f.manager.launch(await f.manager.plan({ port: 17892 }));
  assert.equal(await readFile(cookie, 'utf8'), 'new-login'); await f.manager.close();
  const restored = await f.manager.restoreProfile({ browser: 'chrome', archiveId: refreshed.archiveId, confirm: true });
  assert.equal(restored.restored, true); assert.ok(restored.archivedCurrentId);
  assert.deepEqual(await readFile(cookie), bytes);
  assert.deepEqual(JSON.parse(await readFile(path.join(f.profile, 'Default', 'Preferences'), 'utf8')), preferences);
  assert.equal(await readFile(path.join(f.root, 'browser-profiles', 'archive', 'chrome', restored.archivedCurrentId, 'profile', 'Default', 'Network', 'Cookies'), 'utf8'), 'new-login');
  assert.deepEqual(restored.archives.map(item => item.id), [restored.archivedCurrentId]);
  assert.equal(JSON.stringify(await f.manager.profileArchives({ browser: 'chrome' })).includes(f.root), false);
  await missing(path.join(f.root, 'browser-profiles', '.profile-change.json'));
});

test('profile refresh and restore require explicit default-profile confirmation before changing recovery preferences', async t => {
  const f = await fixture(t);
  await f.manager.launch(await f.manager.plan({ port: 17890 })); f.running = [];
  const file = path.join(f.profile, 'Default', 'Preferences'), original = await readFile(file, 'utf8');
  await assert.rejects(f.manager.refreshProfile({ browser: 'chrome' }), { code: 'CONFIRMATION_REQUIRED' });
  await assert.rejects(f.manager.restoreProfile({ browser: 'chrome', archiveId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }), { code: 'CONFIRMATION_REQUIRED' });
  for (const extra of [{ fresh: true }, { freshId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }, { workspaceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' }, { path: f.profile }]) {
    await assert.rejects(f.manager.refreshProfile({ browser: 'chrome', confirm: true, ...extra }), { code: 'BROWSER_PROFILE_SCOPE_INVALID' });
  }
  await assert.rejects(f.manager.restoreProfile({ browser: 'chrome', archiveId: '../chrome', confirm: true }), { code: 'BROWSER_PROFILE_ARCHIVE_INVALID' });
  await assert.rejects(f.manager.restoreProfile({ browser: 'chrome', archiveId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', confirm: true }), { code: 'BROWSER_PROFILE_ARCHIVE_NOT_FOUND' });
  assert.equal(await readFile(file, 'utf8'), original); await access(path.join(f.profile, '.proxypilot-language.json'));
  assert.equal(f.closeCalls, 0);
});

test('a refresh with no retained data is harmless and restoring history into an empty default profile needs no extra archive', async t => {
  const f = await fixture(t);
  assert.deepEqual(await f.manager.refreshProfile({ confirm: true }), { changed: false, archiveId: null, mode: 'applied', archives: [] });
  await missing(f.profile);
  await put(path.join(f.profile, 'Default', 'Cookies'), 'saved-login');
  const { archiveId } = await f.manager.refreshProfile({ confirm: true });
  const result = await createBrowserManager(f.options).restoreProfile({ archiveId, confirm: true });
  assert.equal(result.archivedCurrentId, null); assert.deepEqual(result.archives, []);
  assert.equal(await readFile(path.join(f.profile, 'Default', 'Cookies'), 'utf8'), 'saved-login');
});

test('refresh refuses any running default, fresh, archive or workspace browser without closing it', async t => {
  for (const relative of ['chrome', path.join('fresh', 'chrome', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'), path.join('archive', 'chrome', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'profile'), path.join('workspaces', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'chrome')]) {
    const f = await fixture(t), runningProfile = path.join(f.root, 'browser-profiles', relative);
    await put(path.join(f.profile, 'Default', 'Cookies'), 'keep-login');
    f.running = [{ pid: 9911, parentPid: 1, createdAt: new Date().toISOString(), executable: f.executable, commandLine: `"${f.executable}" "--user-data-dir=${runningProfile}"` }];
    await assert.rejects(f.manager.refreshProfile({ confirm: true }), { code: 'BROWSER_ALREADY_RUNNING' });
    assert.equal(await readFile(path.join(f.profile, 'Default', 'Cookies'), 'utf8'), 'keep-login');
    assert.equal(f.closeCalls, 0); assert.equal(f.running.length, 1);
  }
});

test('an unreadable browser process blocks profile moves even when the current profile is absent', async t => {
  const f = await fixture(t);
  f.options.processApi.listProcessCandidates = candidateSnapshot(f);
  f.running = [{ pid: 9911, parentPid: 1, createdAt: new Date().toISOString(), executable: '', commandLine: '', name: 'chrome.exe', unreadable: true }];
  await assert.rejects(f.manager.refreshProfile({ confirm: true }), { code: 'PROCESS_UNREADABLE' });
  assert.equal(f.closeCalls, 0); await missing(f.profile);
});

test('linked or non-directory retained profiles and linked archive parents cannot be refreshed or restored', async t => {
  for (const type of ['junction', 'file', 'hardlink']) {
    const f = await fixture(t), foreign = path.join(f.root, 'do-not-touch'); await mkdir(foreign);
    await put(path.join(foreign, 'original'), 'private');
    if (type === 'junction') { await mkdir(path.dirname(f.profile), { recursive: true }); await symlink(foreign, f.profile, 'junction'); }
    else if (type === 'file') await put(f.profile, 'not-a-directory');
    else { await mkdir(f.profile, { recursive: true }); await link(path.join(foreign, 'original'), path.join(f.profile, 'linked-file')); }
    await assert.rejects(f.manager.refreshProfile({ confirm: true }), { code: 'BROWSER_PATH_UNSAFE' });
    assert.equal(await readFile(path.join(foreign, 'original'), 'utf8'), 'private');
  }
  const f = await fixture(t); await put(path.join(f.profile, 'Default', 'Cookies'), 'original');
  const { archiveId } = await f.manager.refreshProfile({ confirm: true });
  const parent = path.join(f.root, 'browser-profiles', 'archive', 'chrome'), backup = path.join(f.root, 'original-archives');
  await rename(parent, backup); await symlink(backup, parent, 'junction');
  await assert.rejects(f.manager.restoreProfile({ confirm: true, archiveId }), { code: 'BROWSER_PATH_UNSAFE' });
  assert.equal(await readFile(path.join(backup, archiveId, 'profile', 'Default', 'Cookies'), 'utf8'), 'original');
});

test('refresh creates a new fingerprint identity but restoring history restores its original seed and login', async t => {
  const x = await fingerprintFixture(t);
  const first = await x.manager.plan({ browser: 'fingerprint', port: 17890 }); await x.manager.launch(first); await x.manager.close();
  await put(path.join(x.profile, 'Default', 'Cookies'), 'old-fingerprint-login');
  const refreshed = await x.manager.refreshProfile({ browser: 'fingerprint', confirm: true });
  const second = await x.manager.plan({ browser: 'fingerprint', port: 17890 });
  assert.notEqual(second.fingerprint.seed, first.fingerprint.seed);
  await x.manager.launch(second); await x.manager.close();
  await x.manager.restoreProfile({ browser: 'fingerprint', archiveId: refreshed.archiveId, confirm: true });
  assert.equal((await x.manager.plan({ browser: 'fingerprint', port: 17890 })).fingerprint.seed, first.fingerprint.seed);
  assert.equal(await readFile(path.join(x.profile, 'Default', 'Cookies'), 'utf8'), 'old-fingerprint-login');
});

test('refreshing the default profile leaves workspace and legacy fresh data byte-for-byte intact', async t => {
  const f = await fixture(t), workspaceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const workspace = await f.manager.plan({ workspaceId, port: 17890 });
  const fresh = await f.manager.plan({ fresh: true, port: 17890 });
  const workspaceCookie = path.join(workspace.profile, 'Default', 'Cookies'), freshCookie = path.join(fresh.profile, 'Default', 'Cookies');
  await put(workspaceCookie, 'workspace-login'); await put(freshCookie, 'legacy-fresh-login');
  await put(path.join(f.profile, 'Default', 'Cookies'), 'default-login');
  const result = await f.manager.refreshProfile({ confirm: true });
  await f.manager.restoreProfile({ confirm: true, archiveId: result.archiveId });
  assert.equal(await readFile(workspaceCookie, 'utf8'), 'workspace-login'); assert.equal(await readFile(freshCookie, 'utf8'), 'legacy-fresh-login');
});

test('mock profile history uses memory only and supports retained refresh, reopen and restore', async t => {
  const f = await fixture(t), runtimeRoot = path.join(f.root, 'mock-never-created');
  const manager = createBrowserManager({ runtimeRoot, mock: true, processApi: new Proxy({}, { get() { assert.fail('mock queried native processes'); } }) });
  assert.equal((await manager.profileArchives()).currentAvailable, false);
  await manager.launch(await manager.plan({ port: 17890 }));
  const refreshed = await manager.refreshProfile({ confirm: true });
  assert.equal(refreshed.mode, 'mocked'); assert.equal(refreshed.changed, true);
  assert.equal((await manager.profileArchives()).currentAvailable, false);
  await manager.launch(await manager.plan({ port: 17890 }));
  const restored = await manager.restoreProfile({ confirm: true, archiveId: refreshed.archiveId });
  assert.equal(restored.archives.length, 1); assert.ok(restored.archivedCurrentId);
  assert.equal((await manager.profileArchives()).currentAvailable, true); await missing(runtimeRoot);
});

test('restart completes a recorded refresh before any default-profile launch can recreate its directory', async t => {
  for (const moved of [false, true]) {
    const f = await fixture(t), id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', createdAt = '2026-10-16T12:00:00.000Z';
    const base = path.join(f.root, 'browser-profiles'), archived = path.join(base, 'archive', 'chrome', id);
    await put(path.join(f.profile, 'Default', 'Cookies'), 'old-login');
    await put(path.join(base, '.profile-change.json'), { version: 1, browser: 'chrome', operation: 'refresh', currentId: id, createdAt });
    if (moved) {
      await put(path.join(archived, 'archive.json'), { version: 1, browser: 'chrome', id, createdAt });
      await rename(f.profile, path.join(archived, 'profile'));
    }
    const manager = createBrowserManager(f.options), next = await manager.plan({ port: 17890 });
    assert.equal(next.profile, f.profile); await missing(f.profile);
    assert.equal(await readFile(path.join(archived, 'profile', 'Default', 'Cookies'), 'utf8'), 'old-login');
    assert.deepEqual((await manager.profileArchives()).archives, [{ id, createdAt }]);
    await missing(path.join(base, '.profile-change.json')); assert.equal(f.launches, 0);
  }
});

test('restart completes each restore boundary and preserves the displaced current login', async t => {
  for (const stage of ['prepared', 'current-archived', 'restored', 'empty-current']) {
    const f = await fixture(t), restoreId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', currentId = stage === 'empty-current' ? null : 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
    const base = path.join(f.root, 'browser-profiles'), target = path.join(base, 'archive', 'chrome', restoreId), displaced = currentId && path.join(base, 'archive', 'chrome', currentId);
    const createdAt = '2026-10-16T12:00:00.000Z';
    await put(path.join(target, 'archive.json'), { version: 1, browser: 'chrome', id: restoreId, createdAt: '2026-10-15T12:00:00.000Z' });
    await put(path.join(target, 'profile', 'Default', 'Cookies'), 'old-login');
    if (currentId) await put(path.join(f.profile, 'Default', 'Cookies'), 'new-login');
    await put(path.join(base, '.profile-change.json'), { version: 1, browser: 'chrome', operation: 'restore', restoreId, currentId, createdAt });
    if (['current-archived', 'restored'].includes(stage)) {
      await put(path.join(displaced, 'archive.json'), { version: 1, browser: 'chrome', id: currentId, createdAt });
      await rename(f.profile, path.join(displaced, 'profile'));
    }
    if (stage === 'restored') await rename(path.join(target, 'profile'), f.profile);
    const manager = createBrowserManager(f.options);
    assert.equal((await manager.plan({ port: 17890 })).profile, f.profile);
    assert.equal(await readFile(path.join(f.profile, 'Default', 'Cookies'), 'utf8'), 'old-login');
    if (currentId) assert.equal(await readFile(path.join(displaced, 'profile', 'Default', 'Cookies'), 'utf8'), 'new-login');
    assert.deepEqual((await manager.profileArchives()).archives.map(item => item.id), currentId ? [currentId] : []);
    await missing(path.join(base, '.profile-change.json')); assert.equal(f.launches, 0);
  }
});

test('invalid or incomplete restore journals block planning instead of creating an empty profile', async t => {
  const baseJournal = { version: 1, browser: 'chrome', operation: 'restore', currentId: null, restoreId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', createdAt: '2026-10-16T12:00:00.000Z' };
  for (const journal of [null, [], {}, { ...baseJournal, browser: '../chrome' }, { ...baseJournal, currentId: '../unsafe' }, { ...baseJournal, operation: 'erase' }, baseJournal]) {
    const f = await fixture(t), marker = path.join(f.root, 'browser-profiles', '.profile-change.json');
    await put(marker, journal === null ? 'null' : journal);
    await assert.rejects(f.manager.plan({ port: 17890 }), { code: 'BROWSER_STATE_INVALID' });
    await missing(f.profile); await access(marker); assert.equal(f.launches, 0);
  }
});

test('pending recovery never moves a live browser and resumes after its normal exit', async t => {
  const f = await fixture(t), id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  await put(path.join(f.profile, 'Default', 'Cookies'), 'old-login');
  const marker = path.join(f.root, 'browser-profiles', '.profile-change.json');
  await put(marker, { version: 1, browser: 'chrome', operation: 'refresh', currentId: id, createdAt: '2026-10-16T12:00:00.000Z' });
  f.running = [{ pid: 9911, parentPid: 1, createdAt: new Date().toISOString(), executable: f.executable, commandLine: `"${f.executable}" "--user-data-dir=${f.profile}"` }];
  await assert.rejects(f.manager.plan({ port: 17890 }), { code: 'BROWSER_ALREADY_RUNNING' });
  assert.equal(await readFile(path.join(f.profile, 'Default', 'Cookies'), 'utf8'), 'old-login'); await access(marker);
  f.running = []; await f.manager.plan({ port: 17890 }); await missing(f.profile); await missing(marker);
  assert.equal((await f.manager.profileArchives()).archives[0].id, id); assert.equal(f.closeCalls, 0);
});
