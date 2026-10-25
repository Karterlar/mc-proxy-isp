import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync } from 'node:fs';
import { access, cp, mkdtemp, mkdir, readdir, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import { prepareFingerprintBrowser, prepareFingerprintBrowserFromBundle } from '../src/fingerprint-browser-install.mjs';
import { FINGERPRINT_RECEIPT, fingerprintFileHash, fingerprintInventory, fingerprintInventoryHash, inspectFingerprintRuntime } from '../src/fingerprint-browser-runtime.mjs';

async function fixture(t) {
  await mkdir(path.resolve('.cache'), { recursive: true });
  const root = await mkdtemp(path.resolve('.cache/fingerprint-install-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, target: path.join(root, 'engine') };
}
async function mockFetch(run) {
  const previous = globalThis.fetch; let calls = 0;
  try {
    globalThis.fetch = async (...args) => { calls++; return run.response(...args); };
    await run.test();
  } finally { globalThis.fetch = previous; }
  return calls;
}

test('pre-cancelled preparation never downloads or creates component directories', async t => {
  const f = await fixture(t); const controller = new AbortController(); controller.abort();
  const calls = await mockFetch({ response: () => assert.fail('cancelled preparation fetched'), test: async () => {
    await assert.rejects(prepareFingerprintBrowser(f.target, { signal: controller.signal }), { code: 'BROWSER_FINGERPRINT_INSTALL_CANCELLED' });
  } });
  assert.equal(calls, 0); assert.deepEqual(await readdir(f.root), []);
});

test('invalid existing component is preserved and cannot trigger a replacement download', async t => {
  const f = await fixture(t); await mkdir(f.target); await writeFile(path.join(f.target, 'original'), 'keep');
  const calls = await mockFetch({ response: () => assert.fail('existing component fetched'), test: async () => {
    await assert.rejects(prepareFingerprintBrowser(f.target), { code: 'BROWSER_FINGERPRINT_INVENTORY_INVALID' });
  } });
  assert.equal(calls, 0); assert.equal(await readFile(path.join(f.target, 'original'), 'utf8'), 'keep');
});

test('missing native bundle requires a local component without fetching or creating directories', async t => {
  const f = await fixture(t);
  const target = path.join(f.root, 'missing-parent', 'engine');
  const calls = await mockFetch({ response: () => assert.fail('missing native component fetched'), test: async () => {
    await assert.rejects(prepareFingerprintBrowser(target), { code: 'BROWSER_FINGERPRINT_BUNDLE_REQUIRED' });
  } });
  assert.equal(calls, 0); await assert.rejects(access(target), { code: 'ENOENT' }); assert.deepEqual(await readdir(f.root), []);
});

test('cancellation while checking a missing component never fetches and progress reveals no paths or secrets', async t => {
  const f = await fixture(t); const controller = new AbortController(); const events = [];
  const calls = await mockFetch({ response: () => assert.fail('cancelled native component fetched'), test: async () => {
    await assert.rejects(prepareFingerprintBrowser(f.target, { signal: controller.signal, onProgress: event => {
      events.push(event); if (event.status === 'checking') controller.abort();
    } }), { code: 'BROWSER_FINGERPRINT_INSTALL_CANCELLED' });
  } });
  assert.equal(calls, 0); assert.deepEqual(events.map(e => e.status), ['checking']);
  assert.equal(JSON.stringify(events).includes(f.root), false); assert.deepEqual(await readdir(f.root), []);
});

async function bundledFixture(t) {
  const f = await fixture(t); const source = path.join(f.root, 'bundle');
  await mkdir(path.join(source, 'locales'), { recursive: true });
  const executable = path.join(source, 'chrome.exe');
  const pe = Buffer.alloc(512); pe.write('MZ'); pe.writeUInt32LE(128, 0x3c); pe.write('PE\0\0', 128); pe.writeUInt16LE(0x8664, 132); pe.writeUInt16LE(0x20b, 152);
  await writeFile(executable, pe);
  await writeFile(path.join(source, 'chrome.dll'), 'public dependency');
  await writeFile(path.join(source, 'locales', 'en-US.pak'), 'public language');
  await writeFile(path.join(source, 'LICENSE'), 'public credits');
  const files = await fingerprintInventory(source);
  const release = { version: '150.0.7871.186', architecture: 'x64', archiveSha256: 'a'.repeat(64), executable: 'chrome.exe',
    executableSha256: await fingerprintFileHash(executable), inventorySha256: fingerprintInventoryHash(files) };
  await writeFile(path.join(source, FINGERPRINT_RECEIPT), JSON.stringify({ version: 1, engineVersion: release.version,
    architecture: release.architecture, archiveSha256: release.archiveSha256, files }));
  return { ...f, source, release, options: { release } };
}

test('offline bundle preparation copies only verified public resources and never downloads', async t => {
  const f = await bundledFixture(t); const events = [];
  await writeFile(path.join(f.source, 'debug.log'), 'non-shipped browser diagnostic');
  const calls = await mockFetch({ response: () => assert.fail('offline preparation fetched'), test: async () => {
    const result = await prepareFingerprintBrowserFromBundle(f.source, f.target, { ...f.options, onProgress: event => events.push(event) });
    assert.equal(result.installed, true); assert.equal(result.source, 'bundle'); assert.equal(result.integrity, 'full');
    assert.equal(result.executable, path.join(f.target, 'chrome.exe'));
    assert.equal((await inspectFingerprintRuntime(f.target, { ...f.options, full: true })).state, 'ready');
    assert.deepEqual(await fingerprintInventory(f.target), await fingerprintInventory(f.source));
    await assert.rejects(access(path.join(f.target, 'debug.log')), { code: 'ENOENT' });
  } });
  assert.equal(calls, 0); assert.ok(events.some(e => e.status === 'copying-bundle'));
  assert.equal(events.at(-1).status, 'installed'); assert.equal(events.at(-1).receivedBytes, events.at(-1).totalBytes);
  assert.equal(JSON.stringify(events).includes(f.root), false);
  assert.deepEqual((await readdir(f.root)).sort(), ['bundle', 'engine']);
});

test('ready installed engine is reused even if the bundle is unavailable', async t => {
  const f = await bundledFixture(t);
  await prepareFingerprintBrowserFromBundle(f.source, f.target, f.options);
  await writeFile(path.join(f.target, 'debug.log'), 'keep existing diagnostic');
  const result = await prepareFingerprintBrowserFromBundle(path.join(f.root, 'unavailable'), f.target, f.options);
  assert.equal(result.installed, false); assert.equal(result.state, 'ready');
  assert.equal(await readFile(path.join(f.target, 'debug.log'), 'utf8'), 'keep existing diagnostic');
});

test('invalid installed engine is preserved without touching profiles or a working bundle', async t => {
  const f = await bundledFixture(t);
  await mkdir(f.target); await writeFile(path.join(f.target, 'existing'), 'preserve for inspection');
  await writeFile(path.join(f.root, 'customer-config'), 'preserve customer config');
  await assert.rejects(prepareFingerprintBrowserFromBundle(f.source, f.target, f.options), { code: 'BROWSER_FINGERPRINT_INVENTORY_INVALID' });
  assert.equal(await readFile(path.join(f.target, 'existing'), 'utf8'), 'preserve for inspection');
  assert.equal(await readFile(path.join(f.root, 'customer-config'), 'utf8'), 'preserve customer config');
  assert.equal((await inspectFingerprintRuntime(f.source, { ...f.options, full: true })).state, 'ready');
});

test('damaged or injected bundled resources fail before creating the installed engine', async t => {
  const f = await bundledFixture(t);
  await writeFile(path.join(f.source, 'injected.dll'), 'untrusted extra executable content');
  await assert.rejects(prepareFingerprintBrowserFromBundle(f.source, f.target, f.options), { code: 'BROWSER_FINGERPRINT_FILES_CHANGED' });
  await assert.rejects(access(f.target), { code: 'ENOENT' });
  assert.deepEqual(await readdir(f.root), ['bundle']);
});

test('aborted bundle preparation leaves no partial engine and retains sibling configuration', async t => {
  const f = await bundledFixture(t); const controller = new AbortController();
  await writeFile(path.join(f.root, 'customer-config'), 'keep');
  await assert.rejects(prepareFingerprintBrowserFromBundle(f.source, f.target, { ...f.options, signal: controller.signal,
    onProgress: event => { if (event.status === 'copying-bundle') controller.abort(); } }), { code: 'BROWSER_FINGERPRINT_INSTALL_CANCELLED' });
  await assert.rejects(access(f.target), { code: 'ENOENT' });
  assert.deepEqual((await readdir(f.root)).sort(), ['bundle', 'customer-config']);
  assert.equal(await readFile(path.join(f.root, 'customer-config'), 'utf8'), 'keep');
});

test('bundle changes during copying cannot be published after an earlier valid inspection', async t => {
  const f = await bundledFixture(t); let changed = false;
  await assert.rejects(prepareFingerprintBrowserFromBundle(f.source, f.target, { ...f.options, onProgress: event => {
    if (event.status === 'copying-bundle' && !changed) { changed = true; writeFileSync(path.join(f.source, 'chrome.dll'), 'tampered resource'); }
  } }), { code: 'BROWSER_FINGERPRINT_INSTALL_FAILED' });
  await assert.rejects(access(f.target), { code: 'ENOENT' });
  assert.deepEqual(await readdir(f.root), ['bundle']);
});

test('bundle preparation refuses linked destination ancestors without writing through them', async t => {
  const f = await bundledFixture(t); const actual = path.join(f.root, 'actual'); const linked = path.join(f.root, 'linked');
  await mkdir(actual); await symlink(actual, linked, process.platform === 'win32' ? 'junction' : 'dir');
  t.after(() => rm(linked, { force: true }));
  await assert.rejects(prepareFingerprintBrowserFromBundle(f.source, path.join(linked, 'engine'), f.options), { code: 'BROWSER_FINGERPRINT_PATH_UNSAFE' });
  assert.deepEqual(await readdir(actual), []);
});

test('portable bundle accepts real Windows 8.3 paths but still rejects short-named junctions', async t => {
  if (process.platform !== 'win32') return t.skip('Windows 8.3 filesystem alias fixture');
  if (process.env.MC_PROXY_NATIVE_SHORT_PATH_TEST !== '1') return t.skip('Opt-in native Windows 8.3 fixture: set MC_PROXY_NATIVE_SHORT_PATH_TEST=1 with filesystem inspection permission');
  const f = await bundledFixture(t);
  const tempParent = path.resolve(tmpdir());
  const tempRoot = await mkdtemp(path.join(tempParent, 'MC Proxy portable bundle fixture-'));
  assert.equal(path.dirname(path.resolve(tempRoot)).toLowerCase(), tempParent.toLowerCase());
  t.after(() => rm(tempRoot, { recursive: true, force: true }));
  const source = path.join(tempRoot, 'Fingerprint Chromium Public Bundle');
  await cp(f.source, source, { recursive: true });
  const script = '$ErrorActionPreference="Stop"; (New-Object -ComObject Scripting.FileSystemObject).GetFolder($env:MC_FP_ALIAS_FIXTURE).ShortPath';
  const { stdout } = await promisify(execFile)('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
    windowsHide: true, timeout: 10000, env: { ...process.env, MC_FP_ALIAS_FIXTURE: source },
  });
  const alias = String(stdout).replace(/^\uFEFF/, '').trim();
  assert.ok(alias, 'Windows returns its filesystem short-path spelling');
  if (!alias.split(/[\\/]/).some(segment => /~[1-9][0-9]*(?:\.|$)/.test(segment))) return t.skip('8.3 aliases disabled on this test volume');
  assert.equal((await inspectFingerprintRuntime(alias, { ...f.options, full: true })).state, 'invalid', 'general runtime paths retain strict canonical boundaries');
  const prepared = await prepareFingerprintBrowserFromBundle(alias, f.target, f.options);
  assert.equal(prepared.installed, true); assert.equal(prepared.integrity, 'full');
  assert.deepEqual(await fingerprintInventory(f.target), await fingerprintInventory(f.source));
  const junction = path.join(tempRoot, 'BUNDLE~1');
  await symlink(source, junction, 'junction');
  t.after(() => rm(junction, { force: true }));
  await assert.rejects(prepareFingerprintBrowserFromBundle(junction, path.join(f.root, 'second-engine'), f.options), { code: 'BROWSER_FINGERPRINT_PATH_UNSAFE' });
  await assert.rejects(access(path.join(f.root, 'second-engine')), { code: 'ENOENT' });
});
