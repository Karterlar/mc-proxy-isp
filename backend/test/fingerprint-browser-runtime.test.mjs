import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, readFile, writeFile, rm, symlink } from 'node:fs/promises';
import { FINGERPRINT_RECEIPT, fingerprintFileHash, fingerprintInventory, fingerprintInventoryHash, inspectFingerprintRuntime, requireFingerprintRuntime, validateFingerprintPe } from '../src/fingerprint-browser-runtime.mjs';

async function fixture(t) {
  const parent = path.resolve('.cache'); await mkdir(parent, { recursive: true });
  const root = await mkdtemp(path.join(parent, 'fingerprint-runtime-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const exe = path.join(root, 'chrome.exe');
  const pe = Buffer.alloc(512); pe.write('MZ'); pe.writeUInt32LE(128, 0x3c); pe.write('PE\0\0', 128); pe.writeUInt16LE(0x8664, 132); pe.writeUInt16LE(0x20b, 152);
  await writeFile(exe, pe); await writeFile(path.join(root, 'chrome.dll'), 'isolated dependency');
  await writeFile(path.join(root, 'LICENSE'), 'fixture credits');
  const files = await fingerprintInventory(root);
  const release = { version: '150.0.7871.186', architecture: 'x64', archiveSha256: 'a'.repeat(64), executable: 'chrome.exe', executableSha256: await fingerprintFileHash(exe), inventorySha256: fingerprintInventoryHash(files) };
  const receipt = { version: 1, engineVersion: release.version, architecture: release.architecture, archiveSha256: release.archiveSha256, files };
  await writeFile(path.join(root, FINGERPRINT_RECEIPT), JSON.stringify(receipt));
  return { root, exe, release, receipt, options: { platform: 'win32', release } };
}

test('pinned runtime validates PE architecture, real executable and full resource inventory', async t => {
  const f = await fixture(t);
  const status = await inspectFingerprintRuntime(f.root, f.options);
  assert.equal(status.state, 'ready'); assert.equal(status.integrity, 'executable');
  assert.equal((await requireFingerprintRuntime(f.root, f.options)).integrity, 'full');
  await writeFile(path.join(f.root, 'debug.log'), 'fixed browser diagnostic log');
  assert.equal((await requireFingerprintRuntime(f.root, f.options)).state, 'ready');
  await writeFile(path.join(f.root, 'chrome.dll'), 'changed dependency');
  assert.equal((await inspectFingerprintRuntime(f.root, f.options)).state, 'ready', 'UI polling checks executable only and reports that scope');
  await assert.rejects(requireFingerprintRuntime(f.root, f.options), { code: 'BROWSER_FINGERPRINT_FILES_CHANGED' });
});

test('rewriting writable receipts cannot authorize changed binaries or fake versions', async t => {
  const f = await fixture(t);
  const pe = await readFile(f.exe); pe[256] = 1; await writeFile(f.exe, pe);
  assert.equal((await inspectFingerprintRuntime(f.root, f.options)).errorCode, 'BROWSER_FINGERPRINT_BINARY_CHANGED');
  const files = await fingerprintInventory(f.root);
  await writeFile(path.join(f.root, FINGERPRINT_RECEIPT), JSON.stringify({ ...f.receipt, files }));
  assert.equal((await inspectFingerprintRuntime(f.root, f.options)).errorCode, 'BROWSER_FINGERPRINT_INVENTORY_INVALID');
  await writeFile(path.join(f.root, FINGERPRINT_RECEIPT), JSON.stringify({ ...f.receipt, engineVersion: '999' }));
  assert.equal((await inspectFingerprintRuntime(f.root, f.options)).errorCode, 'BROWSER_FINGERPRINT_INVENTORY_INVALID');
});

test('a corrected component requires both its source-pinned inventory and revision receipt', async t => {
  const f = await fixture(t), release = { ...f.release, revision: 'canvas-win-x64-150-r1' };
  const options = { ...f.options, release };
  assert.equal((await inspectFingerprintRuntime(f.root, options)).errorCode, 'BROWSER_FINGERPRINT_INVENTORY_INVALID');
  await writeFile(path.join(f.root, FINGERPRINT_RECEIPT), JSON.stringify({ ...f.receipt, componentRevision: release.revision }));
  assert.equal((await requireFingerprintRuntime(f.root, options)).state, 'ready');
  await writeFile(path.join(f.root, 'chrome.dll'), 'unchanged receipt cannot authorize a different DLL');
  await assert.rejects(requireFingerprintRuntime(f.root, options), { code: 'BROWSER_FINGERPRINT_FILES_CHANGED' });
  const files = await fingerprintInventory(f.root);
  await writeFile(path.join(f.root, FINGERPRINT_RECEIPT), JSON.stringify({ ...f.receipt, files, componentRevision: release.revision }));
  assert.equal((await inspectFingerprintRuntime(f.root, options)).errorCode, 'BROWSER_FINGERPRINT_INVENTORY_INVALID');
});

test('unsupported platforms, missing components, invalid PE and extra DLLs fail closed', async t => {
  const f = await fixture(t);
  assert.equal((await inspectFingerprintRuntime(f.root, { ...f.options, platform: 'darwin' })).state, 'unsupported');
  assert.equal((await inspectFingerprintRuntime(path.join(f.root, 'missing'), f.options)).state, 'missing');
  await writeFile(path.join(f.root, 'unexpected.dll'), 'injected');
  assert.equal((await inspectFingerprintRuntime(f.root, { ...f.options, full: true })).errorCode, 'BROWSER_FINGERPRINT_FILES_CHANGED');
  const pe = await readFile(f.exe); pe.writeUInt16LE(0x14c, 132); await writeFile(f.exe, pe);
  await assert.rejects(validateFingerprintPe(f.exe), { code: 'BROWSER_FINGERPRINT_ARCH_INVALID' });
});

test('source-built production pin rejects test-only candidate receipts without weakening full inventory checks', async t => {
  const f = await fixture(t), options = { ...f.options, release: { ...f.release, sourceBuilt: true } };
  await writeFile(path.join(f.root, FINGERPRINT_RECEIPT), JSON.stringify({ ...f.receipt, testOnly: true }));
  await assert.rejects(requireFingerprintRuntime(f.root, options), { code: 'BROWSER_FINGERPRINT_INVENTORY_INVALID' });
  await writeFile(path.join(f.root, FINGERPRINT_RECEIPT), JSON.stringify(f.receipt));
  assert.equal((await requireFingerprintRuntime(f.root, options)).state, 'ready');
  await writeFile(path.join(f.root, 'unexpected.dll'), 'injected');
  await assert.rejects(requireFingerprintRuntime(f.root, options), { code: 'BROWSER_FINGERPRINT_FILES_CHANGED' });
});

test('linked engine roots and inventory links are rejected without reading external files', async t => {
  const f = await fixture(t);
  const link = path.join(path.dirname(f.root), path.basename(f.root) + '-link');
  await symlink(f.root, link, process.platform === 'win32' ? 'junction' : 'dir');
  t.after(() => rm(link, { force: true }));
  assert.equal((await inspectFingerprintRuntime(link, f.options)).errorCode, 'BROWSER_FINGERPRINT_PATH_UNSAFE');
  await symlink(f.root, path.join(f.root, 'loop'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(fingerprintInventory(f.root), { code: 'BROWSER_FINGERPRINT_PATH_UNSAFE' });
});
