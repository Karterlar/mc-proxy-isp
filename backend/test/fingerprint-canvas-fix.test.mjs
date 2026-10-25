import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, open, readFile, readdir, realpath, writeFile, rm, symlink, link } from 'node:fs/promises';
import { FINGERPRINT_CANVAS_FIX as fix, correctFingerprintCanvasWindow, applyFingerprintCanvasFix } from '../src/fingerprint-canvas-fix.mjs';

const invalid = { code: 'BROWSER_FINGERPRINT_CANVAS_FIX_INVALID' };
async function fixture(t) {
  const cache = path.resolve('.cache'); await mkdir(cache, { recursive: true });
  const root = await mkdtemp(path.join(await realpath(cache), 'mc-canvas-fix-test-'));
  const stage = await mkdtemp(path.join(root, '.fingerprint-stage-'));
  const engine = path.join(stage, 'engine'); await mkdir(engine);
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, stage, engine, file: path.join(engine, 'chrome.dll') };
}

test('Canvas correction pins the exact release and changes only its three instruction bytes', () => {
  assert.equal(fix.bytes, 315028992); assert.equal(fix.offset, 0xc392046);
  assert.equal(fix.originalSha256, '6464a50a8f8eae824f85733b52bc42912405390ac7dcb2a7fda7228ea51cbbac');
  assert.equal(fix.fixedSha256, '2a2ca874e7944c9496888b07d56c8dd1ed76bf0a2b87c005874fe0a2729bbeed');
  assert.ok(Object.isFrozen(fix));
  const original = Buffer.from(fix.originalWindow, 'hex'), saved = Buffer.from(original);
  const fixed = correctFingerprintCanvasWindow(original);
  assert.deepEqual(original, saved, 'the pure operation never mutates its caller');
  assert.equal(fixed.subarray(fix.contextBytes, fix.contextBytes + 3).toString('hex'), '4989d0');
  assert.deepEqual(fixed.subarray(0, fix.contextBytes), original.subarray(0, fix.contextBytes));
  assert.deepEqual(fixed.subarray(fix.contextBytes + 3), original.subarray(fix.contextBytes + 3));
  assert.deepEqual(correctFingerprintCanvasWindow(fixed), fixed, 'exact corrected context is idempotent');
});

test('changed context, partial instructions and caller-selected patch parameters cannot authorize bytes', () => {
  const original = Buffer.from(fix.originalWindow, 'hex');
  for (let index = 0; index < original.length; index++) {
    const changed = Buffer.from(original); changed[index] ^= 0xff;
    assert.throws(() => correctFingerprintCanvasWindow(changed), invalid);
  }
  for (const value of [null, new Uint8Array(original), original.subarray(1), Buffer.concat([original, Buffer.alloc(1)])]) assert.throws(() => correctFingerprintCanvasWindow(value), invalid);
  const partial = Buffer.from(original); partial[fix.contextBytes + 1] = 0x89;
  assert.throws(() => correctFingerprintCanvasWindow(partial), invalid);
});

test('existing installed directories are outside the installer correction boundary', async t => {
  const f = await fixture(t), installed = path.join(f.root, 'fingerprint-browser'); await mkdir(installed);
  await writeFile(path.join(installed, 'chrome.dll'), 'keep installed component');
  await assert.rejects(applyFingerprintCanvasFix(installed), invalid);
  assert.equal(await readFile(path.join(installed, 'chrome.dll'), 'utf8'), 'keep installed component');
  for (const directory of [f.stage, '.', '', null, '\\\\server\\share\\engine', f.engine + ':alternate']) await assert.rejects(applyFingerprintCanvasFix(directory), invalid);
});

test('wrong size or preimage is rejected without changing files or accepting injected hashes', async t => {
  const f = await fixture(t); await writeFile(f.file, Buffer.from(fix.originalWindow, 'hex'));
  await writeFile(path.join(f.engine, 'chrome.exe'), 'unrelated file');
  const before = await readFile(f.file);
  await assert.rejects(applyFingerprintCanvasFix(f.engine, { originalSha256: 'anything', bytes: before.length, offset: 32 }), invalid);
  assert.deepEqual(await readFile(f.file), before);
  assert.equal(await readFile(path.join(f.engine, 'chrome.exe'), 'utf8'), 'unrelated file');
  assert.deepEqual((await readdir(f.engine)).sort(), ['chrome.dll', 'chrome.exe']);
});

test('the matching instruction window cannot substitute for the complete pinned DLL digest', async t => {
  const f = await fixture(t), handle = await open(f.file, 'wx');
  try { await handle.truncate(fix.bytes); await handle.write(Buffer.from(fix.originalWindow, 'hex'), 0, fix.originalWindow.length / 2, fix.offset - fix.contextBytes); }
  finally { await handle.close(); }
  await assert.rejects(applyFingerprintCanvasFix(f.engine, { originalSha256: 'caller cannot replace the pin' }), invalid);
  const actual = await open(f.file, 'r'), window = Buffer.alloc(fix.originalWindow.length / 2);
  try { assert.equal((await actual.stat()).size, fix.bytes); await actual.read(window, 0, window.length, fix.offset - fix.contextBytes); }
  finally { await actual.close(); }
  assert.equal(window.toString('hex'), fix.originalWindow);
  assert.deepEqual(await readdir(f.engine), ['chrome.dll']);
});

test('cancellation does not inspect, create or modify staging contents', async t => {
  const f = await fixture(t); await writeFile(f.file, 'unchanged');
  const controller = new AbortController(); controller.abort();
  await assert.rejects(applyFingerprintCanvasFix(f.engine, { signal: controller.signal }), { code: 'BROWSER_FINGERPRINT_INSTALL_CANCELLED' });
  assert.equal(await readFile(f.file, 'utf8'), 'unchanged'); assert.deepEqual(await readdir(f.engine), ['chrome.dll']);
});

test('directory links, file links and hard-linked DLLs cannot enter the correction path', async t => {
  const f = await fixture(t), other = path.join(f.root, 'other'); await mkdir(other);
  await writeFile(path.join(other, 'chrome.dll'), 'external bytes');
  const linkedEngine = path.join(f.stage, 'linked');
  await symlink(other, linkedEngine, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(applyFingerprintCanvasFix(linkedEngine), invalid);
  await symlink(other, path.join(f.engine, 'chrome.dll'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(applyFingerprintCanvasFix(f.engine), invalid);
  await rm(f.file, { force: true }); await link(path.join(other, 'chrome.dll'), f.file);
  await assert.rejects(applyFingerprintCanvasFix(f.engine), invalid);
  assert.equal(await readFile(path.join(other, 'chrome.dll'), 'utf8'), 'external bytes');
});
