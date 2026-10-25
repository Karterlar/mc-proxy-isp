import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { readCandidateRuntime } from './candidate-runtime.mjs';
import { FINGERPRINT_RECEIPT, fingerprintFileHash, fingerprintInventory, fingerprintInventoryHash }
  from '../../../backend/src/fingerprint-browser-runtime.mjs';

const here = fileURLToPath(new URL('./', import.meta.url));
const fixedRoot = path.resolve(here, '../../../.cache/native-engine-build');
const manifestFile = path.join(here, 'source-manifest.json');
const save = (file, value) => writeFile(file, JSON.stringify(value, null, 2));
const required = ['chrome_elf.dll', 'chrome_100_percent.pak', 'chrome_200_percent.pak',
  'icudtl.dat', 'resources.pak', 'v8_context_snapshot.bin', '150.0.7871.186.manifest'];

// These are deliberately tiny parser fixtures, never Chromium build evidence.
// No test claims a completed native build or calls the browser launcher.
async function fixture(t) {
  await mkdir(fixedRoot, { recursive: true });
  const root = await mkdtemp(path.join(fixedRoot, 'candidate-proof-test-'));
  t.after(async () => {
    assert.equal(path.dirname(root), fixedRoot);
    await rm(root, { recursive: true, force: true });
  });
  const output = path.join(root, 'src/out/MCProxy'), runtime = path.join(root, 'candidate-runtime');
  await mkdir(output, { recursive: true });
  const manifest = JSON.parse(await readFile(manifestFile, 'utf8'));
  const manifestHash = await fingerprintFileHash(manifestFile);
  const pe = Buffer.alloc(512); pe.write('MZ'); pe.writeUInt32LE(128, 0x3c);
  pe.write('PE\0\0', 128); pe.writeUInt16LE(0x8664, 132); pe.writeUInt16LE(0x20b, 152);
  await writeFile(path.join(output, 'chrome.exe'), pe);
  pe[256] = 1; await writeFile(path.join(output, 'chrome.dll'), pe);
  const sourceFile = path.join(root, '.mc-native-source.json'), proofFile = path.join(root, '.mc-native-build.json');
  const source = { schemaVersion: 1, sourceReady: true, headChromium: manifest.chromium.revision,
    sourceManifestSha256: manifestHash, patchesVerified: manifest.patches,
    preparedFiles: [{ path: 'fixture.cc', sha256: 'a'.repeat(64) }] };
  await save(sourceFile, source);
  const proof = { schemaVersion: 1, built: true, activated: false, packaged: false, buildRoot: root,
    output, sourceManifestSha256: manifestHash, preparedSourceReceiptSha256: await fingerprintFileHash(sourceFile),
    files: await Promise.all(['chrome.exe', 'chrome.dll'].map(async name => ({ path: name,
      sha256: await fingerprintFileHash(path.join(output, name)) }))) };
  const markerFile = path.join(output, '.mc-native-output.json');
  const marker = { schemaVersion: 1, buildRoot: root, sourceManifestSha256: manifestHash };
  await save(proofFile, proof); await save(markerFile, marker);
  async function outputResources() {
    await mkdir(path.join(output, 'locales'), { recursive: true });
    for (const name of required) await writeFile(path.join(output, name), 'synthetic resource: ' + name);
    await writeFile(path.join(output, 'locales/en-US.pak'), 'synthetic locale');
  }
  async function existingRuntime() {
    await mkdir(path.join(runtime, 'locales'), { recursive: true });
    for (const name of ['chrome.exe', 'chrome.dll']) await copyFile(path.join(output, name), path.join(runtime, name));
    for (const name of required) await writeFile(path.join(runtime, name), 'synthetic resource: ' + name);
    await writeFile(path.join(runtime, 'locales/en-US.pak'), 'synthetic locale');
    const files = await fingerprintInventory(runtime), proofHash = await fingerprintFileHash(proofFile);
    const release = { version: manifest.chromium.version, architecture: 'x64', platform: 'win32', executable: 'chrome.exe',
      revision: `source-win-x64-150-${manifestHash.slice(0, 12)}-${proofHash.slice(0, 12)}`,
      archiveSha256: manifest.chromium.archive.sha256, executableSha256: proof.files[0].sha256,
      inventorySha256: fingerprintInventoryHash(files) };
    await save(path.join(runtime, FINGERPRINT_RECEIPT), { version: 1, engineVersion: release.version,
      architecture: 'x64', componentRevision: release.revision, archiveSha256: release.archiveSha256, files });
    const recordFile = path.join(root, '.mc-native-candidate.json');
    const record = { schemaVersion: 1, testOnly: true, activated: false, packaged: false, runtime, release,
      sourceManifestSha256: manifestHash, buildReceiptSha256: proofHash,
      preparedSourceReceiptSha256: proof.preparedSourceReceiptSha256 };
    await save(recordFile, record);
    return { recordFile, record, files };
  }
  return { root, output, runtime, sourceFile, source, proofFile, proof, markerFile, marker, outputResources, existingRuntime };
}

test('candidate paths cannot select project, production runtime or directories outside the fixed build cache', async () => {
  for (const root of [path.resolve(here, '../../..'), path.resolve(here, '../../../backend/runtime'),
    path.resolve(fixedRoot, '..'), 'relative-path']) {
    await assert.rejects(readCandidateRuntime(root, { platform: 'win32' }), { code: 'CANDIDATE_PATH_UNSAFE' });
  }
});

test('missing successful-build proof refuses preparation and creates no candidate', async t => {
  const f = await fixture(t); await rm(f.proofFile);
  await assert.rejects(readCandidateRuntime(f.root, { prepare: true, platform: 'win32' }), { code: 'ENOENT' });
  await assert.rejects(readFile(path.join(f.runtime, FINGERPRINT_RECEIPT)), { code: 'ENOENT' });
});

test('claimed build success must have exact flags, source manifest and two distinct executable hashes', async t => {
  const f = await fixture(t);
  for (const changed of [{ built: false }, { built: 'true' }, { activated: true }, { packaged: true },
    { sourceManifestSha256: 'b'.repeat(64) }, { files: [f.proof.files[0], f.proof.files[0]] }]) {
    await save(f.proofFile, { ...f.proof, ...changed });
    await assert.rejects(readCandidateRuntime(f.root, { platform: 'win32' }), { code: 'CANDIDATE_BUILD_PROOF_INVALID' });
  }
});

test('changing prepared-source receipt bytes invalidates the recorded build proof', async t => {
  const f = await fixture(t); await save(f.sourceFile, { ...f.source, changedAfterBuild: true });
  await assert.rejects(readCandidateRuntime(f.root, { platform: 'win32' }), { code: 'CANDIDATE_BUILD_PROOF_INVALID' });
});

test('source receipt cannot replace fixed Chromium revision or reviewed custom patch set', async t => {
  const f = await fixture(t);
  for (const changed of [{ headChromium: 'c'.repeat(40) }, { sourceReady: false }, { patchesVerified: [] }]) {
    await save(f.sourceFile, { ...f.source, ...changed });
    await save(f.proofFile, { ...f.proof, preparedSourceReceiptSha256: await fingerprintFileHash(f.sourceFile) });
    await assert.rejects(readCandidateRuntime(f.root, { platform: 'win32' }), { code: 'CANDIDATE_SOURCE_PROOF_INVALID' });
  }
});

test('output must remain inside its owned build root with matching output marker', async t => {
  const f = await fixture(t); await save(f.proofFile, { ...f.proof, output: fixedRoot });
  await assert.rejects(readCandidateRuntime(f.root, { platform: 'win32' }), { code: 'CANDIDATE_BUILD_PROOF_INVALID' });
  await save(f.proofFile, f.proof); await save(f.markerFile, { ...f.marker, buildRoot: fixedRoot });
  await assert.rejects(readCandidateRuntime(f.root, { platform: 'win32' }), { code: 'CANDIDATE_OUTPUT_PROOF_INVALID' });
});

test('compiled executable and DLL hashes are checked before any candidate collection', async t => {
  const f = await fixture(t); await writeFile(path.join(f.output, 'chrome.dll'), 'changed binary');
  await assert.rejects(readCandidateRuntime(f.root, { prepare: true, platform: 'win32' }), { code: 'CANDIDATE_BUILD_BINARY_CHANGED' });
  await assert.rejects(readFile(path.join(f.runtime, FINGERPRINT_RECEIPT)), { code: 'ENOENT' });
});

test('a matching hash does not make a non-x64 executable a valid compiled browser', async t => {
  const f = await fixture(t), file = path.join(f.output, 'chrome.exe');
  const pe = await readFile(file); pe.writeUInt16LE(0x14c, 132); await writeFile(file, pe);
  f.proof.files[0].sha256 = await fingerprintFileHash(file); await save(f.proofFile, f.proof);
  await assert.rejects(readCandidateRuntime(f.root, { prepare: true, platform: 'win32' }), { code: 'BROWSER_FINGERPRINT_ARCH_INVALID' });
});

test('default mode is read-only and tiny PE parser fixtures do not count as a complete native build', async t => {
  const f = await fixture(t), before = await readFile(f.proofFile);
  await assert.rejects(readCandidateRuntime(f.root, { platform: 'win32' }), { code: 'ENOENT' });
  assert.deepEqual(await readFile(f.proofFile), before);
  await assert.rejects(readCandidateRuntime(f.root, { prepare: true, platform: 'win32' }), { code: 'ENOENT' });
  await assert.rejects(readFile(path.join(f.runtime, FINGERPRINT_RECEIPT)), { code: 'ENOENT' });
});

test('candidate collection copies only the explicit public ICD JSON and version manifest with integrity checks', async t => {
  const f = await fixture(t); await f.outputResources();
  const publicNames = ['vk_swiftshader_icd.json', '150.0.7871.186.manifest'];
  await writeFile(path.join(f.output, 'vk_swiftshader.dll'), 'synthetic SwiftShader');
  await writeFile(path.join(f.output, publicNames[0]), '{"ICD":{"library_path":".\\\\vk_swiftshader.dll"}}');
  for (const name of ['private-config.json', 'other-version.manifest']) await writeFile(path.join(f.output, name), 'not public');
  const candidate = await readCandidateRuntime(f.root, { prepare: true, platform: 'win32' });
  assert.equal(candidate.state.state, 'ready');
  const receipt = JSON.parse(await readFile(path.join(f.runtime, FINGERPRINT_RECEIPT), 'utf8'));
  for (const name of publicNames) {
    const original = await readFile(path.join(f.output, name)), target = path.join(f.runtime, name);
    assert.deepEqual(await readFile(target), original);
    assert.equal(receipt.files.find(file => file.path === name)?.sha256, await fingerprintFileHash(target));
    await writeFile(target, 'changed public resource');
    await assert.rejects(readCandidateRuntime(f.runtime, { platform: 'win32' }), { code: 'CANDIDATE_INVENTORY_CHANGED' });
    await writeFile(target, original);
  }
  for (const name of ['private-config.json', 'other-version.manifest']) await assert.rejects(readFile(path.join(f.runtime, name)), { code: 'ENOENT' });
  assert.equal((await readCandidateRuntime(f.runtime, { platform: 'win32' })).state.state, 'ready');
});

test('candidate collection refuses a missing required Windows version assembly manifest', async t => {
  const f = await fixture(t); await f.outputResources();
  await rm(path.join(f.output, '150.0.7871.186.manifest'));
  await assert.rejects(readCandidateRuntime(f.root, { prepare: true, platform: 'win32' }), { code: 'CANDIDATE_RUNTIME_RESOURCES_MISSING' });
  await assert.rejects(readFile(path.join(f.runtime, FINGERPRINT_RECEIPT)), { code: 'ENOENT' });
});

test('existing candidate resource tampering or injected DLL is rejected by complete inventory', async t => {
  const f = await fixture(t); await f.existingRuntime();
  await writeFile(path.join(f.runtime, 'resources.pak'), 'changed resource');
  await assert.rejects(readCandidateRuntime(f.runtime, { platform: 'win32' }), { code: 'CANDIDATE_INVENTORY_CHANGED' });
  await writeFile(path.join(f.runtime, 'injected.dll'), 'injected');
  await assert.rejects(readCandidateRuntime(f.root, { platform: 'win32' }), { code: 'CANDIDATE_INVENTORY_CHANGED' });
});

test('rewritten local inventory cannot authorize a DLL different from successful-build proof', async t => {
  const f = await fixture(t), runtime = await f.existingRuntime();
  await writeFile(path.join(f.runtime, 'chrome.dll'), 'rewritten DLL');
  runtime.record.release.inventorySha256 = fingerprintInventoryHash(await fingerprintInventory(f.runtime));
  await save(runtime.recordFile, runtime.record);
  await assert.rejects(readCandidateRuntime(f.root, { platform: 'win32' }), { code: 'CANDIDATE_INVENTORY_CHANGED' });
});

test('existing candidate is never overwritten and linked build roots are refused', async t => {
  const f = await fixture(t); await mkdir(f.runtime);
  await assert.rejects(readCandidateRuntime(f.root, { prepare: true, platform: 'win32' }), { code: 'CANDIDATE_ALREADY_EXISTS' });
  const link = path.join(f.root, 'linked-build');
  await symlink(f.root, link, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(readCandidateRuntime(link, { platform: 'win32' }), { code: 'CANDIDATE_PATH_UNSAFE' });
  await rm(link, { force: true });
});
