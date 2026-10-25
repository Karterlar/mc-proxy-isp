// Test-only bridge from a completed local build to the existing native fixtures.
// This module never updates production component pins or launches a browser.
import path from 'node:path';
import { constants } from 'node:fs';
import { copyFile, lstat, mkdir, readFile, readdir, realpath, rename, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { FINGERPRINT_RECEIPT, fingerprintFileHash, fingerprintInventory,
  fingerprintInventoryHash, inspectFingerprintRuntime, validateFingerprintPe }
  from '../../../backend/src/fingerprint-browser-runtime.mjs';

const here = fileURLToPath(new URL('./', import.meta.url));
const project = path.resolve(here, '../../..');
const fixedBuildRoot = path.join(project, '.cache/native-engine-build');
const buildReceiptName = '.mc-native-build.json';
const candidateRecordName = '.mc-native-candidate.json';
const runtimeName = 'candidate-runtime';
const sha256 = /^[a-f0-9]{64}$/;
const version = '150.0.7871.186';
const chromium = '0fcdce5f4fdec8d442d7df760cb541f1ca6e446d';
const runtimeExecutables = new Set(['chrome.exe', 'chrome_proxy.exe', 'chrome_pwa_launcher.exe',
  'chrome_crashpad_handler.exe', 'crashpad_handler.exe', 'notification_helper.exe',
  'elevation_service.exe', 'elevated_tracing_service.exe']);
const requiredResources = ['chrome.exe', 'chrome.dll', 'chrome_elf.dll', 'chrome_100_percent.pak',
  'chrome_200_percent.pak', 'icudtl.dat', 'resources.pak', 'v8_context_snapshot.bin', 'locales/en-US.pak',
  `${version}.manifest`];
const failure = code => Object.assign(new Error(code), { code });
const normalized = value => path.resolve(value).replace(/[\\/]+$/, '').toLowerCase();
const samePath = (left, right) => typeof left === 'string' && typeof right === 'string'
  && normalized(left) === normalized(right);
function within(root, target, allowRoot = false) {
  const relative = path.relative(root, target);
  return (allowRoot || !!relative) && !relative.startsWith('..' + path.sep)
    && relative !== '..' && !path.isAbsolute(relative);
}
async function ordinary(file, directory = false) {
  const absolute = path.resolve(file); let cursor = path.parse(absolute).root;
  for (const segment of absolute.slice(cursor.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    const info = await lstat(cursor);
    if (info.isSymbolicLink() || !samePath(await realpath(cursor), cursor)) throw failure('CANDIDATE_PATH_UNSAFE');
  }
  const info = await lstat(absolute);
  if (directory ? !info.isDirectory() : !info.isFile()) throw failure('CANDIDATE_PATH_UNSAFE');
  return info;
}
async function readJson(file) {
  if ((await ordinary(file)).size > 16 * 1024 * 1024) throw failure('CANDIDATE_RECEIPT_INVALID');
  try { return JSON.parse(await readFile(file, 'utf8')); }
  catch { throw failure('CANDIDATE_RECEIPT_INVALID'); }
}
async function reviewedManifest() {
  const runner = path.join(here, 'build-windows.ps1'), manifestFile = path.join(here, 'source-manifest.json');
  await ordinary(runner);
  const pin = (await readFile(runner, 'utf8')).match(/\$ExpectedManifestSha256\s*=\s*'([a-f0-9]{64})'/)?.[1];
  const manifest = await readJson(manifestFile), hash = await fingerprintFileHash(manifestFile);
  if (!pin || hash !== pin || manifest.schemaVersion !== 1 || manifest.chromium?.version !== version
    || manifest.chromium.revision !== chromium || manifest.build?.ready !== true
    || manifest.build.target !== 'chrome' || !sha256.test(manifest.chromium.archive?.sha256 || '')
    || !Array.isArray(manifest.patches) || !manifest.patches.length) throw failure('CANDIDATE_MANIFEST_CHANGED');
  const seen = new Set();
  for (const patch of manifest.patches) {
    if (!/^[A-Za-z0-9_./-]+\.patch$/.test(patch.path) || patch.path.split('/').includes('..')
      || seen.has(patch.path) || !sha256.test(patch.sha256)) throw failure('CANDIDATE_MANIFEST_CHANGED');
    seen.add(patch.path);
    const file = path.resolve(here, patch.path);
    if (!within(here, file)) throw failure('CANDIDATE_MANIFEST_CHANGED');
    await ordinary(file);
    if (await fingerprintFileHash(file) !== patch.sha256) throw failure('CANDIDATE_MANIFEST_CHANGED');
  }
  return { manifest, hash };
}
function patchSet(files) {
  return Array.isArray(files) ? files.map(file => `${file.path}:${file.sha256}`).sort().join('\n') : '';
}
async function buildProof(buildRoot, reviewed) {
  const sourceFile = path.join(buildRoot, '.mc-native-source.json');
  const proofFile = path.join(buildRoot, buildReceiptName);
  const source = await readJson(sourceFile), proof = await readJson(proofFile);
  const sourceHash = await fingerprintFileHash(sourceFile), proofHash = await fingerprintFileHash(proofFile);
  if (source.schemaVersion !== 1 || source.sourceReady !== true || source.headChromium !== chromium
    || source.sourceManifestSha256 !== reviewed.hash || !Array.isArray(source.preparedFiles) || !source.preparedFiles.length
    || patchSet(source.patchesVerified) !== patchSet(reviewed.manifest.patches)) throw failure('CANDIDATE_SOURCE_PROOF_INVALID');
  if (proof.schemaVersion !== 1 || proof.built !== true || proof.activated !== false || proof.packaged !== false
    || !samePath(proof.buildRoot, buildRoot) || proof.sourceManifestSha256 !== reviewed.hash
    || proof.preparedSourceReceiptSha256 !== sourceHash || !path.isAbsolute(proof.output || '')
    || !within(buildRoot, path.resolve(proof.output)) || path.basename(proof.output) === runtimeName
    || !Array.isArray(proof.files) || proof.files.length !== 2) throw failure('CANDIDATE_BUILD_PROOF_INVALID');
  const files = new Map();
  for (const file of proof.files) {
    if (!['chrome.exe', 'chrome.dll'].includes(file.path) || files.has(file.path) || !sha256.test(file.sha256)) {
      throw failure('CANDIDATE_BUILD_PROOF_INVALID');
    }
    files.set(file.path, file.sha256);
  }
  const output = path.resolve(proof.output);
  await ordinary(path.join(buildRoot, 'src'), true);
  await ordinary(output, true);
  const marker = await readJson(path.join(output, '.mc-native-output.json'));
  if (marker.schemaVersion !== 1 || !samePath(marker.buildRoot, buildRoot)
    || marker.sourceManifestSha256 !== reviewed.hash) throw failure('CANDIDATE_OUTPUT_PROOF_INVALID');
  for (const [name, hash] of files) {
    const file = path.join(output, name);
    await ordinary(file);
    if (await fingerprintFileHash(file) !== hash) throw failure('CANDIDATE_BUILD_BINARY_CHANGED');
    await validateFingerprintPe(file);
  }
  return { output, files, proofHash, sourceHash };
}
function publicResource(name) {
  if (/installer|chromedriver|(?:^|[_-])(?:test|tests|unittest|unittests|browsertests|perftests)(?:[_-]|\.|$)/i.test(name)) return false;
  if (name === 'vk_swiftshader_icd.json' || name === `${version}.manifest`) return true;
  const extension = path.extname(name).toLowerCase();
  return extension === '.exe' ? runtimeExecutables.has(name.toLowerCase())
    : ['.dll', '.pak', '.dat', '.bin'].includes(extension);
}
async function resources(output) {
  const names = [];
  for (const item of await readdir(output, { withFileTypes: true })) {
    if (publicResource(item.name)) {
      await ordinary(path.join(output, item.name));
      names.push(item.name);
    }
  }
  const locales = path.join(output, 'locales');
  await ordinary(locales, true);
  for (const item of await readdir(locales, { withFileTypes: true })) {
    if (/^[A-Za-z0-9_-]+\.pak$/.test(item.name)) {
      await ordinary(path.join(locales, item.name));
      names.push('locales/' + item.name);
    }
  }
  if (requiredResources.some(name => !names.includes(name))) throw failure('CANDIDATE_RUNTIME_RESOURCES_MISSING');
  return names.sort();
}
async function inspectCandidate(buildRoot, reviewed, proof, platform) {
  const record = await readJson(path.join(buildRoot, candidateRecordName));
  const runtime = path.join(buildRoot, runtimeName), release = record.release;
  if (record.schemaVersion !== 1 || record.testOnly !== true || record.activated !== false || record.packaged !== false
    || record.sourceManifestSha256 !== reviewed.hash || record.buildReceiptSha256 !== proof.proofHash
    || record.preparedSourceReceiptSha256 !== proof.sourceHash || !samePath(record.runtime, runtime)
    || release?.version !== version || release.architecture !== 'x64' || release.platform !== 'win32'
    || release.executable !== 'chrome.exe' || release.executableSha256 !== proof.files.get('chrome.exe')
    || release.archiveSha256 !== reviewed.manifest.chromium.archive.sha256
    || release.revision !== `source-win-x64-150-${reviewed.hash.slice(0, 12)}-${proof.proofHash.slice(0, 12)}`
    || !sha256.test(release.inventorySha256 || '')) throw failure('CANDIDATE_RECORD_INVALID');
  const actualFiles = await fingerprintInventory(runtime);
  if (fingerprintInventoryHash(actualFiles) !== release.inventorySha256
    || actualFiles.find(file => file.path === 'chrome.dll')?.sha256 !== proof.files.get('chrome.dll')
    || actualFiles.some(file => file.path.includes('/') ? !/^locales\/[A-Za-z0-9_-]+\.pak$/.test(file.path)
      : !publicResource(file.path)) || requiredResources.some(name => !actualFiles.some(file => file.path === name))) {
    throw failure('CANDIDATE_INVENTORY_CHANGED');
  }
  const state = await inspectFingerprintRuntime(runtime, { full: true, platform, release });
  if (state.state !== 'ready') throw failure(state.errorCode);
  return { root: runtime, release, state, testOnly: true, activated: false, packaged: false,
    buildRoot, sourceManifestSha256: reviewed.hash, buildReceiptSha256: proof.proofHash };
}

export async function readCandidateRuntime(root = fixedBuildRoot, { prepare = false, platform = process.platform } = {}) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || /^[\\/]{2}/.test(root) || /[\x00-\x1f\x7f]/.test(root)) {
    throw failure('CANDIDATE_PATH_UNSAFE');
  }
  // Native fixtures can pass either the build root or its returned component directory.
  const buildRoot = path.basename(root) === runtimeName ? path.dirname(root) : path.resolve(root);
  if (!within(fixedBuildRoot, buildRoot, true)) throw failure('CANDIDATE_PATH_UNSAFE');
  await ordinary(buildRoot, true);
  const reviewed = await reviewedManifest(), proof = await buildProof(buildRoot, reviewed);
  const runtime = path.join(buildRoot, runtimeName);
  if (prepare) {
    try { await lstat(runtime); throw failure('CANDIDATE_ALREADY_EXISTS'); }
    catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
    try { await lstat(path.join(buildRoot, candidateRecordName)); throw failure('CANDIDATE_ALREADY_EXISTS'); }
    catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
    const selected = await resources(proof.output), stage = path.join(buildRoot, '.candidate-runtime-stage-' + randomUUID());
    await mkdir(stage);
    await mkdir(path.join(stage, 'locales'));
    const sourceFiles = [];
    for (const name of selected) {
      const source = path.join(proof.output, name), target = path.join(stage, name);
      await ordinary(source);
      const hash = await fingerprintFileHash(source);
      await copyFile(source, target, constants.COPYFILE_EXCL);
      if (await fingerprintFileHash(target) !== hash || await fingerprintFileHash(source) !== hash) {
        throw failure('CANDIDATE_COPY_CHANGED');
      }
      sourceFiles.push({ name, hash });
    }
    const files = await fingerprintInventory(stage);
    const current = await buildProof(buildRoot, reviewed);
    if (current.proofHash !== proof.proofHash || current.sourceHash !== proof.sourceHash
      || (await reviewedManifest()).hash !== reviewed.hash
      || JSON.stringify(await resources(proof.output)) !== JSON.stringify(selected)) throw failure('CANDIDATE_BUILD_CHANGED');
    for (const file of sourceFiles) {
      if (await fingerprintFileHash(path.join(proof.output, file.name)) !== file.hash) throw failure('CANDIDATE_BUILD_CHANGED');
    }
    const release = { version, architecture: 'x64', platform: 'win32', executable: 'chrome.exe',
      revision: `source-win-x64-150-${reviewed.hash.slice(0, 12)}-${proof.proofHash.slice(0, 12)}`,
      archiveSha256: reviewed.manifest.chromium.archive.sha256, executableSha256: proof.files.get('chrome.exe'),
      inventorySha256: fingerprintInventoryHash(files) };
    await writeFile(path.join(stage, FINGERPRINT_RECEIPT), JSON.stringify({ version: 1, engineVersion: version,
      architecture: 'x64', componentRevision: release.revision, archiveSha256: release.archiveSha256, files,
      testOnly: true, activated: false, packaged: false }, null, 2), { flag: 'wx' });
    const stageState = await inspectFingerprintRuntime(stage, { full: true, platform, release });
    if (stageState.state !== 'ready') throw failure(stageState.errorCode);
    await rename(stage, runtime);
    await writeFile(path.join(buildRoot, candidateRecordName), JSON.stringify({ schemaVersion: 1, testOnly: true,
      activated: false, packaged: false, createdAt: new Date().toISOString(), runtime, release,
      sourceManifestSha256: reviewed.hash, preparedSourceReceiptSha256: proof.sourceHash,
      buildReceiptSha256: proof.proofHash }, null, 2), { flag: 'wx' });
  }
  return inspectCandidate(buildRoot, reviewed, proof, platform);
}

if (process.argv[1] && samePath(process.argv[1], fileURLToPath(import.meta.url))) {
  let prepare = false, root = fixedBuildRoot;
  try {
    for (let index = 2; index < process.argv.length; index++) {
      const argument = process.argv[index];
      if (argument === '--prepare') prepare = true;
      else if (argument === '--build-root' && process.argv[index + 1]) root = path.resolve(process.argv[++index]);
      else throw failure('CANDIDATE_ARGUMENT_INVALID');
    }
    const result = await readCandidateRuntime(root, { prepare });
    console.log(JSON.stringify({ mode: prepare ? 'prepare-test-candidate' : 'read-only', ...result }, null, 2));
  } catch (cause) {
    console.error(JSON.stringify({ mode: prepare ? 'prepare-test-candidate' : 'read-only', prepared: false,
      activated: false, packaged: false, error: cause.code || cause.message }, null, 2));
    process.exitCode = 1;
  }
}
