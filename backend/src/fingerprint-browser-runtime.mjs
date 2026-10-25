import path from 'node:path';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { lstat, readFile, readdir, realpath } from 'node:fs/promises';

// Historical publisher pins remain available for explicit migration fixtures.
// Ordinary launches use only the independently built and accepted release below.
export const FINGERPRINT_BROWSER_UPSTREAM_RELEASE = Object.freeze({
  version: '150.0.7871.186', architecture: 'x64', platform: 'win32',
  archive: 'ungoogled-chromium_150.0.7871.186-1.1_windows_x64.zip',
  archiveBytes: 193743241,
  archiveSha256: '4d549c326e51ebbabf562fd365eb5380d9d4a81200da2c60f075c688d9a77e03',
  url: 'https://github.com/adryfish/fingerprint-chromium/releases/download/150.0.7871.186/ungoogled-chromium_150.0.7871.186-1.1_windows_x64.zip',
  executable: 'chrome.exe',
  executableSha256: '65d0807599b5430ffbd9dffb60cd020464815f10557352959e3aa4c125a5c439',
  inventorySha256: '561bf73a2065cd55b87cc8c6d79d06f9364c288f3c4873f37cb243ab334416ea',
});
// A reproducible local correction of the neighbour-row pointer in this exact
// upstream DLL, not a claim that the publisher has issued another release.
// Keep the upstream archive pin; preparation verifies it before applying the
// fixed instruction and then verifies this separate complete resource pin.
export const FINGERPRINT_BROWSER_LEGACY_RELEASE = Object.freeze({
  ...FINGERPRINT_BROWSER_UPSTREAM_RELEASE,
  revision: 'canvas-win-x64-150-r1',
  inventorySha256: 'de439c4e0a5816f6fbe99082a16832d9c73700ca4ce14666b69aedd6733ea851',
});
// Source/build/acceptance evidence: docs/components/fingerprint-browser-150.md.
// archiveSha256 identifies the Chromium source archive, not a downloadable binary.
// No writable receipt, candidate environment flag or remote URL chooses the pin.
export const FINGERPRINT_BROWSER_PREVIOUS_SOURCE_RELEASE = Object.freeze({
  version: '150.0.7871.186', architecture: 'x64', platform: 'win32', sourceBuilt: true,
  revision: 'source-win-x64-150-03f72bc4c004-cd01996c745d',
  archiveSha256: '4ff4b64971c8097631a4f17d2f7fb050e8ede62b1b3c0f1ef0a1fffcac11bbb7',
  executable: 'chrome.exe',
  executableSha256: 'f98ad8b78dc7d89d7dfa4d88e33cfe0595afd3b5222e6696f595a052a4815ec2',
  inventorySha256: '9db2740d1d16aa92d19a025553f989ab3bbf590f3796317260ffd2d0945ce67d',
  sourceManifestSha256: '03f72bc4c0044b62c97877db556b412698adf8a88aa1f6b07ef6149d4af28847',
  buildReceiptSha256: 'cd01996c745df88c45cf6200cd8fc7f2af0a99ba45cfb83baef69c3e02a98e0d',
});
export const FINGERPRINT_BROWSER_RELEASE = Object.freeze({
  version: '150.0.7871.186', architecture: 'x64', platform: 'win32', sourceBuilt: true,
  revision: 'source-win-x64-150-0bf63619ff8d-694812300bff',
  archiveSha256: '4ff4b64971c8097631a4f17d2f7fb050e8ede62b1b3c0f1ef0a1fffcac11bbb7',
  executable: 'chrome.exe',
  executableSha256: 'f98ad8b78dc7d89d7dfa4d88e33cfe0595afd3b5222e6696f595a052a4815ec2',
  inventorySha256: '9a7e3e2f7a2375c6a94e41451ceb7e17feebb33fda0135ad4f0ae5b28ac7dcdc',
  sourceManifestSha256: '0bf63619ff8d5bae8e3cd4fae65f7f0f0bb19543456a0c4dd331e7feb7880680',
  buildReceiptSha256: '694812300bff65b23089110fb29e215a94c6b06e7f21810569be1126d4e0cfc9',
});
export const FINGERPRINT_BROWSER_CACHE_DIRECTORY = 'fingerprint-browser-source-150-r2';
export const FINGERPRINT_BROWSER_INSTALL_DIRECTORY = 'fingerprint-engine-source-150-r2';
export const FINGERPRINT_RECEIPT = '.mc-fingerprint-runtime.json';
const fail = code => Object.assign(new Error('指纹浏览器组件未通过完整性检查，请使用受支持的准备工具安装。'), { code, status: 409 });
const normalized = value => path.resolve(value).replace(/[\\/]+$/, '').toLowerCase();

export async function fingerprintFileHash(file) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

export function fingerprintInventoryHash(files) {
  return createHash('sha256').update(JSON.stringify(files)).digest('hex');
}

async function ordinary(file, directory = false) {
  const absolute = path.resolve(file); let cursor = path.parse(absolute).root;
  for (const segment of absolute.slice(cursor.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    const stat = await lstat(cursor);
    if (stat.isSymbolicLink() || normalized(await realpath(cursor)) !== normalized(cursor)) throw fail('BROWSER_FINGERPRINT_PATH_UNSAFE');
  }
  const stat = await lstat(absolute);
  if (directory ? !stat.isDirectory() : !stat.isFile()) throw fail('BROWSER_FINGERPRINT_PATH_UNSAFE');
  return stat;
}

export async function fingerprintInventory(root) {
  await ordinary(root, true);
  const files = [];
  async function visit(directory) {
    for (const item of await readdir(directory, { withFileTypes: true })) {
      const file = path.join(directory, item.name);
      if (file === path.join(root, FINGERPRINT_RECEIPT)) continue;
      const stat = await ordinary(file, item.isDirectory());
      // Chromium may write this fixed diagnostic file before honoring its
      // profile log switch. It is never executable content; links, directories
      // and large replacements remain invalid, and extra DLL/EXE files fail.
      if (file === path.join(root, 'debug.log') && stat.isFile() && stat.size <= 4 * 1024 * 1024) continue;
      if (item.isDirectory()) await visit(file);
      else files.push({ path: path.relative(root, file).split(path.sep).join('/'), bytes: stat.size, sha256: await fingerprintFileHash(file) });
      if (files.length > 20000) throw fail('BROWSER_FINGERPRINT_INVENTORY_INVALID');
    }
  }
  await visit(root);
  return files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

export async function validateFingerprintPe(file) {
  await ordinary(file);
  const bytes = await readFile(file);
  if (bytes.length < 256 || bytes.toString('ascii', 0, 2) !== 'MZ') throw fail('BROWSER_FINGERPRINT_ARCH_INVALID');
  const offset = bytes.readUInt32LE(0x3c);
  if (offset < 0x40 || offset + 26 > bytes.length || bytes.toString('ascii', offset, offset + 4) !== 'PE\0\0'
    || bytes.readUInt16LE(offset + 4) !== 0x8664 || bytes.readUInt16LE(offset + 24) !== 0x20b) throw fail('BROWSER_FINGERPRINT_ARCH_INVALID');
}

export async function inspectFingerprintRuntime(root, { platform = process.platform, full = false, release = FINGERPRINT_BROWSER_RELEASE } = {}) {
  const base = { version: release.version, architecture: release.architecture, ...(release.revision ? { revision: release.revision } : {}), verified: false };
  if (platform !== 'win32') return { ...base, state: 'unsupported', errorCode: 'BROWSER_FINGERPRINT_PLATFORM_UNSUPPORTED' };
  if (!root) return { ...base, state: 'missing', errorCode: 'BROWSER_FINGERPRINT_NOT_INSTALLED' };
  try {
    if (!path.isAbsolute(root) || /^[\\/]{2}/.test(root) || /[\x00-\x1f\x7f]/.test(root)) throw fail('BROWSER_FINGERPRINT_PATH_UNSAFE');
    await ordinary(root, true);
    const receiptPath = path.join(root, FINGERPRINT_RECEIPT);
    const receiptStat = await ordinary(receiptPath);
    if (receiptStat.size > 8 * 1024 * 1024) throw fail('BROWSER_FINGERPRINT_INVENTORY_INVALID');
    const receipt = JSON.parse(await readFile(receiptPath, 'utf8'));
    if (receipt.version !== 1 || receipt.engineVersion !== release.version || receipt.architecture !== release.architecture
      || release.sourceBuilt === true && receipt.testOnly === true
      || release.revision && receipt.componentRevision !== release.revision
      || receipt.archiveSha256 !== release.archiveSha256 || !Array.isArray(receipt.files) || !receipt.files.length || receipt.files.length > 20000
      || !/^[a-f0-9]{64}$/.test(release.inventorySha256) || fingerprintInventoryHash(receipt.files) !== release.inventorySha256) throw fail('BROWSER_FINGERPRINT_INVENTORY_INVALID');
    const executable = path.join(root, release.executable);
    await validateFingerprintPe(executable);
    if (!/^[a-f0-9]{64}$/.test(release.executableSha256) || await fingerprintFileHash(executable) !== release.executableSha256) throw fail('BROWSER_FINGERPRINT_BINARY_CHANGED');
    // Launches verify every DLL/resource as well as the executable. Status only
    // hashes the executable, so UI polling cannot repeatedly hash the full engine.
    if (full && fingerprintInventoryHash(await fingerprintInventory(root)) !== release.inventorySha256) throw fail('BROWSER_FINGERPRINT_FILES_CHANGED');
    return { ...base, state: 'ready', verified: true, integrity: full ? 'full' : 'executable', executable };
  } catch (cause) {
    return { ...base, state: cause.code === 'ENOENT' ? 'missing' : 'invalid', errorCode: cause.code?.startsWith('BROWSER_FINGERPRINT_') ? cause.code : 'BROWSER_FINGERPRINT_INVENTORY_INVALID' };
  }
}

export async function requireFingerprintRuntime(root, options = {}) {
  const state = await inspectFingerprintRuntime(root, { ...options, full: true });
  if (state.state !== 'ready') throw fail(state.errorCode);
  return state;
}
