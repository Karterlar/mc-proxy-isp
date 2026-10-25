import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile, writeFile, readdir, lstat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { auditEdition, readPublicLicenseConfig } from './edition.mjs';
import { FINGERPRINT_BROWSER_RELEASE, FINGERPRINT_BROWSER_CACHE_DIRECTORY, FINGERPRINT_RECEIPT, inspectFingerprintRuntime, fingerprintInventory } from '../../backend/src/fingerprint-browser-runtime.mjs';
import { createFingerprintSecurityCheck } from '../../backend/src/fingerprint-browser-security.mjs';

const execute = promisify(execFile);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const rootDefault = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const requiredFrontendFiles = ['frontend/index.html', 'frontend/app.js', 'frontend/controller-client.js', 'frontend/workspace-view.js', 'frontend/layout-preferences.js', 'frontend/styles.css', 'frontend/surfaces.css', 'frontend/cosmos.css', 'frontend/cosmos-surfaces.css', 'frontend/layout-preferences.css', 'frontend/quality-report.css', 'frontend/assets/MonaSans-VF.woff2', 'frontend/assets/earth-nasa-globe-east.jpg', 'frontend/browser-tools.js', 'frontend/browser-tools.css', 'frontend/browser-observation.html', 'frontend/browser-observation.js', 'frontend/browser-observation.css', 'frontend/assets/mc-proxy.ico', 'frontend/assets/mc-proxy-256.png', 'frontend/assets/mc-proxy-512.png'];
requiredFrontendFiles.push(...['chrome.png', 'edge.png', 'github.svg', 'youtube.png', 'google.png', 'wikipedia.png', 'claude.png', 'chatgpt.png', 'codex.png'].map(file => `frontend/assets/brands/${file}`));
const licensedFrontendHashes = {
  'frontend/assets/MonaSans-VF.woff2': '54afbce4f1b22c316d6385ebd138011f42e94e4ce695b5ae98e3cab11b4a25e4',
  'frontend/assets/earth-nasa-globe-east.jpg': '3b47b77b49ccd18ecf0aa58610a2047cc68a2e06a1de2e224295a1346aa2dc95',
  'licenses/MonaSans-OFL.txt': '5a7816a9496347d78b9f9e6a702f07dcec3594b35a3d57f891854ba1d5cd7378',
  'frontend/assets/brands/chrome.png': 'df6e0f204a9715c5b505d30f636c1c5511c44dcb08ed50f63e1dd23845ab5df7',
  'frontend/assets/brands/edge.png': '4d755ac02a070a1b4bb1b6f1c88ab493440109a8ac1e314aaced92f94cdc98e9',
  'frontend/assets/brands/github.svg': '6a9577cd4f7fa6b75bde1025af85b944e9dd1388373b55ccba6e9f80ac2eae60',
  'frontend/assets/brands/youtube.png': 'e39dc3d8c2f82ad2375132a8efcf521c232d5e2cf08abeb9bebe1ad94afb2157',
  'frontend/assets/brands/google.png': '5b95eed86b7603081f22edd5da01de4c028b118b20885793b9b3ad5f6cbe1e71',
  'frontend/assets/brands/wikipedia.png': '4c8bf96d667fa2e9f072bdd8e9f25c8ba6ba2ad55df1af7d9ea0dd575c12abee',
  'frontend/assets/brands/claude.png': '4004381309500f25e49a1ae639912ce307ea81da74cc383954a1ac8b9d343fe6',
  'frontend/assets/brands/chatgpt.png': 'c1a05012ec3675d31a73c7a678a9ea952d57a100a0e0994c6b086af18690f655',
  'frontend/assets/brands/codex.png': '8e82b26c98a10e45798ce48124515720657f7735fb8d0853b3f087eaa8a6b74e',
};
requiredFrontendFiles.push('frontend/license-page.js', 'frontend/license-page.css', 'frontend/licensing-admin-page.js', 'frontend/licensing-admin-page.css', 'desktop/admin-startup.mjs', 'desktop/admin-file-policy.mjs');
requiredFrontendFiles.push('frontend/admin-required.html', 'frontend/admin-required.css', 'frontend/admin-required.js', 'desktop/admin-preload.cjs');
requiredFrontendFiles.push('frontend/environment-feedback.js', 'desktop/claude-background.mjs');
requiredFrontendFiles.push('backend/src/windows-admin-access.mjs');
requiredFrontendFiles.push('frontend/dom-updates.js');
export const DEVELOPER_ADMIN_FILES = Object.freeze(['ui.mjs', 'admin.mjs', 'store.mjs', 'runtime.mjs', 'safe-files.mjs'].map(name => `tools/licensing/${name}`));
const entryPath = value => value.replace(/^[/\\]+/, '').replaceAll('\\', '/');
export function isDeveloperAdminFile(value, edition) {
  return edition === 'developer' && DEVELOPER_ADMIN_FILES.includes(entryPath(value));
}
export function missingAdminEntries(entries, edition) {
  const paths = new Set(entries.map(entryPath));
  return edition === 'developer' ? DEVELOPER_ADMIN_FILES.filter(file => !paths.has(file)) : [];
}
export function containsPrivateKey(bytes) {
  return /-----BEGIN(?: RSA| EC| OPENSSH| ENCRYPTED)? PRIVATE KEY-----(?:\r?\n|\\n|\\r\\n)[A-Za-z0-9+/=]/.test(bytes.toString('utf8'));
}
export function missingFrontendEntries(entries) {
  const paths = new Set(entries.map(entry => entry.replace(/^[/\\]+/, '').replaceAll('\\', '/')));
  return requiredFrontendFiles.filter(file => !paths.has(file));
}
export function signingEnvironment(environment) {
  return Object.fromEntries(['CSC_LINK', 'WIN_CSC_LINK', 'CSC_NAME', 'WIN_CSC_NAME', 'CSC_KEY_PASSWORD', 'WIN_CSC_KEY_PASSWORD', 'AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET'].map(name => [name, Boolean(environment[name])]));
}
export function forbiddenEntry(value, edition) {
  if (/(?:^|[/\\])(?:runtime|profiles|reports|\.cache|\.relay|\.network-lock|\.environment|\.imported-vpn|\.proxy-manager|\.license|\.licensing|test|test-fixtures|\.git)(?:[/\\]|$)|(?:^|[/\\])(?:card(?:s|-once|-secrets)?|license(?:-state)?|device(?:-key)?)\.json$|(?:enrollment\.json|accounts\.json|owner-device[^/\\]*\.json|secrets\.env|\.pem$|\.key$|\.log$|\.sqlite(?:-wal|-shm)?$|\.db(?:-wal|-shm)?$)|lightsaildefaultkey/i.test(value)) return true;
  if (!/(?:^|[/\\])tools[/\\]licensing(?:[/\\]|$)/i.test(value)) return false;
  return !isDeveloperAdminFile(value, edition) && !(edition === 'developer' && entryPath(value) === 'tools/licensing');
}
export function executableLevel(bytes) {
  const manifests = executableResources(bytes).filter(resource => resource.type === 24 && resource.name === 1);
  const levels = new Set();
  for (const { data } of manifests) for (const encoding of ['utf8', 'utf16le']) {
    const match = data.toString(encoding).match(/<requestedExecutionLevel\b[^>]*\blevel=["'](asInvoker|highestAvailable|requireAdministrator)["']/);
    if (match) levels.add(match[1]);
  }
  return levels.size === 1 ? [...levels][0] : 'unverified';
}
// Read PE resources rather than searching appended installer payloads, which
// can contain an inner executable's manifest and produce a false UAC result.
export function executableResources(bytes) {
  try {
    const inBounds = (offset, size) => Number.isInteger(offset) && offset >= 0 && size >= 0 && offset + size <= bytes.length;
    if (!inBounds(0, 64) || bytes.toString('ascii', 0, 2) !== 'MZ') return [];
    const pe = bytes.readUInt32LE(0x3c);
    if (!inBounds(pe, 26) || bytes.toString('ascii', pe, pe + 4) !== 'PE\0\0') return [];
    const sectionCount = bytes.readUInt16LE(pe + 6), optionalBytes = bytes.readUInt16LE(pe + 20), optional = pe + 24;
    const magic = bytes.readUInt16LE(optional), directoryBase = magic === 0x20b ? 112 : magic === 0x10b ? 96 : -1;
    if (directoryBase < 0 || optionalBytes < directoryBase + 24 || !inBounds(optional, optionalBytes)) return [];
    const table = optional + optionalBytes;
    if (sectionCount > 96 || !inBounds(table, sectionCount * 40)) return [];
    const sections = Array.from({ length: sectionCount }, (_, i) => {
      const entry = table + i * 40;
      return { rva: bytes.readUInt32LE(entry + 12), size: bytes.readUInt32LE(entry + 16), offset: bytes.readUInt32LE(entry + 20) };
    });
    const mapped = (rva, size) => {
      const section = sections.find(section => rva >= section.rva && rva - section.rva + size <= section.size);
      if (!section || !inBounds(section.offset + rva - section.rva, size)) throw new Error('PE_RESOURCE_INVALID');
      return section.offset + rva - section.rva;
    };
    const resourceRva = bytes.readUInt32LE(optional + directoryBase + 16), resourceBytes = bytes.readUInt32LE(optional + directoryBase + 20);
    if (!resourceRva || !resourceBytes) return [];
    const base = mapped(resourceRva, resourceBytes), result = [], visited = new Set();
    const resourceOffset = (relative, size) => {
      if (relative < 0 || relative + size > resourceBytes) throw new Error('PE_RESOURCE_INVALID');
      return base + relative;
    };
    function directory(relative, keys) {
      if (keys.length > 2 || visited.has(relative)) throw new Error('PE_RESOURCE_INVALID');
      visited.add(relative);
      const position = resourceOffset(relative, 16), count = bytes.readUInt16LE(position + 12) + bytes.readUInt16LE(position + 14);
      if (count > 4096) throw new Error('PE_RESOURCE_INVALID');
      resourceOffset(relative + 16, count * 8);
      for (let i = 0; i < count; i++) {
        const entry = position + 16 + i * 8, rawName = bytes.readUInt32LE(entry), rawData = bytes.readUInt32LE(entry + 4);
        const name = rawName & 0x80000000 ? 'named' : rawName;
        if (rawData & 0x80000000) directory(rawData & 0x7fffffff, [...keys, name]);
        else {
          if (keys.length !== 2) throw new Error('PE_RESOURCE_INVALID');
          const dataEntry = resourceOffset(rawData, 16), rva = bytes.readUInt32LE(dataEntry), size = bytes.readUInt32LE(dataEntry + 4);
          const offset = mapped(rva, size);
          result.push({ type: keys[0], name: keys[1], language: name, data: bytes.subarray(offset, offset + size) });
        }
      }
    }
    directory(0, []);
    return result;
  } catch { return []; }
}
export function executableIconMatches(bytes, ico) {
  if (ico.length < 6 || ico.readUInt16LE(0) !== 0 || ico.readUInt16LE(2) !== 1) return false;
  const count = ico.readUInt16LE(4);
  if (!count || count > 256 || ico.length < 6 + count * 16) return false;
  const resources = new Set(executableResources(bytes).filter(resource => resource.type === 3).map(resource => hash(resource.data)));
  for (let i = 0; i < count; i++) {
    const entry = 6 + i * 16, size = ico.readUInt32LE(entry + 8), offset = ico.readUInt32LE(entry + 12);
    if (!size || offset < 6 + count * 16 || offset + size > ico.length || !resources.has(hash(ico.subarray(offset, offset + size)))) return false;
  }
  return true;
}
export function validateDeliverySettings(pkg) {
  if (pkg.build?.win?.requestedExecutionLevel !== 'asInvoker' || pkg.build.portable?.requestExecutionLevel !== 'user'
    || pkg.build.nsis?.perMachine !== false || pkg.build.nsis.deleteAppDataOnUninstall !== false || pkg.build.nsis.allowElevation !== true || pkg.build.nsis.runAfterFinish !== false)
    throw new Error('DELIVERY_LAUNCH_OR_DATA_PRESERVATION_INVALID');
}
async function ordinary(file) {
  const info = await lstat(file);
  let current = path.parse(path.resolve(file)).root;
  for (const segment of path.resolve(path.dirname(file)).slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment); const parent = await lstat(current);
    if (!parent.isDirectory() || parent.isSymbolicLink()) throw new Error(`PACKAGING_LINK_UNSAFE: ${path.basename(file)}`);
  }
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new Error(`PACKAGING_FILE_UNSAFE: ${path.basename(file)}`);
  return info;
}
export function resourceIncluded(name, filters) {
  const match = pattern => new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replaceAll('*', '.*')}$`).test(name);
  return filters.some(pattern => !pattern.startsWith('!') && match(pattern)) && !filters.some(pattern => pattern.startsWith('!') && match(pattern.slice(1)));
}
async function packagedFiles(directory, prefix = '') {
  const result = [];
  for (const name of await readdir(directory)) {
    const relative = prefix ? `${prefix}/${name}` : name;
    const info = await lstat(path.join(directory, name));
    if (info.isSymbolicLink()) throw new Error(`PACKAGING_LINK_UNSAFE: ${relative}`);
    if (info.isDirectory()) result.push(...await packagedFiles(path.join(directory, name), relative));
    else if (info.isFile() && info.nlink === 1) result.push(relative);
    else throw new Error(`PACKAGING_FILE_UNSAFE: ${relative}`);
  }
  return result;
}
export async function auditInputs(root = rootDefault, options = {}) {
  const edition = await auditEdition(root, options), sourceRoot = edition.sourceRoot;
  const manifest = JSON.parse(await readFile(path.join(sourceRoot, 'licenses/core-provenance.json'), 'utf8'));
  const core = path.join(sourceRoot, 'backend/.cache/core', manifest.directory);
  for (const [name, expected] of Object.entries(manifest.files)) {
    await ordinary(path.join(core, name));
    if (hash(await readFile(path.join(core, name))) !== expected.sha256) throw new Error(`CORE_INPUT_HASH_MISMATCH: ${name}`);
  }
  const archive = path.join(sourceRoot, 'backend/.cache/sing-box.zip');
  await ordinary(archive);
  if (hash(await readFile(archive)) !== manifest.archiveSha256) throw new Error('CORE_ARCHIVE_HASH_MISMATCH');
  for (const name of ['Electron-LICENSE.txt', 'js-yaml-LICENSE.txt', 'argparse-LICENSE.txt', 'sing-box-LICENSE.txt', 'cronet-go-LICENSE.txt', 'Chromium-LICENSE.txt', 'GPL-3.0.txt', 'THIRD-PARTY-NOTICES.txt', 'SOURCE-AVAILABILITY.txt', 'MonaSans-OFL.txt', 'NASA-IMAGERY-NOTICES.txt', 'fingerprint-chromium.txt', 'fingerprint-browser-notice.txt']) await ordinary(path.join(sourceRoot, 'licenses', name));
  for (const file of requiredFrontendFiles) await ordinary(path.join(root, file));
  for (const [file, expected] of Object.entries(licensedFrontendHashes)) {
    if (hash(await readFile(path.join(file.startsWith('licenses/') ? sourceRoot : root, file))) !== expected) throw new Error(`FRONTEND_INPUT_HASH_MISMATCH: ${path.basename(file)}`);
  }
  for (const name of ['FEATURES.md', 'DEVELOPMENT.md', 'ARCHITECTURE.md', 'LICENSING.md']) await ordinary(path.join(sourceRoot, 'docs', name));
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  validateDeliverySettings(pkg);
  const fingerprint = pkg.build.extraResources.filter(resource => resource.to === 'fingerprint-browser');
  if (fingerprint.length !== 1 || fingerprint[0].from !== path.join(sourceRoot, '.cache', FINGERPRINT_BROWSER_CACHE_DIRECTORY)
    || JSON.stringify(fingerprint[0].filter) !== JSON.stringify(['**/*', FINGERPRINT_RECEIPT, '!debug.log'])) throw new Error('FINGERPRINT_BUNDLE_RESOURCE_INVALID');
  const fingerprintState = await inspectFingerprintRuntime(fingerprint[0].from, { platform: 'win32', full: true });
  if (!fingerprintState.verified) throw new Error(`FINGERPRINT_BUNDLE_INPUT_INVALID: ${fingerprintState.errorCode}`);
  for (const resource of pkg.build.extraResources) {
    if (resource.to === 'fingerprint-browser') continue;
    for (const name of await readdir(resource.from)) {
      if (!resourceIncluded(name, resource.filter)) continue;
      if (forbiddenEntry(name) || name === 'client-license-config.json') throw new Error('PACKAGING_RESOURCE_SECRET');
      const file = path.join(resource.from, name); await ordinary(file);
      if (/\.(?:json|txt|env)$/i.test(name) && /-----BEGIN(?: RSA| EC| OPENSSH| ENCRYPTED)? PRIVATE KEY-----/.test(await readFile(file, 'utf8'))) throw new Error('PACKAGING_RESOURCE_PRIVATE_KEY');
    }
  }
  return manifest;
}
async function signature(file) {
  if (process.platform !== 'win32') return 'unverified';
  // The path is passed through a process-local environment variable, never interpolated into PowerShell.
  try {
    const powershell = path.join(process.env.SystemRoot || 'C:/Windows', 'System32/WindowsPowerShell/v1.0');
    // PowerShell 7's inherited module path can hide Windows PowerShell's Security module.
    const { stdout } = await execute(path.join(powershell, 'powershell.exe'), ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', '$ErrorActionPreference="Stop"; Import-Module (Join-Path $PSHOME "Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1") -ErrorAction Stop; [string](Get-AuthenticodeSignature -LiteralPath $env:MC_DELIVERY_FILE).Status'], { env: { ...process.env, PSModulePath: path.join(powershell, 'Modules'), MC_DELIVERY_FILE: file }, windowsHide: true, timeout: 15000, maxBuffer: 8192 });
    const value = stdout.trim();
    return ['Valid', 'NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError', 'NotSupportedFileFormat', 'Incompatible'].includes(value) ? value : 'unverified';
  } catch { return 'unverified'; }
}
export async function auditDelivery(root = rootDefault, options = {}) {
  const edition = await auditEdition(root, options);
  const manifest = await auditInputs(root, options);
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const output = path.resolve(root, pkg.build.directories.output);
  const packaged = path.join(output, 'win-unpacked');
  const archive = path.join(packaged, 'resources/app.asar');
  await ordinary(archive);
  const require = createRequire(import.meta.url);
  const builderRequire = createRequire(require.resolve('electron-builder'));
  const libraryRequire = createRequire(builderRequire.resolve('app-builder-lib'));
  const asar = libraryRequire('@electron/asar');
  const entries = asar.listPackage(archive);
  const forbidden = [...entries.filter(entry => forbiddenEntry(entry, edition.edition)), ...(await packagedFiles(packaged)).filter(entry => forbiddenEntry(entry, edition.edition))];
  forbidden.push(...missingFrontendEntries(entries).map(file => `${file}/MISSING_REQUIRED_FILE`));
  forbidden.push(...missingAdminEntries(entries, edition.edition).map(file => `${file}/MISSING_REQUIRED_FILE`));
  if (!entries.some(entry => entry.replace(/^[/\\]+/, '').replaceAll('\\', '/') === 'desktop/distribution.mjs')) forbidden.push('desktop/distribution.mjs/MISSING_REQUIRED_FILE');
  const comparisons = [];
  const dependencies = new Map();
  for (const entry of entries) {
    const relative = entry.replace(/^[/\\]+/, '').replaceAll('\\', '/');
    const nativeRelative = path.normalize(relative);
    const metadata = asar.statFile(archive, nativeRelative);
    if (metadata.files) { if (isDeveloperAdminFile(relative, edition.edition)) forbidden.push(`${relative}/NOT_REGULAR_FILE`); continue; }
    if (metadata.link) { forbidden.push(relative); continue; }
    if (/^node_modules\//.test(relative)) {
      if (!/^node_modules\/(?:js-yaml|argparse)\//.test(relative)) forbidden.push(relative);
      if (/^node_modules\/[^/]+\/package\.json$/.test(relative)) {
        const dependency = JSON.parse(asar.extractFile(archive, nativeRelative));
        dependencies.set(dependency.name, dependency.version);
      }
      continue;
    }
    if (!/^(?:desktop\/|backend\/src\/|frontend\/|package\.json$)/.test(relative) && !isDeveloperAdminFile(relative, edition.edition)) { forbidden.push(relative); continue; }
    const data = asar.extractFile(archive, nativeRelative);
    if (containsPrivateKey(data)) forbidden.push(`${relative}/PRIVATE_KEY_CONTENT`);
    const source = await readFile(path.join(root, relative));
    comparisons.push({ path: relative, matchesSource: relative === 'package.json' ? ['name', 'productName', 'version', 'main', 'license'].every(key => JSON.parse(data)[key] === JSON.parse(source)[key]) : hash(data) === hash(source) });
  }
  const resourceChecks = [];
  for (const directory of ['licenses', 'offline-chain-test', 'delivery-notes']) {
    const resource = pkg.build.extraResources.find(item => item.to === directory), sourceDirectory = resource.from;
    const names = await readdir(path.join(packaged, 'resources', directory));
    const expectedNames = (await readdir(sourceDirectory)).filter(name => resourceIncluded(name, resource.filter));
    if (expectedNames.some(name => !names.includes(name))) forbidden.push(`${directory}/MISSING_REQUIRED_FILE`);
    for (const name of names) {
      if (forbiddenEntry(name) || !expectedNames.includes(name)) forbidden.push(`${directory}/${name}`);
      const from = path.join(sourceDirectory, name), to = path.join(packaged, 'resources', directory, name);
      await ordinary(to);
      resourceChecks.push({ path: `${directory}/${name}`, matchesSource: hash(await readFile(from)) === hash(await readFile(to)) });
    }
  }
  for (const [name, expected] of Object.entries(manifest.files)) resourceChecks.push({ path: `core/${name}`, matchesSource: hash(await readFile(path.join(packaged, 'resources/core/sing-box-1.14.2', name))) === expected.sha256 });
  const fingerprintDirectory = path.join(packaged, 'resources/fingerprint-browser');
  const fingerprintState = await inspectFingerprintRuntime(fingerprintDirectory, { platform: 'win32', full: true });
  if (!fingerprintState.verified) forbidden.push(`fingerprint-browser/${fingerprintState.errorCode}`);
  else {
    const fingerprintResource = pkg.build.extraResources.find(resource => resource.to === 'fingerprint-browser');
    const expectedFiles = [...(await fingerprintInventory(fingerprintResource.from)).map(file => file.path), FINGERPRINT_RECEIPT];
    const actualFiles = await packagedFiles(fingerprintDirectory);
    if (expectedFiles.length !== actualFiles.length || expectedFiles.some(file => !actualFiles.includes(file))) forbidden.push('fingerprint-browser/UNEXPECTED_OR_MISSING_RESOURCE');
    for (const relative of expectedFiles) resourceChecks.push({ path: `fingerprint-browser/${relative}`, matchesSource: hash(await readFile(path.join(fingerprintResource.from, relative))) === hash(await readFile(path.join(fingerprintDirectory, relative))) });
  }
  for (const name of ['LICENSE.electron.txt', 'LICENSES.chromium.html']) await ordinary(path.join(packaged, name));
  const artifacts = [];
  const iconBytes = await readFile(path.join(root, 'frontend/assets/mc-proxy.ico'));
  for (const name of await readdir(output)) {
    if (!/^MC-Proxy-.*\.exe$/.test(name)) continue;
    if (!name.startsWith(`MC-Proxy-${edition.edition === 'developer' ? 'Developer' : 'Licensed'}-${pkg.version}-Windows-x64-unsigned-test-`)) forbidden.push(name);
    const file = path.join(output, name), info = await ordinary(file);
    const bytes = await readFile(file);
    artifacts.push({ name, bytes: info.size, sha256: hash(bytes), executionLevel: executableLevel(bytes), expectedExecutionLevel: 'asInvoker', iconMatches: executableIconMatches(bytes, iconBytes), signature: await signature(file) });
  }
  const executableSignature = await signature(path.join(packaged, `${pkg.build.productName}.exe`));
  const innerBytes = await readFile(path.join(packaged, `${pkg.build.productName}.exe`));
  const innerExecutionLevel = executableLevel(innerBytes), innerIconMatches = executableIconMatches(innerBytes, iconBytes);
  const report = { version: pkg.version, edition: edition.edition, editionManifest: path.join(path.dirname(root), 'edition-manifest.json'), distributionSha256: edition.distributionSha256, at: new Date().toISOString(), channel: 'unsigned-test', commercialReleaseReady: false, releaseBlockers: ['CODE_SIGNING_NOT_CONFIGURED', 'GPL_DISTRIBUTION_REVIEW_REQUIRED', 'COMPLETE_LIBCRONET_NOTICES_REQUIRED', 'CLEAN_MACHINE_INSTALL_RECOVERY_ACCEPTANCE_REQUIRED'], executableSignature, innerExecutionLevel, innerIconMatches, fingerprintBrowser: { version: FINGERPRINT_BROWSER_RELEASE.version, revision: FINGERPRINT_BROWSER_RELEASE.revision, inventorySha256: FINGERPRINT_BROWSER_RELEASE.inventorySha256, bundled: fingerprintState.verified }, artifacts, forbidden, dependencies: Object.fromEntries(dependencies), comparisons, resourceChecks };
  report.fingerprintBrowser.security = createFingerprintSecurityCheck({ version: FINGERPRINT_BROWSER_RELEASE.version }).snapshot();
  if (report.fingerprintBrowser.security.status !== 'meets-baseline') report.releaseBlockers.push('FINGERPRINT_SECURITY_BASELINE_NOT_MET_OR_UNVERIFIED');
  report.passed = !forbidden.length && comparisons.every(item => item.matchesSource) && resourceChecks.every(item => item.matchesSource) && dependencies.get('js-yaml') === pkg.dependencies['js-yaml'] && dependencies.get('argparse') === '2.0.1' && executableSignature === 'NotSigned' && innerExecutionLevel === 'asInvoker' && innerIconMatches && artifacts.every(item => item.signature === 'NotSigned' && item.executionLevel === item.expectedExecutionLevel && item.iconMatches);
  report.innerExecutableSha256 = hash(innerBytes);
  report.reportPath = path.join(output, 'DELIVERY-AUDIT.json');
  await writeFile(report.reportPath, `${JSON.stringify(report, null, 2)}\n`);
  await writeFile(path.join(output, 'SHA256SUMS.txt'), artifacts.map(item => `${item.sha256}  ${item.name}\n`).join(''));
  return report;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const options = {}, args = process.argv.slice(2); let stagingRoot;
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--staging-root') stagingRoot = args[++i];
      else if (args[i] === '--edition') options.expectedEdition = args[++i];
      else if (args[i] === '--license-config') options.expectedLicenseConfig = await readPublicLicenseConfig(args[++i]);
      else throw new Error('AUDIT_ARGUMENT_INVALID');
    }
    if (!stagingRoot || !['developer', 'licensed'].includes(options.expectedEdition) || (options.expectedEdition === 'licensed' && !options.expectedLicenseConfig)) throw new Error('Use audit.mjs --staging-root <generated app directory> --edition developer|licensed [--license-config <public JSON>]');
    const report = await auditDelivery(path.resolve(stagingRoot), options);
    console.log(JSON.stringify({ passed: report.passed, edition: report.edition, channel: report.channel, commercialReleaseReady: false, reportPath: report.reportPath })); if (!report.passed) process.exitCode = 1;
  }
  catch (cause) { console.error(cause.code || cause.message); process.exitCode = 1; }
}
