import path from 'node:path';
import { mkdir, lstat, readFile, readdir, copyFile, writeFile, realpath } from 'node:fs/promises';
import { randomUUID, createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { validateLicenseConfig } from '../../backend/src/license-format.mjs';
import { forbiddenEntry, DEVELOPER_ADMIN_FILES, isDeveloperAdminFile, containsPrivateKey, validateDeliverySettings } from './audit.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const json = value => `${JSON.stringify(value, null, 2)}\n`;
export const EDITIONS = Object.freeze({
  developer: Object.freeze({ productName: 'MC Proxy Developer', appId: 'com.mcproxy.desktop.developer', artifactLabel: 'Developer' }),
  licensed: Object.freeze({ productName: 'MC Proxy', appId: 'com.mcproxy.desktop.licensed', artifactLabel: 'Licensed' })
});
export function distributionModule(distribution) {
  return `const distribution = ${JSON.stringify(distribution)};\nObject.freeze(distribution.licenseConfig.publicKeys ?? {});\nObject.freeze(distribution.licenseConfig);\nexport const DISTRIBUTION = Object.freeze(distribution);\n`;
}
export function parseBuildArguments(args) {
  let edition = 'developer', licenseConfigPath; const targets = [];
  const seen = new Set();
  for (let i = 0; i < args.length; i++) {
    const value = args[i];
    if (['--edition', '--license-config'].includes(value)) {
      if (seen.has(value) || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('BUILD_ARGUMENT_INVALID');
      seen.add(value);
      if (value === '--edition') edition = args[++i]; else licenseConfigPath = args[++i];
    } else if (['dir', 'nsis', 'portable'].includes(value) && !targets.includes(value)) targets.push(value);
    else throw new Error('BUILD_ARGUMENT_INVALID');
  }
  if (!Object.hasOwn(EDITIONS, edition) || (edition === 'licensed' && !licenseConfigPath) || (edition === 'developer' && licenseConfigPath)) throw new Error('BUILD_EDITION_CONFIG_REQUIRED');
  if (!targets.length) targets.push('dir');
  return { edition, licenseConfigPath, targets };
}
async function directoryWithoutLinks(directory) {
  const absolute = path.resolve(directory); let current = path.parse(absolute).root;
  for (const part of absolute.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part); const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('PACKAGING_DIRECTORY_UNSAFE');
  }
  return absolute;
}
async function ordinaryFile(file, maxBytes = 32 * 1024 * 1024, { allowDependencyHardlinks = false } = {}) {
  await directoryWithoutLinks(path.dirname(file));
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink() || (info.nlink !== 1 && !allowDependencyHardlinks) || info.nlink < 1 || info.size > maxBytes) throw new Error('PACKAGING_FILE_UNSAFE');
  return info;
}
export async function readPublicLicenseConfig(file) {
  await ordinaryFile(path.resolve(file), 32768);
  const config = validateLicenseConfig(JSON.parse(await readFile(file, 'utf8')));
  if (config.mode !== 'required') throw new Error('LICENSED_EDITION_REQUIRES_REQUIRED_CONFIG');
  return config;
}
function below(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative && !relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative);
}
export async function prepareEdition(root, { edition = 'developer', licenseConfigPath } = {}) {
  root = await realpath(await directoryWithoutLinks(path.resolve(root)));
  if (!Object.hasOwn(EDITIONS, edition) || (edition === 'developer' && licenseConfigPath)) throw new Error('BUILD_EDITION_INVALID');
  const licenseConfig = edition === 'developer' ? { version: 1, mode: 'development' } : await readPublicLicenseConfig(licenseConfigPath ?? (() => { throw new Error('LICENSED_EDITION_REQUIRES_EXPLICIT_CONFIG'); })());
  const distribution = { edition, licenseConfig };
  await ordinaryFile(path.join(root, 'package.json'), 65536);
  const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  if (!pkg.build || !/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(pkg.version) || Object.keys(pkg.dependencies ?? {}).join(',') !== 'js-yaml') throw new Error('PACKAGING_PROJECT_INVALID');
  validateDeliverySettings(pkg);
  const stagingBase = path.join(root, '.cache', 'packaging');
  await mkdir(stagingBase, { recursive: true }); await directoryWithoutLinks(stagingBase);
  const runRoot = path.join(stagingBase, `${edition}-${randomUUID()}`), stagingRoot = path.join(runRoot, 'app');
  if (!below(stagingBase, stagingRoot)) throw new Error('PACKAGING_STAGE_OUTSIDE_CACHE');
  await mkdir(stagingRoot, { recursive: true, mode: 0o700 });
  const copiedFiles = [];
  async function copyTree(relative, source = path.join(root, relative), { allowDependencyHardlinks = false } = {}) {
    const destination = path.join(stagingRoot, relative), info = await lstat(source);
    if (info.isSymbolicLink()) throw new Error('PACKAGING_LINK_UNSAFE');
    if (isDeveloperAdminFile(relative, edition) && !info.isFile()) throw new Error('PACKAGING_FILE_UNSAFE');
    if (relative.replaceAll('\\', '/') === 'desktop/test' || relative.replaceAll('\\', '/').startsWith('desktop/test/')) return;
    if (forbiddenEntry(relative, edition)) throw new Error('PACKAGING_SECRET_PATH');
    if (info.isDirectory()) {
      if (relative.replaceAll('\\', '/') === 'desktop/test') return;
      await mkdir(destination, { recursive: true });
      for (const name of await readdir(source)) await copyTree(path.join(relative, name), path.join(source, name), { allowDependencyHardlinks });
    } else {
      await ordinaryFile(source, 32 * 1024 * 1024, { allowDependencyHardlinks });
      const bytes = await readFile(source);
      if (containsPrivateKey(bytes)) throw new Error('PACKAGING_PRIVATE_KEY_CONTENT');
      await mkdir(path.dirname(destination), { recursive: true });
      await copyFile(source, destination);
      await ordinaryFile(destination);
      copiedFiles.push({ path: relative.replaceAll('\\', '/'), sha256: hash(bytes) });
    }
  }
  for (const relative of ['desktop', 'backend/src', 'frontend']) await copyTree(relative);
  if (edition === 'developer') for (const relative of DEVELOPER_ADMIN_FILES) await copyTree(relative);
  const projectRequire = createRequire(path.join(root, 'package.json'));
  async function dependency(require, name, version) {
    const packageFile = await realpath(require.resolve(`${name}/package.json`));
    if (!below(path.join(root, 'node_modules'), packageFile)) throw new Error('PACKAGING_DEPENDENCY_OUTSIDE_PROJECT');
    await ordinaryFile(packageFile, 65536, { allowDependencyHardlinks: true });
    const metadata = JSON.parse(await readFile(packageFile, 'utf8'));
    if (metadata.name !== name || metadata.version !== version) throw new Error('PACKAGING_DEPENDENCY_VERSION_MISMATCH');
    await copyTree(path.join('node_modules', name), path.dirname(packageFile), { allowDependencyHardlinks: true });
    return createRequire(packageFile);
  }
  const yamlRequire = await dependency(projectRequire, 'js-yaml', pkg.dependencies['js-yaml']);
  await dependency(yamlRequire, 'argparse', '2.0.1');
  const identity = EDITIONS[edition], outputDirectory = path.join(root, 'dist', `${pkg.version}-unsigned`, edition);
  const absoluteSource = value => { const resolved = path.resolve(root, value); if (!below(root, resolved)) throw new Error('PACKAGING_RESOURCE_OUTSIDE_PROJECT'); return resolved; };
  const stagedPackage = { ...pkg, packageManager: 'traversal', productName: identity.productName, devDependencies: undefined, scripts: undefined, build: { ...pkg.build, productName: identity.productName, appId: identity.appId,
    files: edition === 'developer' ? [...pkg.build.files, ...DEVELOPER_ADMIN_FILES] : pkg.build.files,
    electronDist: absoluteSource(pkg.build.electronDist), directories: { ...pkg.build.directories, output: outputDirectory, buildResources: absoluteSource(pkg.build.directories.buildResources) },
    extraResources: pkg.build.extraResources.map(resource => ({ ...resource, from: absoluteSource(resource.from), filter: resource.to === 'licenses' ? [...resource.filter, '!client-license-config.json'] : edition === 'developer' && resource.to === 'delivery-notes' ? [...resource.filter, 'LICENSING.md'] : resource.filter })),
    win: { ...pkg.build.win, icon: absoluteSource(pkg.build.win.icon) },
    nsis: { ...pkg.build.nsis, include: absoluteSource(pkg.build.nsis.include), artifactName: `MC-Proxy-${identity.artifactLabel}-\${version}-Windows-x64-unsigned-test-setup.exe` },
    portable: { ...pkg.build.portable, artifactName: `MC-Proxy-${identity.artifactLabel}-\${version}-Windows-x64-unsigned-test-portable.exe` } } };
  const moduleText = distributionModule(distribution);
  await writeFile(path.join(stagingRoot, 'desktop/distribution.mjs'), moduleText, { mode: 0o600 });
  await writeFile(path.join(stagingRoot, 'package.json'), json(stagedPackage), { flag: 'wx', mode: 0o600 });
  const moduleEntry = copiedFiles.find(entry => entry.path === 'desktop/distribution.mjs');
  if (moduleEntry) moduleEntry.sha256 = hash(moduleText); else copiedFiles.push({ path: 'desktop/distribution.mjs', sha256: hash(moduleText) });
  copiedFiles.push({ path: 'package.json', sha256: hash(json(stagedPackage)) });
  const manifest = { version: 1, edition, sourceRoot: root, stagingRoot, outputDirectory, distribution, distributionSha256: hash(moduleText), copiedFiles: copiedFiles.sort((a, b) => a.path.localeCompare(b.path)) };
  const manifestPath = path.join(runRoot, 'edition-manifest.json');
  await writeFile(manifestPath, json(manifest), { flag: 'wx', mode: 0o600 });
  return { edition, distribution, stagingRoot, manifestPath, outputDirectory };
}
export async function auditEdition(stagingRoot, { expectedEdition, expectedLicenseConfig, manifestPath = path.join(path.dirname(stagingRoot), 'edition-manifest.json') } = {}) {
  stagingRoot = await directoryWithoutLinks(path.resolve(stagingRoot));
  await ordinaryFile(manifestPath, 1024 * 1024);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (manifest.version !== 1 || manifest.stagingRoot !== stagingRoot || !Object.hasOwn(EDITIONS, manifest.edition) || path.resolve(manifestPath) !== path.join(path.dirname(stagingRoot), 'edition-manifest.json') || !below(path.join(manifest.sourceRoot, '.cache', 'packaging'), stagingRoot) || path.basename(stagingRoot) !== 'app') throw new Error('EDITION_MANIFEST_INVALID');
  if (expectedEdition && manifest.edition !== expectedEdition) throw new Error('EDITION_MISMATCH');
  const distribution = manifest.distribution;
  if (!distribution || Object.keys(distribution).sort().join(',') !== 'edition,licenseConfig' || distribution.edition !== manifest.edition) throw new Error('EDITION_DISTRIBUTION_INVALID');
  const config = validateLicenseConfig(distribution.licenseConfig);
  if (manifest.edition === 'developer') {
    if (JSON.stringify(distribution.licenseConfig) !== JSON.stringify({ version: 1, mode: 'development' })) throw new Error('DEVELOPER_EDITION_CONFIG_INVALID');
  } else if (config.mode !== 'required') throw new Error('LICENSED_EDITION_REQUIRES_REQUIRED_CONFIG');
  if (expectedLicenseConfig && JSON.stringify(config) !== JSON.stringify(validateLicenseConfig(expectedLicenseConfig))) throw new Error('EDITION_PUBLIC_CONFIG_MISMATCH');
  const moduleFile = path.join(stagingRoot, 'desktop/distribution.mjs');
  await ordinaryFile(moduleFile, 32768);
  const actual = await readFile(moduleFile, 'utf8'), expected = distributionModule(distribution);
  if (actual !== expected || hash(actual) !== manifest.distributionSha256) throw new Error('EDITION_MODULE_MISMATCH');
  const pkg = JSON.parse(await readFile(path.join(stagingRoot, 'package.json'), 'utf8')), identity = EDITIONS[manifest.edition];
  if (pkg.productName !== identity.productName || pkg.build.productName !== identity.productName || pkg.build.appId !== identity.appId || pkg.build.directories.output !== manifest.outputDirectory || manifest.outputDirectory !== path.join(manifest.sourceRoot, 'dist', `${pkg.version}-unsigned`, manifest.edition)) throw new Error('EDITION_PACKAGE_MISMATCH');
  validateDeliverySettings(pkg);
  if (!Array.isArray(manifest.copiedFiles)) throw new Error('EDITION_MANIFEST_INVALID');
  const expectedFiles = new Map();
  for (const entry of manifest.copiedFiles) {
    if (!entry || typeof entry.path !== 'string' || (!/^(?:desktop\/|backend\/src\/|frontend\/|node_modules\/(?:js-yaml|argparse)\/|package\.json$)/.test(entry.path) && !isDeveloperAdminFile(entry.path, manifest.edition)) || entry.path.includes('..') || forbiddenEntry(entry.path, manifest.edition) || expectedFiles.has(entry.path)) throw new Error('EDITION_MANIFEST_INVALID');
    expectedFiles.set(entry.path, entry.sha256);
  }
  if (manifest.edition === 'developer' && DEVELOPER_ADMIN_FILES.some(file => !expectedFiles.has(file) || !pkg.build.files.includes(file))) throw new Error('EDITION_ADMIN_MISSING');
  async function verifyTree(directory, prefix = '') {
    for (const name of await readdir(directory)) {
      const relative = prefix ? `${prefix}/${name}` : name, file = path.join(directory, name), info = await lstat(file);
      if (info.isSymbolicLink() || forbiddenEntry(relative, manifest.edition)) throw new Error('PACKAGING_LINK_OR_SECRET_UNSAFE');
      if (info.isDirectory()) await verifyTree(file, relative);
      else {
        await ordinaryFile(file);
        const bytes = await readFile(file);
        if (containsPrivateKey(bytes)) throw new Error('PACKAGING_PRIVATE_KEY_CONTENT');
        if (!expectedFiles.has(relative) || hash(bytes) !== expectedFiles.get(relative)) throw new Error('EDITION_SOURCE_MISMATCH');
        if (isDeveloperAdminFile(relative, manifest.edition)) {
          const source = path.join(manifest.sourceRoot, relative);
          await ordinaryFile(source);
          if (hash(await readFile(source)) !== hash(bytes)) throw new Error('EDITION_SOURCE_MISMATCH');
        }
        expectedFiles.delete(relative);
      }
    }
  }
  await verifyTree(stagingRoot);
  if (expectedFiles.size) throw new Error('EDITION_SOURCE_MISSING');
  return manifest;
}
