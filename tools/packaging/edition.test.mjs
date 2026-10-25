import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, link, symlink, rename, realpath, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { prepareEdition, auditEdition, distributionModule, parseBuildArguments, readPublicLicenseConfig } from './edition.mjs';
import { DEVELOPER_ADMIN_FILES } from './audit.mjs';

async function fixture(action) {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), 'proxypilot-edition-')));
  try {
    const pkg = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
    await writeFile(path.join(root, 'package.json'), JSON.stringify(pkg));
    for (const directory of ['desktop/test', 'backend/src', 'frontend/assets', 'node_modules/js-yaml', 'node_modules/argparse', 'tools/licensing/test']) await mkdir(path.join(root, directory), { recursive: true });
    await writeFile(path.join(root, 'desktop/main.mjs'), 'export const desktop = true;\n');
    await writeFile(path.join(root, 'desktop/distribution.mjs'), distributionModule({ edition: 'developer', licenseConfig: { version: 1, mode: 'development' } }));
    await writeFile(path.join(root, 'desktop/test/omitted.test.mjs'), 'throw new Error("must not ship");\n');
    await writeFile(path.join(root, 'backend/src/server.mjs'), 'export const server = true;\n');
    await writeFile(path.join(root, 'frontend/index.html'), '<!doctype html><p>Fixture</p>');
    for (const file of DEVELOPER_ADMIN_FILES) await writeFile(path.join(root, file), `export const moduleName = '${path.basename(file)}';\n`);
    for (const file of ['tools/licensing/service.mjs', 'tools/licensing/omitted.test.mjs', 'tools/licensing/test/fixture.mjs', 'tools/licensing/signing-private.pem', 'tools/licensing/billing.sqlite']) await writeFile(path.join(root, file), 'MUST_NOT_SHIP');
    for (const [name, version] of [['js-yaml', pkg.dependencies['js-yaml']], ['argparse', '2.0.1']]) await writeFile(path.join(root, `node_modules/${name}/package.json`), JSON.stringify({ name, version }));
    const publicKey = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
    const config = { version: 1, mode: 'required', serviceUrl: 'https://licenses.example.com', publicKeys: { 'fixture-1': publicKey } }, configPath = path.join(root, 'public-license.json');
    await writeFile(configPath, JSON.stringify(config));
    return await action({ root, pkg, config, configPath });
  } finally {
    assert.ok(path.resolve(root).startsWith(await realpath(tmpdir()) + path.sep) && path.basename(root).startsWith('proxypilot-edition-'));
    await rm(root, { recursive: true, force: true });
  }
}
test('build arguments default to developer and licensed demands one explicit public config', () => {
  assert.deepEqual(parseBuildArguments([]), { edition: 'developer', licenseConfigPath: undefined, targets: ['dir'] });
  assert.deepEqual(parseBuildArguments(['nsis', 'portable']), { edition: 'developer', licenseConfigPath: undefined, targets: ['nsis', 'portable'] });
  assert.deepEqual(parseBuildArguments(['--edition', 'licensed', '--license-config', 'public.json', 'dir']), { edition: 'licensed', licenseConfigPath: 'public.json', targets: ['dir'] });
  for (const args of [['--edition', 'licensed'], ['--edition', 'other'], ['--license-config', 'public.json'], ['--edition', 'developer', '--edition', 'licensed'], ['--license-config'], ['nsis', 'nsis'], ['--publish']]) assert.throws(() => parseBuildArguments(args));
});
test('preparation isolates minimal app inputs and two identities without changing source or producing delivery artifacts', async () => fixture(async ({ root, configPath, config, pkg }) => {
  const source = await readFile(path.join(root, 'desktop/distribution.mjs'), 'utf8');
  const developer = await prepareEdition(root), licensed = await prepareEdition(root, { edition: 'licensed', licenseConfigPath: configPath });
  assert.notEqual(developer.stagingRoot, licensed.stagingRoot);
  assert.equal(await readFile(path.join(root, 'desktop/distribution.mjs'), 'utf8'), source);
  assert.equal((await readdir(developer.stagingRoot)).sort().join(','), 'backend,desktop,frontend,node_modules,package.json,tools');
  assert.equal((await readdir(licensed.stagingRoot)).includes('tools'), false);
  assert.equal((await readdir(path.join(developer.stagingRoot, 'desktop'))).includes('test'), false);
  assert.equal(await readFile(path.join(developer.stagingRoot, 'desktop/distribution.mjs'), 'utf8'), source);
  const staged = JSON.parse(await readFile(path.join(licensed.stagingRoot, 'package.json'), 'utf8'));
  assert.equal(staged.productName, 'MC Proxy'); assert.equal(staged.build.appId, 'com.mcproxy.desktop.licensed');
  assert.equal(staged.build.win.requestedExecutionLevel, 'asInvoker');
  assert.equal(staged.build.portable.requestExecutionLevel, 'user');
  assert.equal(staged.build.nsis.perMachine, false); assert.equal(staged.build.nsis.deleteAppDataOnUninstall, false);
  assert.equal(staged.build.nsis.guid, pkg.build.nsis.guid);
  assert.deepEqual(staged.build.extraResources.find(item => item.to === 'fingerprint-browser').filter, ['**/*', '.mc-fingerprint-runtime.json', '!debug.log']);
  assert.equal(staged.packageManager, 'traversal');
  assert.equal(JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8')).packageManager, pkg.packageManager);
  assert.equal(staged.build.directories.output, path.join(root, 'dist', `${pkg.version}-unsigned`, 'licensed'));
  for (const field of [staged.build.electronDist, staged.build.directories.buildResources, staged.build.win.icon, staged.build.nsis.include, ...staged.build.extraResources.map(item => item.from)]) assert.equal(path.isAbsolute(field), true);
  assert(staged.build.extraResources.find(item => item.to === 'licenses').filter.includes('!client-license-config.json'));
  assert.equal(staged.devDependencies, undefined); assert.equal(staged.scripts, undefined);
  const verified = await auditEdition(licensed.stagingRoot, { expectedEdition: 'licensed', expectedLicenseConfig: config });
  assert.equal(verified.distribution.licenseConfig.mode, 'required');
  assert.equal((await auditEdition(developer.stagingRoot, { expectedEdition: 'developer' })).edition, 'developer');
  await assert.rejects(readdir(path.join(root, 'dist')), { code: 'ENOENT' });
}));

test('developer packages only the exact admin modules and source package filters stay unchanged', async () => fixture(async ({ root, pkg, configPath }) => {
  const developer = await prepareEdition(root), licensed = await prepareEdition(root, { edition: 'licensed', licenseConfigPath: configPath });
  assert.deepEqual((await readdir(path.join(developer.stagingRoot, 'tools/licensing'))).sort(), DEVELOPER_ADMIN_FILES.map(file => path.basename(file)).sort());
  const developerPackage = JSON.parse(await readFile(path.join(developer.stagingRoot, 'package.json'), 'utf8'));
  const licensedPackage = JSON.parse(await readFile(path.join(licensed.stagingRoot, 'package.json'), 'utf8'));
  assert.deepEqual(developerPackage.build.files, [...pkg.build.files, ...DEVELOPER_ADMIN_FILES]);
  assert.deepEqual(licensedPackage.build.files, pkg.build.files);
  assert.deepEqual(JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8')).build.files, pkg.build.files);
  const developerManifest = await auditEdition(developer.stagingRoot, { expectedEdition: 'developer' });
  assert.deepEqual(developerManifest.copiedFiles.filter(file => file.path.startsWith('tools/')).map(file => file.path).sort(), [...DEVELOPER_ADMIN_FILES].sort());
  await assert.rejects(readFile(path.join(licensed.stagingRoot, 'tools/licensing/ui.mjs')), { code: 'ENOENT' });
}));

test('edition auditing rejects changed UAC and uninstall policies even with a matching manifest hash', async () => fixture(async ({ root }) => {
  const profile = await prepareEdition(root);
  const packageFile = path.join(profile.stagingRoot, 'package.json'), manifest = JSON.parse(await readFile(profile.manifestPath, 'utf8'));
  const pkg = JSON.parse(await readFile(packageFile, 'utf8'));
  for (const [section, key, value] of [['win', 'requestedExecutionLevel', 'requireAdministrator'], ['portable', 'requestExecutionLevel', 'admin'], ['nsis', 'deleteAppDataOnUninstall', true], ['nsis', 'perMachine', true]]) {
    const bad = structuredClone(pkg); bad.build[section][key] = value;
    const bytes = Buffer.from(JSON.stringify(bad)); await writeFile(packageFile, bytes);
    manifest.copiedFiles.find(entry => entry.path === 'package.json').sha256 = createHash('sha256').update(bytes).digest('hex');
    await writeFile(profile.manifestPath, JSON.stringify(manifest));
    await assert.rejects(auditEdition(profile.stagingRoot), /LAUNCH_OR_DATA_PRESERVATION_INVALID/);
  }
}));

test('both edition audits reject admin modules outside the whitelist and licensed rejects even whitelisted modules', async () => fixture(async ({ root, configPath }) => {
  const developer = await prepareEdition(root), licensed = await prepareEdition(root, { edition: 'licensed', licenseConfigPath: configPath });
  await writeFile(path.join(developer.stagingRoot, 'tools/licensing/service.mjs'), 'export const forbidden = true;');
  await assert.rejects(auditEdition(developer.stagingRoot), /LINK_OR_SECRET_UNSAFE/);
  await mkdir(path.join(licensed.stagingRoot, 'tools/licensing'), { recursive: true });
  await writeFile(path.join(licensed.stagingRoot, 'tools/licensing/ui.mjs'), 'export const forbidden = true;');
  await assert.rejects(auditEdition(licensed.stagingRoot), /LINK_OR_SECRET_UNSAFE/);
}));

test('developer audit requires every admin module and checks current source hashes and private-key content', async () => fixture(async ({ root }) => {
  const profile = await prepareEdition(root);
  const manifest = JSON.parse(await readFile(profile.manifestPath, 'utf8'));
  const ui = 'tools/licensing/ui.mjs', source = path.join(root, ui), staged = path.join(profile.stagingRoot, ui);
  const original = await readFile(source, 'utf8');
  await writeFile(source, 'export const tampered = true;');
  await assert.rejects(auditEdition(profile.stagingRoot), /SOURCE_MISMATCH/);
  await writeFile(source, original);
  const missing = { ...manifest, copiedFiles: manifest.copiedFiles.filter(file => file.path !== ui) };
  await writeFile(profile.manifestPath, JSON.stringify(missing));
  await assert.rejects(auditEdition(profile.stagingRoot), /ADMIN_MISSING/);
  const secret = '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----';
  await writeFile(staged, secret);
  manifest.copiedFiles.find(file => file.path === ui).sha256 = createHash('sha256').update(secret).digest('hex');
  await writeFile(profile.manifestPath, JSON.stringify(manifest));
  await assert.rejects(auditEdition(profile.stagingRoot), /PRIVATE_KEY_CONTENT/);
}));

test('developer admin inputs must be regular unlinked files and cannot embed private keys', async () => fixture(async ({ root }) => {
  const ui = path.join(root, 'tools/licensing/ui.mjs');
  const linked = path.join(root, 'admin-hardlink.mjs');
  await link(ui, linked);
  await assert.rejects(prepareEdition(root), /FILE_UNSAFE/);
  await rm(linked);
  await writeFile(ui, '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----');
  await assert.rejects(prepareEdition(root), /PRIVATE_KEY_CONTENT/);
  await rm(ui); await mkdir(ui);
  await assert.rejects(prepareEdition(root), /FILE_UNSAFE/);
}));
test('licensed preparation rejects development, HTTP, private keys and linked config before staging', async () => fixture(async ({ root, configPath, config }) => {
  await assert.rejects(prepareEdition(root, { edition: 'licensed' }), /EXPLICIT_CONFIG/);
  await assert.rejects(prepareEdition(root, { edition: 'developer', licenseConfigPath: configPath }), /EDITION_INVALID/);
  await writeFile(configPath, JSON.stringify({ ...config, mode: 'development' }));
  await assert.rejects(readPublicLicenseConfig(configPath), /REQUIRED_CONFIG/);
  await writeFile(configPath, JSON.stringify({ ...config, serviceUrl: 'http://127.0.0.1:8787' }));
  await assert.rejects(readPublicLicenseConfig(configPath), { code: 'INVALID_LICENSE_CONFIG' });
  await writeFile(configPath, JSON.stringify({ ...config, privateKey: 'never ship a private key' }));
  await assert.rejects(readPublicLicenseConfig(configPath), { code: 'INVALID_LICENSE_CONFIG' });
  await writeFile(configPath, JSON.stringify(config));
  await link(configPath, path.join(root, 'hardlinked.json'));
  await assert.rejects(readPublicLicenseConfig(configPath), /FILE_UNSAFE/);
}));
test('staging rejects user data, secret content, source hard links and source junctions', async () => fixture(async ({ root }) => {
  const secret = path.join(root, 'frontend/signing-private.pem'); await writeFile(secret, 'private');
  await assert.rejects(prepareEdition(root), /SECRET_PATH/); await rm(secret);
  const source = path.join(root, 'frontend/index.html'), linked = path.join(root, 'frontend/hard-linked.html'); await link(source, linked);
  await assert.rejects(prepareEdition(root), /FILE_UNSAFE/); await rm(linked);
  const junction = path.join(root, 'frontend/linked'); await symlink(path.join(root, 'desktop'), junction, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(prepareEdition(root), /LINK_UNSAFE/); await rm(junction);
  const privateText = path.join(root, 'frontend/leak.txt'); await writeFile(privateText, '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----');
  await assert.rejects(prepareEdition(root), /PRIVATE_KEY_CONTENT/);
  await writeFile(privateText, JSON.stringify({ privateKey: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----' }));
  await assert.rejects(prepareEdition(root), /PRIVATE_KEY_CONTENT/);
}));
test('edition audit detects mode/key changes, modified embedded module and extra files', async () => fixture(async ({ root, configPath, config }) => {
  const profile = await prepareEdition(root, { edition: 'licensed', licenseConfigPath: configPath });
  await assert.rejects(auditEdition(profile.stagingRoot, { expectedEdition: 'developer' }), /EDITION_MISMATCH/);
  await assert.rejects(auditEdition(profile.stagingRoot, { expectedEdition: 'licensed', expectedLicenseConfig: { ...config, serviceUrl: 'https://other.example.com' } }), /PUBLIC_CONFIG_MISMATCH/);
  const module = path.join(profile.stagingRoot, 'desktop/distribution.mjs'), original = await readFile(module, 'utf8');
  await writeFile(module, original.replace('"mode":"required"', '"mode":"development"'));
  await assert.rejects(auditEdition(profile.stagingRoot, { expectedEdition: 'licensed' }), /MODULE_MISMATCH/);
  await writeFile(module, original); await writeFile(path.join(profile.stagingRoot, 'frontend/extra.html'), 'extra');
  await assert.rejects(auditEdition(profile.stagingRoot, { expectedEdition: 'licensed' }), /SOURCE_MISMATCH/);
}));
test('pnpm dependency junctions resolve only inside node_modules and stage ordinary dependency copies', async () => fixture(async ({ root }) => {
  const yamlModules = path.join(root, 'node_modules/.pnpm/js-yaml@4.3.2/node_modules');
  const argparseModules = path.join(root, 'node_modules/.pnpm/argparse@2.0.1/node_modules');
  await mkdir(yamlModules, { recursive: true }); await mkdir(argparseModules, { recursive: true });
  const yaml = path.join(yamlModules, 'js-yaml'), argparse = path.join(argparseModules, 'argparse');
  await rename(path.join(root, 'node_modules/js-yaml'), yaml); await rename(path.join(root, 'node_modules/argparse'), argparse);
  await symlink(yaml, path.join(root, 'node_modules/js-yaml'), process.platform === 'win32' ? 'junction' : 'dir');
  await symlink(argparse, path.join(yamlModules, 'argparse'), process.platform === 'win32' ? 'junction' : 'dir');
  const profile = await prepareEdition(root);
  for (const name of ['js-yaml', 'argparse']) {
    const target = path.join(profile.stagingRoot, 'node_modules', name);
    assert.equal((await lstat(target)).isSymbolicLink(), false); assert.equal((await lstat(path.join(target, 'package.json'))).nlink, 1);
  }
  assert.equal((await auditEdition(profile.stagingRoot, { expectedEdition: 'developer' })).edition, 'developer');
}));
test('dependency resolution refuses packages redirected outside project node_modules', async () => fixture(async ({ root }) => {
  const outside = path.join(root, 'external-js-yaml');
  await rename(path.join(root, 'node_modules/js-yaml'), outside);
  await symlink(outside, path.join(root, 'node_modules/js-yaml'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(prepareEdition(root), /DEPENDENCY_OUTSIDE_PROJECT/);
}));
test('validated dependency store hard links expand to ordinary staging copies while staging hard links fail audit', async () => fixture(async ({ root }) => {
  for (const name of ['js-yaml', 'argparse']) {
    const source = path.join(root, 'node_modules', name, 'package.json');
    await link(source, path.join(root, 'node_modules', `${name}-store-copy.json`));
    assert.equal((await lstat(source)).nlink, 2);
  }
  const profile = await prepareEdition(root);
  for (const name of ['js-yaml', 'argparse']) assert.equal((await lstat(path.join(profile.stagingRoot, 'node_modules', name, 'package.json'))).nlink, 1);
  await auditEdition(profile.stagingRoot, { expectedEdition: 'developer' });
  await link(path.join(profile.stagingRoot, 'node_modules/js-yaml/package.json'), path.join(path.dirname(profile.stagingRoot), 'stage-hardlink.json'));
  await assert.rejects(auditEdition(profile.stagingRoot, { expectedEdition: 'developer' }), /FILE_UNSAFE/);
}));
