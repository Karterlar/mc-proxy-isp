import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { signingEnvironment, forbiddenEntry, executableLevel, executableIconMatches, missingFrontendEntries, requiredFrontendFiles, resourceIncluded, DEVELOPER_ADMIN_FILES, missingAdminEntries, containsPrivateKey, validateDeliverySettings } from './audit.mjs';

function executableResource(type, data) {
  const resourceSize = 88 + data.length, rawSize = Math.ceil(resourceSize / 512) * 512, bytes = Buffer.alloc(512 + rawSize);
  bytes.write('MZ'); bytes.writeUInt32LE(0x80, 0x3c); bytes.write('PE\0\0', 0x80);
  bytes.writeUInt16LE(0x8664, 0x84); bytes.writeUInt16LE(1, 0x86); bytes.writeUInt16LE(240, 0x94); bytes.writeUInt16LE(0x20b, 0x98);
  bytes.writeUInt32LE(0x1000, 0x98 + 112 + 16); bytes.writeUInt32LE(resourceSize, 0x98 + 112 + 20);
  const section = 0x98 + 240;
  bytes.write('.rsrc', section); bytes.writeUInt32LE(resourceSize, section + 8); bytes.writeUInt32LE(0x1000, section + 12); bytes.writeUInt32LE(rawSize, section + 16); bytes.writeUInt32LE(512, section + 20);
  for (const offset of [0, 24, 48]) bytes.writeUInt16LE(1, 512 + offset + 14);
  bytes.writeUInt32LE(type, 528); bytes.writeUInt32LE(0x80000000 + 24, 532);
  bytes.writeUInt32LE(1, 552); bytes.writeUInt32LE(0x80000000 + 48, 556);
  bytes.writeUInt32LE(1033, 576); bytes.writeUInt32LE(72, 580);
  bytes.writeUInt32LE(0x1000 + 88, 584); bytes.writeUInt32LE(data.length, 588); data.copy(bytes, 600);
  return bytes;
}

test('delivery audit rejects private data, tests, keys, and credentials', () => {
  for (const value of ['.license/device.json', '.licensing/admin.json', 'tools/licensing/admin.mjs', 'licenses/billing.sqlite', 'licenses/billing.db-wal', 'frontend/card-once.json', 'desktop/license-state.json', 'backend/src/device-key.json']) assert.equal(forbiddenEntry(value), true, value);
  for (const value of ['backend/runtime/config.json', 'runtime/.network-lock/journal.json', 'enrollment.json', 'owner-device-01.json', 'accounts.json', 'client.secrets.env', 'LightsailDefaultKey.pem', 'desktop/test/main.test.mjs', 'profiles/Default/Cookies', 'tools/test-fixtures/test-key.pem', '.cache/desktop.log']) assert.equal(forbiddenEntry(value), true, value);
  for (const value of ['backend/src/config.mjs', 'node_modules/js-yaml/LICENSE', 'licenses/sing-box-LICENSE.txt', 'offline-chain-test/Repair-Network.ps1']) assert.equal(forbiddenEntry(value), false, value);
});

test('developer admin exception is limited to exact module paths while all licensed admin implementations remain forbidden', () => {
  for (const file of DEVELOPER_ADMIN_FILES) {
    assert.equal(forbiddenEntry(file, 'developer'), false, file);
    assert.equal(forbiddenEntry(`/${file}`, 'developer'), false, file);
    assert.equal(forbiddenEntry(file, 'licensed'), true, file);
  }
  assert.equal(forbiddenEntry('tools/licensing', 'developer'), false);
  for (const file of ['tools/licensing/service.mjs', 'tools/licensing/ui.test.mjs', 'tools/licensing/UI.mjs', 'tools/licensing/sub/ui.mjs', 'resources/tools/licensing/ui.mjs', 'tools/licensing/signing-private.pem', 'tools/licensing/billing.db', 'tools/licensing/card-once.json']) assert.equal(forbiddenEntry(file, 'developer'), true, file);
  assert.deepEqual(missingAdminEntries(DEVELOPER_ADMIN_FILES.map(file => `/${file}`), 'developer'), []);
  assert.deepEqual(missingAdminEntries([], 'licensed'), []);
  for (const file of DEVELOPER_ADMIN_FILES) assert.deepEqual(missingAdminEntries(DEVELOPER_ADMIN_FILES.filter(entry => entry !== file), 'developer'), [file]);
});

test('module secret scan rejects embedded PEM keys without rejecting code that generates private keys', () => {
  assert.equal(containsPrivateKey(Buffer.from('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----')), true);
  assert.equal(containsPrivateKey(Buffer.from(JSON.stringify({ privateKey: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----' }))), true);
  assert.equal(containsPrivateKey(Buffer.from("export const header = '-----BEGIN PRIVATE KEY-----';")), false);
});
test('resource filters keep notices but exclude the external licensing mode template', () => {
  const filters = ['*.txt', '*.json', '!client-license-config.json'];
  assert.equal(resourceIncluded('THIRD-PARTY-NOTICES.txt', filters), true);
  assert.equal(resourceIncluded('core-provenance.json', filters), true);
  assert.equal(resourceIncluded('client-license-config.json', filters), false);
  assert.equal(resourceIncluded('signing-private.pem', filters), false);
});
test('signing checks expose booleans only', () => {
  const result = signingEnvironment({ CSC_LINK: 'private-certificate-location', CSC_KEY_PASSWORD: 'never-print-secret' });
  assert.equal(result.CSC_LINK, true); assert.equal(result.CSC_KEY_PASSWORD, true); assert.equal(result.WIN_CSC_LINK, false);
  assert(!JSON.stringify(result).includes('secret')); assert(Object.values(result).every(value => typeof value === 'boolean'));
});
test('actual executable manifests distinguish normal and administrator launch', () => {
  for (const encoding of ['utf8', 'utf16le']) for (const level of ['asInvoker', 'highestAvailable', 'requireAdministrator']) assert.equal(executableLevel(executableResource(24, Buffer.from(`<requestedExecutionLevel level="${level}" uiAccess="false"/>`, encoding))), level);
  assert.equal(executableLevel(Buffer.from('MZ no verifiable manifest')), 'unverified');
  const actual = executableResource(24, Buffer.from('<requestedExecutionLevel level="asInvoker"/>'));
  assert.equal(executableLevel(Buffer.concat([actual, Buffer.from('<requestedExecutionLevel level="requireAdministrator"/>')])), 'asInvoker');
  assert.equal(executableLevel(Buffer.concat([executableResource(3, Buffer.from('icon')), Buffer.from('<requestedExecutionLevel level="requireAdministrator"/>')])), 'unverified');
  for (const truncated of [actual.subarray(0, 100), actual.subarray(0, 520)]) assert.equal(executableLevel(truncated), 'unverified');
});

test('executable icon checks inspect native icon resources rather than an appended payload', () => {
  const image = Buffer.from('icon-image-payload'), ico = Buffer.alloc(22 + image.length);
  ico.writeUInt16LE(1, 2); ico.writeUInt16LE(1, 4); ico.writeUInt32LE(image.length, 14); ico.writeUInt32LE(22, 18); image.copy(ico, 22);
  assert.equal(executableIconMatches(executableResource(3, image), ico), true);
  assert.equal(executableIconMatches(Buffer.concat([executableResource(3, Buffer.from('other')), ico]), ico), false);
  assert.equal(executableIconMatches(Buffer.from('MZ'), ico), false);
  assert.equal(executableIconMatches(executableResource(3, image), ico.subarray(0, 21)), false);
});
test('delivery audit rejects missing UI resources even when every included file matches its source', () => {
  const files = [...requiredFrontendFiles];
  assert.deepEqual(missingFrontendEntries(files.map(file => `/${file}`)), []);
  assert.deepEqual(missingFrontendEntries(files.map(file => `\\${file.replaceAll('/', '\\')}`)), []);
  for (const file of requiredFrontendFiles) {
    assert.deepEqual(missingFrontendEntries(files.filter(included => included !== file)), [file]);
  }
});
test('installation remains per-user and preserves recovery data without killing processes', async () => {
  const pkg = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.build.win.requestedExecutionLevel, 'asInvoker');
  assert.equal(pkg.build.nsis.perMachine, false); assert.equal(pkg.build.nsis.deleteAppDataOnUninstall, false);
  assert.equal(pkg.build.portable.requestExecutionLevel, 'user'); assert.equal(pkg.build.nsis.runAfterFinish, false); assert.equal(pkg.build.nsis.allowElevation, true);
  validateDeliverySettings(pkg);
  for (const [section, key, bad] of [['win', 'requestedExecutionLevel', 'requireAdministrator'], ['portable', 'requestExecutionLevel', 'admin'], ['nsis', 'perMachine', true], ['nsis', 'deleteAppDataOnUninstall', true]]) {
    const tampered = structuredClone(pkg); tampered.build[section][key] = bad;
    assert.throws(() => validateDeliverySettings(tampered), /LAUNCH_OR_DATA_PRESERVATION_INVALID/);
  }
  for (const key of ['nsis', 'portable']) assert(pkg.build[key].artifactName.includes('unsigned-test'));
  for (const file of ['frontend/admin-required.html', 'frontend/admin-required.css', 'frontend/admin-required.js', 'desktop/admin-preload.cjs']) assert(requiredFrontendFiles.includes(file), file);
  assert(pkg.build.files.includes('desktop/admin-preload.cjs'));
  const installer = await readFile(new URL('./installer.nsh', import.meta.url), 'utf8');
  assert(installer.includes('customCheckAppRunning')); assert(installer.includes('SetErrorLevel 1602'));
  assert(installer.includes('customUnInit')); assert(installer.includes('--delete-app-data'));
  assert(!/KillProcess|Stop-Process|taskkill|RMDir/i.test(installer)); assert(installer.includes('recovery-tools'));
  assert(installer.includes('$APPDATA\\${PRODUCT_NAME}\\recovery-tools'));
  assert(!installer.includes('$APPDATA\\MC Proxy\\recovery-tools'));
});
test('ordinary delivery does not compile or ship the isolated network-lock experiment', async () => {
  const pkg = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  assert(!pkg.build.extraResources.some(resource => /network-lock/i.test(resource.from + '/' + resource.to)));
  const build = await readFile(new URL('./build.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(build, /compile-helper|MCProxy\.NetworkLock|NETWORK_LOCK_BUILD/);
  const audit = await readFile(new URL('./audit.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(audit, /network-lock\/provenance|auditNetworkLockInputs|missingNetworkLockEntries/);
});
