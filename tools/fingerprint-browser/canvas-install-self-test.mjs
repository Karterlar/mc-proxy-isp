// Real public-component installation acceptance; no browser launch, packaging,
// customer files, VPN/ISP requests or host network/environment changes.
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { prepareFingerprintBrowserFromBundle } from '../../backend/src/fingerprint-browser-install.mjs';
import { FINGERPRINT_BROWSER_RELEASE as release, FINGERPRINT_BROWSER_UPSTREAM_RELEASE as upstream, FINGERPRINT_RECEIPT,
  fingerprintFileHash, fingerprintInventory, fingerprintInventoryHash, inspectFingerprintRuntime } from '../../backend/src/fingerprint-browser-runtime.mjs';
import { FINGERPRINT_CANVAS_FIX as fix } from '../../backend/src/fingerprint-canvas-fix.mjs';

const project = fileURLToPath(new URL('../../', import.meta.url));
const source = path.resolve(process.argv[2] || path.join(project, '.cache/fingerprint-browser'));
const cache = path.join(project, '.cache'); await mkdir(cache, { recursive: true });
const directory = await mkdtemp(path.join(await realpath(cache), 'canvas-install-acceptance-'));
const target = path.join(directory, 'public-component-canvas-r1');
const report = { startedAt: new Date().toISOString(), scope: 'public upstream component -> isolated corrected copy; synthetic legacy data only; no network, browser launch or packaging', checks: [], errors: [] };
const check = (name, passed, details) => { report.checks.push({ name, passed, ...(details ? { details } : {}) }); assert.ok(passed, name); };
const noTarget = async directory => { try { await access(directory); return false; } catch (cause) { if (cause.code === 'ENOENT') return true; throw cause; } };
const synthetic = new Map([
  ['runtime/config.json', Buffer.from('{"fixture":true,"listen":{"host":"127.0.0.1","port":17890},"mode":"global-tun"}\n')],
  ['runtime/licensing/customer-license.json', Buffer.from('synthetic legacy licence bytes; never a real licence\r\n')],
  [`runtime/browser-profiles/workspaces/${randomUUID()}/fingerprint/.mc-fingerprint.json`, Buffer.from('{"version":1,"seed":3324349380,"cores":8}\n')],
  ['runtime/browser-profiles/fingerprint/Default/Network/Cookies', Buffer.from([0, 17, 35, 255, 4, 0, 99])],
  ['runtime/.browser-workspaces/workspaces.json', Buffer.from('{"version":1,"items":[],"fixture":"old workspace index"}\n')],
  ['runtime/onboarding-preferences.json', Buffer.from('{"fingerprintNativeGraphics":false,"browser":"fingerprint","fixture":true}\n')],
]);
const oldFetch = globalThis.fetch; let networkCalls = 0;
globalThis.fetch = async () => { networkCalls++; throw new Error('Network is forbidden by this offline installation fixture.'); };
try {
  if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('This public-component acceptance requires Windows x64.');
  for (const [relative, bytes] of synthetic) { const file = path.join(directory, relative); await mkdir(path.dirname(file), { recursive: true }); await writeFile(file, bytes, { flag: 'wx' }); }
  const before = await inspectFingerprintRuntime(source, { full: true, release: upstream });
  check('source is the unchanged pinned public upstream component', before.state === 'ready' && before.verified === true && before.integrity === 'full');
  const sourceFiles = await fingerprintInventory(source), sourceReceipt = await readFile(path.join(source, FINGERPRINT_RECEIPT));
  check('upstream DLL matches the exact preimage digest', await fingerprintFileHash(path.join(source, fix.file)) === fix.originalSha256);
  check('uncorrected component is not accepted for ordinary browser launches', (await inspectFingerprintRuntime(source, { full: true })).state === 'invalid');

  const progress = [];
  const installed = await prepareFingerprintBrowserFromBundle(source, target, { onProgress: event => progress.push(event.status) });
  check('normal offline installer publishes the corrected isolated component', installed.installed === true && installed.verified === true && installed.revision === fix.revision && progress.at(-1) === 'installed');
  const fixed = await inspectFingerprintRuntime(target, { full: true });
  check('ordinary runtime inspection accepts the complete fixed inventory', fixed.state === 'ready' && fixed.verified === true && fixed.integrity === 'full');
  check('fixed DLL and complete resources match independent production pins', await fingerprintFileHash(path.join(target, fix.file)) === fix.fixedSha256 && fingerprintInventoryHash(await fingerprintInventory(target)) === release.inventorySha256);
  const receipt = JSON.parse(await readFile(path.join(target, FINGERPRINT_RECEIPT), 'utf8'));
  check('receipt identifies the local correction without changing the publisher archive pin', receipt.componentRevision === fix.revision && receipt.archiveSha256 === upstream.archiveSha256 && receipt.engineVersion === upstream.version);

  const reused = await prepareFingerprintBrowserFromBundle(path.join(directory, 'absent-bundle'), target);
  check('already-ready corrected component is reused even without its bundle', reused.installed === false && reused.verified === true && reused.revision === fix.revision);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(prepareFingerprintBrowserFromBundle(source, path.join(directory, 'pre-cancelled'), { signal: controller.signal }), { code: 'BROWSER_FINGERPRINT_INSTALL_CANCELLED' });
  check('pre-cancelled preparation publishes nothing', await noTarget(path.join(directory, 'pre-cancelled')));
  const copying = new AbortController(); let copyingBegan = false;
  await assert.rejects(prepareFingerprintBrowserFromBundle(source, path.join(directory, 'copy-cancelled'), { signal: copying.signal, onProgress: event => {
    if (event.status === 'copying-bundle' && event.receivedBytes > 0) { copyingBegan = true; copying.abort(); }
  } }), { code: 'BROWSER_FINGERPRINT_INSTALL_CANCELLED' });
  check('cancellation after copying starts leaves no target or staging directory', copyingBegan && await noTarget(path.join(directory, 'copy-cancelled')) && !(await readdir(directory)).some(name => name.startsWith('.fingerprint-stage-')));

  const unexpected = path.join(target, 'unexpected-fixture.dll');
  await writeFile(unexpected, 'synthetic unexpected dependency', { flag: 'wx' });
  try {
    check('an extra DLL makes full runtime verification fail closed', (await inspectFingerprintRuntime(target, { full: true })).errorCode === 'BROWSER_FINGERPRINT_FILES_CHANGED');
    await assert.rejects(prepareFingerprintBrowserFromBundle(source, target), { code: 'BROWSER_FINGERPRINT_FILES_CHANGED' });
    check('installer preserves an invalid existing component for inspection', await readFile(unexpected, 'utf8') === 'synthetic unexpected dependency');
  } finally { await rm(unexpected, { force: true }); }
  check('removing only the fixture extra DLL restores the fixed verification', (await inspectFingerprintRuntime(target, { full: true })).state === 'ready');
  for (const [relative, bytes] of synthetic) check(`synthetic legacy bytes preserved: ${relative}`, (await readFile(path.join(directory, relative))).equals(bytes));
  check('original component inventory and receipt are byte-for-byte unchanged', fingerprintInventoryHash(await fingerprintInventory(source)) === fingerprintInventoryHash(sourceFiles)
    && (await readFile(path.join(source, FINGERPRINT_RECEIPT))).equals(sourceReceipt));
  check('no installation branch made a network request', networkCalls === 0);
  report.component = { version: release.version, revision: release.revision, upstreamInventorySha256: upstream.inventorySha256, fixedInventorySha256: release.inventorySha256, fixedDllSha256: fix.fixedSha256 };
} catch (cause) {
  report.errors.push({ code: cause.code || 'CANVAS_INSTALL_ACCEPTANCE_FAILED', message: cause.message }); process.exitCode = 1;
} finally {
  globalThis.fetch = oldFetch;
  report.completedAt = new Date().toISOString();
  await writeFile(path.join(directory, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ output: directory, checks: report.checks.length, passed: report.checks.filter(item => item.passed).length, errors: report.errors }));
}
