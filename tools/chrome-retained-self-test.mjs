// Real headed Chrome acceptance through the production browser manager.
// CfT is a separately downloaded testing build, never the customer's installed
// Chrome. No CDP, injected browser shims, accounts or host network changes.
import assert from 'node:assert/strict';
import path from 'node:path';
import http from 'node:http';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdir, mkdtemp, readFile, writeFile, open, lstat, realpath, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createBrowserManager } from '../backend/src/browser-session.mjs';

const project = fileURLToPath(new URL('../', import.meta.url));
const engineRoot = path.join(project, '.cache', 'chrome-retained-acceptance-engine');
const metadataUrl = 'https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json';
const run = promisify(execFile);
const powershell = path.win32.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
// Codex's PowerShell 7 host exports its module directory. The production
// Windows PowerShell 5 subprocess must load Windows modules, not PS7 binaries.
// Scope this correction to this disposable harness process and its children.
if (process.platform === 'win32') process.env.PSModulePath = [path.win32.join(path.dirname(powershell), 'Modules'), path.win32.join(process.env.ProgramFiles || 'C:\\Program Files', 'WindowsPowerShell', 'Modules')].join(';');
const shell = async (script, input, timeout = 30000) => JSON.parse((await run(powershell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
  windowsHide: true, timeout, maxBuffer: 1048576, env: { ...process.env, MC_CHROME_ACCEPTANCE_INPUT: JSON.stringify(input) },
})).stdout.trim());
const sha256 = async file => createHash('sha256').update(await readFile(file)).digest('hex');
const inspectExecutable = executable => shell(String.raw`
$ErrorActionPreference='Stop'
$inputData=$env:MC_CHROME_ACCEPTANCE_INPUT|ConvertFrom-Json
$signature=Get-AuthenticodeSignature -LiteralPath $inputData.executable
$version=(Get-Item -LiteralPath $inputData.executable).VersionInfo
@{signatureStatus=[string]$signature.Status;signer=[string]$signature.SignerCertificate.Subject;signerThumbprint=[string]$signature.SignerCertificate.Thumbprint;productName=[string]$version.ProductName;companyName=[string]$version.CompanyName;productVersion=[string]$version.ProductVersion;fileVersion=[string]$version.FileVersion}|ConvertTo-Json -Compress
`, { executable });

async function prepareEngine() {
  assert.equal(process.platform, 'win32', 'Windows native manager acceptance only');
  await mkdir(engineRoot, { recursive: true });
  // Reuse the measured official testing build without a network request. A
  // refresh regression must work offline once this separate tool is prepared.
  const cachedVersions = (await readdir(engineRoot, { withFileTypes: true })).filter(item => item.isDirectory() && /^\d+\.\d+\.\d+\.\d+$/.test(item.name)).map(item => item.name).sort((left, right) => right.localeCompare(left, undefined, { numeric: true }));
  let version = cachedVersions[0], metadata;
  if (!version || process.argv.includes('--update-engine')) {
    const metadataResponse = await fetch(metadataUrl, { signal: AbortSignal.timeout(30000), redirect: 'error' });
    assert.ok(metadataResponse.ok, `official metadata HTTP ${metadataResponse.status}`);
    metadata = await metadataResponse.json(); version = metadata.channels?.Stable?.version;
  }
  assert.match(version, /^\d+\.\d+\.\d+\.\d+$/);
  const expectedUrl = `https://storage.googleapis.com/chrome-for-testing-public/${version}/win64/chrome-win64.zip`;
  if (metadata) assert.equal(metadata.channels.Stable.downloads.chrome.find(item => item.platform === 'win64')?.url, expectedUrl);
  const directory = path.join(engineRoot, version), archive = path.join(directory, 'chrome-win64.zip'), destination = path.join(directory, 'extracted');
  const executable = path.join(destination, 'chrome-win64', 'chrome.exe'), receiptFile = path.join(directory, 'receipt.json');
  await mkdir(directory, { recursive: true });
  let previous;
  try { previous = JSON.parse(await readFile(receiptFile, 'utf8')); } catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
  if (!previous) {
    assert.ok(metadata, 'Cached testing build has no receipt; explicitly use --update-engine to prepare it');
    const response = await fetch(expectedUrl, { signal: AbortSignal.timeout(180000), redirect: 'error' });
    assert.ok(response.ok && response.body, `official Chrome archive HTTP ${response.status}`);
    const expectedSize = Number(response.headers.get('content-length')); assert.ok(expectedSize > 1000000 && expectedSize < 500000000);
    const file = await open(archive, 'wx'), hash = createHash('sha256'); let size = 0;
    try { for await (const part of response.body) { size += part.length; assert.ok(size <= expectedSize); hash.update(part); await file.write(part); } }
    finally { await file.close(); }
    assert.equal(size, expectedSize);
    const archiveSha256 = hash.digest('hex');
    // Extraction is confined to the new version directory. Validate every ZIP
    // path before extraction; neither absolute paths nor traversal is allowed.
    const extraction = await shell(String.raw`
$ErrorActionPreference='Stop'
$inputData=$env:MC_CHROME_ACCEPTANCE_INPUT|ConvertFrom-Json
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[IO.Compression.ZipFile]::OpenRead($inputData.archive)
try {
 foreach($entry in $zip.Entries) {
  $entryName=$entry.FullName.Replace('\','/')
  if(-not $entryName.StartsWith('chrome-win64/') -or $entryName.Contains(':') -or @($entryName.Split('/')|Where-Object {$_ -eq '..' -or $_ -eq '.'}).Count -gt 0) {throw 'Unsafe ZIP path'}
 }
 $count=$zip.Entries.Count
} finally {$zip.Dispose()}
if(Test-Path -LiteralPath $inputData.destination) {throw 'Extraction destination already exists without a validated receipt'}
[IO.Compression.ZipFile]::ExtractToDirectory($inputData.archive,$inputData.destination)
@{entries=$count;extracted=$true}|ConvertTo-Json -Compress
`, { archive, destination }, 180000);
    assert.equal(extraction.extracted, true);
    const identity = await inspectExecutable(executable);
    assert.ok(['Valid', 'NotSigned'].includes(identity.signatureStatus), `Unexpected Authenticode status: ${identity.signatureStatus}`);
    if (identity.signatureStatus === 'Valid') assert.match(identity.signer, /(?:^|,\s*)O=Google LLC(?:,|$)/);
    assert.equal(identity.productName, 'Google Chrome for Testing'); assert.match(identity.companyName, /Google/i); assert.equal(identity.productVersion, version);
    previous = { metadataUrl, metadataTimestamp: metadata.timestamp, channel: 'Stable', product: 'Chrome for Testing; not installed user Chrome', authentication: identity.signatureStatus === 'Valid' ? 'Google Authenticode and official Google HTTPS archive' : 'official Google HTTPS metadata/archive; CfT executable is unsigned, no Authenticode publisher verification', version, archiveUrl: expectedUrl, archiveBytes: size, archiveSha256, archiveSha256Source: 'locally measured; CfT metadata supplies no publisher SHA256', executableSha256: await sha256(executable), extraction, identity, preparedAt: new Date().toISOString() };
    await writeFile(receiptFile, JSON.stringify(previous, null, 2) + '\n');
  }
  assert.equal(previous.version, version); assert.equal(previous.archiveUrl, expectedUrl);
  assert.equal((await lstat(archive)).size, previous.archiveBytes); assert.equal(await sha256(archive), previous.archiveSha256);
  assert.equal(await sha256(executable), previous.executableSha256);
  const identity = await inspectExecutable(executable);
  assert.equal(identity.signatureStatus, previous.identity.signatureStatus); assert.equal(identity.signerThumbprint, previous.identity.signerThumbprint); assert.equal(identity.productVersion, version);
  // Same narrow permission policy used by the existing verified engine
  // installer: sandbox processes may read public binaries, never user data.
  const publicDirectory = path.dirname(executable);
  assert.equal((await realpath(publicDirectory)).toLowerCase(), publicDirectory.toLowerCase());
  await run('icacls.exe', [publicDirectory, '/grant', '*S-1-15-2-1:(OI)(CI)RX', '*S-1-15-2-2:(OI)(CI)RX', '/T', '/C'], { windowsHide: true, timeout: 30000, maxBuffer: 1048576 });
  return { ...previous, executable, receiptFile, sandboxBinaryPermissions: 'read/execute for ALL APPLICATION PACKAGES and ALL RESTRICTED APPLICATION PACKAGES on this public test binary directory only; profile ACL unchanged' };
}

const engine = await prepareEngine();
if (process.argv.includes('--prepare-only')) { console.log(JSON.stringify(engine, null, 2)); process.exit(0); }
const directory = await mkdtemp(path.join(project, '.cache', 'chrome-retained-acceptance-'));
const runtimeRoot = path.join(directory, 'runtime'); await mkdir(runtimeRoot);
const reportFile = path.join(directory, 'report.json');
const refreshScenario = process.argv.includes('--profile-refresh');
const report = { startedAt: new Date().toISOString(), scenario: refreshScenario ? 'manual-profile-refresh-and-recovery' : 'retained-profile-reopen-and-workspace-isolation', engine, runtimeRoot, method: 'headed production manager; no CDP, Playwright, automation flags or API shims', boundaries: 'disposable profiles and localhost HTTP only; every proxy request outside local fixtures rejected; host proxy, TUN and firewall unchanged; no customer files or accounts', checks: [], observations: [], errors: [] };
const check = (name, passed, details) => { report.checks.push({ name, passed, ...(details ? { details } : {}) }); assert.ok(passed, name); };
const prefix = `/s/${randomBytes(24).toString('base64url')}/`;
let active, pending, manager, timer, observerRequests = 0, harnessPageChecks = 0, proxyRequests = 0, connectRequests = 0;
const proxyLog = [];

async function probe(sampleId, prefix, marker) {
  try {
    const cookieBefore = document.cookie.split('; ').find(value => value.startsWith('mc_retained='))?.slice('mc_retained='.length) || null;
    const localBefore = localStorage.getItem('mc_retained');
    document.cookie = `mc_retained=${marker}; Path=/; SameSite=Lax; Max-Age=3600`;
    localStorage.setItem('mc_retained', marker);
    const version = await navigator.userAgentData?.getHighEntropyValues(['uaFullVersion']);
    const routed = await fetch('http://mc-chrome-retained.invalid/ping', { cache: 'no-store' }).then(response => response.json());
    const blockedConnect = await fetch('https://mc-chrome-retained.invalid/ping', { cache: 'no-store' }).then(() => false, () => true);
    await fetch(prefix + 'report', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ sampleId, cookieBefore, localBefore, cookieAfter: document.cookie.includes(`mc_retained=${marker}`), localAfter: localStorage.getItem('mc_retained') === marker, webdriver: navigator.webdriver, userAgent: navigator.userAgent, browserVersion: version?.uaFullVersion, routed, blockedConnect }) });
    document.querySelector('p').textContent = 'Local verification complete. This disposable window will close automatically.';
  } catch (cause) { await fetch(prefix + 'report', { method: 'POST', body: JSON.stringify({ sampleId, error: String(cause) }) }); }
}
const observer = http.createServer(async (request, response) => {
  if (request.method === 'GET' && request.url === prefix && active) {
    if (/^Mozilla\//.test(request.headers['user-agent'] || '')) observerRequests++; else harnessPageChecks++;
    active.requestCookie = request.headers.cookie || '';
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    response.end(`<!doctype html><title>MC Proxy Chrome retained-profile acceptance</title><h1>Local Chrome verification</h1><p>Disposable profiles only. No customer account or public website.</p><script>(${probe.toString()})(${JSON.stringify(active.sampleId)},${JSON.stringify(prefix)},${JSON.stringify(active.marker)});</script>`); return;
  }
  if (request.method === 'POST' && request.url === prefix + 'report') {
    try {
      let body = ''; for await (const part of request) { body += part; assert.ok(body.length <= 16384); }
      const value = JSON.parse(body); assert.equal(value.sampleId, active?.sampleId); assert.ok(pending);
      response.writeHead(200).end(); pending.resolve(value); pending = null;
    } catch { response.writeHead(400).end(); } return;
  }
  response.writeHead(404).end();
});
const proxy = http.createServer((request, response) => {
  proxyRequests++;
  if (request.url === 'http://mc-chrome-retained.invalid/ping') { response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store', 'access-control-allow-origin': '*' }); response.end('{"route":"local-proxy-fixture"}'); return; }
  proxyLog.push({ kind: 'http', target: String(request.url).slice(0, 300), rejected: true }); response.writeHead(502).end();
});
proxy.on('connect', (request, socket) => { connectRequests++; proxyLog.push({ kind: 'connect', target: String(request.url).slice(0, 300), rejected: true }); socket.end('HTTP/1.1 502 Local acceptance rejected external connection\r\nConnection: close\r\n\r\n'); });
const sockets = new Set();
for (const server of [observer, proxy]) server.on('connection', socket => {
  sockets.add(socket); socket.once('close', () => sockets.delete(socket));
  // Normal browser shutdown may reset a rejected CONNECT socket. Preserve the
  // observation instead of letting the fixture crash with an unhandled event.
  socket.on('error', cause => { (report.fixtureSocketEvents ||= []).push({ code: cause.code || 'SOCKET_ERROR', message: cause.message }); });
});
const listen = server => new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => resolve(server.address().port)); });
const closeServer = server => new Promise(resolve => { server.closeAllConnections?.(); server.close(resolve); });
const observerPort = await listen(observer), port = await listen(proxy), observationUrl = `http://127.0.0.1:${observerPort}${prefix}`;
const options = { runtimeRoot, candidates: [{ id: 'chrome', executable: engine.executable }], closeTimeoutMs: 15000 };
const configFile = path.join(runtimeRoot, 'config.json'), authorizationFile = path.join(runtimeRoot, 'license.json');
await writeFile(configFile, 'disposable connection sentinel'); await writeFile(authorizationFile, 'disposable authorization sentinel');

async function sample({ workspaceId, marker, expected, label }) {
  manager = createBrowserManager(options);
  active = { sampleId: randomUUID(), marker, requestCookie: '' };
  const received = new Promise((resolve, reject) => { pending = { resolve }; timer = setTimeout(() => reject(new Error(`Local observation timed out: ${label}`)), 45000); }); received.catch(() => {});
  try {
    const plan = await manager.plan({ browser: 'chrome', service: 'observation', observationUrl, observationPort: observerPort, workspaceId, port, language: 'en-US', fresh: false });
    check(`${label}: no fingerprint, automation, remote-debug or weakened sandbox flags`, !plan.fingerprint && !plan.args.some(arg => /^--(?:fingerprint|disable-spoofing|timezone|enable-automation|remote-debugging|no-sandbox|disable-web-security|ignore-certificate-errors)(?:=|$)/.test(arg)));
    const pageCheck = await fetch(observationUrl, { signal: AbortSignal.timeout(5000) });
    check(`${label}: exact token observation URL serves local fixture HTML`, pageCheck.ok && (await pageCheck.text()).includes('MC Proxy Chrome retained-profile acceptance'));
    await manager.launch(plan);
    const initialManifest = JSON.parse(await readFile(path.join(runtimeRoot, 'browser-session.json'), 'utf8'));
    const nativeWindow = await shell(String.raw`
$ErrorActionPreference='Stop'
$inputData=$env:MC_CHROME_ACCEPTANCE_INPUT|ConvertFrom-Json
$current=Get-CimInstance Win32_Process -Filter ('ProcessId = '+[int]$inputData.identity.pid)
if($current.ExecutablePath -ine $inputData.identity.executable -or $current.CommandLine -cne $inputData.identity.commandLine) {throw 'Owned process identity changed'}
$native=Get-Process -Id ([int]$inputData.identity.pid)
$all=@(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'")
$owned=@($current)
do {
 $added=@($all|Where-Object {$_.ExecutablePath -ieq $inputData.identity.executable -and $owned.ProcessId -contains $_.ParentProcessId -and $owned.ProcessId -notcontains $_.ProcessId})
 $owned+=@($added)
} while ($added.Count -gt 0)
$tree=@($owned|ForEach-Object {@{pid=[int]$_.ProcessId;parentPid=[int]$_.ParentProcessId;creationTime=$_.CreationDate.ToUniversalTime().ToString('o');commandLine=[string]$_.CommandLine;executable=[string]$_.ExecutablePath}})
@{pid=[int]$native.Id;windowTitle=[string]$native.MainWindowTitle;windowHandle=[string]$native.MainWindowHandle;responding=[bool]$native.Responding;commandLine=[string]$current.CommandLine;processTree=$tree}|ConvertTo-Json -Depth 4 -Compress
`, { identity: initialManifest.identity });
    (report.launchDiagnostics ||= []).push({ label, plan, nativeWindow });
    console.log(`Chrome owned window: ${label}; title=${JSON.stringify(nativeWindow.windowTitle)}; handle=${nativeWindow.windowHandle}`);
    const value = await received; assert.ok(!value.error, value.error);
    const status = await manager.status(), manifest = JSON.parse(await readFile(path.join(runtimeRoot, 'browser-session.json'), 'utf8'));
    check(`${label}: production manager proves native PID, executable, profile and creation identity`, status.managed === true && status.browser === 'chrome' && manifest.identity?.pid > 0 && manifest.identity.executable.toLowerCase() === engine.executable.toLowerCase());
    check(`${label}: Cookie and localStorage match expected prior state`, value.cookieBefore === expected && value.localBefore === expected);
    check(`${label}: server Cookie header independently matches persisted state`, expected ? active.requestCookie.includes(`mc_retained=${expected}`) : !active.requestCookie.includes('mc_retained='));
    check(`${label}: persistent Cookie and localStorage write succeeds`, value.cookieAfter && value.localAfter);
    check(`${label}: native product version is truthful and webdriver is false`, value.browserVersion === engine.version && value.webdriver === false);
    check(`${label}: HTTP proxy fixture and blocked HTTPS CONNECT work`, value.routed.route === 'local-proxy-fixture' && value.blockedConnect);
    const observation = { label, sampleId: active.sampleId, workspaceId: workspaceId || null, profile: plan.profile, cookieBefore: value.cookieBefore, localBefore: value.localBefore, browserVersion: value.browserVersion, userAgent: value.userAgent, webdriver: value.webdriver, identity: manifest.identity };
    report.observations.push(observation);
    const closed = await manager.close(); check(`${label}: verified normal close succeeds`, closed.closed === true && (await manager.status()).running === false);
    manager = null; await writeFile(reportFile, JSON.stringify(report, null, 2) + '\n'); console.log(`Completed Chrome sample: ${label}`); return observation;
  } finally { clearTimeout(timer); pending = null; }
}
try {
  const globalMarker = randomBytes(12).toString('hex'), firstMarker = randomBytes(12).toString('hex'), secondMarker = randomBytes(12).toString('hex');
  const firstId = randomUUID(), secondId = randomUUID();
  if (refreshScenario) {
    const initial = await sample({ label: 'before-refresh-old-default', marker: globalMarker, expected: null });
    const sentinel = '.mc-acceptance-preserved-data.txt';
    const oldBytes = Buffer.from(`old disposable profile ${randomUUID()}\n`, 'utf8'), newBytes = Buffer.from(`new disposable profile ${randomUUID()}\n`, 'utf8');
    await writeFile(path.join(initial.profile, sentinel), oldBytes, { flag: 'wx' });
    const workspace = await sample({ label: 'independent-workspace-before-refresh', workspaceId: firstId, marker: firstMarker, expected: null });
    manager = createBrowserManager(options);
    const before = await manager.profileArchives({ browser: 'chrome' });
    check('archive listing detects the existing default profile and starts empty', before.browser === 'chrome' && before.currentAvailable === true && before.archives.length === 0);
    const refreshed = await manager.refreshProfile({ browser: 'chrome', confirm: true });
    report.profileRefresh = refreshed;
    check('explicit refresh archives old profile and reports the new retained state', refreshed.changed === true && typeof refreshed.archiveId === 'string' && refreshed.archiveId.length > 0 && refreshed.archives.some(item => item.id === refreshed.archiveId));
    const archivePath = archiveId => {
      assert.match(archiveId, /^[a-zA-Z0-9_-]+$/);
      return path.join(runtimeRoot, 'browser-profiles', 'archive', 'chrome', archiveId, 'profile');
    };
    const oldArchive = archivePath(refreshed.archiveId);
    check('old profile bytes remain in the archive and are not copied into the fresh profile', (await readFile(path.join(oldArchive, sentinel))).equals(oldBytes) && await readFile(path.join(initial.profile, sentinel)).then(() => false, cause => { if (cause.code === 'ENOENT') return true; throw cause; }));
    const archives = await manager.profileArchives({ browser: 'chrome' });
    check('archived old profile remains selectable with a valid timestamp', archives.archives.some(item => item.id === refreshed.archiveId && Number.isFinite(Date.parse(item.createdAt))));
    manager = null;
    const blank = await sample({ label: 'after-refresh-new-default', marker: secondMarker, expected: null });
    check('refresh keeps the canonical default profile path', blank.profile === initial.profile);
    await writeFile(path.join(blank.profile, sentinel), newBytes, { flag: 'wx' });
    const retained = await sample({ label: 'refreshed-default-reopened', marker: secondMarker, expected: secondMarker });
    check('the newly refreshed profile remains fixed on later launches', retained.profile === initial.profile);
    manager = createBrowserManager(options);
    const restored = await manager.restoreProfile({ browser: 'chrome', archiveId: refreshed.archiveId, confirm: true });
    report.profileRestore = restored;
    check('explicit recovery restores the selected archive and archives current data', restored.restored === true && typeof restored.archivedCurrentId === 'string' && restored.archivedCurrentId !== refreshed.archiveId && restored.archives.some(item => item.id === restored.archivedCurrentId));
    check('recovery preserves both old restored bytes and the newer archived bytes', (await readFile(path.join(initial.profile, sentinel))).equals(oldBytes) && (await readFile(path.join(archivePath(restored.archivedCurrentId), sentinel))).equals(newBytes));
    manager = null;
    const recovered = await sample({ label: 'recovered-old-default', marker: globalMarker, expected: globalMarker });
    check('recovery preserves the canonical path and the old website state', recovered.profile === initial.profile);
    const unaffected = await sample({ label: 'independent-workspace-after-recovery', workspaceId: firstId, marker: firstMarker, expected: firstMarker });
    check('default refresh and recovery leave the named workspace path and state intact', unaffected.profile === workspace.profile && workspace.profile !== initial.profile);
  } else {
    const initial = await sample({ label: 'retained-default-first', marker: globalMarker, expected: null });
    const reopened = await sample({ label: 'retained-default-reopened', marker: globalMarker, expected: globalMarker });
    check('default retained profile path stays fixed after normal close and new manager', initial.profile === reopened.profile);
    const first = await sample({ label: 'workspace-A-first', workspaceId: firstId, marker: firstMarker, expected: null });
    const again = await sample({ label: 'workspace-A-reopened', workspaceId: firstId, marker: firstMarker, expected: firstMarker });
    check('named workspace path stays fixed after close and manager restart', first.profile === again.profile);
    const other = await sample({ label: 'workspace-B-isolated', workspaceId: secondId, marker: secondMarker, expected: null });
    check('different named workspace and default have distinct paths', new Set([first.profile, other.profile, initial.profile]).size === 3);
    await sample({ label: 'workspace-A-after-B', workspaceId: firstId, marker: firstMarker, expected: firstMarker });
  }
  check('connection and authorization sentinels are byte-identical', await readFile(configFile, 'utf8') === 'disposable connection sentinel' && await readFile(authorizationFile, 'utf8') === 'disposable authorization sentinel');
  check('each local page used its narrow observer bypass and HTTP proxy', observerRequests === 6 && proxyRequests >= 6 && connectRequests >= 6);
} catch (cause) { report.errors.push({ code: cause.code || 'ACCEPTANCE_FAILED', message: cause.message }); process.exitCode = 1; }
finally {
  clearTimeout(timer); pending = null;
  if (manager) { try { report.finalClose = await manager.close(); } catch (cause) { report.errors.push({ code: cause.code || 'CLEANUP_FAILED', message: cause.message }); process.exitCode = 1; } }
  try {
    const recorded = (report.launchDiagnostics || []).flatMap(item => item.nativeWindow.processTree || []);
    const remaining = await shell(String.raw`
$ErrorActionPreference='Stop'
$inputData=$env:MC_CHROME_ACCEPTANCE_INPUT|ConvertFrom-Json
$remaining=@()
foreach($prior in $inputData.processes) {
 $live=Get-CimInstance Win32_Process -Filter ('ProcessId = '+[int]$prior.pid)
 if($live -and $live.ExecutablePath -ieq $prior.executable -and $live.CommandLine -ceq $prior.commandLine -and $live.CreationDate.ToUniversalTime().ToString('o') -ceq $prior.creationTime) {$remaining+=@{pid=[int]$live.ProcessId;creationTime=$prior.creationTime}}
}
ConvertTo-Json -InputObject @($remaining) -Compress
`, { processes: recorded });
    report.remainingOwnedProcesses = remaining;
    check('all recorded owned Chrome processes have exited without matching unrelated PIDs', remaining.length === 0, remaining);
  } catch (cause) { report.errors.push({ code: cause.code || 'PROCESS_CLEANUP_CHECK_FAILED', message: cause.message }); process.exitCode = 1; }
  for (const socket of sockets) socket.destroy();
  await closeServer(observer); await closeServer(proxy);
  report.network = { observerRequests, harnessPageChecks, proxyRequests, connectRequests, rejectedRequests: proxyLog };
  report.finishedAt = new Date().toISOString(); report.summary = { passed: report.checks.filter(item => item.passed).length, failed: report.checks.filter(item => !item.passed).length, errors: report.errors.length };
  await writeFile(reportFile, JSON.stringify(report, null, 2) + '\n'); console.log(JSON.stringify({ reportFile, ...report.summary }));
}
