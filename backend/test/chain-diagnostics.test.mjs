import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate, createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm, readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import tls from 'node:tls';
import net from 'node:net';
import { once } from 'node:events';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { createChainDiagnosticManifest, classifyChainFailure } from '../src/chain-diagnostics.mjs';
import { relayCertificate } from './relay-fixture.mjs';
import { parseWindowsCommandLine } from '../src/windows-process.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const run = promisify(execFile);
const config = {
  relay: { type: 'http', host: '192.0.2.8', port: 443, auth: 'password', tls: { enabled: true, serverName: 'localhost', certificate: relayCertificate } },
  upstream: { type: 'socks', host: 'isp.test', port: 1234, auth: 'password', username: 'MUST_NOT_EXPORT_USERNAME', password: 'MUST_NOT_EXPORT_PASSWORD' },
  listen: { host: '127.0.0.1', port: 17890 },
  probe: { expectedExitIps: ['203.0.113.8'] },
};

test('diagnostics export uses current relay DER fingerprint and never serializes secrets or certificate', () => {
  const manifest = createChainDiagnosticManifest({ config, corePath: path.join(root, 'core', 'sing-box.exe'), runtimeRoot: path.join(root, 'runtime'), appPath: path.join(root, 'MC Proxy.exe') });
  assert.equal(manifest.relay.certificateSha256, createHash('sha256').update(new X509Certificate(relayCertificate).raw).digest('hex').toUpperCase());
  assert.equal(manifest.isp.configured, true);
  assert.equal(manifest.recovery.firewallDirectory, path.join(root, 'runtime', '.network-lock'));
  assert.equal(manifest.recovery.automaticUnlock, false);
  assert.doesNotMatch(JSON.stringify(manifest), /MUST_NOT_EXPORT|BEGIN CERTIFICATE|ISP_PASSWORD|ISP_USERNAME/);
  assert.equal(manifest.runtime.wintunPath, null);
  assert.equal(manifest.runtime.wintunDelivery, 'embedded-in-core');
  assert.equal(manifest.connectionMode, 'relay');
  assert.equal(manifest.runtime.transportMode, 'tun');
});

test('VPN compatibility export omits even stale relay metadata and gives no TUN or VPN-off instructions', () => {
  const manifest = createChainDiagnosticManifest({ config: { ...config, connectionMode: 'vpn-compat' }, lastFailure: { code: 'RELAY_TIMEOUT' } });
  assert.equal(manifest.connectionMode, 'vpn-compat'); assert.equal(manifest.relay, null);
  assert.equal(manifest.runtime.transportMode, 'http'); assert.equal(manifest.runtime.wintunDelivery, 'not-applicable');
  assert.equal(manifest.isp.host, config.upstream.host); assert.deepEqual(manifest.expectedExitIps, config.probe.expectedExitIps);
  assert.match(manifest.lastFailure.action, /保持外部 VPN 开启/);
  assert.doesNotMatch(JSON.stringify(manifest), /192\.0\.2\.8|certificateSha256|MUST_NOT_EXPORT|确认已关闭其他 VPN/);
  assert.match(manifest.limitations.join(' '), /Keep the external VPN enabled/);
  assert.throws(() => createChainDiagnosticManifest({ config: { ...config, connectionMode: 'unknown' } }), { code: 'DIAGNOSTICS_INVALID' });
});

test('imported VPN diagnostics describe local HTTP scope without exposing node or YAML credentials', () => {
  const manifest = createChainDiagnosticManifest({ config: { ...config, connectionMode: 'vpn-import', vpnNode: { uuid: 'PRIVATE_VPN_UUID', server: 'private-node.invalid', tls: { reality: { public_key: 'PRIVATE_REALITY_KEY', short_id: 'PRIVATE_SHORT_ID' } } }, rawYaml: 'PRIVATE_RAW_YAML' }, lastFailure: { code: 'RELAY_TIMEOUT', message: 'PRIVATE_VPN_UUID' } });
  assert.equal(manifest.connectionMode, 'vpn-import'); assert.equal(manifest.relay, null);
  assert.equal(manifest.runtime.transportMode, 'http'); assert.equal(manifest.runtime.wintunDelivery, 'not-applicable');
  assert.deepEqual(manifest.expectedExitIps, config.probe.expectedExitIps);
  assert.match(manifest.lastFailure.action, /无需运行外部 VPN/);
  assert.match(manifest.limitations.join(' '), /No external VPN is required/);
  assert.match(manifest.limitations.join(' '), /Only applications configured to use the local HTTP proxy/);
  assert.doesNotMatch(JSON.stringify(manifest), /PRIVATE_|private-node\.invalid|MUST_NOT_EXPORT|192\.0\.2\.8|Keep the external VPN enabled|确认已关闭其他 VPN/);
});

test('missing provider and relay remain explicit, without old demo addresses or invented readiness', () => {
  const manifest = createChainDiagnosticManifest({});
  assert.equal(manifest.isp.configured, false);
  assert.equal(manifest.relay, null);
  assert.equal(manifest.localProxy.port, null);
  assert.deepEqual(manifest.expectedExitIps, []);
});

test('manifest fails closed for missing pin source, hostname entry or relative executable', () => {
  for (const relay of [{ ...config.relay, host: 'relay.test' }, { ...config.relay, tls: { ...config.relay.tls, certificate: '' } }]) {
    assert.throws(() => createChainDiagnosticManifest({ config: { ...config, relay } }), { code: 'DIAGNOSTICS_INVALID' });
  }
  assert.throws(() => createChainDiagnosticManifest({ config, corePath: 'relative.exe' }), { code: 'DIAGNOSTICS_INVALID' });
  assert.throws(() => createChainDiagnosticManifest({ config, appPath: path.join(root, 'bad.cmd') }), { code: 'DIAGNOSTICS_INVALID' });
});

test('failure diagnosis distinguishes stages only when structured evidence supplies the stage', () => {
  assert.equal(classifyChainFailure({ statusCode: 407 }, 'relay').code, 'RELAY_AUTH_REJECTED');
  assert.equal(classifyChainFailure({ statusCode: 407 }, 'isp').code, 'ISP_AUTH_REJECTED');
  assert.equal(classifyChainFailure({ code: 'PROXY_CONNECT_REJECTED', message: 'isp password=secret' }).code, 'CHAIN_CONNECT_REJECTED_UNKNOWN_STAGE');
  assert.equal(classifyChainFailure({ code: 'ERR_TLS_CERT_ALTNAME_INVALID' }, 'relay').code, 'RELAY_CERTIFICATE_REJECTED');
  assert.equal(classifyChainFailure({ code: 'ETIMEDOUT' }, 'isp').code, 'ISP_TIMEOUT');
  const manifest = createChainDiagnosticManifest({ config, lastFailure: { code: 'nonsense', message: 'SECRET_TOKEN' } });
  assert.equal(manifest.lastFailure.historical, true);
  assert.doesNotMatch(JSON.stringify(manifest), /SECRET_TOKEN/);
});

test('PowerShell 5.1 portable helpers compile and preserve empty/single IP arrays', { skip: process.platform !== 'win32', timeout: 30000 }, async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'mc-proxy-diagnostics-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const script = path.join(root, 'tools', 'offline-chain-test', 'Test-ChainReadiness.ps1');
  const manifestFile = path.join(directory, 'manifest.json');
  await writeFile(manifestFile, JSON.stringify(createChainDiagnosticManifest({ config })));
  const quote = text => `'${text.replaceAll("'", "''")}'`;
  const code = `
. ${quote(script)} -LibraryOnly
Initialize-Transport
$manifest = Read-Manifest ${quote(manifestFile)}
$route = [pscustomobject]@{ errors=@(); bestRoute=[pscustomobject]@{physicalAdapter=$true;interfaceIndex=1;nextHop='192.168.1.1';destinationPrefix='0.0.0.0/0';sourceAddress='192.168.1.2'} }
@{ expectedCount=@($manifest.expectedExitIps).Count; correctRoute=(Compare-PhysicalRoute $route $route '192.168.1.2'); wrongRoute=(Compare-PhysicalRoute $route $route '172.20.1.2'); ip=(Read-ExitIp 'ipify' '{"ip":"203.0.113.8"}'); restricted=(Get-ServiceAssessment 403 $true); auth=(Get-ServiceAssessment 401 $true) } | ConvertTo-Json -Compress
`;
  const result = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(code, 'utf16le').toString('base64')], { windowsHide: true, timeout: 25000 });
  const parsed = JSON.parse(result.stdout.trim());
  assert.equal(parsed.expectedCount, 1);
  assert.equal(parsed.correctRoute, true);
  assert.equal(parsed.wrongRoute, false);
  assert.equal(parsed.ip, '203.0.113.8');
  assert.equal(parsed.restricted, 'reachable-access-restricted');
  assert.equal(parsed.auth, 'reachable-authentication-required');
  await writeFile(manifestFile, JSON.stringify(createChainDiagnosticManifest({})));
  const empty = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(`. ${quote(script)} -LibraryOnly; @( (Read-Manifest ${quote(manifestFile)}).expectedExitIps ).Count`, 'utf16le').toString('base64')], { windowsHide: true, timeout: 10000 });
  assert.equal(empty.stdout.trim(), '0');
  const legacy = createChainDiagnosticManifest({ config }); delete legacy.connectionMode;
  await writeFile(manifestFile, JSON.stringify(legacy));
  const old = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(`. ${quote(script)} -LibraryOnly; $manifest=Read-Manifest ${quote(manifestFile)}; Get-Field $manifest 'connectionMode' 'relay'`, 'utf16le').toString('base64')], { windowsHide: true, timeout: 10000 });
  assert.equal(old.stdout.trim(), 'relay');
});

test('portable TUN scripts skip both HTTP VPN modes before any network or core checks', { skip: process.platform !== 'win32', timeout: 30000 }, async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'mc-proxy-vpn-diagnostics-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const script = path.join(directory, 'Test-ChainReadiness.ps1');
  await writeFile(script, await readFile(path.join(root, 'tools/offline-chain-test/Test-ChainReadiness.ps1'), 'utf8'));
  const manifestFile = path.join(directory, 'manifest.json');
  for (const mode of ['vpn-compat', 'vpn-import']) {
  await writeFile(manifestFile, JSON.stringify(createChainDiagnosticManifest({ config: { ...config, connectionMode: mode }, corePath: path.join(directory, 'missing-core.exe') })));
  for (const connected of [false, true]) {
    let result;
    try {
      await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, '-ManifestPath', manifestFile, '-NonInteractive', ...(connected ? ['-CheckConnectedTunnel'] : [])], { windowsHide: true, timeout: 10000 });
      assert.fail('compatibility TUN checks must return pending exit code 10');
    } catch (cause) { assert.equal(cause.code, 10); result = cause; }
    assert.match(result.stdout, mode === 'vpn-import' ? /no external VPN is required/ : /keep your external VPN enabled/);
    if (mode === 'vpn-import') assert.doesNotMatch(result.stdout, /keep your external VPN enabled/);
    assert.doesNotMatch(result.stdout, /Close OTHER VPN|RELAY_NOT_CONFIGURED|CORE_FILE_MISSING|VPN_CONFLICT|ADMIN_REQUIRED/);
  }
  }
  const logs = await readdir(path.join(directory, 'logs')); assert.equal(logs.length, 4);
  for (const log of logs) {
    const summary = JSON.parse(await readFile(path.join(directory, 'logs', log, 'summary.json'), 'utf8'));
    assert.ok(['vpn-compat', 'vpn-import'].includes(summary.connectionMode)); assert.equal(summary.status, 'mode-not-applicable'); assert.equal(summary.exitCode, 10);
    assert.deepEqual(summary.checks.map(check => check.code), ['MANIFEST_LOADED', summary.connectionMode === 'vpn-import' ? 'VPN_IMPORT_USE_APP_NETWORK_CHECK' : 'VPN_COMPAT_USE_APP_NETWORK_CHECK']);
    assert.equal(summary.networkBefore, null); assert.equal(summary.networkAfter, null); assert.equal(summary.relay, null);
    assert.deepEqual(summary.exits, []); assert.deepEqual(summary.services, []);
    assert.ok(summary.endedAt);
  }
});

test('native recovery launch preserves the manifest runtime root as one quoted argument and rejects missing or injected roots', { skip: process.platform !== 'win32', timeout: 30000 }, async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'mc-proxy-recovery-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtimeRoot = path.join(directory, "Source Runtime's Data"), appPath = path.join(directory, 'MC Proxy.exe');
  await mkdir(runtimeRoot); await writeFile(appPath, 'not an executable: Start-Process must always be mocked');
  const manifestFile = path.join(directory, 'manifest.json');
  const manifest = createChainDiagnosticManifest({ config, runtimeRoot, appPath });
  const cases = [runtimeRoot, `${runtimeRoot}\\`, path.parse(directory).root, null, path.join(directory, 'missing'), `${runtimeRoot}" --mock`, 'C:relative', '\\\\server\\share', `${runtimeRoot}:stream`];
  await writeFile(manifestFile, JSON.stringify({ manifest, cases }));
  const quote = text => `'${text.replaceAll("'", "''")}'`;
  const source = `
. ${quote(path.join(root, 'tools/offline-chain-test/Test-ChainReadiness.ps1'))} -LibraryOnly
$fixture = Get-Content -LiteralPath ${quote(manifestFile)} -Raw -Encoding UTF8 | ConvertFrom-Json
$script:launches = @()
function Start-Process { param($FilePath, $ArgumentList, $WindowStyle); $script:launches += [pscustomobject]@{file=$FilePath;arguments=@($ArgumentList);windowStyle=$WindowStyle} }
$results = @()
foreach ($item in $fixture.cases) {
    $fixture.manifest.runtime.runtimeRoot = $item
    try { $results += [pscustomobject]@{started=(Start-RecoveryApp $fixture.manifest);error=$null} }
    catch { $results += [pscustomobject]@{started=$false;error=$_.Exception.Message} }
}
@{results=$results;launches=$script:launches} | ConvertTo-Json -Depth 6 -Compress
`;
  const result = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(source, 'utf16le').toString('base64')], { windowsHide: true, timeout: 25000 });
  const evidence = JSON.parse(result.stdout.trim()); assert.equal(evidence.launches.length, 3);
  for (let index = 0; index < 3; index++) {
    assert.equal(evidence.results[index].started, true); assert.equal(evidence.launches[index].file, appPath); assert.equal(evidence.launches[index].windowStyle, 'Normal');
    assert.deepEqual(parseWindowsCommandLine(evidence.launches[index].arguments.join(' ')), ['--runtime-root', cases[index]]);
  }
  for (const invalid of evidence.results.slice(3)) { assert.equal(invalid.started, false); assert.equal(invalid.error, 'RECOVERY_RUNTIME_INVALID'); }
});

test('native offline TLS verifies the actual leaf pin and rejects wrong pin/name and an unavailable relay', { skip: process.platform !== 'win32' || !process.env.SING_BOX_BIN || process.env.MC_PROXY_NATIVE_TLS_TEST !== '1', timeout: 30000 }, async t => {
  const pair = await run(process.env.SING_BOX_BIN, ['generate', 'tls-keypair', 'localhost'], { windowsHide: true, timeout: 5000 });
  const key = pair.stdout.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)?.[0];
  const cert = pair.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0];
  assert.ok(key && cert);
  const server = tls.createServer({ key, cert }, socket => socket.end());
  server.on('tlsClientError', () => {});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => server.close(resolve)));
  const free = net.createServer(); free.listen(0, '127.0.0.1'); await once(free, 'listening');
  const closedPort = free.address().port; await new Promise(resolve => free.close(resolve));
  const port = server.address().port;
  const pin = createHash('sha256').update(new X509Certificate(cert).raw).digest('hex').toUpperCase();
  const script = path.join(root, 'tools', 'offline-chain-test', 'Test-ChainReadiness.ps1').replaceAll("'", "''");
  const source = `
. '${script}' -LibraryOnly
Initialize-Transport
$good = [McProxyOffline.Transport]::Relay('127.0.0.1', ${port}, 'localhost', '${pin}', 2000)
$badPin = [McProxyOffline.Transport]::Relay('127.0.0.1', ${port}, 'localhost', '${'0'.repeat(64)}', 2000)
$badName = [McProxyOffline.Transport]::Relay('127.0.0.1', ${port}, 'wrong.invalid', '${pin}', 2000)
$closed = [McProxyOffline.Transport]::Relay('127.0.0.1', ${closedPort}, 'localhost', '${pin}', 1000)
@{ good=$good.code; badPin=$badPin.code; badName=$badName.code; closed=$closed.code; local=$good.localAddress; pin=$good.certificateSha256; exceptionType=$good.exceptionType } | ConvertTo-Json -Compress
`;
  const result = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(source, 'utf16le').toString('base64')], { windowsHide: true, timeout: 20000 });
  const evidence = JSON.parse(result.stdout.trim());
  assert.equal(evidence.good, 'RELAY_TLS_VERIFIED', JSON.stringify(evidence));
  assert.equal(evidence.badPin, 'RELAY_CERTIFICATE_REJECTED');
  assert.equal(evidence.badName, 'RELAY_CERTIFICATE_REJECTED');
  assert.ok(['RELAY_UNREACHABLE', 'RELAY_TIMEOUT'].includes(evidence.closed));
  assert.equal(evidence.local, '127.0.0.1');
  assert.equal(evidence.pin, pin);
});
