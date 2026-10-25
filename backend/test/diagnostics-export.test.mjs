import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, readdir, readFile, writeFile, symlink, rm, lstat } from 'node:fs/promises';
import { exportChainDiagnostics } from '../src/diagnostics-export.mjs';
import { relayFixture } from './relay-fixture.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.diagnostics-export-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('offline export includes network repair and derives a credential-free manifest before an ISP exists', async t => {
  const root = await fixture(t);
  const result = await exportChainDiagnostics({ runtimeRoot: root, config: { relay: relayFixture() }, appPath: path.join(root, 'MC Proxy.exe'), lastFailure: { code: 'RELAY_UNREACHABLE', message: 'PRIVATE_SECRET' } });
  assert.equal(result.directory, path.join(root, 'offline-diagnostics'));
  assert.equal(result.files.length, 9); assert.ok(result.files.includes('run-preflight.cmd')); assert.ok(result.files.includes('Repair-Network.ps1')); assert.ok(result.files.includes('Repair-Network.cmd'));
  const manifest = JSON.parse(await readFile(path.join(result.directory, 'manifest.json'), 'utf8'));
  assert.equal(manifest.relay.host, '192.0.2.50'); assert.equal(manifest.isp.configured, false);
  assert.equal(manifest.recovery.automaticUnlock, false);
  assert.doesNotMatch(JSON.stringify(result), /BEGIN CERTIFICATE|PRIVATE_SECRET|RELAY_PASSWORD/);
  const script = await readFile(path.join(result.directory, 'Test-ChainReadiness.ps1'), 'utf8');
  assert.match(script, /Read-Manifest/);
  const again = await exportChainDiagnostics({ runtimeRoot: root, config: { relay: relayFixture() } });
  assert.equal(again.files.length, 9);
  assert.equal((await readdir(result.directory)).some(name => name.endsWith('.tmp')), false);
});

test('diagnostics export rejects linked destinations and never overwrites outside its fixed directory', async t => {
  const root = await fixture(t); const outside = path.join(root, 'untouched'); await mkdir(outside);
  await writeFile(path.join(outside, 'manifest.json'), 'original');
  await symlink(outside, path.join(root, 'offline-diagnostics'), process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(exportChainDiagnostics({ runtimeRoot: root }), { code: 'DIAGNOSTICS_EXPORT_FAILED' });
  assert.equal(await readFile(path.join(outside, 'manifest.json'), 'utf8'), 'original');
  assert.deepEqual(await readdir(outside), ['manifest.json']);
});

test('mock offline export returns a preview without creating directories or reading scripts', async t => {
  const root = await fixture(t); const absent = path.join(root, 'absent');
  const result = await exportChainDiagnostics({ runtimeRoot: absent, sourceDirectory: path.join(root, 'no-scripts'), mock: true });
  assert.equal(result.directory, null); assert.equal(result.mock, true); assert.equal(result.manifest.isp.configured, false);
  await assert.rejects(lstat(absent), { code: 'ENOENT' });
});

test('imported VPN export copies only fixed tools and safe metadata, excluding private profiles and raw YAML', async t => {
  const root = await fixture(t);
  const privateDirectory = path.join(root, '.imported-vpn'); await mkdir(privateDirectory);
  await writeFile(path.join(privateDirectory, 'profile.json'), 'PRIVATE_VPN_UUID PRIVATE_NODE_ENDPOINT');
  await writeFile(path.join(root, 'profile.yaml'), 'PRIVATE_RAW_YAML');
  const result = await exportChainDiagnostics({ runtimeRoot: root, config: { connectionMode: 'vpn-import', relay: relayFixture(), vpnNode: { uuid: 'PRIVATE_VPN_UUID', server: 'PRIVATE_NODE_ENDPOINT' }, rawYaml: 'PRIVATE_RAW_YAML' } });
  assert.equal(result.files.length, 9);
  assert.equal(result.manifest.connectionMode, 'vpn-import'); assert.equal(result.manifest.relay, null);
  assert.equal(result.manifest.runtime.transportMode, 'http');
  for (const name of result.files) assert.doesNotMatch(await readFile(path.join(result.directory, name), 'utf8'), /PRIVATE_VPN_UUID|PRIVATE_NODE_ENDPOINT|PRIVATE_RAW_YAML/);
  const readme = await readFile(path.join(result.directory, 'README.zh-CN.txt'), 'utf8');
  assert.ok(readme.startsWith('本诊断包用于 YAML VPN → ISP 导入线路。'));
  assert.match(readme, /无需运行外部 VPN/);
  assert.equal(await readFile(path.join(root, 'profile.yaml'), 'utf8'), 'PRIVATE_RAW_YAML');
  assert.equal((await readdir(result.directory)).some(name => /yaml|profile|imported/i.test(name)), false);
});
