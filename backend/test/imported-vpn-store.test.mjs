import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, writeFile, readdir, rm } from 'node:fs/promises';
import { createImportedVpnStore } from '../src/imported-vpn-store.mjs';
import { vpnYamlNode } from './vpn-fixture.mjs';
import { createHash } from 'node:crypto';

async function fixture(t) {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.imported-vpn-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const stateDir = path.join(root, '.imported-vpn');
  return { root, stateDir, file: path.join(stateDir, 'nodes.json'), store: createImportedVpnStore({ stateDir }) };
}
const yaml = () => JSON.stringify({ proxies: [vpnYamlNode(), { name: 'unsupported private password', type: 'ss', password: 'NEVER_LOG_SECRET' }, vpnYamlNode({ name: 'Second node', port: 8443 })], dns: { nameserver: ['https://IGNORED_SECRET.invalid'] }, rules: ['MATCH,DIRECT'] });

test('import stores only private normalized nodes while status, auto and explicit selection survive restart', async t => {
  const f = await fixture(t);
  assert.equal((await f.store.status()).available, false); assert.deepEqual(await readdir(f.root), []);
  const status = await f.store.import(yaml(), { expectedId: null });
  assert.equal(status.available, true); assert.equal(status.total, 3); assert.equal(status.supported, 2); assert.equal(status.unsupported, 1);
  assert.equal(status.selectedIndex, null); assert.deepEqual(status.nodes.map(node => node.index), [1, 3]);
  assert.deepEqual(status.unsupportedNodes, [{ index: 2, code: 'VPN_NODE_INVALID' }]);
  assert.doesNotMatch(JSON.stringify(status), /private\.invalid|11111111|public_key|NEVER_LOG|IGNORED_SECRET|MATCH,DIRECT/);
  const raw = await readFile(f.file, 'utf8');
  assert.doesNotMatch(raw, /dns|rules|NEVER_LOG|IGNORED_SECRET|MATCH,DIRECT|unsupported private password/);
  assert.match(raw, /vpn-entry/); assert.equal((await f.store.load()).nodes[0].outbound.server, 'vpn.private.invalid');
  assert.deepEqual((await f.store.candidates()).map(node => node.index), [1, 3]);
  const selected = await f.store.select(3, { expectedId: status.id });
  assert.equal(selected.id, status.id); assert.equal(selected.selectedIndex, 3);
  const restarted = createImportedVpnStore({ stateDir: f.stateDir });
  assert.deepEqual(await restarted.status(), selected); assert.deepEqual((await restarted.candidates()).map(node => node.index), [3]);
  await restarted.select(null, { expectedId: selected.id });
  assert.deepEqual((await restarted.candidates()).map(node => node.index), [1, 3]);
  const replaced = await restarted.import(yaml(), { expectedId: selected.id });
  assert.equal(replaced.id, status.id); assert.equal(replaced.selectedIndex, null);
  assert.deepEqual(replaced.changeSummary, { added: 0, removed: 0, kept: 2, renamed: 0, unchanged: true });
});

test('exact duplicates keep original indices and selection follows full private identity across refresh order changes', async t => {
  const f = await fixture(t);
  const first = await f.store.import(JSON.stringify({ proxies: [vpnYamlNode(), vpnYamlNode({ name: 'Alias' }), vpnYamlNode({ name: 'Second', port: 8443 })] }));
  assert.equal(first.total, 3); assert.equal(first.supported, 2); assert.equal(first.duplicates, 1); assert.equal(first.unsupported, 0);
  assert.deepEqual(first.duplicateNodes, [{ index: 2, duplicateOf: 1, code: 'VPN_NODE_DUPLICATE' }]);
  await assert.rejects(f.store.select(2), { code: 'VPN_NODE_NOT_FOUND' });
  await f.store.select(3);
  const same = await f.store.import(JSON.stringify({ proxies: [vpnYamlNode(), vpnYamlNode({ name: 'Alias' }), vpnYamlNode({ name: 'Second', port: 8443 })] }));
  assert.equal(same.id, first.id); assert.equal(same.selectedIndex, 3); assert.equal(same.changeSummary.unchanged, true);
  const raw = await readFile(f.file); await f.store.import(JSON.stringify({ proxies: [vpnYamlNode(), vpnYamlNode({ name: 'Alias' }), vpnYamlNode({ name: 'Second', port: 8443 })] }));
  assert.deepEqual(await readFile(f.file), raw, 'a repeated unchanged import does not rewrite the record');
  const changed = await f.store.import(JSON.stringify({ proxies: [vpnYamlNode({ name: 'Renamed second', port: 8443 }), vpnYamlNode({ name: 'New', port: 9443 }), vpnYamlNode()] }));
  assert.notEqual(changed.id, first.id); assert.equal(changed.selectedIndex, 1);
  assert.deepEqual(changed.changeSummary, { added: 1, removed: 0, kept: 2, renamed: 1, unchanged: false });
  assert.doesNotMatch(JSON.stringify(changed), /vpn\.private|11111111|public_key|[a-f0-9]{64}/);
  const removed = await f.store.import(JSON.stringify({ proxies: [vpnYamlNode()] }));
  assert.equal(removed.selectedIndex, null); assert.deepEqual(removed.changeSummary, { added: 0, removed: 2, kept: 1, renamed: 0, unchanged: false });
  assert.deepEqual(await createImportedVpnStore({ stateDir: f.stateDir }).status(), removed);
});

test('legacy duplicate records remain readable and map an old selected alias without rewriting old bytes', async t => {
  const f = await fixture(t); await f.store.import(yaml());
  const record = await f.store.load(); delete record.duplicates; delete record.changeSummary;
  record.nodes.push({ ...structuredClone(record.nodes[0]), index: 4, name: 'Old alias' }); record.total = 4; record.selectedIndex = 4;
  const raw = Buffer.from(JSON.stringify(record)); await writeFile(f.file, raw);
  const status = await f.store.status(); assert.equal(status.selectedIndex, 1); assert.equal(status.duplicates, 1);
  assert.deepEqual((await f.store.candidates()).map(node => node.index), [1]); assert.deepEqual(await readFile(f.file), raw);
});

test('unsupported, invalid selection and stale import IDs never overwrite saved private nodes', async t => {
  const f = await fixture(t); const status = await f.store.import(yaml()); const raw = await readFile(f.file);
  await assert.rejects(f.store.import('proxies: []'), { code: 'VPN_IMPORT_NO_SUPPORTED_NODES' });
  await assert.rejects(f.store.import('proxies: [PRIVATE_SECRET'), cause => cause.code === 'VPN_YAML_INVALID' && !cause.message.includes('PRIVATE_SECRET'));
  await assert.rejects(f.store.import(yaml(), { expectedId: null }), { code: 'VPN_IMPORT_CONFLICT' });
  for (const index of [2, 0, '1', undefined]) await assert.rejects(f.store.select(index, { expectedId: status.id }), { code: 'VPN_NODE_NOT_FOUND' });
  await assert.rejects(f.store.select(1, { expectedId: 'old-import-id' }), { code: 'VPN_IMPORT_CONFLICT' });
  assert.deepEqual(await readFile(f.file), raw);
});

test('failed atomic replacement and outside edits retain the previous file and scrub filesystem errors', async t => {
  const f = await fixture(t); const status = await f.store.import(yaml()); const raw = await readFile(f.file);
  const denied = createImportedVpnStore({ stateDir: f.stateDir, dependencies: { rename: async () => { throw new Error('PRIVATE_PATH_OR_SECRET'); } } });
  await assert.rejects(denied.select(1, { expectedId: status.id }), cause => cause.code === 'VPN_IMPORT_WRITE_FAILED' && !cause.message.includes('PRIVATE_PATH_OR_SECRET'));
  assert.deepEqual(await readFile(f.file), raw); assert.deepEqual((await readdir(f.stateDir)).sort(), ['.gitignore', 'nodes.json']);
  const changed = Buffer.concat([raw, Buffer.from('\n')]);
  const concurrent = createImportedVpnStore({ stateDir: f.stateDir, dependencies: { writePrivate: async (target, contents) => {
    await writeFile(target, contents, { flag: 'wx', mode: 0o600 }); await writeFile(f.file, changed);
  } } });
  await assert.rejects(concurrent.select(1), { code: 'VPN_IMPORT_CONFLICT' });
  assert.deepEqual(await readFile(f.file), changed);
});

test('tampered arbitrary outbound fields and linked paths are never exposed or accepted', async t => {
  const f = await fixture(t); await f.store.import(yaml());
  const record = await f.store.load(); record.nodes[0].outbound.detour = 'direct';
  await writeFile(f.file, JSON.stringify(record));
  await assert.rejects(f.store.status(), { code: 'VPN_IMPORT_INVALID' });
  await assert.rejects(f.store.candidates(), { code: 'VPN_IMPORT_INVALID' });
  const linked = createImportedVpnStore({ stateDir: f.stateDir, dependencies: { lstat: async () => ({ isSymbolicLink: () => true }) } });
  await assert.rejects(linked.status(), { code: 'VPN_IMPORT_INVALID' });
});

test('mock import and selection never use injected files or any network and return copies', async () => {
  const forbidden = () => assert.fail('mock import cannot access native resources');
  const store = createImportedVpnStore({ mock: true, dependencies: Object.fromEntries(['readFile', 'lstat', 'open', 'writePrivate', 'rename', 'createPrivateDirectory'].map(key => [key, forbidden])) });
  const imported = await store.import(yaml()); assert.equal(imported.mock, true);
  await store.select(1); const nodes = await store.candidates(); nodes[0].outbound.server = 'tampered.invalid';
  assert.equal((await store.candidates())[0].outbound.server, 'vpn.private.invalid');
  assert.equal((await store.select(null)).selectedIndex, null);
});

test('explicit valid YAML import archives invalid old bytes and recovers without accepting an old profile ID', async t => {
  const f = await fixture(t); const first = await f.store.import(yaml());
  const brokenRecords = [Buffer.from('{PRIVATE_BROKEN_JSON\r\n'), Buffer.from(JSON.stringify({ version: 99, oldSecret: 'PRIVATE_OLD_RECORD' }))];
  for (const [offset, raw] of brokenRecords.entries()) {
    await writeFile(f.file, raw);
    await assert.rejects(f.store.status(), { code: 'VPN_IMPORT_INVALID' });
    await assert.rejects(f.store.import(yaml(), { expectedId: first.id }), { code: 'VPN_IMPORT_CONFLICT' });
    assert.deepEqual(await readFile(f.file), raw);
    const recovered = offset ? await f.store.import(yaml(), { expectedId: null }) : await f.store.import(yaml());
    assert.equal(recovered.available, true); assert.equal(recovered.selectedIndex, null); assert.equal(recovered.supported, 2);
    assert.doesNotMatch(JSON.stringify(recovered), /PRIVATE_|private\.invalid|11111111/);
    const archives = (await readdir(f.stateDir)).filter(name => name.startsWith('nodes-archive-'));
    assert.equal(archives.length, offset + 1);
    const archived = await Promise.all(archives.map(name => readFile(path.join(f.stateDir, name))));
    assert.ok(archived.some(bytes => bytes.equals(raw)));
    const restarted = createImportedVpnStore({ stateDir: f.stateDir });
    assert.deepEqual(await restarted.status(), recovered); assert.deepEqual((await restarted.candidates()).map(node => node.index), [1, 3]);
  }
});

test('invalid-record archive failure or preparation conflict preserves original bytes and never weakens path safety', async t => {
  const f = await fixture(t); await f.store.import(yaml());
  const raw = Buffer.from('{retain invalid original'); await writeFile(f.file, raw);
  const failed = createImportedVpnStore({ stateDir: f.stateDir, dependencies: { writePrivate: async () => { throw new Error('PRIVATE_DISK_ERROR'); } } });
  await assert.rejects(failed.import(yaml(), { expectedId: null }), cause => cause.code === 'VPN_IMPORT_WRITE_FAILED' && !cause.message.includes('PRIVATE_DISK_ERROR'));
  assert.deepEqual(await readFile(f.file), raw);
  const changed = Buffer.from('{new concurrent invalid record');
  const racing = createImportedVpnStore({ stateDir: f.stateDir, dependencies: { writePrivate: async (target, contents) => {
    await writeFile(target, contents, { flag: 'wx', mode: 0o600 });
    if (path.basename(target).startsWith('nodes-archive-')) await writeFile(f.file, changed);
  } } });
  await assert.rejects(racing.import(yaml()), { code: 'VPN_IMPORT_CONFLICT' });
  assert.deepEqual(await readFile(f.file), changed);
  const archives = (await readdir(f.stateDir)).filter(name => name.startsWith('nodes-archive-'));
  assert.equal(archives.length, 1); assert.deepEqual(await readFile(path.join(f.stateDir, archives[0])), raw);
  const linked = createImportedVpnStore({ stateDir: f.stateDir, dependencies: { lstat: async () => ({ isSymbolicLink: () => true }) } });
  await assert.rejects(linked.import(yaml()), { code: 'VPN_IMPORT_INVALID' });
  const denied = createImportedVpnStore({ stateDir: f.stateDir, dependencies: { readFile: async () => { throw Object.assign(new Error('PRIVATE_PERMISSION_ERROR'), { code: 'EACCES' }); } } });
  await assert.rejects(denied.import(yaml()), cause => cause.code === 'VPN_IMPORT_READ_FAILED' && !cause.message.includes('PRIVATE_PERMISSION_ERROR'));
  assert.deepEqual(await readFile(f.file), changed);
});

test('legacy records gain safe metadata without changing the original outbound hash or bytes until explicit save', async t => {
  const f = await fixture(t); await f.store.import(yaml());
  const legacy = await f.store.load(); delete legacy.format;
  for (const node of legacy.nodes) { delete node.protocol; delete node.transport; }
  const raw = Buffer.from(JSON.stringify(legacy)); await writeFile(f.file, raw);
  const before = createHash('sha256').update(JSON.stringify(legacy.nodes[0].outbound)).digest('hex');
  const restarted = createImportedVpnStore({ stateDir: f.stateDir });
  const status = await restarted.status(); assert.equal(status.format, 'clash-yaml');
  assert.deepEqual(status.nodes[0], { index: 1, name: 'Imported test node', protocol: 'vless', transport: 'tcp' });
  const after = createHash('sha256').update(JSON.stringify((await restarted.candidates())[0].outbound)).digest('hex');
  assert.equal(after, before); assert.deepEqual(await readFile(f.file), raw);
});

test('generic formats persist and all-unsupported diagnostics and oversized alias imports never replace the saved profile', async t => {
  const f = await fixture(t);
  const uri = 'vless://11111111-2222-4333-8444-555555555555@127.0.0.1:443?security=none&type=tcp';
  const saved = await f.store.import(uri); assert.equal(saved.format, 'share-uri');
  assert.deepEqual(saved.nodes[0], { index: 1, name: 'Node 1', protocol: 'vless', transport: 'tcp' });
  const raw = await readFile(f.file);
  await assert.rejects(f.store.import(JSON.stringify({ outbounds: [{ type: 'direct', tag: 'PRIVATE_SERVER_OR_TOKEN' }] })), cause => {
    assert.equal(cause.code, 'VPN_IMPORT_NO_SUPPORTED_NODES');
    assert.deepEqual(cause.unsupportedNodes, [{ index: 1, code: 'VPN_NODE_TYPE_UNSUPPORTED' }]);
    assert.ok(!JSON.stringify(cause.unsupportedNodes).includes('PRIVATE_')); return true;
  });
  const aliases = 'proxies:\n  - &node\n    name: alias\n    type: ss\n    server: 127.0.0.1\n    port: 8388\n    cipher: aes-128-gcm\n    password: ' + 'x'.repeat(8192) + '\n' + Array.from({ length: 255 }, () => '  - *node').join('\n');
  await assert.rejects(f.store.import(aliases), { code: 'VPN_YAML_SIZE_INVALID' });
  assert.deepEqual(await readFile(f.file), raw); assert.equal((await f.store.status()).id, saved.id);
  const xray = await f.store.import(JSON.stringify({ outbounds: [{ protocol: 'vless', settings: { vnext: [{ address: 'private-server.invalid', port: 443,
    users: [{ id: '11111111-2222-4333-8444-555555555555', encryption: 'none' }] }] } }] }), { expectedId: saved.id });
  const restarted = await createImportedVpnStore({ stateDir: f.stateDir }).status();
  assert.equal(restarted.format, 'v2ray-json'); assert.equal(restarted.id, xray.id);
  assert.deepEqual(restarted.nodes, [{ index: 1, name: 'Node 1', protocol: 'vless', transport: 'tcp' }]);
  assert.doesNotMatch(JSON.stringify(restarted), /private-server|11111111/);
});
