import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createClaudeCleanupManager, createWindowsClaudeCleanupAdapter } from '../src/claude-cleanup.mjs';

const home = 'C:\\Users\\Fixture';
const inventory = () => ({ targets: [{ path: `${home}\\.claude`, kind: 'directory', files: 3, bytes: 120, fingerprint: 'version-1' }, { path: `${home}\\.claude.json`, kind: 'file', files: 1, bytes: 42, fingerprint: 'version-2' }], runningProcesses: [], residuals: [{ kind: 'environment', name: 'ANTHROPIC_API_KEY', scope: 'User' }] });
function fixture(options = {}) {
  let value = inventory(); const calls = []; let removed = 0;
  const adapter = { inspect: async input => { calls.push(input); return structuredClone(value); }, remove: async input => { calls.push(input); removed++; const deleted = value.targets.map(item => item.path); value.targets = []; return { deleted, residuals: value.residuals }; } };
  const manager = createClaudeCleanupManager({ homeDir: home, localAppDataDir: `${home}\\AppData\\Local`, configDir: undefined, adapter, ...options });
  return { manager, adapter, calls, value: () => value, set: update => { value = update; }, removed: () => removed };
}

test('preview lists destructive scope and never reads contents or removes files', async () => {
  const f = fixture(); const preview = await f.manager.preview();
  assert.equal(preview.totalFiles, 4);
  assert.equal(preview.totalBytes, 162);
  assert.equal(preview.canConfirm, true);
  assert.equal(preview.targets[0].fingerprint, undefined);
  assert.equal(f.removed(), 0);
  assert.match(preview.warnings.join(''), /不可一键撤销/);
  assert.match(preview.warnings.join(''), /WSL/);
  assert.equal(preview.residuals[0].name, 'ANTHROPIC_API_KEY');
  assert.ok(!JSON.stringify(preview).includes('value'));
});

test('explicit confirmation removes only inventory-bound allowlisted data and returns residuals', async () => {
  const f = fixture(); const preview = await f.manager.preview();
  const result = await f.manager.confirm({ confirmationToken: preview.confirmationToken, confirmed: true });
  assert.equal(result.complete, true);
  assert.equal(result.deleted.length, 2);
  assert.equal(result.residuals[0].name, 'ANTHROPIC_API_KEY');
  assert.deepEqual(f.calls.find(call => call.expected)?.expected, inventory().targets);
  assert.equal(f.removed(), 1);
  await assert.rejects(f.manager.confirm({ confirmationToken: preview.confirmationToken, confirmed: true }), { code: 'CONFIRMATION_INVALID' });
});

test('no deletion without manual confirmation even with a valid token', async () => {
  const f = fixture(); const preview = await f.manager.preview();
  await assert.rejects(f.manager.confirm({ confirmationToken: preview.confirmationToken }), { code: 'CONFIRMATION_REQUIRED' });
  assert.equal(f.removed(), 0);
});

test('expired token is rejected and cannot be reused', async () => {
  let now = 0; const f = fixture({ now: () => now, ttlMs: 1000 });
  const preview = await f.manager.preview(); now = 1001;
  await assert.rejects(f.manager.confirm({ confirmationToken: preview.confirmationToken, confirmed: true }), { code: 'CONFIRMATION_INVALID' });
  assert.equal(f.removed(), 0);
});

test('running Claude processes disable confirm and prevent deletion', async () => {
  const f = fixture(); const running = inventory(); running.runningProcesses = [{ pid: 123, name: 'claude.exe' }]; f.set(running);
  const preview = await f.manager.preview();
  assert.equal(preview.canConfirm, false);
  await assert.rejects(f.manager.confirm({ confirmationToken: preview.confirmationToken, confirmed: true }), { code: 'CLAUDE_RUNNING' });
  assert.equal(f.removed(), 0);
});

test('new processes, new files, or changed timestamps invalidate the plan', async () => {
  for (const change of ['process', 'file', 'fingerprint']) {
    const f = fixture(); const preview = await f.manager.preview(); const updated = inventory();
    if (change === 'process') updated.runningProcesses = [{ pid: 99, name: 'node.exe' }];
    if (change === 'file') updated.targets.push({ path: `${home}\\.claude.json.backup.1234`, kind: 'file', files: 1, bytes: 2, fingerprint: 'v3' });
    if (change === 'fingerprint') updated.targets[0].fingerprint = 'modified';
    f.set(updated);
    await assert.rejects(f.manager.confirm({ confirmationToken: preview.confirmationToken, confirmed: true }), { code: change === 'process' ? 'CLAUDE_RUNNING' : 'CLAUDE_INVENTORY_CHANGED' });
    assert.equal(f.removed(), 0);
  }
});

test('adapter cannot expand scope to projects, home itself, sibling roots or arbitrary paths', async () => {
  for (const target of [home, `${home}\\Projects\\repo\\.claude`, 'C:\\Users\\Fixture2\\.claude', 'C:\\Windows', `${home}\\Documents`]) {
    const f = fixture(); const changed = inventory(); changed.targets[0].path = target; f.set(changed);
    await assert.rejects(f.manager.preview(), { code: 'CLAUDE_PATH_UNSAFE' });
  }
});

test('dedicated custom Claude config directories are included while projects are reported and preserved', async () => {
  const known = fixture({ configDir: `${home}\\.claude-work` }); await known.manager.preview();
  assert.ok(known.calls[0].targets.includes(`${home}\\.claude-work`));
  const unsafe = fixture({ configDir: `${home}\\Projects\\personal` }); const preview = await unsafe.manager.preview();
  assert.ok(!unsafe.calls[0].targets.includes(`${home}\\Projects\\personal`));
  assert.match(preview.warnings.join(''), /CLAUDE_CONFIG_DIR/);
});

test('adapter link and worktree rejections stop all destructive work', async () => {
  for (const code of ['CLAUDE_PATH_UNSAFE', 'CLAUDE_PROJECT_PRESENT', 'CLAUDE_PROCESS_UNREADABLE']) {
    const f = fixture(); f.adapter.inspect = async () => { throw Object.assign(new Error('blocked'), { code }); };
    await assert.rejects(f.manager.preview(), { code });
    assert.equal(f.removed(), 0);
  }
});

test('independent previews are consumed independently and old snapshots fail after cleanup', async () => {
  const f = fixture(); const first = await f.manager.preview(); const second = await f.manager.preview();
  await f.manager.confirm({ confirmationToken: first.confirmationToken, confirmed: true });
  await assert.rejects(f.manager.confirm({ confirmationToken: second.confirmationToken, confirmed: true }), { code: 'CLAUDE_INVENTORY_CHANGED' });
});

test('mock cleanup never calls injected host adapter', async () => {
  const forbidden = () => { throw new Error('host access'); };
  const manager = createClaudeCleanupManager({ mock: true, adapter: { inspect: forbidden, remove: forbidden } });
  const preview = await manager.preview();
  const result = await manager.confirm({ confirmationToken: preview.confirmationToken, confirmed: true });
  assert.equal(result.mock, true);
  assert.equal(result.complete, true);
});

test('Windows adapter uses data-only payload, literal leaf removals and reparse/process checks', async () => {
  const calls = [];
  const adapter = createWindowsClaudeCleanupAdapter({ platform: 'win32', execFile: (file, args, options, callback) => { calls.push({ file, args, options }); callback(null, JSON.stringify({ ok: true, value: { deleted: [] } })); } });
  const value = `${home}\\.claude-$(whoami)`;
  await adapter.remove({ homeDir: home, roots: [home], targets: [value], expected: [] });
  const source = Buffer.from(calls[0].args.at(-1), 'base64').toString('utf16le');
  assert.ok(!source.includes(value));
  assert.match(source, /ReparsePoint/);
  assert.match(source, /CLAUDE_PROJECT_PRESENT/);
  assert.match(source, /Remove-Item -LiteralPath \$location -Force/);
  assert.doesNotMatch(source, /Remove-Item[^\n]*-Recurse/);
  assert.match(source, /GetValueNames/);
  assert.match(source, /if \(@\(Processes\)\.Count -gt 0\)/);
  assert.equal(calls[0].options.windowsHide, true);
});

test('native errors are controlled and never expose command output or credentials', async () => {
  const adapter = createWindowsClaudeCleanupAdapter({ platform: 'win32', execFile: (_f, _a, _o, cb) => cb(new Error('secret credentials'), 'private') });
  await assert.rejects(adapter.inspect({}), e => e.code === 'CLAUDE_INSPECT_FAILED' && !/secret|private/.test(e.message));
});

test('native scanner helpers preserve volume roots and avoid the automatic Matches variable', { skip: process.platform !== 'win32' }, async () => {
  let source;
  const adapter = createWindowsClaudeCleanupAdapter({ platform: 'win32', execFile: (_f, args, _o, callback) => { source = Buffer.from(args.at(-1), 'base64').toString('utf16le'); callback(null, '{"ok":true,"value":{}}'); } });
  await adapter.inspect({});
  const full = source.slice(source.indexOf('function Full('), source.indexOf('function Assert-Safe('));
  const scanner = source.slice(source.indexOf('function Processes {'), source.indexOf('function Inventory('));
  const fixture = String.raw`
function Get-CimInstance {
  return @(
    [pscustomobject]@{Name='node.exe';ProcessId=1;CommandLine='node unrelated.js'},
    [pscustomobject]@{Name='claude.exe';ProcessId=2;CommandLine=$null},
    [pscustomobject]@{Name='node.exe';ProcessId=3;CommandLine='node C:\tools\@anthropic-ai\claude-code\cli.js'},
    [pscustomobject]@{Name='node.exe';ProcessId=4;CommandLine='node different.js'}
  )
}
@{root=(Full 'D:\');directory=(Full 'D:\fixture\');processes=@(Processes)} | ConvertTo-Json -Depth 5 -Compress
`;
  const output = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue';\n" + full + scanner + fixture, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  const result = JSON.parse(output);
  assert.equal(result.root, 'D:\\');
  assert.equal(result.directory, 'D:\\fixture');
  assert.deepEqual(result.processes.map(item => item.pid), [2, 3]);
});
