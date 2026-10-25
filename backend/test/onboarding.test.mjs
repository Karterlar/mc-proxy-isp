import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, readdir, rm, rename, writeFile, mkdir, symlink } from 'node:fs/promises';
import { createOnboardingManager } from '../src/onboarding.mjs';
import { parseSecrets, loadConfig, loadSecrets, buildSingBox } from '../src/config.mjs';
import { relayFixture, relaySecrets } from './relay-fixture.mjs';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { createImportedVpnStore } from '../src/imported-vpn-store.mjs';
import { createLicenseClient } from '../src/license-client.mjs';
import { signLicense } from '../src/license-format.mjs';
import { vpnYamlNode } from './vpn-fixture.mjs';

const input = { type: 'socks', host: 'gateway.provider.test', port: 1080, username: 'test-account', password: 'test-password', expectedExitIps: ['203.0.113.8'] };
const fingerprintDefaults = { fingerprintLanguage: 'auto', fingerprintTimezone: 'auto', fingerprintNativeGraphics: false, fingerprintFresh: false };
async function fixture(t, options = {}) {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.onboarding-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configPath = path.join(root, 'config.json'); const secretsPath = path.join(root, 'upstream.secrets.env');
  const settings = { runtimeRoot: root, configPath, secretsPath, ...options };
  return { root, configPath, secretsPath, settings, manager: createOnboardingManager(settings) };
}
const rawPair = async ({ configPath, secretsPath }) => [await readFile(configPath, 'utf8'), await readFile(secretsPath, 'utf8')];

test('trusted preparation injects relay credentials before verification and persists both layers without public disclosure', async t => {
  const item = await fixture(t); let prepared = false;
  const result = await item.manager.saveConfiguration(input, {
    prepareConfiguration: async candidate => { prepared = true; return { config: { ...candidate.config, relay: relayFixture() }, secrets: { ...candidate.secrets, ...relaySecrets } }; },
    verifyConfiguration: async candidate => {
      assert.equal(prepared, true); assert.deepEqual(candidate.config.relay, relayFixture());
      assert.equal(candidate.secrets.RELAY_PASSWORD, relaySecrets.RELAY_PASSWORD);
      assert.equal(candidate.secrets.ISP_PASSWORD, input.password);
      return { expectedExitIps: ['203.0.113.8'] };
    },
  });
  assert.deepEqual(result.relay, { host: '192.0.2.50', port: 443, serverName: 'localhost' });
  assert.doesNotMatch(JSON.stringify(result), /BEGIN CERTIFICATE|relay-test-user|relay-test-password/);
  const saved = await loadConfig(item.configPath);
  assert.deepEqual(await loadSecrets(item.secretsPath, saved), { ISP_USERNAME: input.username, ISP_PASSWORD: input.password, ...relaySecrets });
  await item.manager.saveConfiguration({ ...input, username: '', password: '' });
  assert.deepEqual(await loadSecrets(item.secretsPath, saved), { ISP_USERNAME: input.username, ISP_PASSWORD: input.password, ...relaySecrets }, 'legacy local edit preserves its enrolled relay credential layer');
});

test('VPN compatibility removes only the active relay layer, keeps ISP pin and TLS, and can return to enrolled relay', async t => {
  const item = await fixture(t);
  const attachRelay = async candidate => ({ config: { ...candidate.config, relay: relayFixture() }, secrets: { ...candidate.secrets, ...relaySecrets } });
  await item.manager.saveConfiguration({ ...input, type: 'http' }, { prepareConfiguration: attachRelay });
  const prior = await loadConfig(item.configPath);
  prior.upstream.tls = { enabled: true, serverName: 'gateway.provider.test' };
  prior.listen.port = 18765; prior.probe.timeoutMs = 12000;
  await writeFile(item.configPath, JSON.stringify(prior));
  const enrollmentDirectory = path.join(item.root, '.relay');
  const enrollmentPath = path.join(enrollmentDirectory, 'enrollment.json');
  await mkdir(enrollmentDirectory); await writeFile(enrollmentPath, 'retained enrollment');
  const edit = { type: 'http', host: input.host, port: input.port, connectionMode: 'vpn-compat', vpnConfirmed: true, expectedExitIps: ['203.0.113.99'] };
  const saved = await item.manager.saveConfiguration(edit, {
    prepareConfiguration: async candidate => {
      assert.equal(candidate.config.connectionMode, 'vpn-compat');
      assert.equal(candidate.config.relay, undefined);
      assert.deepEqual(candidate.secrets, { ISP_USERNAME: input.username, ISP_PASSWORD: input.password });
      assert.deepEqual(candidate.config.probe.expectedExitIps, input.expectedExitIps);
      return candidate;
    },
    verifyConfiguration: async candidate => {
      assert.equal((await loadConfig(item.configPath)).connectionMode, 'relay');
      assert.deepEqual(candidate.config.probe.expectedExitIps, input.expectedExitIps);
      return { expectedExitIps: input.expectedExitIps, checks: [{ source: 'ipify', ip: input.expectedExitIps[0] }] };
    },
  });
  assert.equal(saved.connectionMode, 'vpn-compat'); assert.equal(saved.relay, undefined);
  assert.deepEqual(saved.expectedExitIps, input.expectedExitIps);
  const config = await loadConfig(item.configPath); const secrets = await loadSecrets(item.secretsPath, config);
  assert.equal(config.connectionMode, 'vpn-compat'); assert.equal(config.relay, undefined);
  assert.deepEqual(config.upstream, prior.upstream); assert.deepEqual(config.listen, prior.listen); assert.deepEqual(config.probe, prior.probe);
  assert.deepEqual(secrets, { ISP_USERNAME: input.username, ISP_PASSWORD: input.password });
  assert.doesNotMatch(await readFile(item.secretsPath, 'utf8'), /RELAY_/);
  assert.deepEqual(buildSingBox(config, secrets).outbounds.map(outbound => outbound.tag), ['isp-upstream']);
  assert.equal(await readFile(enrollmentPath, 'utf8'), 'retained enrollment');
  assert.equal((await createOnboardingManager(item.settings).configuration()).connectionMode, 'vpn-compat');
  const restored = await item.manager.saveConfiguration({ ...edit, connectionMode: 'relay' }, {
    prepareConfiguration: attachRelay,
    verifyConfiguration: async candidate => {
      assert.equal(candidate.config.connectionMode, 'relay'); assert.deepEqual(candidate.config.relay, relayFixture());
      assert.deepEqual(candidate.config.probe.expectedExitIps, input.expectedExitIps);
      return { expectedExitIps: input.expectedExitIps };
    },
  });
  assert.equal(restored.connectionMode, 'relay'); assert.ok(restored.relay);
  assert.deepEqual(await loadSecrets(item.secretsPath, await loadConfig(item.configPath)), { ...secrets, ...relaySecrets });
  assert.equal(await readFile(enrollmentPath, 'utf8'), 'retained enrollment');
});

test('VPN confirmation and mode validation precede preparation and preserve saved files on rejection', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input); const before = await rawPair(item);
  let calls = 0; const unexpected = async () => { calls++; throw new Error('must not prepare or verify'); };
  for (const vpnConfirmed of [undefined, false]) await assert.rejects(item.manager.saveConfiguration({ ...input, connectionMode: 'vpn-compat', vpnConfirmed }, { prepareConfiguration: unexpected, verifyConfiguration: unexpected }), { code: 'VPN_CONFIRMATION_REQUIRED' });
  for (const changes of [{ connectionMode: 'direct' }, { connectionMode: null }, { vpnConfirmed: 'true' }]) await assert.rejects(item.manager.saveConfiguration({ ...input, ...changes }, { prepareConfiguration: unexpected, verifyConfiguration: unexpected }), { code: 'ONBOARDING_CONFIG_INVALID' });
  assert.equal(calls, 0); assert.deepEqual(await rawPair(item), before);
  assert.equal((await item.manager.configuration()).connectionMode, 'relay');
});

test('VPN import saves without external-VPN confirmation, removes active relay credentials and retains ISP pin on verification rollback', async t => {
  const item = await fixture(t);
  await item.manager.saveConfiguration(input, { prepareConfiguration: async candidate => ({ config: { ...candidate.config, relay: relayFixture() }, secrets: { ...candidate.secrets, ...relaySecrets } }) });
  const before = await rawPair(item);
  const edit = { type: input.type, host: input.host, port: input.port, connectionMode: 'vpn-import', expectedExitIps: ['203.0.113.99'] };
  await assert.rejects(item.manager.saveConfiguration(edit, { verifyConfiguration: async candidate => {
    assert.equal(candidate.config.connectionMode, 'vpn-import'); assert.equal(candidate.config.relay, undefined);
    assert.deepEqual(candidate.config.probe.expectedExitIps, input.expectedExitIps);
    assert.deepEqual(candidate.secrets, { ISP_USERNAME: input.username, ISP_PASSWORD: input.password });
    return { expectedExitIps: ['203.0.113.99'] };
  } }), { code: 'SETUP_EXIT_MISMATCH' });
  assert.deepEqual(await rawPair(item), before);
  await assert.rejects(item.manager.saveConfiguration(edit, { prepareConfiguration: async candidate => ({ config: { ...candidate.config, relay: relayFixture() }, secrets: { ...candidate.secrets, ...relaySecrets } }) }), { code: 'ONBOARDING_CONFIG_INVALID' });
  assert.deepEqual(await rawPair(item), before);
  const saved = await item.manager.saveConfiguration(edit, { verifyConfiguration: async () => ({ expectedExitIps: input.expectedExitIps }) });
  assert.equal(saved.connectionMode, 'vpn-import'); assert.equal(saved.relay, undefined); assert.deepEqual(saved.expectedExitIps, input.expectedExitIps);
  const config = await loadConfig(item.configPath); const secrets = await loadSecrets(item.secretsPath, config);
  assert.equal(config.relay, undefined); assert.deepEqual(secrets, { ISP_USERNAME: input.username, ISP_PASSWORD: input.password });
  assert.doesNotMatch(await readFile(item.secretsPath, 'utf8'), /RELAY_/);
  assert.equal((await createOnboardingManager(item.settings).configuration()).connectionMode, 'vpn-import');
});

test('failed VPN verification, changed exit or invalid relay preparation cannot replace the relay configuration', async t => {
  const item = await fixture(t);
  await item.manager.saveConfiguration(input, { prepareConfiguration: async candidate => ({ config: { ...candidate.config, relay: relayFixture() }, secrets: { ...candidate.secrets, ...relaySecrets } }) });
  const before = await rawPair(item); const edit = { type: input.type, host: input.host, port: input.port, connectionMode: 'vpn-compat', vpnConfirmed: true };
  await assert.rejects(item.manager.saveConfiguration(edit, { verifyConfiguration: async () => { throw Object.assign(new Error('upstream blocked'), { code: 'SETUP_EXIT_MISMATCH' }); } }), { code: 'SETUP_EXIT_MISMATCH' });
  await assert.rejects(item.manager.saveConfiguration(edit, { verifyConfiguration: async () => ({ expectedExitIps: ['203.0.113.99'] }) }), { code: 'SETUP_EXIT_MISMATCH' });
  await assert.rejects(item.manager.saveConfiguration(edit, { verifyConfiguration: async () => ({ expectedExitIps: input.expectedExitIps, checks: [{ source: 'ipify', ip: '203.0.113.99' }] }) }), { code: 'SETUP_EXIT_MISMATCH' });
  await assert.rejects(item.manager.saveConfiguration(edit, { prepareConfiguration: async candidate => ({ config: { ...candidate.config, relay: relayFixture() }, secrets: { ...candidate.secrets, ...relaySecrets } }) }), { code: 'ONBOARDING_CONFIG_INVALID' });
  assert.deepEqual(await rawPair(item), before);
});

test('VPN mode transaction failure restores active relay and credentials byte for byte', async t => {
  const item = await fixture(t);
  await item.manager.saveConfiguration(input, { prepareConfiguration: async candidate => ({ config: { ...candidate.config, relay: relayFixture() }, secrets: { ...candidate.secrets, ...relaySecrets } }) });
  const before = await rawPair(item); let failOnce = true;
  const manager = createOnboardingManager({ ...item.settings, dependencies: { rename: async (from, to) => {
    if (to === item.secretsPath && failOnce) { failOnce = false; throw new Error('disk full'); }
    return rename(from, to);
  } } });
  await assert.rejects(manager.saveConfiguration({ type: input.type, host: input.host, port: input.port, connectionMode: 'vpn-compat', vpnConfirmed: true }, { verifyConfiguration: async () => ({ expectedExitIps: input.expectedExitIps }) }), { code: 'ONBOARDING_WRITE_FAILED' });
  assert.deepEqual(await rawPair(item), before);
  assert.deepEqual(await readdir(path.join(item.root, '.onboarding')), ['.gitignore']);
});

test('reading a fresh installation does not create directories or infer completion from runtime existence', async t => {
  const { manager, root } = await fixture(t);
  assert.deepEqual(await manager.status(), { firstRun: true, preferences: { autoOptimize: true, browser: 'chrome', fresh: false, externalReport: false, takeoverMode: 'global', relayRoutingMode: 'global', ...fingerprintDefaults }, completedAt: null, mock: false });
  assert.equal((await manager.configuration()).available, false);
  assert.deepEqual(await readdir(root), []);
  await assert.rejects(manager.preferences({ completed: true }), { code: 'ONBOARDING_CONFIGURATION_REQUIRED' });
});

test('preferences survive restart and completion requires a usable pinned configuration', async t => {
  const item = await fixture(t, { now: () => Date.parse('2026-10-02T01:00:00Z') });
  await item.manager.saveConfiguration({ ...input, expectedExitIps: [] });
  assert.equal((await item.manager.configuration()).available, false);
  await assert.rejects(item.manager.preferences({ completed: true }), { code: 'ONBOARDING_CONFIGURATION_REQUIRED' });
  await item.manager.saveConfiguration(input);
  const selected = await item.manager.preferences({ autoOptimize: false, browser: 'edge', fresh: false, completed: true });
  assert.equal(selected.firstRun, false);
  assert.equal(selected.completedAt, '2026-10-02T01:00:00.000Z');
  assert.deepEqual(await createOnboardingManager(item.settings).status(), selected);
  assert.equal((await item.manager.preferences({ autoOptimize: true })).completedAt, selected.completedAt);
  assert.equal((await item.manager.preferences({ completed: false })).firstRun, true);
});

test('credentials are privately serialized as literal JSON strings and never returned', async t => {
  const item = await fixture(t);
  const password = 'literal-$(do-not-execute)-`quotes`-#-"-\\';
  const saved = await item.manager.saveConfiguration({ ...input, password });
  const config = await loadConfig(item.configPath);
  assert.deepEqual(await loadSecrets(item.secretsPath, config), { ISP_USERNAME: input.username, ISP_PASSWORD: password });
  for (const response of [saved, await item.manager.configuration(), await item.manager.status()]) {
    assert.equal(JSON.stringify(response).includes(password), false);
    assert.equal(JSON.stringify(response).includes(input.username), false);
  }
  assert.equal(saved.available, true); assert.equal(saved.credentialsConfigured, true);
  assert.deepEqual(await readdir(path.join(item.root, '.onboarding')), ['.gitignore']);
  assert.equal(JSON.stringify(config).includes(password), false);
});

test('same endpoint preserves blank credentials, custom listener/probes/TLS, and omitted pins', async t => {
  const item = await fixture(t);
  await item.manager.saveConfiguration({ ...input, type: 'http' });
  const config = JSON.parse(await readFile(item.configPath, 'utf8'));
  config.listen.port = 18765; config.probe.timeoutMs = 12345; config.probe.exitUrl = 'https://check.provider.test/ip';
  config.upstream.tls = { enabled: true, serverName: 'certificate.provider.test' };
  await writeFile(item.configPath, JSON.stringify(config));
  const saved = await item.manager.saveConfiguration({ type: 'http', host: input.host.toUpperCase(), port: input.port, username: '', password: '' });
  assert.deepEqual(saved.expectedExitIps, input.expectedExitIps);
  assert.deepEqual(parseSecrets(await readFile(item.secretsPath, 'utf8')), { ISP_USERNAME: input.username, ISP_PASSWORD: input.password });
  const changed = JSON.parse(await readFile(item.configPath, 'utf8'));
  assert.deepEqual(changed.listen, config.listen); assert.deepEqual(changed.probe, config.probe); assert.deepEqual(changed.upstream.tls, config.upstream.tls);
});

test('changing endpoint or account cannot silently carry old credentials', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input);
  const before = await rawPair(item);
  for (const changed of [{ host: 'other.provider.test' }, { port: 1090 }, { type: 'http' }]) {
    await assert.rejects(item.manager.saveConfiguration({ ...input, ...changed, password: '' }), { code: 'ONBOARDING_NEW_CREDENTIALS_REQUIRED' });
  }
  await assert.rejects(item.manager.saveConfiguration({ ...input, username: 'different-account', password: '' }), { code: 'ONBOARDING_CONFIG_INVALID' });
  assert.deepEqual(await rawPair(item), before);
  const updated = await item.manager.saveConfiguration({ ...input, host: 'new.provider.test', expectedExitIps: undefined });
  assert.deepEqual(updated.expectedExitIps, []); assert.equal(updated.available, false);
});

test('explicit clear switches to no authentication and leaves a valid empty secrets file', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input);
  const saved = await item.manager.saveConfiguration({ host: input.host, port: input.port, type: input.type, clearCredentials: true });
  assert.equal(saved.auth, 'none'); assert.equal(saved.available, true);
  assert.deepEqual(parseSecrets(await readFile(item.secretsPath, 'utf8')), {});
  await assert.rejects(item.manager.saveConfiguration({ ...input, clearCredentials: true }), { code: 'ONBOARDING_CREDENTIALS_INVALID' });
});

test('invalid inputs neither call verifier nor modify existing files', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input); const before = await rawPair(item);
  let calls = 0;
  for (const invalid of [{ port: '1080' }, { port: 0 }, { host: 'https://secret:pass@host.test' }, { host: 'provider.example' }, { type: 'direct' }, { username: 'line\nbreak' }, { expectedExitIps: ['not-an-ip'] }, { unexpected: true }]) {
    await assert.rejects(item.manager.saveConfiguration({ ...input, ...invalid }, { verifyConfiguration: async () => { calls++; } }));
  }
  assert.equal(calls, 0); assert.deepEqual(await rawPair(item), before);
  for (const invalid of [{ browser: 'firefox' }, { autoOptimize: 'yes' }, { fresh: 0 }, { completed: 'yes' }, { unknown: true }]) await assert.rejects(item.manager.preferences(invalid), { code: 'ONBOARDING_PREFERENCES_INVALID' });
});

test('setup verification receives retained credentials, uses copies, and adds only sanitized evidence', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input);
  const before = await rawPair(item);
  const saved = await item.manager.saveConfiguration({ type: input.type, host: input.host, port: input.port }, { verifyConfiguration: async ({ config, secrets }) => {
    assert.deepEqual(await rawPair(item), before);
    assert.equal(secrets.ISP_PASSWORD, input.password);
    assert.deepEqual(config.probe.expectedExitIps, input.expectedExitIps);
    config.listen.port = 19191; secrets.ISP_PASSWORD = 'mutated-copy';
    return { expectedExitIps: ['203.0.113.9'], checks: [{ source: 'ipify', ip: '203.0.113.9', password: 'never-return' }], secret: 'never-return' };
  } });
  assert.deepEqual(saved.expectedExitIps, ['203.0.113.9']);
  assert.deepEqual(saved.verification, { expectedExitIps: ['203.0.113.9'], checks: [{ source: 'ipify', ip: '203.0.113.9' }], mock: false });
  assert.equal((await loadConfig(item.configPath)).listen.port, 17890);
  assert.equal(parseSecrets(await readFile(item.secretsPath, 'utf8')).ISP_PASSWORD, input.password);
});

test('failed or invalid verification never changes configuration', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input); const before = await rawPair(item);
  await assert.rejects(item.manager.saveConfiguration(input, { verifyConfiguration: async () => { throw Object.assign(new Error('核验失败'), { code: 'SETUP_CHECK_FAILED' }); } }), { code: 'SETUP_CHECK_FAILED' });
  for (const result of [{ expectedExitIps: [] }, { expectedExitIps: ['invalid'] }, { expectedExitIps: ['203.0.113.9'], checks: [{ source: '../invalid', ip: '203.0.113.9' }] }]) {
    await assert.rejects(item.manager.saveConfiguration(input, { verifyConfiguration: async () => result }), { code: 'ONBOARDING_VERIFICATION_INVALID' });
  }
  assert.deepEqual(await rawPair(item), before);
});

test('a failure replacing secrets rolls back configuration byte for byte', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input); const before = await rawPair(item);
  let failOnce = true;
  const manager = createOnboardingManager({ ...item.settings, dependencies: { rename: async (from, to) => {
    if (to === item.secretsPath && failOnce) { failOnce = false; throw new Error('simulated disk error'); }
    return rename(from, to);
  } } });
  await assert.rejects(manager.saveConfiguration({ ...input, password: 'new-password', expectedExitIps: ['203.0.113.9'] }), { code: 'ONBOARDING_WRITE_FAILED' });
  assert.deepEqual(await rawPair(item), before);
  assert.deepEqual(await readdir(path.join(item.root, '.onboarding')), ['.gitignore']);
});

test('restart repairs a failed rollback before exposing completion or configuration', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input); const before = await rawPair(item);
  let replacementStarted = false;
  const broken = createOnboardingManager({ ...item.settings, dependencies: { rename: async (from, to) => {
    if (to === item.secretsPath || (replacementStarted && to === item.configPath)) throw new Error('persistent write error');
    if (to === item.configPath) replacementStarted = true;
    return rename(from, to);
  } } });
  await assert.rejects(broken.saveConfiguration({ ...input, expectedExitIps: ['203.0.113.9'], password: 'changed-password' }), { code: 'ONBOARDING_RECOVERY_REQUIRED' });
  const pending = JSON.parse(await readFile(path.join(item.root, '.onboarding', 'pending.json'), 'utf8'));
  assert.equal(pending.phase, 'prepared');
  const restarted = createOnboardingManager(item.settings);
  await restarted.status(); assert.deepEqual(await rawPair(item), before);
  assert.equal((await restarted.configuration()).available, true);
});

test('interrupted first save restores absence of both configuration files', async t => {
  const item = await fixture(t);
  const broken = createOnboardingManager({ ...item.settings, dependencies: { rename: async (from, to) => {
    if (to === item.secretsPath) throw new Error('no space');
    return rename(from, to);
  } } });
  await assert.rejects(broken.saveConfiguration(input), { code: 'ONBOARDING_WRITE_FAILED' });
  assert.equal((await item.manager.configuration()).available, false);
  assert.deepEqual((await readdir(item.root)).filter(name => name !== '.onboarding'), []);
});

test('external edits during a failed transaction are retained with recovery journal', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input);
  const external = JSON.stringify({ external: 'changed by another program' });
  const broken = createOnboardingManager({ ...item.settings, dependencies: { rename: async (from, to) => {
    if (to === item.secretsPath) { await writeFile(item.configPath, external); throw new Error('simulated failure'); }
    return rename(from, to);
  } } });
  await assert.rejects(broken.saveConfiguration({ ...input, expectedExitIps: ['203.0.113.9'] }), { code: 'ONBOARDING_RECOVERY_REQUIRED' });
  assert.equal(await readFile(item.configPath, 'utf8'), external);
  await assert.rejects(createOnboardingManager(item.settings).status(), { code: 'ONBOARDING_CONFIG_CONFLICT' });
});

test('invalid legacy config is visible as unavailable and requires explicit fresh credentials', async t => {
  const item = await fixture(t);
  await writeFile(item.configPath, '{ invalid config');
  await writeFile(item.secretsPath, 'ISP_PASSWORD="orphan-secret"\n');
  const result = await item.manager.configuration();
  assert.equal(result.available, false); assert.equal(result.errorCode, 'ONBOARDING_CONFIG_INVALID');
  await assert.rejects(item.manager.saveConfiguration({ host: input.host, port: input.port, type: input.type }), { code: 'ONBOARDING_NEW_CREDENTIALS_REQUIRED' });
  assert.equal((await item.manager.saveConfiguration(input)).available, true);
});

test('invalid legacy secrets cannot silently switch an authenticated endpoint to unauthenticated', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input);
  await writeFile(item.secretsPath, 'INVALID_KEY=private\n');
  assert.equal((await item.manager.configuration()).errorCode, 'ONBOARDING_CREDENTIALS_INVALID');
  await assert.rejects(item.manager.saveConfiguration({ type: input.type, host: input.host, port: input.port }), { code: 'ONBOARDING_NEW_CREDENTIALS_REQUIRED' });
  assert.equal((await item.manager.saveConfiguration(input)).available, true);
  await rm(item.secretsPath);
  await assert.rejects(item.manager.saveConfiguration({ type: input.type, host: input.host, port: input.port }), { code: 'ONBOARDING_NEW_CREDENTIALS_REQUIRED' });
  assert.equal((await loadConfig(item.configPath)).upstream.auth, 'password');
});

test('tampered rollback originals are refused without overwriting the current pair', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input);
  let started = false;
  const broken = createOnboardingManager({ ...item.settings, dependencies: { rename: async (from, to) => {
    if (to === item.secretsPath || (started && to === item.configPath)) throw new Error('persistent error');
    if (to === item.configPath) started = true;
    return rename(from, to);
  } } });
  await assert.rejects(broken.saveConfiguration({ ...input, expectedExitIps: ['203.0.113.9'] }), { code: 'ONBOARDING_RECOVERY_REQUIRED' });
  const record = JSON.parse(await readFile(path.join(item.root, '.onboarding', 'pending.json'), 'utf8'));
  await writeFile(path.join(item.root, '.onboarding', record.id, 'config.before'), '{}');
  const before = await rawPair(item);
  await assert.rejects(createOnboardingManager(item.settings).status(), { code: 'ONBOARDING_RECOVERY_REQUIRED' });
  assert.deepEqual(await rawPair(item), before);
});

test('a committed pair survives interruption of journal cleanup and is not rolled back', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input);
  const journalPath = path.join(item.root, '.onboarding', 'pending.json');
  const interrupted = createOnboardingManager({ ...item.settings, dependencies: { rm: async (file, options) => {
    if (file === journalPath) throw new Error('journal cleanup interrupted');
    return rm(file, options);
  } } });
  await assert.rejects(interrupted.saveConfiguration({ ...input, expectedExitIps: ['203.0.113.9'], password: 'committed-password' }), { code: 'ONBOARDING_RECOVERY_REQUIRED' });
  assert.equal(JSON.parse(await readFile(journalPath, 'utf8')).phase, 'committed');
  await createOnboardingManager(item.settings).status();
  assert.deepEqual((await loadConfig(item.configPath)).probe.expectedExitIps, ['203.0.113.9']);
  assert.equal(parseSecrets(await readFile(item.secretsPath, 'utf8')).ISP_PASSWORD, 'committed-password');
  assert.deepEqual(await readdir(path.join(item.root, '.onboarding')), ['.gitignore']);
});

test('overlapping state paths and linked target directories are rejected', async t => {
  const item = await fixture(t);
  for (const settings of [{ configPath: path.join(item.root, '.onboarding', 'preferences.json') }, { secretsPath: item.configPath }]) assert.throws(() => createOnboardingManager({ ...item.settings, ...settings }), { code: 'ONBOARDING_PATH_INVALID' });
  const target = path.join(item.root, 'real'); const linked = path.join(item.root, 'linked');
  await mkdir(target);
  await symlink(target, linked, process.platform === 'win32' ? 'junction' : 'dir');
  const manager = createOnboardingManager({ ...item.settings, configPath: path.join(linked, 'config.json') });
  await assert.rejects(manager.saveConfiguration(input), { code: 'ONBOARDING_PATH_INVALID' });
  assert.deepEqual(await readdir(target), []);
});

test('explicit external launcher files stay readable but cannot be saved or have their ACLs changed', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input);
  const before = await rawPair(item);
  const forbidden = () => { throw new Error('external paths must remain read-only'); };
  const manager = createOnboardingManager({ ...item.settings, runtimeRoot: path.join(item.root, 'separate-runtime'), dependencies: Object.fromEntries(['rename', 'rm', 'rmdir', 'open', 'writePrivate', 'createPrivateDirectory'].map(name => [name, forbidden])) });
  assert.equal((await manager.status()).firstRun, true);
  const config = await manager.configuration();
  assert.equal(config.readOnly, true); assert.equal(config.available, true);
  assert.equal(config.host, input.host);
  assert.equal(JSON.stringify(config).includes(input.password), false);
  await assert.rejects(manager.saveConfiguration(input, { verifyConfiguration: forbidden }), { code: 'ONBOARDING_CONFIG_READONLY' });
  assert.deepEqual(await rawPair(item), before);
});

test('mock onboarding never touches filesystem dependencies or supplied host verifier', async t => {
  const item = await fixture(t);
  const deny = () => { throw new Error('host access'); };
  const manager = createOnboardingManager({ ...item.settings, mock: true, dependencies: { lstat: deny, realpath: deny, readFile: deny, rename: deny, rm: deny, open: deny, writePrivate: deny, createPrivateDirectory: deny } });
  assert.equal((await manager.status()).firstRun, true);
  assert.equal((await manager.status()).preferences.browser, 'chrome');
  assert.equal((await manager.status()).preferences.fresh, false);
  const result = await manager.saveConfiguration(input, { verifyConfiguration: deny });
  assert.equal(result.verification.mock, true);
  assert.equal((await manager.preferences({ completed: true })).firstRun, false);
  assert.equal((await manager.configuration()).mock, true);
  assert.deepEqual(await readdir(item.root), []);
});

test('mock VPN mode keeps confirmation and pin requirements without native access or verifier calls', async t => {
  const item = await fixture(t); const deny = () => { throw new Error('host access'); };
  const manager = createOnboardingManager({ ...item.settings, mock: true, dependencies: { lstat: deny, realpath: deny, readFile: deny, rename: deny, rm: deny, open: deny, writePrivate: deny, createPrivateDirectory: deny } });
  await manager.saveConfiguration(input, { prepareConfiguration: async candidate => ({ config: { ...candidate.config, relay: relayFixture() }, secrets: { ...candidate.secrets, ...relaySecrets } }), verifyConfiguration: deny });
  const edit = { type: input.type, host: input.host, port: input.port, connectionMode: 'vpn-compat', vpnConfirmed: true };
  const result = await manager.saveConfiguration(edit, { verifyConfiguration: deny });
  assert.equal(result.connectionMode, 'vpn-compat'); assert.equal(result.relay, undefined);
  assert.deepEqual(result.expectedExitIps, input.expectedExitIps); assert.equal(result.verification.mock, true);
  await assert.rejects(manager.saveConfiguration({ type: input.type, host: input.host, port: input.port }), { code: 'VPN_CONFIRMATION_REQUIRED' });
  assert.equal((await manager.configuration()).connectionMode, 'vpn-compat');
  assert.deepEqual(await readdir(item.root), []);
});

test('concurrent preference saves merge in order without losing changes', async t => {
  const { manager } = await fixture(t);
  await Promise.all([manager.preferences({ browser: 'edge' }), manager.preferences({ autoOptimize: false }), manager.preferences({ fresh: false }), manager.preferences({ takeoverMode: 'application' }), manager.preferences({ relayRoutingMode: 'smart' })]);
  assert.deepEqual((await manager.status()).preferences, { browser: 'edge', autoOptimize: false, fresh: false, externalReport: false, takeoverMode: 'application', relayRoutingMode: 'smart', ...fingerprintDefaults });
});

test('fingerprint identity settings persist independently of legacy fresh/browser preferences and network credentials', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration(input); const before = await rawPair(item);
  await item.manager.preferences({ browser: 'fingerprint', fingerprintLanguage: 'ja-JP', fingerprintTimezone: 'Asia/Tokyo', fingerprintNativeGraphics: false });
  const restarted = createOnboardingManager(item.settings);
  await restarted.preferences({ fresh: false });
  const prefs = (await restarted.status()).preferences;
  assert.equal(prefs.browser, 'fingerprint'); assert.equal(prefs.fingerprintFresh, false);
  assert.equal(prefs.fingerprintLanguage, 'ja-JP'); assert.equal(prefs.fingerprintTimezone, 'Asia/Tokyo'); assert.equal(prefs.fingerprintNativeGraphics, false);
  await restarted.preferences({ fingerprintFresh: true }); assert.equal((await restarted.status()).preferences.fresh, false);
  const file = path.join(item.root, '.onboarding', 'preferences.json'), raw = await readFile(file, 'utf8');
  for (const changes of [{ fingerprintLanguage: 'bad tag' }, { fingerprintTimezone: 'Mars/Base' }, { fingerprintFresh: 'yes' }, { fingerprintNativeGraphics: 1 }]) {
    await assert.rejects(restarted.preferences(changes), { code: 'ONBOARDING_PREFERENCES_INVALID' });
    assert.equal(await readFile(file, 'utf8'), raw);
  }
  assert.deepEqual(await rawPair(item), before);
});

test('legacy version 1 browser preferences remain unchanged by release defaults and repeated reads', async t => {
  const item = await fixture(t); const dir = path.join(item.root, '.onboarding'); await mkdir(dir);
  const file = path.join(dir, 'preferences.json');
  const original = { version: 1, preferences: { browser: 'chrome', autoOptimize: false, fresh: true, externalReport: true, takeoverMode: 'smart', relayRoutingMode: 'smart' }, completedAt: '2026-10-01T00:00:00.000Z' };
  const legacy = JSON.stringify(original);
  await writeFile(file, legacy);
  const prefs = (await item.manager.status()).preferences;
  assert.equal(prefs.browser, 'chrome'); assert.equal(prefs.fresh, true); assert.deepEqual(Object.fromEntries(Object.keys(fingerprintDefaults).map(key => [key, prefs[key]])), fingerprintDefaults);
  assert.equal(await readFile(file, 'utf8'), legacy);
  await createOnboardingManager(item.settings).status();
  assert.equal(await readFile(file, 'utf8'), legacy, 'a repeated start does not rewrite preferences');
  assert.deepEqual(await readdir(dir), ['preferences.json'], 'reading never creates a migration receipt');
  await item.manager.preferences({ browser: 'edge' });
  assert.equal((await createOnboardingManager(item.settings).status()).preferences.browser, 'edge', 'a later customer choice persists');
});

test('browser defaults preserve ISP, imported VPN, authorization, and browser profile files byte for byte', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration({ ...input, connectionMode: 'vpn-import' });
  const retained = ['config.json', 'upstream.secrets.env', '.vpn-config/nodes.json', '.license/device.json', '.license/state.json', 'browser-profiles/chrome/Default/Cookies', 'browser-profiles/fingerprint/.mc-fingerprint.json'];
  for (const relative of retained.slice(2)) {
    const file = path.join(item.root, relative); await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, Buffer.from(`synthetic retained data: ${relative}\u0000\xff`, 'utf8'));
  }
  const before = await Promise.all(retained.map(relative => readFile(path.join(item.root, relative))));
  const directory = path.join(item.root, '.onboarding');
  const original = { version: 1, preferences: { browser: 'edge', autoOptimize: false, fresh: false, fingerprintFresh: true, fingerprintLanguage: 'ja-JP', fingerprintTimezone: 'Asia/Tokyo', fingerprintNativeGraphics: true, takeoverMode: 'application', relayRoutingMode: 'smart' }, completedAt: '2026-10-01T00:00:00.000Z' };
  await writeFile(path.join(directory, 'preferences.json'), JSON.stringify(original));
  const upgraded = await createOnboardingManager(item.settings).status();
  assert.deepEqual(upgraded.preferences, { ...fingerprintDefaults, externalReport: false, ...original.preferences });
  assert.equal(upgraded.completedAt, original.completedAt); assert.equal(upgraded.firstRun, false);
  assert.deepEqual(await Promise.all(retained.map(relative => readFile(path.join(item.root, relative)))), before);
  assert.equal((await createOnboardingManager(item.settings).configuration()).connectionMode, 'vpn-import');
});

test('an existing signed offline license and selected imported VPN remain usable after the browser upgrade', async t => {
  const item = await fixture(t); await item.manager.saveConfiguration({ ...input, connectionMode: 'vpn-import' });
  const vpnState = path.join(item.root, '.vpn-config');
  const imported = createImportedVpnStore({ stateDir: vpnState });
  const vpn = await imported.import(JSON.stringify({ proxies: [vpnYamlNode(), vpnYamlNode({ name: 'Second', port: 8443 })] }));
  await imported.select(2, { expectedId: vpn.id });
  const signing = generateKeyPairSync('ed25519'); const timestamp = Date.UTC(2026, 9, 12, 0);
  const licenseOptions = { stateDir: path.join(item.root, '.license'), now: () => timestamp,
    config: { version: 1, mode: 'required', publicKeys: { upgrade: signing.publicKey.export({ type: 'spki', format: 'pem' }) } },
    getDeviceIdentity: async () => 'synthetic-upgrade-machine', request: () => { throw new Error('offline upgrade must not call an authorization service'); },
    dependencies: { monotonic: () => 0, createPrivateDirectory: directory => mkdir(directory, { mode: 0o700 }) } };
  const oldClient = createLicenseClient(licenseOptions); let newClient;
  try {
    await oldClient.initialize();
    const { deviceId, deviceKeyHash } = oldClient.status();
    const licenseId = randomUUID();
    await oldClient.importLicense(signLicense({ version: 1, licenseId, deviceId, deviceKeyHash, generation: 1, plan: 'isp-30d-single', status: 'active', issuedAt: timestamp,
      expiresAt: timestamp + 86400000 * 30, offlineUntil: timestamp + 86400000, ispExpiresAt: timestamp + 86400000 * 30, vpsExpiresAt: null },
    { privateKey: signing.privateKey.export({ type: 'pkcs8', format: 'pem' }), keyId: 'upgrade' }));
    await oldClient.close();
    const files = ['config.json', 'upstream.secrets.env', '.vpn-config/nodes.json', '.license/device.json', '.license/state.json'];
    const before = await Promise.all(files.map(file => readFile(path.join(item.root, file))));
    await writeFile(path.join(item.root, '.onboarding', 'preferences.json'), JSON.stringify({ version: 1, preferences: { browser: 'chrome', autoOptimize: false, fresh: false, takeoverMode: 'global' }, completedAt: '2026-10-01T00:00:00.000Z' }));
    const current = await createOnboardingManager(item.settings).status();
    assert.equal(current.preferences.browser, 'chrome'); assert.equal(current.firstRun, false);
    assert.deepEqual(await Promise.all(files.map(file => readFile(path.join(item.root, file)))), before);
    assert.equal((await createImportedVpnStore({ stateDir: vpnState }).status()).selectedIndex, 2);
    newClient = createLicenseClient(licenseOptions);
    await newClient.initialize();
    assert.equal(newClient.assertAllowed().allowed, true); assert.equal(newClient.status().licenseId, licenseId);
    assert.equal(newClient.status().deviceId, deviceId); assert.equal(newClient.status().deviceKeyHash, deviceKeyHash);
    const configuration = await createOnboardingManager(item.settings).configuration();
    assert.equal(configuration.available, true); assert.equal(configuration.connectionMode, 'vpn-import');
  } finally { await oldClient.close(); await newClient?.close(); }
});

test('explicit browser and separate profile choices survive restart for every supported browser', async t => {
  const item = await fixture(t);
  for (const browser of ['chrome', 'edge', 'fingerprint']) for (const fresh of [false, true]) {
    const saved = await item.manager.preferences({ browser, fresh, fingerprintFresh: !fresh });
    const current = await createOnboardingManager(item.settings).status();
    assert.deepEqual(current, saved);
    assert.equal(current.preferences.browser, browser); assert.equal(current.preferences.fresh, fresh);
    assert.equal(current.preferences.fingerprintFresh, !fresh);
  }
  assert.equal((await readdir(path.join(item.root, '.onboarding'))).includes('fingerprint-default-1.6.2.json'), false);
});

test('old browser-default receipts are not consulted or changed when reading and saving preferences', async t => {
  const item = await fixture(t); const directory = path.join(item.root, '.onboarding'); await mkdir(directory);
  const file = path.join(directory, 'preferences.json');
  const receipt = path.join(directory, 'fingerprint-default-1.6.2.json');
  const oldReceipt = '{"version":1,"appliedAt":"2026-10-12T00:00:00.000Z"}';
  await writeFile(receipt, oldReceipt);
  const manager = createOnboardingManager({ ...item.settings, dependencies: { readFile: async (target, ...args) => {
    assert.notEqual(target, receipt, 'retired receipts must not be read'); return readFile(target, ...args);
  }, rename: async (from, to) => {
    assert.notEqual(to, receipt, 'retired receipts must not be rewritten'); return rename(from, to);
  } } });
  const original = { version: 1, preferences: { browser: 'fingerprint', autoOptimize: false, fresh: true }, completedAt: null };
  const raw = JSON.stringify(original); await writeFile(file, raw);
  assert.equal((await manager.status()).preferences.browser, 'fingerprint');
  assert.equal(await readFile(file, 'utf8'), raw);
  await manager.preferences({ browser: 'chrome', fresh: false });
  assert.equal((await createOnboardingManager(item.settings).status()).preferences.browser, 'chrome');
  assert.equal(await readFile(receipt, 'utf8'), oldReceipt);
});

test('a damaged or linked retired receipt cannot block preferences or alter saved browser choices', async t => {
  const item = await fixture(t); const directory = path.join(item.root, '.onboarding'); await mkdir(directory);
  const file = path.join(directory, 'preferences.json');
  const original = JSON.stringify({ version: 1, preferences: { browser: 'edge', autoOptimize: true, fresh: false }, completedAt: null });
  const receipt = path.join(directory, 'fingerprint-default-1.6.2.json');
  await writeFile(file, original); await writeFile(receipt, '{"version":1,"appliedAt":"invalid"}');
  assert.equal((await item.manager.status()).preferences.browser, 'edge');
  assert.equal(await readFile(file, 'utf8'), original);
  assert.equal(await readFile(receipt, 'utf8'), '{"version":1,"appliedAt":"invalid"}');
  await rm(receipt);
  const elsewhere = path.join(item.root, 'elsewhere'); await mkdir(elsewhere);
  await symlink(elsewhere, receipt, process.platform === 'win32' ? 'junction' : 'dir');
  assert.equal((await item.manager.status()).preferences.browser, 'edge');
  assert.equal(await readFile(file, 'utf8'), original);
  await item.manager.preferences({ browser: 'fingerprint' });
  assert.equal((await createOnboardingManager(item.settings).status()).preferences.browser, 'fingerprint');
  assert.deepEqual(await readdir(elsewhere), [], 'retired receipt links are never followed for writes');
});

test('unknown persisted preference fields are not reflected into the API', async t => {
  const item = await fixture(t);
  await item.manager.preferences({ browser: 'edge' });
  const file = path.join(item.root, '.onboarding', 'preferences.json');
  const record = JSON.parse(await readFile(file, 'utf8'));
  record.preferences.password = 'must-not-echo';
  await writeFile(file, JSON.stringify(record));
  await assert.rejects(item.manager.status(), error => error.code === 'ONBOARDING_STATE_INVALID' && !error.message.includes('must-not-echo'));
});


test('external reports require opt-in and legacy preferences default to disabled', async t => {
  const item = await fixture(t);
  assert.equal((await item.manager.status()).preferences.externalReport, false);
  await item.manager.preferences({ externalReport: true });
  assert.equal((await createOnboardingManager(item.settings).status()).preferences.externalReport, true);
  await assert.rejects(item.manager.preferences({ externalReport: 'yes' }), { code: 'ONBOARDING_PREFERENCES_INVALID' });
  const file = path.join(item.root, '.onboarding', 'preferences.json');
  const legacy = JSON.parse(await readFile(file, 'utf8')); delete legacy.preferences.externalReport;
  await writeFile(file, JSON.stringify(legacy));
  assert.equal((await createOnboardingManager(item.settings).status()).preferences.externalReport, false);
  assert.equal(Object.hasOwn(JSON.parse(await readFile(file, 'utf8')).preferences, 'externalReport'), false);
});

test('takeover preferences survive restart and independent partial updates without changing configuration', async t => {
  const item = await fixture(t);
  await item.manager.saveConfiguration(input);
  const before = await rawPair(item);
  for (const takeoverMode of ['application', 'smart', 'global']) {
    await item.manager.preferences({ takeoverMode });
    const restarted = createOnboardingManager(item.settings);
    assert.equal((await restarted.status()).preferences.takeoverMode, takeoverMode);
    await restarted.preferences({ relayRoutingMode: 'smart', browser: 'edge' });
    assert.deepEqual((await restarted.status()).preferences, { autoOptimize: true, browser: 'edge', fresh: false, externalReport: false, takeoverMode, relayRoutingMode: 'smart', ...fingerprintDefaults });
  }
  const restarted = createOnboardingManager(item.settings);
  await restarted.preferences({ relayRoutingMode: 'global', fresh: false });
  assert.deepEqual((await createOnboardingManager(item.settings).status()).preferences, { autoOptimize: true, browser: 'edge', fresh: false, externalReport: false, takeoverMode: 'global', relayRoutingMode: 'global', ...fingerprintDefaults });
  assert.deepEqual(await rawPair(item), before);
});

test('legacy version 1 takeover preferences fill only missing values without rewriting a read', async t => {
  const item = await fixture(t);
  await item.manager.saveConfiguration(input);
  await item.manager.preferences({ browser: 'edge', autoOptimize: false, fresh: false, externalReport: true, takeoverMode: 'application', relayRoutingMode: 'smart', completed: true });
  const file = path.join(item.root, '.onboarding', 'preferences.json');
  const original = JSON.parse(await readFile(file, 'utf8'));
  for (const missing of [['takeoverMode', 'relayRoutingMode'], ['takeoverMode'], ['relayRoutingMode']]) {
    const legacy = structuredClone(original);
    for (const key of missing) delete legacy.preferences[key];
    const raw = JSON.stringify(legacy);
    await writeFile(file, raw);
    const manager = createOnboardingManager(item.settings);
    const current = await manager.status();
    const expected = { ...original.preferences };
    for (const key of missing) expected[key] = 'global';
    assert.deepEqual(current.preferences, expected);
    assert.equal(current.completedAt, original.completedAt);
    assert.equal(await readFile(file, 'utf8'), raw);
    await manager.preferences({ fresh: true });
    assert.deepEqual(JSON.parse(await readFile(file, 'utf8')), { ...original, preferences: { ...expected, fresh: true } });
  }
});

test('invalid takeover enums fail before persisted preferences are replaced or exposed', async t => {
  const item = await fixture(t);
  await item.manager.preferences({ takeoverMode: 'smart', relayRoutingMode: 'smart' });
  const file = path.join(item.root, '.onboarding', 'preferences.json');
  const raw = await readFile(file, 'utf8');
  for (const changes of [{ takeoverMode: 'tun' }, { takeoverMode: null }, { takeoverMode: false }, { takeoverMode: [] }, { relayRoutingMode: 'application' }, { relayRoutingMode: null }, { relayRoutingMode: true }, { relayRoutingMode: {} }, { routingMode: 'global' }]) {
    await assert.rejects(item.manager.preferences(changes), { code: 'ONBOARDING_PREFERENCES_INVALID' });
    assert.equal(await readFile(file, 'utf8'), raw);
    const record = JSON.parse(raw);
    Object.assign(record.preferences, changes);
    await writeFile(file, JSON.stringify(record));
    await assert.rejects(createOnboardingManager(item.settings).status(), { code: 'ONBOARDING_STATE_INVALID' });
    await writeFile(file, raw);
  }
});
