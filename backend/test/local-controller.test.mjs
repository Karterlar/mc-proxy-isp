import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdtemp, readFile, rm, rename, writeFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import { once } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { startController } from '../src/local-controller.mjs';
import { createBrowserManager } from '../src/browser-session.mjs';
import { createBrowserWorkspaceManager } from '../src/browser-workspaces.mjs';
import { createServiceReminderManager } from '../src/service-reminders.mjs';
import { createCustomerDelivery, CUSTOMER_DELIVERY_MAX_BYTES } from '../src/customer-delivery.mjs';
import { signLicense } from '../src/license-format.mjs';
import { createEnvironmentManager, createMockEnvironmentAdapter } from '../src/environment-manager.mjs';
import { createClaudeCleanupManager } from '../src/claude-cleanup.mjs';
import { createOnboardingManager } from '../src/onboarding.mjs';
import { createSetupVerifier } from '../src/setup-verification.mjs';
import { createQualityReportStore } from '../src/quality-report.mjs';
import { createRelayManager } from '../src/relay-client.mjs';
import { createImportedVpnStore } from '../src/imported-vpn-store.mjs';
import { connectTunnel } from '../src/probe.mjs';
import { shortlistImportedNodes } from '../src/imported-node-shortlist.mjs';
import { relayFixture, relaySecrets } from './relay-fixture.mjs';
import { loadConfig, loadSecrets } from '../src/config.mjs';
import { createChainDiagnosticManifest } from '../src/chain-diagnostics.mjs';
import { exportChainDiagnostics } from '../src/diagnostics-export.mjs';

const fingerprint = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const failure = code => Object.assign(new Error('private credential must never escape'), { code });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

test('fingerprint security check is explicit, cannot select a URL and cannot hold disconnect', async t => {
  let calls=0; const gate=deferred(), baseline={status:'outdated',engineVersion:'150.0.7871.186',baselineVersion:'155.0.8059.85'};
  const f=await fixture(t,{shutdownOnCleanup:true,fingerprintSecurity:{snapshot:()=>baseline,check:async()=>{calls++;await gate.promise;return baseline;}}});
  assert.equal((await f.get('/api/browser/fingerprint')).data.data.security.status,'outdated');
  assert.equal(calls,0);
  assert.equal((await f.post('/api/browser/fingerprint/security',{})).data.error.code,'CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/browser/fingerprint/security',{confirm:true,url:'http://other.invalid/'})).status,400);
  assert.equal(calls,0);assert.equal((await f.start()).status,200);
  const checking=f.post('/api/browser/fingerprint/security',{confirm:true});
  for(let i=0;i<20&&!calls;i++)await delay(5);
  assert.equal(calls,1);
  const stopping=await f.stop();assert.equal(stopping.status,200);assert.equal(f.running,false,'check is outside the routing queue');
  gate.resolve();assert.equal((await checking).data.data.security.status,'outdated');
});

test('manual browser profile refresh works offline, retains the chosen browser and switches only its pure-session preference off', async t => {
  const f = await fixture(t, { shutdownOnCleanup: true });
  await f.onboarding.preferences({ browser: 'fingerprint', fresh: true, fingerprintFresh: true });
  const calls = [];
  f.browsers.refreshProfile = async input => { calls.push(input); return { changed: true, archiveId: randomUUID(), archives: [], mode: 'mocked' }; };
  f.browsers.profileArchives = async input => ({ browser: input.browser, currentAvailable: true, archives: [] });
  const listed = await f.get('/api/browser/profiles?browser=chrome');
  assert.equal(listed.status, 200, JSON.stringify({ response: listed.data, startupRecovery: (await f.get('/api/status')).data.data.startupRecovery }));
  for (const query of ['', '?browser=chrome&browser=edge', '?browser=../other', '?browser=chrome&path=other']) assert.equal((await f.get('/api/browser/profiles' + query)).status, 400);
  assert.equal((await f.post('/api/browser/profiles/refresh', { browser: 'chrome' })).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/browser/profiles/refresh', { confirm: true, browser: 'chrome', path: '../other' })).status, 400);
  assert.equal(calls.length, 0);
  const refreshed = await f.post('/api/browser/profiles/refresh', { confirm: true, browser: 'chrome' });
  assert.equal(refreshed.status, 200, JSON.stringify(refreshed.data));
  assert.deepEqual(calls, [{ browser: 'chrome', confirm: true }]);
  const preferences = (await f.onboarding.status()).preferences;
  assert.equal(preferences.browser, 'fingerprint'); assert.equal(preferences.fresh, false); assert.equal(preferences.fingerprintFresh, true);
  assert.equal(f.probeCalls + f.systemProbeCalls + f.requestCalls, 0); assert.equal(f.running, false); assert.deepEqual(f.events, []);
});

test('profile replacement safely closes only the matching owned browser, keeps the proxy and expires pending launch plans', async t => {
  const f = await fixture(t, { shutdownOnCleanup: true }); await f.start();
  const plan = (await f.plan()).data.data, order = [];
  f.browserRunning = true;
  f.browsers.status = async () => ({ running: f.browserRunning, managed: true, browser: f.browserRunning ? 'chrome' : null });
  f.browsers.close = async () => { order.push('close'); if (f.closeError) throw f.closeError; f.browserRunning = false; };
  f.browsers.refreshProfile = async () => { order.push('refresh'); return { changed: true, archives: [] }; };
  const before = [...f.events], probes = f.probeCalls;
  const result = await f.post('/api/browser/profiles/refresh', { confirm: true, browser: 'chrome' });
  assert.equal(result.status, 200, JSON.stringify(result.data)); assert.deepEqual(order, ['close', 'refresh']);
  assert.equal(f.running, true); assert.equal(f.browserRunning, false); assert.equal(f.probeCalls, probes); assert.deepEqual(f.events, before);
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: plan.token })).data.error.code, 'CONFIRMATION_INVALID');
  const failedPlan = (await f.plan()).data.data;
  f.browserRunning = true; f.closeError = failure('BROWSER_CLOSE_TIMEOUT'); order.length = 0;
  assert.equal((await f.post('/api/browser/profiles/refresh', { confirm: true, browser: 'chrome' })).data.error.code, 'BROWSER_CLOSE_TIMEOUT');
  assert.deepEqual(order, ['close']); assert.equal(f.running, true); assert.equal(f.browserRunning, true);
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: failedPlan.token })).data.error.code, 'CONFIRMATION_INVALID');
  f.closeError = null;
});

test('profile restore validates its archive before closing and never closes another browser or a named workspace', async t => {
  const f = await fixture(t, { shutdownOnCleanup: true }); const calls = [];
  f.browsers.status = async () => ({ running: true, managed: true, browser: 'edge' });
  f.browsers.close = async () => calls.push('close');
  f.browsers.restoreProfile = async value => { calls.push(value); return { restored: true }; };
  assert.equal((await f.post('/api/browser/profiles/restore', { confirm: true, browser: 'chrome', archiveId: '../other' })).status, 400);
  assert.equal((await f.post('/api/browser/profiles/restore', { confirm: true, browser: 'chrome', archiveId: randomUUID() })).data.error.code, 'BROWSER_PROFILE_SCOPE_MISMATCH');
  f.browsers.status = async () => ({ running: true, managed: true, browser: 'chrome', workspaceId: randomUUID() });
  assert.equal((await f.post('/api/browser/profiles/restore', { confirm: true, browser: 'chrome', archiveId: randomUUID() })).data.error.code, 'BROWSER_PROFILE_SCOPE_MISMATCH');
  assert.deepEqual(calls, []);
  f.browsers.status = async () => ({ running: false });
});

test('default-profile refresh and restore refuse an active fresh window before closing or archiving any data', async t => {
  const f = await fixture(t, { shutdownOnCleanup: true }), calls = [];
  await f.onboarding.preferences({ fresh: true });
  f.browsers.status = async () => ({ running: true, managed: true, browser: 'chrome', fresh: true });
  f.browsers.close = async () => calls.push('close');
  f.browsers.refreshProfile = async () => calls.push('refresh');
  f.browsers.restoreProfile = async () => calls.push('restore');
  const before = (await f.onboarding.status()).preferences;
  for (const action of ['refresh', 'restore']) {
    const result = await f.post(`/api/browser/profiles/${action}`, { confirm: true, browser: 'chrome', ...(action === 'restore' ? { archiveId: randomUUID() } : {}) });
    assert.equal(result.status, 409); assert.equal(result.data.error.code, 'BROWSER_PROFILE_FRESH_RUNNING');
    assert.match(result.data.error.message, /纯净空间.*默认保留资料/);
  }
  assert.deepEqual(calls, []); assert.deepEqual((await f.onboarding.status()).preferences, before);
  assert.equal(f.probeCalls + f.systemProbeCalls + f.requestCalls, 0);
  f.browsers.status = async () => ({ running: false });
});

test('fingerprint profile restore preserves ordinary fresh preferences and reports a post-move preference failure without discarding the archive', async t => {
  const f = await fixture(t, { shutdownOnCleanup: true });
  await f.onboarding.preferences({ fresh: true, fingerprintFresh: true });
  const archiveId = randomUUID(), calls = [];
  f.browsers.restoreProfile = async input => { calls.push(input); return { restored: true, archivedCurrentId: randomUUID(), archives: [{ id: archiveId, createdAt: new Date().toISOString() }] }; };
  const restored = await f.post('/api/browser/profiles/restore', { confirm: true, browser: 'fingerprint', archiveId });
  assert.equal(restored.status, 200, JSON.stringify(restored.data));
  const preferences = (await f.onboarding.status()).preferences;
  assert.equal(preferences.fresh, true); assert.equal(preferences.fingerprintFresh, false);
  const write = f.onboarding.preferences; f.onboarding.preferences = async () => { throw failure('ONBOARDING_WRITE_FAILED'); };
  const failed = await f.post('/api/browser/profiles/restore', { confirm: true, browser: 'fingerprint', archiveId });
  assert.equal(failed.data.error.code, 'BROWSER_PROFILE_PREFERENCES_FAILED'); assert.equal(calls.length, 2);
  f.onboarding.preferences = write;
});

test('refreshing a running named environment creates its replacement and preserves the ISP, default profile and browser choice', async t => {
  const f = await workspaceFixture(t, { shutdownOnCleanup: true }), old = await f.createWorkspace('长期账号', 'chrome');
  await f.post('/api/workspaces/start', { confirm: true, id: old.id });
  const config = structuredClone(f.config), browser = (await f.onboarding.status()).preferences.browser;
  f.browsers.refreshProfile = async () => assert.fail('A named environment must not refresh the default profile');
  assert.equal((await f.post('/api/browser/profiles/refresh', { confirm: true, browser: 'chrome' })).data.error.code, 'BROWSER_PROFILE_SCOPE_MISMATCH');
  const refreshed = await f.post('/api/workspaces/refresh', { confirm: true, id: old.id });
  assert.equal(refreshed.status, 200, JSON.stringify(refreshed.data));
  const next = refreshed.data.data.workspace;
  assert.notEqual(next.id, old.id); assert.equal(next.browser, 'chrome'); assert.deepEqual(next.services, old.services);
  assert.equal(f.browserRunning, false); assert.equal(f.running, true); assert.deepEqual(f.config, config);
  assert.equal((await f.onboarding.status()).preferences.browser, browser);
  assert.equal((await f.get('/api/workspaces')).data.data.items.find(item => item.id === old.id).archivedAt !== null, true);
  assert.equal((await f.post('/api/workspaces/refresh', { confirm: true, id: old.id })).data.error.code, 'WORKSPACE_ARCHIVED');
});

test('saved manual work and daily profiles operate offline without probing or starting the proxy; original recovery remains separate', async t => {
  const environment = createEnvironmentManager({ mock: true });
  const original = (await environment.check()).current;
  const f = await fixture(t, { mock: true, environment });
  const preferences = { work: { mode: 'custom', countryCode: 'JP', timeZoneId: 'Tokyo Standard Time', preferredLanguage: 'ja-JP', culture: 'zh-SG' }, daily: { countryCode: 'CN', timeZoneId: 'China Standard Time', preferredLanguage: 'zh-CN', culture: 'zh-CN' } };
  assert.equal((await f.post('/api/environment/preferences', preferences)).data.error.code, 'CONFIRMATION_REQUIRED');
  const saved = await f.post('/api/environment/preferences', { ...preferences, confirm: true });
  assert.equal(saved.status, 200); assert.deepEqual(saved.data.data.current, original);
  assert.equal((await f.post('/api/environment/optimize', { confirm: true })).status, 200);
  assert.equal(environment.status().current.culture, 'zh-SG'); assert.equal(environment.status().current.homeGeoId, 122);
  const restored = await f.post('/api/environment/restore', { confirm: true });
  assert.equal(restored.status, 200); assert.equal(restored.data.data.optimization.restoreSource, 'daily');
  assert.equal(restored.data.data.current.timeZoneId, 'China Standard Time');
  assert.equal(restored.data.data.current.culture, 'zh-CN');
  assert.equal((await f.post('/api/environment/restore-original')).data.error.code, 'CONFIRMATION_REQUIRED');
  const reset = await f.post('/api/environment/restore-original', { confirm: true });
  assert.equal(reset.status, 200); assert.deepEqual(reset.data.data.current, original);
  assert.equal(f.probeCalls + f.requestCalls, 0); assert.equal(f.running, false);
});

test('profile save rejects invalid input without OS mutation and exit-following work still requires a verified connection', async t => {
  const environment = createEnvironmentManager({ mock: true });
  const original = (await environment.check()).current;
  const f = await fixture(t, { mock: true, environment });
  const preferences = environment.status().preferences;
  const response = await f.post('/api/environment/preferences', { confirm: true, ...preferences, work: { ...preferences.work, culture: 'en-US' } });
  assert.equal(response.status, 400); assert.equal(response.data.error.code, 'ENVIRONMENT_PROFILE_INVALID');
  assert.deepEqual(environment.status().current, original);
  assert.notEqual((await f.post('/api/environment/optimize', { confirm: true })).status, 200);
  assert.equal(f.running, false);
});

test('browser observation binds the real local page to the active verified route and expires on session end', async t => {
  const f = await fixture(t, { shutdownOnCleanup: true });
  assert.notEqual((await f.post('/api/browser-observation/start', { confirm: true, browser: 'chrome', launch: false })).status, 200);
  assert.equal((await f.start()).status, 200);
  assert.equal((await f.post('/api/browser-observation/start', { confirm: true, launch: false, url: 'https://invalid.test' })).status, 400);
  const started = await f.post('/api/browser-observation/start', { confirm: true, browser: 'chrome', launch: false });
  assert.equal(started.status, 200); const url = started.data.data.url;
  assert.equal((await fetch(url)).status, 200);
  const context = await (await fetch(url + 'context')).json();
  assert.deepEqual(context.expectedExitIps, ['203.0.113.8']); assert.equal(context.browser, 'chrome');
  assert.equal((await f.get('/api/browser-observation')).data.data.status, 'waiting');
  assert.equal(f.browserRunning, false); assert.equal(f.running, true);
  assert.equal((await f.stop()).status, 200);
  assert.equal((await fetch(url)).status, 410);
  assert.equal((await f.get('/api/browser-observation')).data.data.report, null);
});

test('managed observation launch uses only its local observer page and keeps proxy protections', async t => {
  const f = await fixture(t, { shutdownOnCleanup: true }); await f.start();
  const started = await f.post('/api/browser-observation/start', { confirm: true, browser: 'chrome' });
  assert.equal(started.status, 200); assert.equal(f.browserRunning, true); assert.equal(f.running, true);
  assert.equal((await fetch(started.data.data.url + 'context')).status, 200);
  const again = await f.post('/api/browser-observation/start', { confirm: true, browser: 'chrome' });
  assert.equal(again.data.error.code, 'BROWSER_ALREADY_RUNNING');
  await f.post('/api/browser/close', { confirm: true });
  assert.equal((await fetch(started.data.data.url)).status, 410);
  assert.equal(f.running, true);
});

test('a failed browser close updates cached browser state without losing the error or changing the proxy', async t => {
  const f = await fixture(t, { shutdownOnCleanup: true }); await f.start();
  f.browserRunning = true;
  f.server.state.browser = { running: true, browser: 'chrome' };
  f.browsers.close = async () => { f.browserRunning = false; throw failure('BROWSER_CLOSE_TIMEOUT'); };
  const response = await f.post('/api/browser/close', { confirm: true });
  assert.equal(response.data.error.code, 'BROWSER_CLOSE_TIMEOUT');
  assert.equal(f.server.state.browser.running, false);
  assert.equal(f.running, true);
  f.browsers.close = async () => ({ closed: true, running: false });
});

test('fingerprint settings survive partial legacy preference changes without changing the running route', async t => {
  const f = await fixture(t); await f.start(); const events = [...f.events];
  const set = await f.post('/api/browser/fingerprint/settings', { confirm: true, language: 'ja-JP', timezone: 'Asia/Tokyo', nativeGraphics: false });
  assert.equal(set.status, 200); assert.equal(set.data.data.settings.resolvedLanguage, 'ja-JP');
  assert.equal(set.data.data.settings.resolvedTimezone, 'Asia/Tokyo'); assert.equal(set.data.data.settings.nativeGraphics, false);
  await f.post('/api/onboarding/preferences', { fresh: false });
  assert.equal((await f.get('/api/browser/fingerprint')).data.data.settings.language, 'ja-JP');
  assert.equal((await f.post('/api/browser/fingerprint/settings', { confirm: true, timezone: 'Mars/Base' })).status, 400);
  assert.equal((await f.get('/api/browser/fingerprint')).data.data.settings.timezone, 'Asia/Tokyo');
  assert.equal(f.running, true); assert.deepEqual(f.events, events);
});

test('automatic fingerprint region reads the verified ISP without requiring Windows optimization or public reports', async t => {
  const requested = []; let location = { country_code: 'JP', city: 'Tokyo', timezone: { id: 'Asia/Tokyo' } };
  const environment = createEnvironmentManager({ mock: true });
  environment.optimize = () => assert.fail('browser localization must not change Windows settings');
  const f = await fixture(t, { environment, request: async (url, settings) => {
    requested.push([url.hostname, settings.proxyPort]);
    return JSON.stringify({ success: true, ip: '203.0.113.8', ...location });
  } });
  await f.post('/api/proxy/start', { confirm: true, optimize: false, externalReport: false });
  await f.get('/api/browser/fingerprint'); assert.equal(requested.length, 0, 'status polling performs no network request');
  const planned = (await f.post('/api/browser/plan', { browser: 'fingerprint' })).data.data;
  assert.equal(planned.browser, '指纹浏览器'); assert.equal(planned.language, 'ja-JP'); assert.equal(planned.fingerprint.timezone, 'Asia/Tokyo');
  assert.deepEqual(requested, [['ipwho.is', 17890]]);
  assert.equal((await f.get('/api/status')).data.data.report, null);
  const settings = (await f.get('/api/browser/fingerprint')).data.data.settings;
  assert.equal(settings.languageSource, 'verified-exit'); assert.equal(settings.timezoneSource, 'verified-exit');
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: planned.token })).status, 200);
  assert.equal(requested.length, 1, 'confirmation reuses the matching fresh geography');
  await f.post('/api/browser/close', { confirm: true });
  f.clock += 90_001; location = { country_code: 'SG', city: 'Singapore', timezone: { id: 'Asia/Singapore' } };
  const expired = (await f.get('/api/browser/fingerprint')).data.data.settings;
  assert.equal(expired.languageSource, 'local-environment'); assert.equal(requested.length, 1);
  const updated = (await f.post('/api/browser/plan', { browser: 'fingerprint' })).data.data;
  assert.equal(updated.language, 'en-SG'); assert.equal(updated.fingerprint.timezone, 'Asia/Singapore');
  assert.equal(updated.fingerprint.seed, planned.fingerprint.seed, 'exit geography never rotates the stable identity');
  assert.equal(requested.length, 2); assert.equal(f.running, true);
});

test('manual fingerprint region skips geography and observation uses the same automatic resolver as website launches', async t => {
  const choices = [];
  const f = await fixture(t, { shutdownOnCleanup: true, request: async () => JSON.stringify({ success: true, ip: '203.0.113.8', country_code: 'JP', city: 'Tokyo', timezone: { id: 'Asia/Tokyo' } }) });
  await f.start();
  await f.post('/api/browser/fingerprint/settings', { confirm: true, language: 'en-GB', timezone: 'Europe/London' });
  const manual = (await f.post('/api/browser/plan', { browser: 'fingerprint' })).data.data;
  assert.equal(manual.language, 'en-GB'); assert.equal(manual.fingerprint.timezone, 'Europe/London'); assert.equal(f.requestCalls, 0);
  const manualSettings = (await f.get('/api/browser/fingerprint')).data.data.settings;
  assert.equal(manualSettings.languageSource, 'manual'); assert.equal(manualSettings.timezoneSource, 'manual');
  await f.post('/api/browser/fingerprint/settings', { confirm: true, language: 'auto', timezone: 'auto' });
  const original = f.browsers.plan;
  f.browsers.plan = async options => { choices.push(options); return original(options); };
  const observed = await f.post('/api/browser-observation/start', { confirm: true, browser: 'fingerprint' });
  assert.equal(observed.status, 200); assert.equal(choices[0].language, 'ja-JP'); assert.equal(choices[0].timezone, 'Asia/Tokyo');
  assert.equal(f.requestCalls, 1);
  await f.post('/api/browser/close', { confirm: true });
  await f.post('/api/onboarding/preferences', { browser: 'fingerprint' });
  await f.server.openWebsite('claude');
  assert.equal(choices.at(-1).language, 'ja-JP'); assert.equal(choices.at(-1).timezone, 'Asia/Tokyo'); assert.equal(f.requestCalls, 1);
});

test('failed geography falls back explicitly and never revives an unrelated previously optimized region', async t => {
  const environment = createEnvironmentManager({ mock: true });
  await environment.optimize({ geo: { verified: true, ip: '203.0.113.99', countryCode: 'JP', timezone: 'Asia/Tokyo' }, localize: true });
  const f = await fixture(t, { environment, request: async () => { throw failure('PROBE_TIMEOUT'); } });
  await f.start();
  const planned = await f.post('/api/browser/plan', { browser: 'fingerprint' });
  assert.equal(planned.status, 200);
  const settings = (await f.get('/api/browser/fingerprint')).data.data.settings;
  assert.equal(settings.alignmentSource, 'local-environment'); assert.equal(settings.alignmentCode, 'GEO_UNVERIFIED');
  assert.equal(settings.languageSource, 'local-environment'); assert.equal(settings.timezoneSource, 'local-environment');
  assert.equal(settings.resolvedTimezone, Intl.DateTimeFormat().resolvedOptions().timeZone);
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: planned.data.data.token })).status, 200);
  assert.equal(f.requestCalls, 1, 'a recorded temporary failure does not repeat the same timeout at confirmation');
  assert.equal(f.running, true); assert.doesNotMatch(JSON.stringify(settings), /private credential/);
  await f.post('/api/browser/close', { confirm: true });
  await f.post('/api/browser/plan', { browser: 'fingerprint' });
  assert.equal(f.requestCalls, 2, 'an explicit new launch plan retries a failed geography service');
  await f.post('/api/browser/fingerprint/settings', { confirm: true, language: 'ja-JP', timezone: 'Asia/Tokyo' });
  assert.equal((await f.get('/api/browser/fingerprint')).data.data.settings.alignmentCode, undefined, 'manual settings do not inherit an irrelevant automatic warning');
});

test('a subsequent verified multi-site report replaces a temporary browser geography failure', async t => {
  let failed = true;
  const f = await fixture(t, { request: async url => {
    if (failed) throw failure('PROBE_TIMEOUT');
    if (url.hostname === 'api.ipify.org') return JSON.stringify({ ip: '203.0.113.8' });
    if (url.hostname === 'www.cloudflare.com') return 'ip=203.0.113.8';
    return JSON.stringify({ success: true, ip: '203.0.113.8', country_code: 'JP', timezone: { id: 'Asia/Tokyo' } });
  } });
  await f.start(); await f.post('/api/browser/plan', { browser: 'fingerprint' });
  assert.equal((await f.get('/api/browser/fingerprint')).data.data.settings.alignmentCode, 'GEO_UNVERIFIED');
  failed = false;
  assert.equal((await f.post('/api/probes', { multi: true, thirdParty: false })).status, 200);
  f.clock = Date.now();
  const settings = (await f.get('/api/browser/fingerprint')).data.data.settings;
  assert.equal(settings.resolvedLanguage, 'ja-JP'); assert.equal(settings.resolvedTimezone, 'Asia/Tokyo');
  assert.equal(settings.alignmentCode, undefined); assert.equal(settings.languageSource, 'verified-exit');
});

test('unknown country language is reported separately from the verified exit timezone', async t => {
  const f = await fixture(t, { request: async () => JSON.stringify({ success: true, ip: '203.0.113.8', country_code: 'BE', city: 'Brussels', timezone: { id: 'Europe/Brussels' } }) });
  await f.start(); await f.post('/api/browser/plan', { browser: 'fingerprint' });
  const settings = (await f.get('/api/browser/fingerprint')).data.data.settings;
  assert.equal(settings.languageSource, 'local-environment'); assert.equal(settings.timezoneSource, 'verified-exit');
  assert.equal(settings.resolvedTimezone, 'Europe/Brussels');
});

test('disconnect promptly cancels fingerprint geography and late results cannot authorize a new session', { timeout: 4000 }, async t => {
  const entered = deferred(), release = deferred();
  const f = await fixture(t, { request: async () => { entered.resolve(); await release.promise; return JSON.stringify({ success: true, ip: '203.0.113.8', country_code: 'JP', timezone: { id: 'Asia/Tokyo' } }); } });
  await f.start(); const planning = f.post('/api/browser/plan', { browser: 'fingerprint' }); await entered.promise;
  assert.equal((await Promise.race([f.stop(), delay(750).then(() => { throw new Error('Geography held disconnect'); })])).status, 200);
  assert.equal((await planning).data.error.code, 'CONNECTION_CANCELED');
  assert.equal((await f.start()).status, 200); release.resolve(); await delay(10);
  const settings = (await f.get('/api/browser/fingerprint')).data.data.settings;
  assert.equal(settings.languageSource, 'local-environment'); assert.equal(settings.timezoneSource, 'local-environment');
  assert.equal(f.browserRunning, false); assert.equal(f.running, true);
});

test('fingerprint confirmation rejects expired geography that resolves differently or a different allowed exit IP', async t => {
  let country = 'JP', timezone = 'Asia/Tokyo', ip = '203.0.113.8';
  const f = await fixture(t, { request: async () => JSON.stringify({ success: true, ip, country_code: country, timezone: { id: timezone } }) });
  f.config.probe.expectedExitIps.push('203.0.113.9'); f.probe = async () => ({ ok: true, status: 'verified', exitIp: ip, elapsedMs: 1 });
  await f.get('/api/status');
  const started = await f.start(); assert.equal(started.status, 200, JSON.stringify(started.data));
  const firstResponse = await f.post('/api/browser/plan', { browser: 'fingerprint' });
  assert.equal(firstResponse.status, 200, JSON.stringify(firstResponse.data)); const first = firstResponse.data.data;
  f.clock += 90_001; country = 'US'; timezone = 'America/New_York';
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: first.token })).data.error.code, 'CONFIRMATION_INVALID');
  assert.equal(f.browserRunning, false);
  const second = (await f.post('/api/browser/plan', { browser: 'fingerprint' })).data.data;
  f.clock += 90_001; ip = '203.0.113.9';
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: second.token })).data.error.code, 'CONFIRMATION_INVALID');
  assert.equal(f.browserRunning, false); assert.equal(f.running, true);
});

test('fingerprint component preparation is a background task and shutdown cancels only that task', { timeout: 5000 }, async t => {
  const entered = deferred(); let aborted = false, calls = 0;
  const f = await fixture(t, { installFingerprintBrowser: async ({ signal, onProgress }) => {
    calls++; onProgress({ status: 'extracting', receivedBytes: 100, totalBytes: 100 }); entered.resolve();
    await new Promise((resolve, reject) => signal.addEventListener('abort', () => { aborted = true; reject(failure('FINGERPRINT_ENGINE_INSTALL_ABORTED')); }, { once: true }));
  } });
  t.after(() => f.server.shutdown()); await f.start();
  assert.equal((await f.post('/api/browser/fingerprint/install', { confirm: true, target: 'C:/untrusted' })).status, 400);
  assert.equal((await f.post('/api/browser/fingerprint/install', { confirm: true })).status, 200); await entered.promise;
  assert.equal((await f.get('/api/browser/fingerprint')).data.data.install.status, 'extracting');
  await f.post('/api/browser/fingerprint/install', { confirm: true }); assert.equal(calls, 1);
  const stopped = await Promise.race([f.stop(), delay(750).then(() => { throw new Error('Disconnect waited for optional engine preparation'); })]);
  assert.equal(stopped.status, 200); assert.equal(f.running, false); assert.equal(aborted, false);
  await f.server.shutdown(); assert.equal(aborted, true);
});

test('bundled fingerprint copying and its failure stage remain visible without blocking connection', { timeout: 5000 }, async t => {
  const entered = deferred(), release = deferred();
  const f = await fixture(t, { fingerprintBundleRoot: path.resolve('.cache/isolated-public-engine-fixture'), installFingerprintBrowser: async ({ onProgress }) => {
    onProgress({ status: 'copying-bundle', receivedBytes: 64, totalBytes: 128 }); entered.resolve(); await release.promise;
    throw failure('BROWSER_FINGERPRINT_INSTALL_FAILED');
  } });
  assert.equal((await f.post('/api/browser/fingerprint/install', { confirm: true })).status, 200); await entered.promise;
  const copying = (await f.get('/api/browser/fingerprint')).data.data.install;
  assert.equal(copying.status, 'copying-bundle'); assert.equal(copying.receivedBytes, 64); assert.equal(copying.totalBytes, 128);
  assert.equal((await f.start()).status, 200); assert.equal(f.running, true);
  release.resolve();
  for (let retry = 0; retry < 40; retry++) {
    const installation = (await f.get('/api/browser/fingerprint')).data.data.install;
    if (installation.status === 'failed') { assert.equal(installation.failedStage, 'copying-bundle'); assert.equal(installation.code, 'BROWSER_FINGERPRINT_INSTALL_FAILED'); break; }
    if (retry === 39) assert.fail('bundled copying did not publish its failure state');
    await delay(10);
  }
  assert.equal(f.running, true); assert.equal((await f.stop()).status, 200);
});

function installTrafficGate(f) {
  f.runtime.holdTraffic = async () => { f.events.push('traffic-block'); f.trafficBlocked = true; f.trafficBlockConfirmed = true; return f.runtime.status(); };
  f.runtime.resumeTraffic = async () => { f.events.push('traffic-resume'); f.trafficBlocked = false; f.trafficBlockConfirmed = true; return f.runtime.status(); };
}

test('canceling a stalled connection drains it without waiting for the late read or allowing it to overwrite reconnection', { timeout: 4000 }, async t => {
  const f = await fixture(t), entered = deferred(), release = deferred();
  const success = { ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 };
  f.probe = async () => { entered.resolve(); await release.promise; return success; };
  const starting = f.start(); await entered.promise;
  assert.equal((await f.get('/api/snapshot')).data.data.connectionCancellation.active, true);
  assert.equal((await f.start()).data.error.code, 'CONNECTION_IN_PROGRESS');
  const stopped = await Promise.race([f.stop(), delay(750).then(() => { throw new Error('Cancellation waited for a stalled read'); })]);
  assert.equal(stopped.status, 200); assert.equal(f.running, false);
  assert.equal((await starting).data.error.code, 'CONNECTION_CANCELED');
  f.probe = async () => success;
  assert.equal((await f.start()).status, 200);
  const current = structuredClone(f.server.state.proxy.exit);
  release.resolve(); await delay(10);
  assert.deepEqual(f.server.state.proxy.exit, current); assert.equal(f.running, true);
});

test('disconnect cancels slow application target reads and late replies cannot be reused after reconnection', { timeout: 4000 }, async t => {
  const entered = deferred(), release = deferred(); let targetReads = 0;
  const f = await fixture(t, { request: async () => { targetReads++; entered.resolve(); await release.promise; return { statusCode: 200 }; } });
  assert.equal((await f.start()).status, 200);
  const checking = f.post('/api/applications/check', { service: 'claude', path: 'proxy' }); await entered.promise;
  assert.equal((await Promise.race([f.stop(), delay(750).then(() => { throw new Error('Target read held disconnect'); })])).status, 200);
  assert.equal((await checking).data.error.code, 'CONNECTION_CANCELED'); assert.equal(f.running, false);
  assert.equal((await f.start()).status, 200); release.resolve(); await delay(10);
  const before = targetReads;
  const checked = await f.post('/api/applications/check', { service: 'claude', path: 'proxy', force: false });
  assert.equal(checked.status, 200); assert.equal(checked.data.data.reused, undefined); assert(targetReads > before);
  assert.equal(f.running, true);
});

test('expiry keeps TUN and a stable paused application endpoint until explicit resume or disconnect', async t => {
  const licensing = licenseStub(), f = await fixture(t, { licenseClient: licensing, state: { mode: 'tun' } });
  installTrafficGate(f); assert.equal((await f.start()).status, 200);
  const endpoint = await f.server.applicationProxy(); f.events.length = 0;
  Object.assign(licensing.permission, { allowed: false, reason: 'LICENSE_EXPIRED', status: 'expired' });
  await f.server.enforceLicense();
  const held = (await f.get('/api/snapshot')).data.data;
  assert.equal(f.running, true); assert.equal(f.trafficBlocked, true); assert.equal(held.connectionResult.status, 'paused');
  assert.equal(held.applicationProxy.port, endpoint.port); assert.equal(held.applicationProxy.accepting, false);
  assert(!f.events.includes('proxy-stop')); assert(!f.events.includes('network-unlock'));
  await assert.rejects(f.server.applicationProxy(), { code: 'LICENSE_EXPIRED' });
  assert.equal((await f.post('/api/proxy/resume', { confirm: true })).data.error.code, 'LICENSE_EXPIRED');
  Object.assign(licensing.permission, { allowed: true, reason: null, status: 'active' });
  const resumed = await f.post('/api/proxy/resume', { confirm: true });
  assert.equal(resumed.status, 200); assert.equal(resumed.data.data.proxy.trafficBlocked, false); assert.equal(resumed.data.data.applicationProxy.port, endpoint.port);
  assert.equal(resumed.data.data.applicationProxy.accepting, true);
  assert.equal((await f.stop()).status, 200); assert.equal(f.running, false);
});

test('startup detects expiry before the timer runs and preserves the just-created TUN', async t => {
  const licensing = licenseStub(), f = await fixture(t, { licenseClient: licensing, state: { mode: 'tun' } });
  installTrafficGate(f);
  const start = f.runtime.start;
  f.runtime.start = async input => { const result = await start(input); Object.assign(licensing.permission, { allowed: false, reason: 'LICENSE_EXPIRED', status: 'expired' }); return result; };
  assert.equal((await f.start()).data.error.code, 'LICENSE_EXPIRED');
  assert.equal(f.running, true); assert.equal(f.trafficBlocked, true); assert(!f.events.includes('proxy-stop'));
});

test('unconfirmed traffic hold never reports a paused route or removes the owned TUN', async t => {
  const licensing = licenseStub(), f = await fixture(t, { licenseClient: licensing, state: { mode: 'tun' } });
  assert.equal((await f.start()).status, 200);
  f.runtime.holdTraffic = async () => { f.trafficBlocked = true; f.trafficBlockConfirmed = false; return f.runtime.status(); };
  Object.assign(licensing.permission, { allowed: false, reason: 'LICENSE_EXPIRED', status: 'expired' });
  await f.server.enforceLicense();
  const state = (await f.get('/api/status')).data.data;
  assert.equal(state.connectionResult.status, 'pause-unconfirmed'); assert.equal(state.proxy.trafficHoldStatus, 'failed');
  assert.equal(f.running, true); assert(!f.events.includes('proxy-stop'));
});

test('expiry during the final resume gateway bind re-blocks TUN and never reports a successful resume', async t => {
  const licensing = licenseStub(); let running = false, accepting = false, expireOnBind = false;
  const gateway = { status: () => ({ running, accepting, port: running ? 19001 : null }),
    start: async () => { running = true; accepting = true; if (expireOnBind) Object.assign(licensing.permission, { allowed: false, reason: 'LICENSE_EXPIRED', status: 'expired' }); return { port: 19001 }; },
    pause: () => { accepting = false; }, stop: async () => { running = accepting = false; } };
  const f = await fixture(t, { licenseClient: licensing, applicationGateway: gateway, state: { mode: 'tun' } });
  installTrafficGate(f); assert.equal((await f.start()).status, 200); await f.server.applicationProxy();
  Object.assign(licensing.permission, { allowed: false, reason: 'LICENSE_EXPIRED', status: 'expired' }); await f.server.enforceLicense();
  Object.assign(licensing.permission, { allowed: true, reason: null, status: 'active' }); expireOnBind = true; f.events.length = 0;
  const resumed = await f.post('/api/proxy/resume', { confirm: true });
  assert.equal(resumed.data.error.code, 'LICENSE_EXPIRED'); assert.equal(f.running, true); assert.equal(f.trafficBlocked, true);
  assert.equal(accepting, false); assert.equal(running, true); assert(!f.events.includes('proxy-stop'));
  assert.equal((await f.get('/api/snapshot')).data.data.connectionResult.status, 'paused');
});

test('network re-verification rebinds a paused application gateway at the existing address', async t => {
  const f = await fixture(t, { state: { mode: 'tun' } }); assert.equal((await f.start()).status, 200);
  const endpoint = await f.server.applicationProxy();
  f.server.suspendNetwork();
  const paused = (await f.get('/api/snapshot')).data.data.applicationProxy;
  assert.equal(paused.port, endpoint.port); assert.equal(paused.accepting, false);
  const resumed = await f.server.networkChanged('resume');
  assert.equal(resumed.applicationProxy.port, endpoint.port); assert.equal(resumed.applicationProxy.accepting, true);
  assert.equal(f.events.includes('proxy-stop'), false);
});

test('license expiry during gateway binding refuses the lease and retains its paused address', async t => {
  const licensing = licenseStub(); let port = null, accepting = false, stops = 0;
  const gateway = { status: () => ({ running: Boolean(port), accepting, port }),
    start: async () => { port = 19001; accepting = true; Object.assign(licensing.permission, { allowed: false, reason: 'LICENSE_EXPIRED' }); return { port }; },
    pause: () => { accepting = false; }, stop: async () => { stops++; port = null; accepting = false; } };
  const f = await fixture(t, { licenseClient: licensing, applicationGateway: gateway });
  assert.equal((await f.start()).status, 200);
  await assert.rejects(f.server.applicationProxy(), { code: 'LICENSE_EXPIRED' });
  assert.equal(port, 19001); assert.equal(accepting, false); assert.equal(stops, 0);
});

test('a new verified connection rebinds a retained application gateway without changing its address', async t => {
  const f = await fixture(t); assert.equal((await f.start()).status, 200);
  const endpoint = await f.server.applicationProxy();
  f.probe = async () => { throw failure('EXIT_IP_MISMATCH'); };
  assert.equal((await f.post('/api/probes')).data.error.code, 'EXIT_IP_MISMATCH');
  const paused = (await f.get('/api/snapshot')).data.data.applicationProxy;
  assert.equal(paused.port, endpoint.port); assert.equal(paused.accepting, false); assert.equal(f.running, false);
  f.probe = async () => ({ ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 });
  const restarted = await f.start(); assert.equal(restarted.status, 200);
  assert.equal(restarted.data.data.applicationProxy.port, endpoint.port); assert.equal(restarted.data.data.applicationProxy.accepting, true);
});

function licenseStub(overrides = {}) {
  const permission = { mode: 'required', status: 'active', allowed: true, reason: null, licenseId: 'test-customer', expiresAt: Date.now() + 86400000 };
  return {
    permission,
    initialize: async () => permission,
    status: () => ({ ...permission }),
    assertAllowed: () => { if (!permission.allowed) throw failure(permission.reason || 'LICENSE_REQUIRED'); },
    deviceApplication: () => JSON.stringify({ request: { action: 'offline', devicePublicKey: 'PUBLIC-ONLY' }, signature: 'TEST' }),
    activate: async () => ({ ...permission }), importLicense: async () => ({ ...permission }), refresh: async () => ({ ...permission }), close() {},
    ...overrides,
  };
}

test('unactivated license blocks admission before ISP work but leaves recovery and diagnostics usable', async t => {
  const licensing = licenseStub(); Object.assign(licensing.permission, { allowed: false, status: 'unactivated', reason: 'LICENSE_REQUIRED' });
  const f = await fixture(t, { licenseClient: licensing });
  assert.equal((await f.start()).data.error.code, 'LICENSE_REQUIRED');
  assert.equal((await f.plan()).data.error.code, 'LICENSE_REQUIRED');
  await assert.rejects(f.server.applicationProxy(), { code: 'LICENSE_REQUIRED' });
  assert.equal(f.probeCalls, 0); assert.equal(f.systemProbeCalls, 0); assert.deepEqual(f.events, []);
  assert.equal((await f.get('/api/diagnostics')).status, 200);
  assert.equal((await f.get('/api/license/status')).data.data.status, 'unactivated');
  assert.equal((await f.get('/api/license/device')).data.data.application.request.devicePublicKey, 'PUBLIC-ONLY');
  assert.equal((await f.stop()).status, 200);
  assert.equal((await f.post('/api/environment/restore-original', { confirm: true })).status, 200);
  await f.server.beginNetworkRepair(); await f.server.finishNetworkRepair();
});

test('a slow or failed license refresh cannot hold disconnect or alter a valid connection', async t => {
  const entered = deferred(), release = deferred();
  const licensing = licenseStub({ refresh: async () => { entered.resolve(); await release.promise; throw failure('LICENSE_TIMEOUT'); } });
  const f = await fixture(t, { licenseClient: licensing }); await f.start();
  const revision = f.server.state.revision, probes = f.probeCalls;
  const refresh = f.post('/api/license/refresh'); await entered.promise;
  const snapshot = (await f.get('/api/snapshot')).data.data;
  assert.equal(snapshot.statusRead.state, 'cached'); assert.equal(snapshot.proxy.running, true); assert.equal(snapshot.license.allowed, true);
  assert.equal(f.probeCalls, probes); assert.equal(f.server.state.revision, revision);
  const stopped = await Promise.race([f.stop(), delay(1000).then(() => { throw new Error('licensing refresh blocked disconnect'); })]);
  assert.equal(stopped.status, 200); assert.equal(f.running, false);
  release.resolve(); assert.equal((await refresh).data.error.code, 'LICENSE_TIMEOUT');
  assert.equal((await f.start()).status, 200, 'a transient cloud failure does not revoke a valid signed permission');
});

test('paid expiry drains owned sessions while preserving an existing lock and recovery access', async t => {
  const licensing = licenseStub(), f = await fixture(t, { licenseClient: licensing, lockSimulation: true });
  await f.start(); await f.launch(); f.networkLocked = true;
  f.events.length = 0; Object.assign(licensing.permission, { allowed: false, status: 'expired', reason: 'LICENSE_EXPIRED' });
  await f.server.enforceLicense();
  assert.equal(f.running, false); assert.equal(f.browserRunning, false); assert.equal(f.networkLocked, true);
  assert(f.events.indexOf('browser-close') < f.events.indexOf('proxy-stop'));
  assert(!f.events.includes('network-unlock'));
  assert.equal((await f.get('/api/snapshot')).data.data.lastError.code, 'LICENSE_EXPIRED');
  assert.equal((await f.post('/api/environment/restore-original', { confirm: true })).status, 200);
  assert.equal((await f.start()).data.error.code, 'LICENSE_EXPIRED');
  Object.assign(licensing.permission, { allowed: true, status: 'active', reason: null });
  assert.equal((await f.start()).status, 200);
});

test('licensing requests use control authentication and cannot change distribution trust', async t => {
  const licensing = licenseStub(), f = await fixture(t, { licenseClient: licensing });
  assert.equal((await f.get('/api/license/device', { headers: { 'x-mc-control-token': '0'.repeat(64) } })).status, 401);
  for (const pathname of ['/api/license/activate', '/api/license/import', '/api/license/refresh']) {
    const result = await f.post(pathname, { mode: 'development', publicKeys: {}, serviceUrl: 'https://attacker.invalid' });
    assert.equal(result.status, 400); assert.equal(result.data.error.code, 'INPUT_INVALID');
  }
  assert.equal(licensing.permission.mode, 'required'); assert.equal(f.probeCalls, 0);
});

test('expiry revokes an in-flight connection before the operation queue becomes available', async t => {
  const entered = deferred(), release = deferred(), licensing = licenseStub();
  const f = await fixture(t, { licenseClient: licensing });
  f.probe = async () => { entered.resolve(); await release.promise; return { ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 }; };
  const start = f.start(); await entered.promise;
  const revision = f.server.state.revision;
  Object.assign(licensing.permission, { allowed: false, status: 'expired', reason: 'LICENSE_EXPIRED' });
  const stopping = f.server.enforceLicense();
  assert.equal(f.server.state.proxy.requestedStop, true);
  assert(f.server.state.revision > revision, 'admission is revoked before the stalled exit check returns');
  release.resolve(); assert.equal((await start).data.ok, false); await stopping;
  assert.equal(f.running, false); assert.equal((await f.get('/api/snapshot')).data.data.lastError.code, 'LICENSE_EXPIRED');
});

test('manual webpage comparison preserves CONNECT failure and target HTTP error as separate layers', async t => {
  const entered = deferred(), release = deferred(); let active = 0;
  const f = await fixture(t, { request: async url => {
    if (++active === 2) entered.resolve(); await release.promise;
    if (url.hostname === 'ping0.cc') throw Object.assign(failure('PROXY_CONNECT_REJECTED'), { diagnostic: { httpStatus: 502, message: 'PRIVATE_SECRET' } });
    return { statusCode: 500 };
  } });
  await f.start();
  const checking = f.post('/api/applications/check', { service: 'browser', path: 'proxy' });
  await entered.promise; release.resolve();
  const result = (await checking).data.data;
  assert.equal(active, 2, 'Fixed targets run concurrently; no serial target timeout is added');
  assert.deepEqual(result.checks.map(check => [check.stage, check.connectHttpStatus, check.targetHttpStatus, check.transportReachable]), [
    ['proxy-connect', 502, undefined, false], ['target-response', undefined, 500, true],
  ]);
  assert.equal(result.transportReady, false); assert.equal(f.running, true);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_SECRET|private credential/);
});

async function fixture(t, options = {}) {
  const f = {
    config: { version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type: 'http', host: '192.0.2.1', port: 443, auth: 'none' }, probe: { expectedExitIps: ['203.0.113.8'], exitUrl: 'https://example.test/ip', timeoutMs: 1000 } },
    running: false, browserRunning: false, clock: Date.now(), events: [], probeCalls: 0, systemProbeCalls: 0, requestCalls: 0,
    readError: null, stopError: null, closeError: null,
    ...options.state,
  };
  f.vpnConfigStore = options.vpnConfigStore || createImportedVpnStore({ stateDir: path.resolve('.cache/controller-vpn-test-never-created'), mock: true });
  f.runtime = {
    readConfig: async () => { if (f.readError) throw f.readError; return structuredClone(f.config); },
    start: async input => { f.startInput = structuredClone(input); f.events.push('proxy-start'); f.running = true; return f.runtime.status(); },
    status: async () => ({ running: f.running, managed: f.running, port: 17890, mode: f.mode || 'http', tunReady: f.tunReady ?? true, configHash: f.running ? (f.sessionHash ||= fingerprint(f.config)) : null,
      sessionId: f.sessionId || null, protections: f.protections || null, trafficBlocked: f.trafficBlocked === true, trafficBlockConfirmed: f.trafficBlockConfirmed === true,
      vpnNodeHash: f.running && f.startInput?.vpnNode ? fingerprint(f.startInput.vpnNode) : null,
      compatibility: f.running && f.config.connectionMode === 'vpn-import' ? { strategy: 'imported-node' } : f.running && f.config.connectionMode === 'vpn-compat' ? { strategy: f.startInput?.vpnProxy ? `${f.startInput.vpnProxy.type}-proxy` : 'system', ...(f.startInput?.vpnProxy ? { proxy: f.startInput.vpnProxy } : {}) } : null }),
    stop: async () => { f.events.push('proxy-stop'); if (f.stopError) throw f.stopError; f.running = false; f.sessionHash = null; },
  };
  if (options.lockSimulation) f.runtime.networkLock = {
    status: async () => ({ state: f.networkLocked ? 'locked' : 'unlocked', locked: !!f.networkLocked, persistent: true, canUnlock: !!f.networkLocked }),
    unlock: async () => { f.events.push('network-unlock'); f.networkLocked = false; return { state: 'unlocked' }; },
    reload: async () => { f.events.push('network-reload'); },
  };
  if (options.lockSimulation) f.runtime.armNetworkLock = async () => {
    f.events.push('network-arm');
    if (f.armError) throw f.armError;
    f.networkLocked = true;
    return f.runtime.status();
  };
  const plans = createBrowserManager({ mock: true, runtimeRoot: path.resolve('.cache/controller-test-never-created'), fingerprintRoot: path.resolve('.cache/controller-test-fingerprint-never-created') });
  f.browsers = {
    ...plans,
    status: async () => ({ running: f.browserRunning, browser: f.browserRunning ? 'chrome' : null, language: f.browserRunning ? 'en-US' : null }),
    launch: async plan => { await plans.launch(plan); f.events.push('browser-launch'); f.browserRunning = true; return { launched: true, mode: 'launched' }; },
    close: async () => { f.events.push('browser-close'); if (f.closeError) throw f.closeError; f.browserRunning = false; return { closed: true }; },
  };
  f.probe = async () => ({ ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 });
  f.systemProbe = options.systemProbe || (async () => ({ ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 }));
  f.onboarding = options.onboarding || createOnboardingManager({ mock: true });
  f.server = await startController({
    port: 0, mock: options.mock || false, healthIntervalMs: options.healthIntervalMs ?? 0,
    runtimeRoot: options.runtimeRoot,
    autoReport: options.autoReport ?? false,
    environment: options.environment || createEnvironmentManager({ stateDir: path.resolve('.cache/mock-environment'), mock: true }),
    claudeCleanup: createClaudeCleanupManager({ mock: true }),
    onboarding: f.onboarding,
    setupVerifier: options.setupVerifier || createSetupVerifier({ mock: true }),
    qualityReports: options.qualityReports || createQualityReportStore({ mock: true }),
    importedProbeBudgetMs: options.importedProbeBudgetMs,
    applicationGateway: options.applicationGateway,
    shortlistImportedNodes: options.shortlistImportedNodes || ((nodes, settings) => shortlistImportedNodes(nodes, { ...settings, probe: options.importedTcpProbe || (async () => ({ status: 'reachable', tcpLatencyMs: 1 })) })),
    relayManager: options.relayManager || createRelayManager({ mock: true }), requireRelay: options.requireRelay,
    vpnConfigStore: f.vpnConfigStore,
    subscriptions: options.subscriptions,
    licenseClient: options.licenseClient, licenseIntervalMs: options.licenseIntervalMs ?? 0,
    loadSecrets: options.loadSecrets || (async () => ({})),
    exportDiagnostics: options.exportDiagnostics || (async input => ({ directory: null, files: [], mock: input.mock })), recoveryAppPath: options.recoveryAppPath,
    now: () => f.clock, runtime: f.runtime, browsers: options.browsers || (options.mock ? plans : f.browsers),
    workspaces: options.workspaces || createBrowserWorkspaceManager({ runtimeRoot: path.resolve('.cache/controller-workspaces-never-created'), mock: true, now: () => f.clock }),
    serviceReminders: options.serviceReminders || createServiceReminderManager({ mock: true, now: () => f.clock }),
    deliveryImporter: options.deliveryImporter,
    fingerprintRoot: options.fingerprintRoot, fingerprintBundleRoot: options.fingerprintBundleRoot, installFingerprintBrowser: options.installFingerprintBrowser,
    fingerprintSecurity: options.fingerprintSecurity,
    onDiagnostic: options.onDiagnostic,
    directHttpsRequest: options.directHttpsRequest || (() => assert.fail('system business requests must be explicitly injected')),
    probe: async (...args) => { f.probeCalls++; return f.probe(...args); },
    probeSystemExit: async (...args) => { f.systemProbeCalls++; return f.systemProbe(...args); },
    compatibilityRoutes: options.compatibilityRoutes || (async () => [{ strategy: 'system', source: 'test' }]),
    requestViaProxy: async (...args) => { f.requestCalls++; return options.request ? options.request(...args) : 'ok'; },
  });
  t.after(() => options.shutdownOnCleanup ? f.server.shutdown() : new Promise(resolve => f.server.close(resolve)));
  const url = `http://127.0.0.1:${f.server.address().port}`;
  f.get = async (pathname, init = {}) => {
    const response = await fetch(url + pathname, { ...init, headers: { ...f.server.controlHeaders(), ...init.headers } });
    return { status: response.status, data: await response.json(), headers: response.headers };
  };
  f.url = url;
  f.post = (pathname, body = {}, headers = {}) => f.get(pathname, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  f.start = () => f.post('/api/proxy/start', { confirm: true });
  f.plan = () => f.post('/api/browser/plan', { browser: 'chrome', service: 'claude' });
  f.launch = async () => { const plan = await f.plan(); assert.equal(plan.status, 200); return f.post('/api/browser/launch', { confirm: true, token: plan.data.data.token }); };
  f.stop = () => f.post('/api/session/end', { confirm: true });
  return f;
}

async function workspaceFixture(t, options = {}) {
  const f = await fixture(t, options);
  const launch = f.browsers.launch, close = f.browsers.close;
  f.browsers.launch = async plan => { const result = await launch(plan); f.workspaceId = plan.workspaceId; f.currentBrowserPlan = structuredClone(plan); return result; };
  f.browsers.close = async () => { const result = await close(); f.workspaceId = null; return result; };
  f.browsers.status = async () => ({ running: f.browserRunning, managed: f.browserRunning, browser: f.browserRunning ? f.currentBrowserPlan?.browserId || 'chrome' : null, language: f.browserRunning ? 'en-US' : null, ...(f.workspaceId ? { workspaceId: f.workspaceId } : {}) });
  await f.post('/api/onboarding/preferences', { autoOptimize: false, externalReport: false, relayRoutingMode: 'global', fingerprintFresh: true });
  f.createWorkspace = async (name = '工作', browser) => {
    const created = await f.post('/api/workspaces/create', { confirm: true, name, services: ['chatgpt', 'claude'], ...(browser === undefined ? {} : { browser }) });
    assert.equal(created.status, 200, JSON.stringify(created.data));
    return created.data.data.items.at(-1);
  };
  return f;
}

async function identityWorkspaceFixture(t) {
  const f = await workspaceFixture(t, { shutdownOnCleanup: true });
  const create = f.createWorkspace;
  f.createWorkspace = name => create(name, 'fingerprint');
  const launch = f.browsers.launch;
  f.browsers.launch = async plan => { const result = await launch(plan); f.currentBrowserPlan = structuredClone(plan); return result; };
  f.browsers.status = async () => ({ running: f.browserRunning, managed: f.browserRunning, browser: f.browserRunning ? f.currentBrowserPlan?.browserId || 'fingerprint' : null,
    ...(f.browserRunning && f.currentBrowserPlan ? { language: f.currentBrowserPlan.language, port: f.currentBrowserPlan.port,
      fingerprint: f.currentBrowserPlan.fingerprint ? { ...f.currentBrowserPlan.fingerprint, engineVersion: '150.0.7871.186' } : undefined, observationPort: f.currentBrowserPlan.observationPort,
      ...(f.currentBrowserPlan.workspaceId ? { workspaceId: f.currentBrowserPlan.workspaceId } : {}) } : {}) });
  f.browsers.openObservation = async input => { f.observationAppend = input; if (f.appendError) throw f.appendError; return { mode: 'appended', reused: true }; };
  return f;
}

test('each user environment captures its identity policy independently of later global defaults', async t => {
  const f = await identityWorkspaceFixture(t);
  await f.post('/api/browser/fingerprint/settings', { confirm: true, language: 'ja-JP', timezone: 'Asia/Tokyo', nativeGraphics: false });
  const first = await f.createWorkspace('客户 A');
  assert.deepEqual(first.identity, { version: 1, language: 'ja-JP', timezone: 'Asia/Tokyo', nativeGraphics: false });
  await f.post('/api/browser/fingerprint/settings', { confirm: true, language: 'en-GB', timezone: 'Europe/London', nativeGraphics: true });
  const second = await f.createWorkspace('客户 B');
  assert.equal(second.identity.language, 'en-GB');
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: first.id })).status, 200);
  assert.equal(f.currentBrowserPlan.language, 'ja-JP'); assert.equal(f.currentBrowserPlan.fingerprint.timezone, 'Asia/Tokyo');
  assert.equal(f.currentBrowserPlan.fingerprint.nativeGraphics, false);
  assert.ok(f.currentBrowserPlan.observationPort > 1023, 'real workspace launch reserves only its observer port');
  assert.equal((await f.post('/api/workspaces/update', { confirm: true, id: first.id, identity: second.identity })).data.error.code, 'WORKSPACE_ACTIVE');
  await f.post('/api/browser/close', { confirm: true });
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: second.id })).status, 200);
  assert.equal(f.currentBrowserPlan.language, 'en-GB'); assert.equal(f.currentBrowserPlan.fingerprint.nativeGraphics, true);
  assert.equal(f.events.filter(event => event === 'proxy-start').length, 1, 'identity switching keeps the same verified core');
});

test('replacing an environment archives the old identity without starting a route or losing restore access', async t => {
  const f = await identityWorkspaceFixture(t), first = await f.createWorkspace('客户 A'), before = [...f.events];
  const response = await f.post('/api/workspaces/replace', { confirm: true, id: first.id });
  assert.equal(response.status, 200, JSON.stringify(response.data));
  const result = response.data.data, replacement = result.workspace;
  assert.notEqual(replacement.id, first.id); assert.equal(replacement.replacesId, first.id);
  assert.deepEqual(replacement.identity, first.identity); assert.equal(replacement.lastOpenedAt, null);
  assert.ok(result.items.find(item => item.id === first.id).archivedAt);
  assert.deepEqual(f.events, before); assert.equal(f.running, false);
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: first.id })).data.error.code, 'WORKSPACE_ARCHIVED');
  assert.equal((await f.post('/api/workspaces/restore', { confirm: true, id: first.id })).status, 200);
  assert.equal((await f.get('/api/workspaces')).data.data.items.find(item => item.id === first.id).archivedAt, null);
  assert.equal((await f.post('/api/workspaces/replace', { confirm: true, id: first.id, copyCookies: true })).status, 400);
});

test('fingerprint rotation explicitly targets the selected idle environment and cannot close another environment', async t => {
  const f = await identityWorkspaceFixture(t), first = await f.createWorkspace('客户 A'), second = await f.createWorkspace('客户 B');
  const calls = [];
  f.browsers.rotateFingerprint = async input => { calls.push(input); return { changed: true, workspaceId: input.workspaceId }; };
  const rotated = await f.post('/api/browser/fingerprint/rotate', { confirm: true, workspaceId: second.id });
  assert.equal(rotated.status, 200, JSON.stringify(rotated.data));
  assert.deepEqual(calls, [{ confirm: true, workspaceId: second.id }]);
  assert.equal(f.running, false); assert.equal(f.probeCalls, 0, 'an idle identity can rotate without connecting or probing an ISP');
  await f.post('/api/workspaces/start', { confirm: true, id: first.id });
  assert.equal((await f.post('/api/browser/fingerprint/rotate', { confirm: true, workspaceId: second.id })).data.error.code, 'WORKSPACE_ACTIVE');
  assert.equal(calls.length, 1); assert.equal(f.browserRunning, true); assert.equal(f.running, true);
});

test('current workspace observation appends to its real profile and uses its running identity despite changed defaults', async t => {
  const f = await identityWorkspaceFixture(t), item = await f.createWorkspace('客户 A');
  await f.post('/api/workspaces/update', { confirm: true, id: item.id, identity: { version: 1, language: 'ja-JP', timezone: 'Asia/Tokyo', nativeGraphics: false } });
  await f.post('/api/workspaces/start', { confirm: true, id: item.id });
  await f.post('/api/browser/fingerprint/settings', { confirm: true, language: 'en-GB', timezone: 'Europe/London' });
  const launchCount = f.events.filter(event => event === 'browser-launch').length;
  const response = await f.post('/api/browser-observation/start', { confirm: true, browser: 'fingerprint', workspaceId: item.id });
  assert.equal(response.status, 200, JSON.stringify(response.data));
  assert.equal(f.observationAppend.workspaceId, item.id); assert.equal(f.observationAppend.port, 17890);
  assert.equal(f.events.filter(event => event === 'browser-launch').length, launchCount, 'a diagnostic must not launch a different profile');
  const context = await (await fetch(response.data.data.url + 'context')).json();
  assert.equal(context.workspaceId, item.id); assert.equal(context.language, 'ja-JP'); assert.equal(context.timezone, 'Asia/Tokyo');
  assert.equal(context.expectedIdentity.platformVersion, '19.0.0'); assert.equal(context.expectedIdentity.seed, undefined);
  f.appendError = Object.assign(new Error('No narrow exception'), { code: 'BROWSER_OBSERVATION_RESTART_REQUIRED', status: 409 });
  const failed = await f.post('/api/browser-observation/start', { confirm: true, browser: 'fingerprint', workspaceId: item.id });
  assert.equal(failed.data.error.code, 'BROWSER_OBSERVATION_RESTART_REQUIRED');
  assert.equal((await f.get('/api/browser-observation')).data.data.status, 'unverified');
  assert.equal(f.running, true); assert.equal(f.browserRunning, true);
});

test('generic fingerprint preference changes invalidate pending default browser plans', async t => {
  const f = await identityWorkspaceFixture(t); await f.start();
  const planned = await f.post('/api/browser/plan', { browser: 'fingerprint', service: 'claude' });
  assert.equal(planned.status, 200);
  await f.post('/api/onboarding/preferences', { fingerprintLanguage: 'ja-JP', fingerprintTimezone: 'Asia/Tokyo' });
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: planned.data.data.token })).data.error.code, 'CONFIRMATION_INVALID');
  assert.equal(f.browserRunning, false); assert.equal(f.running, true);
});

test('closing a default browser outside the controller invalidates its managed observation as soon as status refreshes', async t => {
  const f = await identityWorkspaceFixture(t); await f.start();
  const planned = (await f.post('/api/browser/plan', { browser: 'fingerprint' })).data.data;
  await f.post('/api/browser/launch', { confirm: true, token: planned.token });
  const observed = await f.post('/api/browser-observation/start', { confirm: true, browser: 'fingerprint' });
  assert.equal(observed.status, 200, JSON.stringify(observed.data));
  const target = await (await fetch(observed.data.data.url + 'context')).json();
  assert.equal(target.workspaceId, null); assert.equal(target.managedLaunchVerified, true);
  f.browserRunning = false; // The user clicked the browser's own window close button.
  await f.get('/api/status');
  assert.equal((await fetch(observed.data.data.url + 'context')).status, 410);
  assert.equal((await f.get('/api/browser-observation')).data.data.status, 'unverified');
  assert.equal(f.running, true);
});

test('workspace metadata is separate from live configuration and binds only pinned ISP identity', async t => {
  const f = await workspaceFixture(t), config = structuredClone(f.config), beforeLicense = (await f.get('/api/license/status')).data.data;
  const item = await f.createWorkspace();
  assert.equal(item.bindingMatches, true); assert.equal(item.binding, undefined);
  assert.deepEqual(f.config, config); assert.deepEqual(f.events, []);
  assert.equal((await f.post('/api/workspaces/create', { name: 'missing confirmation', services: ['claude'] })).status, 400);
  assert.equal((await f.post('/api/workspaces/update', { confirm: true, id: item.id, binding: 'b'.repeat(64) })).status, 400);
  const renamed = await f.post('/api/workspaces/update', { confirm: true, id: item.id, name: '客户工作', services: ['claude'] });
  assert.equal(renamed.data.data.items[0].name, '客户工作');
  f.config.listen.port = 17891; f.config.upstream.auth = 'userpass';
  assert.equal((await f.get('/api/workspaces')).data.data.items[0].bindingMatches, true, 'port and credentials are not workspace ISP identity');
  f.config.upstream.host = '192.0.2.2';
  assert.equal((await f.get('/api/workspaces')).data.data.items[0].bindingMatches, false);
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: item.id })).data.error.code, 'WORKSPACE_BINDING_MISMATCH');
  assert.deepEqual(f.events, []); assert.equal(f.probeCalls, 0);
  assert.equal((await f.post('/api/workspaces/update', { confirm: true, id: item.id, rebind: true })).data.data.items[0].bindingMatches, true);
  f.config.probe.expectedExitIps = [];
  assert.equal((await f.post('/api/workspaces/update', { confirm: true, id: item.id, rebind: true })).data.error.code, 'EXPECTED_EXIT_REQUIRED');
  assert.equal((await f.post('/api/workspaces/remove', { confirm: true, id: item.id })).data.data.items.length, 0);
  assert.deepEqual((await f.get('/api/license/status')).data.data, beforeLicense);
});

test('one-click work uses saved route preference, opens one stable Chrome workspace and repeated clicks never duplicate tabs', async t => {
  const f = await workspaceFixture(t), item = await f.createWorkspace(); let planned;
  const plan = f.browsers.plan; f.browsers.plan = input => { planned = input; return plan(input); };
  const result = await f.post('/api/workspaces/start', { confirm: true, id: item.id });
  assert.equal(result.status, 200, JSON.stringify(result.data)); assert.equal(f.startInput.mode, 'tun'); assert.equal(f.startInput.routingMode, 'global');
  assert.equal(planned.browser, 'chrome'); assert.equal(planned.fresh, false); assert.equal(planned.workspaceId, item.id); assert.deepEqual(planned.services, ['chatgpt', 'claude']);
  assert.equal((await f.get('/api/workspaces')).data.data.activeId, item.id);
  const events = [...f.events], checks = f.probeCalls;
  const reused = await f.post('/api/workspaces/start', { confirm: true, id: item.id });
  assert.equal(reused.data.data.reused, true); assert.deepEqual(f.events, events); assert(f.probeCalls > checks);
  assert.equal((await f.post('/api/workspaces/update', { confirm: true, id: item.id, name: 'Busy' })).data.error.code, 'WORKSPACE_ACTIVE');
  assert.equal((await f.post('/api/workspaces/remove', { confirm: true, id: item.id })).data.error.code, 'WORKSPACE_ACTIVE');
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: item.id, mode: 'http' })).status, 400);
  await f.stop();
});

test('Chrome environments keep their fixed browser and profile across close, reopen, preference changes and replacement', async t => {
  const f = await workspaceFixture(t), item = await f.createWorkspace('Chrome 客户');
  assert.equal(item.browser, 'chrome');
  assert.equal(item.identity, undefined, 'ordinary environments do not present fingerprint settings');
  for (const browser of [null, 'unknown', 12]) assert.equal((await f.post('/api/workspaces/create', { confirm: true, name: 'Invalid', services: ['claude'], browser })).data.error.code, 'WORKSPACE_BROWSER_INVALID');
  assert.equal((await f.get('/api/workspaces')).data.data.defaultBrowser, 'chrome');
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: item.id })).status, 200);
  const first = structuredClone(f.currentBrowserPlan);
  assert.equal(first.browserId, 'chrome'); assert.equal(first.fresh, undefined); assert.equal(first.fingerprint, undefined);
  assert.ok(first.profile.endsWith(path.join('workspaces', item.id, 'chrome')));
  assert.doesNotMatch(first.args.join('\n'), /--fingerprint|--disable-spoofing|--timezone=/);
  assert.ok(first.observationPort > 1023, 'workspace Chrome reserves its narrow local observer exception');
  assert.equal((await f.post('/api/browser/close', { confirm: true })).status, 200);
  await f.post('/api/onboarding/preferences', { browser: 'fingerprint', fresh: true, fingerprintFresh: true });
  assert.equal((await f.get('/api/workspaces')).data.data.defaultBrowser, 'fingerprint');
  assert.equal((await f.createWorkspace('新增指纹环境')).browser, 'fingerprint', 'new cards follow an explicit saved browser preference');
  assert.equal((await f.createWorkspace('Edge 环境', 'edge')).browser, 'edge', 'an explicit card choice overrides the global preference');
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: item.id })).status, 200);
  assert.equal(f.currentBrowserPlan.browserId, 'chrome'); assert.equal(f.currentBrowserPlan.profile, first.profile);
  assert.equal(f.currentBrowserPlan.fresh, undefined); assert.equal(f.events.filter(event => event === 'proxy-start').length, 1);
  await f.post('/api/browser/close', { confirm: true });
  assert.equal((await f.post('/api/browser/plan', { workspaceId: item.id, browser: 'edge' })).data.error.code, 'BROWSER_WORKSPACE_INVALID');
  assert.equal((await f.post('/api/browser/plan', { workspaceId: item.id, fresh: true })).data.error.code, 'BROWSER_WORKSPACE_INVALID');
  const saved = await f.post('/api/browser/plan', { workspaceId: item.id });
  assert.equal(saved.status, 200); assert.equal(saved.data.data.browserId, 'chrome'); assert.equal(saved.data.data.fresh, false);
  assert.equal((await f.post('/api/workspaces/update', { confirm: true, id: item.id, browser: 'fingerprint' })).status, 400);
  assert.equal((await f.post('/api/workspaces/update', { confirm: true, id: item.id, identity: { version: 1, language: 'ja-JP', timezone: 'Asia/Tokyo', nativeGraphics: false } })).data.error.code, 'BROWSER_WORKSPACE_INVALID');
  assert.equal((await f.post('/api/browser/fingerprint/rotate', { confirm: true, workspaceId: item.id })).data.error.code, 'BROWSER_WORKSPACE_INVALID');
  const replacement = await f.post('/api/workspaces/replace', { confirm: true, id: item.id });
  assert.equal(replacement.status, 200, JSON.stringify(replacement.data)); assert.equal(replacement.data.data.workspace.browser, 'chrome');
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: replacement.data.data.workspace.id })).status, 200);
  assert.equal(f.currentBrowserPlan.browserId, 'chrome'); assert.notEqual(f.currentBrowserPlan.profile, first.profile);
  await f.stop();
});

test('ordinary workspace observation appends only to the same managed profile without fingerprint work', async t => {
  const f = await workspaceFixture(t), item = await f.createWorkspace('Chrome 检测');
  const next = await f.createWorkspace('另一个 Chrome');
  f.browsers.openObservation = async input => { f.observationAppend = input; return { mode: 'appended', reused: true }; };
  await f.post('/api/workspaces/start', { confirm: true, id: item.id });
  const profile = f.currentBrowserPlan.profile, launches = f.events.filter(event => event === 'browser-launch').length;
  await f.post('/api/onboarding/preferences', { browser: 'fingerprint' });
  const observed = await f.post('/api/browser-observation/start', { confirm: true, workspaceId: item.id });
  assert.equal(observed.status, 200, JSON.stringify(observed.data)); assert.equal(f.observationAppend.workspaceId, item.id);
  assert.equal(f.currentBrowserPlan.profile, profile); assert.equal(f.events.filter(event => event === 'browser-launch').length, launches);
  assert.equal(f.requestCalls, 0, 'ordinary browser diagnostics never resolve fingerprint geography');
  const context = await (await fetch(observed.data.data.url + 'context')).json();
  assert.equal(context.workspaceId, item.id); assert.equal(context.expectedIdentity, null);
  assert.equal((await f.post('/api/browser-observation/start', { confirm: true, workspaceId: item.id, browser: 'fingerprint' })).data.error.code, 'BROWSER_WORKSPACE_INVALID');
  assert.equal((await f.post('/api/browser-observation/start', { confirm: true, workspaceId: next.id })).data.error.code, 'WORKSPACE_OBSERVATION_TARGET_REQUIRED');
  const status = f.browsers.status;
  f.browsers.status = async () => ({ ...await status(), managed: false });
  assert.equal((await f.post('/api/browser-observation/start', { confirm: true, workspaceId: item.id })).data.error.code, 'WORKSPACE_OBSERVATION_TARGET_REQUIRED');
  f.browsers.status = status;
  await f.post('/api/browser/close', { confirm: true });
  assert.equal((await f.post('/api/browser-observation/start', { confirm: true, workspaceId: item.id, launch: false })).data.error.code, 'WORKSPACE_OBSERVATION_TARGET_REQUIRED');
  await f.stop();
});

test('legacy workspace metadata without a browser keeps the original fingerprint profile despite the Chrome default', async t => {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.legacy-browser-workspace-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const workspaces = createBrowserWorkspaceManager({ runtimeRoot: root });
  const f = await workspaceFixture(t, { workspaces });
  const original = await f.createWorkspace('旧客户', 'fingerprint');
  const file = path.join(root, '.browser-workspaces', 'workspaces.json');
  const record = JSON.parse(await readFile(file, 'utf8')); delete record.items[0].browser;
  const raw = JSON.stringify(record); await writeFile(file, raw);
  assert.equal((await f.get('/api/workspaces')).data.data.items[0].browser, 'fingerprint');
  assert.equal(await readFile(file, 'utf8'), raw, 'reading does not migrate old profile metadata');
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: original.id })).status, 200);
  assert.equal(f.currentBrowserPlan.browserId, 'fingerprint'); assert.ok(f.currentBrowserPlan.profile.endsWith(path.join('workspaces', original.id, 'fingerprint')));
  assert.ok(f.currentBrowserPlan.fingerprint); await f.stop();
});

test('workspace switching requires confirmation, safely closes only browser and preserves an already verified proxy session', async t => {
  const f = await workspaceFixture(t), first = await f.createWorkspace('First'), second = await f.createWorkspace('Second');
  await f.post('/api/workspaces/start', { confirm: true, id: first.id });
  const events = [...f.events];
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: second.id })).data.error.code, 'WORKSPACE_SWITCH_CONFIRM_REQUIRED');
  assert.deepEqual(f.events, events);
  f.closeError = failure('BROWSER_CLOSE_TIMEOUT');
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: second.id, confirmSwitch: true })).data.error.code, 'BROWSER_CLOSE_TIMEOUT');
  assert.equal(f.running, true); assert.equal(f.workspaceId, first.id);
  f.closeError = null; f.events.length = 0;
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: second.id, confirmSwitch: true })).status, 200);
  assert.deepEqual(f.events, ['browser-close', 'browser-launch']); assert.equal(f.workspaceId, second.id); assert.equal(f.running, true);
  await f.stop();
});

test('one-click work cannot bypass an existing customer licence or expiry while browser planning waits', async t => {
  const licensing = licenseStub(), f = await workspaceFixture(t, { licenseClient: licensing }), item = await f.createWorkspace();
  Object.assign(licensing.permission, { allowed: false, status: 'expired', reason: 'LICENSE_EXPIRED' });
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: item.id })).data.error.code, 'LICENSE_EXPIRED');
  assert.deepEqual(f.events, []); assert.equal(f.probeCalls, 0);
  Object.assign(licensing.permission, { allowed: true, status: 'active', reason: null });
  const plan = f.browsers.plan; f.browsers.plan = async input => { const result = await plan(input); Object.assign(licensing.permission, { allowed: false, reason: 'LICENSE_EXPIRED' }); return result; };
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: item.id })).data.error.code, 'LICENSE_EXPIRED');
  assert.equal(f.browserRunning, false); assert(!f.events.includes('browser-launch'));
  await f.stop();
});

test('disconnect cancels one-click work during verification and late network results cannot open a workspace', { timeout: 4000 }, async t => {
  const f = await workspaceFixture(t), item = await f.createWorkspace(), entered = deferred(), release = deferred();
  f.probe = async () => { entered.resolve(); await release.promise; return { ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 }; };
  const starting = f.post('/api/workspaces/start', { confirm: true, id: item.id }); await entered.promise;
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: item.id })).data.error.code, 'CONNECTION_IN_PROGRESS');
  assert.equal((await Promise.race([f.stop(), delay(750).then(() => { throw new Error('Workspace cancellation held disconnect'); })])).status, 200);
  assert.equal((await starting).data.error.code, 'CONNECTION_CANCELED'); assert.equal(f.running, false); assert.equal(f.browserRunning, false);
  release.resolve(); await delay(10); assert(!f.events.includes('browser-launch'));
});

test('external VPN workspace start still requires customer VPN confirmation before network verification', async t => {
  const f = await workspaceFixture(t); f.config.connectionMode = 'vpn-compat';
  await f.get('/api/status');
  const item = await f.createWorkspace();
  assert.equal((await f.post('/api/workspaces/start', { confirm: true, id: item.id })).data.error.code, 'VPN_CONFIRMATION_REQUIRED');
  assert(!f.events.includes('browser-launch')); assert.equal(f.probeCalls, 0);
});

test('reminder API stores only resource metadata, rejects caller binding and leaves active connection and licence untouched', async t => {
  const licensing = licenseStub(), f = await fixture(t, { licenseClient: licensing });
  await f.start(); const connection = structuredClone(f.server.state.proxy), events = [...f.events], licence = licensing.status(), probes = f.probeCalls;
  const initial = await f.get('/api/reminders');
  assert.equal(initial.status, 200); assert.equal(initial.data.data.items.find(item => item.kind === 'isp').state, 'unknown');
  const saved = await f.post('/api/reminders/save', { confirm: true, kind: 'isp', expiresOn: '2030-01-01', expectedRevision: initial.data.data.revision });
  assert.equal(saved.status, 200, JSON.stringify(saved.data));
  const current = (await f.get('/api/reminders')).data.data, isp = current.items.find(item => item.kind === 'isp');
  assert.equal(isp.expiresOn, '2030-01-01'); assert.equal(isp.source, 'manual'); assert.equal(isp.reminderOnly, true); assert.equal(isp.binding, undefined);
  assert.equal((await f.post('/api/reminders/save', { confirm: true, kind: 'isp', expiresOn: '2030-01-02', expectedRevision: current.revision, binding: 'a'.repeat(64) })).data.error.code, 'INPUT_INVALID');
  assert.equal((await f.get('/api/reminders')).data.data.revision, current.revision);
  assert.deepEqual(f.server.state.proxy, connection); assert.deepEqual(f.events, events); assert.equal(f.probeCalls, probes); assert.deepEqual(licensing.status(), licence);
  f.config.upstream.host = '192.0.2.99';
  const switched = (await f.get('/api/reminders')).data.data.items.find(item => item.kind === 'isp');
  assert.equal(switched.state, 'unknown'); assert.equal(switched.expiresOn, null); assert.equal(switched.source, 'unknown');
  assert.deepEqual(f.events, events); assert.deepEqual(licensing.status(), licence);
  await f.stop();
});

test('one-click support report forces a current chain check and returns redacted evidence even after probe failure', async t => {
  const f = await workspaceFixture(t); await f.createWorkspace('PRIVATE_WORKSPACE_NAME'); await f.start();
  const before = f.probeCalls;
  const checked = await f.post('/api/support/report');
  assert.equal(checked.status, 200); assert.equal(checked.data.data.run.chainCheck, 'verified'); assert(f.probeCalls > before, 'fresh cached proof must still be measured again');
  assert.equal(checked.data.data.workspace.count, 1); assert.equal(checked.data.data.privacy.includesCredentials, false); assert.equal(f.running, true);
  assert.equal((await f.post('/api/support/report', { url: 'https://private.invalid/token', config: 'PRIVATE_CREDENTIAL' })).status, 400);
  f.probe = async () => { throw Object.assign(new Error('PRIVATE_CREDENTIAL 198.51.100.27 https://private.invalid/token'), { code: 'PROBE_TIMEOUT' }); };
  const failed = await f.post('/api/support/report');
  assert.equal(failed.status, 200); assert.equal(failed.data.data.run.chainCheck, 'failed'); assert.equal(failed.data.data.run.code, 'PROBE_TIMEOUT');
  const json = JSON.stringify([checked.data.data, failed.data.data]);
  assert.doesNotMatch(json, /PRIVATE_WORKSPACE_NAME|PRIVATE_CREDENTIAL|private credential|203\.0\.113\.8|192\.0\.2\.1|198\.51\.100\.27|https?:\/\//);
  f.probe = async () => ({ ok: true, status: 'verified', exitIp: '203.0.113.8', elapsedMs: 1 });
  const native = await f.server.createSupportReport(); assert.equal(native.run.chainCheck, 'verified');
  await f.stop();
  const simulation = await fixture(t, { mock: true }); await simulation.start();
  const simulated = await simulation.post('/api/support/report'); assert.equal(simulated.status, 200); assert.equal(simulated.data.data.run.chainCheck, 'mocked');
  assert.equal(simulated.data.data.summary.simulation, true);
  await simulation.stop();
});

function deliveryText(now = Date.now()) {
  const signed = signLicense({ version: 2, licenseId: randomUUID(), deviceId: 'a'.repeat(64), deviceKeyHash: 'b'.repeat(64), generation: 1,
    plan: 'isp-30d-single', status: 'active', issuedAt: now, expiresAt: now + 30 * 86400000, offlineUntil: now + 86400000,
    resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: null }, { keyId: 'controller-test', privateKey: generateKeyPairSync('ed25519').privateKey });
  return createCustomerDelivery({ licenseText: JSON.stringify(signed), connectionMode: 'vpn-import', takeoverMode: 'global',
    isp: { type: 'socks', host: '192.0.2.55', port: 35959, username: 'PRIVATE_DELIVERY_USER', password: 'PRIVATE_DELIVERY_SECRET', expectedExitIps: ['203.0.113.8'] }, vpnText: importedYaml(1) });
}

test('delivery controller tokens are one-use and expire without exposing their private payload or changing legacy licence import', async t => {
  let imports = 0, previews = 0, licenceImports = 0;
  const licensing = licenseStub({ importLicense: async () => { licenceImports++; return { allowed: true, state: 'active' }; } });
  const importer = { recover: async () => ({ recovered: false }), preview: async () => { previews++; return { containsCredentials: true, license: { verified: true } }; },
    import: async () => { imports++; return { imported: true, mock: false }; } };
  const f = await fixture(t, { deliveryImporter: importer, licenseClient: licensing }), text = deliveryText(f.clock), original = structuredClone(f.config);
  const preview = await f.post('/api/delivery/preview', { text }); assert.equal(preview.status, 200);
  assert.doesNotMatch(JSON.stringify(preview.data), /PRIVATE_DELIVERY|192\.0\.2\.55|fixture-node|licenseText|vpnText/);
  assert.equal((await f.post('/api/delivery/import', { token: preview.data.data.token })).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal(imports, 0);
  assert.equal((await f.post('/api/delivery/import', { confirm: true, token: preview.data.data.token })).status, 200); assert.equal(imports, 1);
  assert.equal((await f.post('/api/delivery/import', { confirm: true, token: preview.data.data.token })).data.error.code, 'CONFIRMATION_INVALID'); assert.equal(imports, 1);
  const expiring = await f.post('/api/delivery/preview', { text }); f.clock += 5 * 60000 + 1;
  assert.equal((await f.post('/api/delivery/import', { confirm: true, token: expiring.data.data.token })).data.error.code, 'CONFIRMATION_INVALID'); assert.equal(imports, 1);
  assert.equal((await f.post('/api/delivery/preview', { text, path: 'C:\\private\\file' })).data.error.code, 'INPUT_INVALID');
  assert.equal((await f.post('/api/delivery/import', { confirm: true, token: 'not-token', text })).data.error.code, 'INPUT_INVALID');
  assert.equal((await f.post('/api/delivery/preview', { text: '{malformed' })).data.error.code, 'DELIVERY_INVALID');
  assert.equal((await f.post('/api/delivery/preview', { text: 'x'.repeat(CUSTOMER_DELIVERY_MAX_BYTES + 1) })).data.error.code, 'DELIVERY_SIZE_INVALID');
  assert.equal(previews, 2); assert.deepEqual(f.config, original); assert.deepEqual(f.events, []);
  assert.equal((await f.post('/api/license/import', { text: 'existing separate license file' })).status, 200); assert.equal(licenceImports, 1);
});

test('real delivery importer refuses active sessions and preflight errors before any configuration or authorization change', async t => {
  const f = await fixture(t), text = deliveryText(f.clock), original = structuredClone(f.config);
  const preview = await f.post('/api/delivery/preview', { text }); assert.equal(preview.status, 200, JSON.stringify(preview.data));
  await f.start(); const activePreview = await f.post('/api/delivery/preview', { text });
  const events = [...f.events], active = await f.post('/api/delivery/import', { confirm: true, token: activePreview.data.data.token });
  assert.equal(active.data.error.code, 'SETUP_SESSION_ACTIVE'); assert.deepEqual(f.events, events); assert.equal(f.running, true); assert.deepEqual(f.config, original);
  await f.stop();
  const failed = await fixture(t, { licenseClient: licenseStub() });
  const before = structuredClone(failed.config), license = (await failed.get('/api/license/status')).data.data;
  const invalid = await failed.post('/api/delivery/preview', { text: deliveryText(failed.clock) });
  assert.equal(invalid.data.error.code, 'DELIVERY_DEVICE_INVALID'); assert.deepEqual(failed.config, before); assert.deepEqual(failed.events, []); assert.equal(failed.probeCalls, 0);
  assert.deepEqual((await failed.get('/api/license/status')).data.data, license);
});

test('disconnect aborts delivery verification before commit and legacy licence writes cannot race an active delivery', { timeout: 4000 }, async t => {
  const entered = deferred(), aborted = deferred(), verification = deferred(), cleanup = deferred();
  let committed = false, cleaned = false, stoppedBeforeCleanup = false, f, licenceImports = 0;
  t.after(() => cleanup.resolve());
  const licensing = licenseStub({ importLicense: async () => { licenceImports++; return { allowed: true }; } });
  const importer = { recover: async () => ({ recovered: false }), preview: async () => ({ containsCredentials: true }),
    import: async (_input, { signal } = {}) => {
      assert(signal instanceof AbortSignal, 'controller must pass its cancellation signal into staged network verification');
      entered.resolve();
      try {
        await Promise.race([verification.promise, new Promise((resolve, reject) => signal.addEventListener('abort', () => {
          aborted.resolve(); reject(failure('CONNECTION_CANCELED'));
        }, { once: true }))]);
        committed = true;
        return { imported: true };
      } finally { await cleanup.promise; cleaned = true; }
    } };
  f = await fixture(t, { deliveryImporter: importer, licenseClient: licensing });
  const original = structuredClone(f.config), preview = await f.post('/api/delivery/preview', { text: deliveryText(f.clock) });
  const importing = f.post('/api/delivery/import', { confirm: true, token: preview.data.data.token });
  await Promise.race([entered.promise, importing.then(result => { throw new Error(JSON.stringify(result)); })]);
  const standalone = await f.post('/api/license/import', { text: 'existing standalone grant' });
  assert.equal(standalone.data.error.code, 'DELIVERY_BUSY'); assert.equal(licenceImports, 0);
  const stopping = f.stop().then(result => { stoppedBeforeCleanup = !cleaned; return result; });
  await Promise.race([aborted.promise, delay(750).then(() => { throw new Error('Delivery verification did not promptly receive cancellation'); })]);
  assert.equal(await Promise.race([stopping.then(() => 'stopped'), delay(40).then(() => 'pending')]), 'pending', 'disconnect must wait until staged resources are safely cleaned');
  assert.equal((await f.post('/api/license/import', { text: 'grant while cleaning' })).data.error.code, 'DELIVERY_BUSY');
  cleanup.resolve();
  const stopped = await Promise.race([stopping, delay(750).then(() => { throw new Error('Delivery cleanup held disconnect'); })]);
  assert.equal(stopped.status, 200); assert.equal((await importing).data.error.code, 'CONNECTION_CANCELED');
  assert.equal(stoppedBeforeCleanup, false); assert.equal(cleaned, true);
  verification.resolve(); await delay(20);
  assert.equal(committed, false); assert.equal(f.running, false); assert.equal(f.browserRunning, false);
  assert.deepEqual(f.config, original); assert(!f.events.includes('proxy-start')); assert(!f.events.includes('browser-launch'));
  assert.equal((await f.post('/api/license/import', { text: 'existing standalone grant' })).status, 200); assert.equal(licenceImports, 1);
});

test('subscription API preserves live leases for unchanged input and ends the owned session only after a committed node change', async t => {
  let f, changed = false, calls = 0;
  f = await fixture(t, { subscriptions: {
    refresh: async ({ expectedId }) => { calls++; await f.vpnConfigStore.import(importedYaml(1).replaceAll('fixture-node', changed ? 'updated-node' : 'fixture-node'), { expectedId }); },
    clear: async () => {},
  } });
  f.config.connectionMode = 'vpn-import';
  await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) });
  await f.get('/api/status');
  assert.equal((await f.start()).status, 200); await f.launch();
  const before = (await f.get('/api/status')).data.data, profile = before.vpnConfig.id;
  assert.equal((await f.post('/api/vpn/subscription/refresh', { expectedId: profile })).status, 400);
  assert.equal((await f.post('/api/vpn/subscription/refresh', { confirm: true, url: 'private', unknown: true })).status, 400);
  assert.equal(calls, 0);
  const unchanged = await f.post('/api/vpn/subscription/refresh', { confirm: true, expectedId: profile });
  assert.equal(unchanged.status, 200); assert.equal(unchanged.data.data.sessionEnded, false);
  assert.equal(f.running, true); assert.equal(f.browserRunning, true); assert.equal(f.server.state.revision, before.revision);
  changed = true;
  const updated = await f.post('/api/vpn/subscription/refresh', { confirm: true, expectedId: profile });
  assert.equal(updated.status, 200); assert.equal(updated.data.data.sessionEnded, true);
  assert.notEqual(updated.data.data.vpnConfig.id, profile); assert.equal(f.running, false); assert.equal(f.browserRunning, false);
  assert.deepEqual(f.events.slice(-2), ['browser-close', 'proxy-stop']);
});

test('subscription failure keeps the active route, profile and public fixed error without exposing credentials', async t => {
  const f = await fixture(t, { subscriptions: { refresh: async () => { throw failure('VPN_SUBSCRIPTION_ROUTE_CHANGED'); } } });
  f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) }); await f.get('/api/status'); assert.equal((await f.start()).status, 200);
  const before = (await f.get('/api/status')).data.data;
  const failed = await f.post('/api/vpn/subscription/refresh', { confirm: true, expectedId: before.vpnConfig.id, url: 'https://subscription.invalid/?token=PRIVATE_SUB_TOKEN' });
  assert.equal(failed.data.error.code, 'VPN_SUBSCRIPTION_ROUTE_CHANGED');
  assert.doesNotMatch(JSON.stringify(failed), /PRIVATE_SUB_TOKEN|private credential/);
  assert.equal(f.running, true); assert.equal((await f.get('/api/status')).data.data.vpnConfig.id, before.vpnConfig.id);
  assert.equal(f.server.state.revision, before.revision);
});

test('paused network lock capability preserves subscription refresh and clear without stopping the active route', async t => {
  let f, refreshCalls = 0, clearCalls = 0;
  f = await fixture(t, { lockSimulation: true, subscriptions: {
    refresh: async ({ expectedId }) => { refreshCalls++; await f.vpnConfigStore.import(importedYaml(1), { expectedId }); },
    clear: async () => { clearCalls++; },
  } });
  f.runtime.networkLock.canArm = false;
  const lockStatus = f.runtime.networkLock.status;
  f.runtime.networkLock.status = async () => ({ ...await lockStatus(), canArm: false, developmentPaused: true });
  f.config.connectionMode = 'vpn-import';
  await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) });
  await f.get('/api/status');
  assert.equal((await f.start()).status, 200); await f.launch();
  const before = (await f.get('/api/status')).data.data;
  assert.equal(before.networkLock.canArm, false); assert.equal(before.networkLock.developmentPaused, true);
  for (const operation of ['refresh', 'clear']) {
    const result = await f.post(`/api/vpn/subscription/${operation}`, { confirm: true, expectedId: before.vpnConfig.id });
    assert.equal(result.status, 200); assert.equal(result.data.data.sessionEnded, false);
    assert.equal(result.data.data.vpnConfig.id, before.vpnConfig.id);
    assert.equal(f.running, true); assert.equal(f.browserRunning, true);
    assert.equal(f.server.state.revision, before.revision);
  }
  assert.equal(refreshCalls, 1); assert.equal(clearCalls, 1);
  assert.equal(f.events.includes('network-arm'), false); assert.equal(f.events.includes('proxy-stop'), false);
});

test('Fake-IP recovery requires explicit idle-session acknowledgment and hides private archive information', async t => {
  const f = await fixture(t); let recoveries = 0;
  f.runtime.recoverFakeIpCache = async () => { recoveries++; return { recovered: true, archived: true, mock: false, privateArchive: 'C:\\PRIVATE_BACKUP' }; };
  for(const body of [{}, { confirm: true }, { confirm: true, applicationsClosed: false }, { confirm: true, applicationsClosed: true, path: 'foreign' }]) {
    assert.equal((await f.post('/api/network/cache/recover', body)).status, 400);
  }
  await f.start();
  assert.equal((await f.post('/api/network/cache/recover', { confirm: true, applicationsClosed: true })).status, 409); assert.equal(recoveries, 0);
  await f.stop();
  const result = await f.post('/api/network/cache/recover', { confirm: true, applicationsClosed: true });
  assert.equal(result.status, 200); assert.equal(recoveries, 1);
  assert.deepEqual(result.data.data, { recovered: true, archived: true, mock: false });
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_BACKUP/);
});

test('TUN policy arguments are allowlisted and HTTP cannot accept a global policy', async t => {
  const f = await fixture(t, { state: { mode: 'tun' } });
  assert.equal((await f.post('/api/proxy/start', { confirm: true, mode: 'tun', routingMode: 'unsafe-direct' })).status, 400);
  assert.equal((await f.post('/api/proxy/start', { confirm: true, mode: 'http', routingMode: 'global' })).status, 400);
  assert.equal(f.events.length, 0);
  assert.equal((await f.post('/api/proxy/start', { confirm: true, mode: 'tun', routingMode: 'safe-rules' })).status, 200);
  assert.equal(f.startInput.routingMode, 'safe-rules'); assert.deepEqual(f.startInput.applicationPaths, []);
});

test('explicit Fake-IP recovery preserves a retained network lock and refuses an active browser', async t => {
  const f = await fixture(t, { lockSimulation: true, state: { networkLocked: true } }); let recoveries = 0;
  f.runtime.recoverFakeIpCache = async () => { recoveries++; return { recovered: true, archived: true, mock: false }; };
  f.browserRunning = true;
  assert.equal((await f.post('/api/network/cache/recover', { confirm: true, applicationsClosed: true })).status, 409);
  assert.equal(recoveries, 0);
  f.browserRunning = false;
  const result = await f.post('/api/network/cache/recover', { confirm: true, applicationsClosed: true });
  assert.equal(result.status, 200); assert.equal(recoveries, 1); assert.equal(f.networkLocked, true);
  assert.equal(f.events.includes('network-unlock'), false);
});

test('Mock workflow is explicit and never claims a real browser or verified exit', async t => {
  const f = await fixture(t, { mock: true });
  assert.equal((await f.start()).data.data.proxy.exitStatus, 'mocked');
  const plan = await f.plan();
  assert.equal(plan.data.data.url, 'https://claude.ai/');
  assert.equal(plan.data.data.language, 'en-US');
  assert.equal(plan.data.data.executable, undefined);
  const launched = await f.post('/api/browser/launch', { confirm: true, token: plan.data.data.token });
  assert.deepEqual([launched.status, launched.data.data.mode, launched.data.data.launched], [200, 'mocked', false]);
  assert.equal((await f.stop()).data.data.ended, true);
  assert.equal(f.probeCalls + f.requestCalls, 0);
});

test('native local requests cannot read or mutate control state without the current session credential', async t => {
  const f = await fixture(t, { mock: true });
  const before = f.server.state.revision;
  for (const pathname of ['/api/status', '/api/onboarding']) {
    const response = await fetch(f.url + pathname);
    assert.equal(response.status, 401); assert.equal((await response.json()).error.code, 'CONTROL_AUTH_REQUIRED');
  }
  for (const credential of ['', '0'.repeat(64), f.server.controlHeaders()['x-mc-control-token'] + 'x']) {
    const response = await fetch(f.url + '/api/proxy/start', { method: 'POST', headers: { 'content-type': 'application/json', 'x-mc-control-token': credential }, body: JSON.stringify({ confirm: true }) });
    assert.equal(response.status, 401);
  }
  assert.equal(f.server.state.revision, before); assert.equal(f.server.state.proxy.running, false);
  assert.equal((await f.start()).status, 200);
  const other = await fixture(t, { mock: true });
  assert.equal((await other.get('/api/status', { headers: f.server.controlHeaders() })).status, 401);
  const page = await (await fetch(f.url + '/')).text();
  assert.equal(page.includes(f.server.controlHeaders()['x-mc-control-token']), false);
  assert.equal(JSON.stringify((await f.get('/api/status')).data).includes(f.server.controlHeaders()['x-mc-control-token']), false);
});

test('GET status and diagnostics never probe; POST checks third parties only when selected', async t => {
  const f = await fixture(t);
  await f.get('/api/status'); await f.get('/api/diagnostics');
  assert.equal((await f.get('/api/probes')).status, 405);
  assert.equal(f.probeCalls, 0);
  await f.start();
  assert.equal((await f.post('/api/probes')).data.data.summary.reachable, 1);
  assert.equal(f.requestCalls, 0);
  assert.equal((await f.post('/api/probes', { thirdParty: true })).data.data.summary.reachable, 4);
  assert.equal(f.requestCalls, 3);
});

test('onboarding and status expose browser availability without executable paths', async t => {
  const f = await fixture(t);
  const choices = [{ id: 'chrome', label: 'Chrome', available: false }, { id: 'edge', label: 'Edge', available: true }];
  f.browsers.listBrowsers = async () => choices;
  assert.deepEqual((await f.get('/api/onboarding')).data.data.browserOptions, choices);
  assert.deepEqual((await f.get('/api/status')).data.data.browserOptions, choices);
  assert.equal(f.probeCalls + f.systemProbeCalls, 0);
});

test('manual browser rescan refreshes cached availability without ISP probes or changing the connection revision', async t => {
  const f = await fixture(t); let scans = 0;
  f.browsers.listBrowsers = async () => [{ id: 'chrome', label: 'Google Chrome', available: false }];
  f.browsers.rescan = async () => { scans++; return [{ id: 'chrome', label: 'Google Chrome', available: true }]; };
  await f.get('/api/onboarding'); const revision = f.server.state.revision;
  for (let i = 0; i < 3; i++) await f.get('/api/status'); assert.equal(scans, 0);
  assert.equal((await f.post('/api/browsers/rescan', { executable: 'PRIVATE_PATH' })).status, 400);
  const refreshed = await f.post('/api/browsers/rescan'); assert.equal(refreshed.status, 200); assert.equal(refreshed.data.data.browserOptions[0].available, true);
  assert.equal((await f.get('/api/status')).data.data.browserOptions[0].available, true);
  assert.equal(scans, 1); assert.equal(f.server.state.revision, revision); assert.equal(f.probeCalls + f.requestCalls, 0);
});

test('manual browser paths require confirmation, return no executable and revoke pending browser tokens', async t => {
  const f = await fixture(t); await f.start(); const planned = await f.plan();
  assert.equal((await f.post('/api/browsers/path', { browser: 'chrome', executable: 'C:\\Custom Chrome\\chrome.exe' })).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/browsers/path', { browser: 'chrome', executable: 'chrome.exe', confirm: true })).data.error.code, 'BROWSER_EXECUTABLE_INVALID');
  const result = await f.post('/api/browsers/path', { browser: 'chrome', executable: 'C:\\Custom Chrome\\chrome.exe', confirm: true });
  assert.equal(result.status, 200); assert.doesNotMatch(JSON.stringify(result.data), /Custom Chrome|executable/);
  assert.equal((await f.post('/api/browser/launch', { token: planned.data.data.token, confirm: true })).data.error.code, 'CONFIRMATION_INVALID');
  assert.equal((await f.post('/api/browsers/path', { browser: 'chrome', executable: null, confirm: true })).status, 200);
  assert.equal(f.browserRunning, false);
});

test('browser plan defaults to a real IP page and keeps every website service in the fixed allowlist', async t => {
  const f = await fixture(t); await f.start();
  const defaultPlan = await f.post('/api/browser/plan', { browser: 'chrome', fresh: true });
  assert.equal(defaultPlan.status, 200); assert.equal(defaultPlan.data.data.service, 'exit'); assert.equal(defaultPlan.data.data.url, 'https://api.ipify.org/');
  assert.equal(defaultPlan.data.data.network.browserExitVerification, 'unverified');
  for (const [service, url] of Object.entries({ google: 'https://www.google.com/', wikipedia: 'https://www.wikipedia.org/', github: 'https://github.com/', youtube: 'https://www.youtube.com/', chatgpt: 'https://chatgpt.com/', claude: 'https://claude.ai/', tiktok: 'https://www.tiktok.com/' })) {
    const plan = await f.post('/api/browser/plan', { browser: 'edge', service }); assert.equal(plan.status, 200); assert.equal(plan.data.data.url, url);
  }
  assert.equal((await f.post('/api/browser/plan', { service: 'https://evil.invalid/' })).data.error.code, 'SERVICE_INVALID');
  assert.equal(f.browserRunning, false, 'planning never launches a browser or claims a browser-observed IP');
});

test('closing a browser preserves verified TUN exits and application leases while revoking only browser plans', async t => {
  let gatewayRunning = false;
  const gateway = { status: () => ({ running: gatewayRunning }), stop: async () => { gatewayRunning = false; }, start: async () => { gatewayRunning = true; return { port: 19001 }; } };
  const f = await fixture(t, { state: { mode: 'tun' }, applicationGateway: gateway }); await f.start();
  const unused = await f.plan();
  const cleanup = await f.post('/api/cleanup/preview', { items: ['browserCache'] }); assert.equal(cleanup.status, 200);
  assert.equal((await f.launch()).status, 200); await f.server.applicationProxy();
  const revision = f.server.state.revision, exit = structuredClone(f.server.state.proxy.exit), systemExit = structuredClone(f.server.state.proxy.systemExit);
  const probes = f.probeCalls + f.systemProbeCalls; f.events.length = 0;
  f.closeError = failure('BROWSER_CLOSE_TIMEOUT');
  assert.equal((await f.post('/api/browser/close', { confirm: true })).data.error.code, 'BROWSER_CLOSE_TIMEOUT');
  assert.equal(f.browserRunning, true); assert.equal(f.running, true); assert.equal(gatewayRunning, true);
  assert.deepEqual(f.server.state.proxy.exit, exit); assert.deepEqual(f.server.state.proxy.systemExit, systemExit);
  f.closeError = null;
  assert.equal((await f.post('/api/browser/close', { confirm: true })).status, 200);
  const status = (await f.get('/api/status')).data.data;
  assert.equal(status.proxy.running, true); assert.equal(status.proxy.exitStatus, 'verified'); assert.equal(status.proxy.systemNetwork.status, 'verified');
  assert.equal(status.browser.running, false); assert.equal(status.applicationProxy.running, true);
  assert.equal(f.server.state.revision, revision); assert.equal(f.probeCalls + f.systemProbeCalls, probes);
  assert.deepEqual(f.server.state.proxy.exit, exit); assert.deepEqual(f.server.state.proxy.systemExit, systemExit);
  assert.deepEqual(f.events, ['browser-close', 'browser-close']);
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: unused.data.data.token })).data.error.code, 'CONFIRMATION_INVALID');
  assert.equal(f.server.state.plans.has(cleanup.data.data.token), true, 'browser closure cannot discard unrelated confirmation plans');
  const next = await f.post('/api/browser/plan', { service: 'google' }); assert.equal(next.status, 200);
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: next.data.data.token })).status, 200);
});

test('browser rescan and manual path changes retain both network observations without a new ISP probe', async t => {
  const f = await fixture(t, { state: { mode: 'tun' } }); await f.start();
  const revision = f.server.state.revision, exit = structuredClone(f.server.state.proxy.exit), systemExit = structuredClone(f.server.state.proxy.systemExit);
  const probes = f.probeCalls + f.systemProbeCalls;
  for (const [route, body] of [['/api/browsers/rescan', {}], ['/api/browsers/path', { executable: 'C:\\Custom Chrome\\chrome.exe', confirm: true }]]) {
    assert.equal((await f.post(route, body)).status, 200);
    const status = (await f.get('/api/status')).data.data;
    assert.equal(status.proxy.running, true); assert.equal(status.proxy.exitStatus, 'verified'); assert.equal(status.proxy.systemNetwork.status, 'verified');
    assert.equal(f.server.state.revision, revision); assert.equal(f.probeCalls + f.systemProbeCalls, probes);
    assert.deepEqual(f.server.state.proxy.exit, exit); assert.deepEqual(f.server.state.proxy.systemExit, systemExit);
  }
});

test('a queued browser close also revokes the plan created by the preceding in-flight operation', async t => {
  const f = await fixture(t); await f.start();
  const previous = await f.plan(), entered = deferred(), release = deferred(), original = f.browsers.plan;
  f.browsers.plan = async input => { entered.resolve(); await release.promise; return original(input); };
  const planning = f.plan(); await entered.promise;
  const revision = f.server.state.revision, closing = f.post('/api/browser/close', { confirm: true });
  try {
    for (let attempt = 0; attempt < 100 && f.server.state.plans.has(previous.data.data.token); attempt++) await delay(5);
    assert.equal(f.server.state.plans.has(previous.data.data.token), false, 'close intent must revoke existing browser plans before it waits in the operation queue');
  } finally { release.resolve(); }
  const [planned, closed] = await Promise.all([planning, closing]); assert.equal(planned.status, 200); assert.equal(closed.status, 200);
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: planned.data.data.token })).data.error.code, 'CONFIRMATION_INVALID');
  assert.equal(f.server.state.revision, revision); assert.equal(f.running, true); assert.equal(f.browserRunning, false);
  assert.equal((await f.get('/api/status')).data.data.proxy.exitStatus, 'verified');
});

test('control requests reject cross-site, wrong Host, non-JSON and array bodies', async t => {
  const f = await fixture(t);
  for (const headers of [{ origin: 'https://evil.example' }, { 'sec-fetch-site': 'cross-site' }]) {
    const response = await f.post('/api/proxy/start', { confirm: true }, headers);
    assert.equal(response.status, 403);
  }
  const wrongHost = await new Promise(resolve => {
    http.get({ host: '127.0.0.1', port: f.server.address().port, path: '/api/status', headers: { host: 'evil.example' } }, response => { response.resume(); resolve(response.statusCode); });
  });
  assert.equal(wrongHost, 403);
  assert.equal((await f.post('/api/proxy/start', {}, { 'content-type': 'text/plain' })).status, 415);
  assert.equal((await f.post('/api/proxy/start', [])).status, 400);
  assert.equal((await f.post('/api/proxy/start')).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal(f.events.length, 0);
  const page = await fetch(`http://127.0.0.1:${f.server.address().port}/`);
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  for (const module of ['controller-client.js', 'workspace-view.js']) {
    const asset = await fetch(`${f.url}/${module}`);
    assert.equal(asset.status, 200); assert.match(asset.headers.get('content-type'), /javascript/);
  }
  assert.equal((await f.get('/backend/runtime/config.json')).status, 404);
});

test('new local UI assets preserve strict CSP, correct MIME and the explicit static allowlist', async t => {
  const f = await fixture(t);
  const assets = [
    ['/dom-updates.js', 'text/javascript; charset=utf-8'],
    ['/cosmos.css', 'text/css; charset=utf-8'],
    ['/cosmos-surfaces.css', 'text/css; charset=utf-8'],
    ['/assets/MonaSans-VF.woff2', 'font/woff2'],
    ['/assets/earth-nasa-globe-east.jpg', 'image/jpeg'],
  ];
  const brands = await readdir(new URL('../../frontend/assets/brands/', import.meta.url));
  for (const brand of brands.filter(name => /\.(png|svg)$/.test(name))) {
    assets.push([`/assets/brands/${brand}`, brand.endsWith('.svg') ? 'image/svg+xml' : 'image/png']);
  }
  for (const [route, mime] of assets) {
    const response = await fetch(f.url + route);
    assert.equal(response.status, 200, route);
    assert.equal(response.headers.get('content-type'), mime, route);
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(response.headers.get('content-security-policy'), "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    const bytes = Buffer.from(await response.arrayBuffer());
    assert.deepEqual(bytes, await readFile(new URL(`../../frontend${route}`, import.meta.url)));
    const head = await fetch(f.url + route, { method: 'HEAD' });
    assert.equal(head.status, 200); assert.equal(head.headers.get('content-type'), mime);
    assert.equal((await head.arrayBuffer()).byteLength, 0);
  }
  for (const route of ['/assets/earth-nasa-cloud-layer.jpg', '/assets/MonaSans-OFL.txt', '/licenses/MonaSans-OFL.txt', '/v2.js', '/assets/%2e%2e/%2e%2e/package.json', '/assets/brands/application-sources.json', '/assets/brands/codex-source.json', '/assets/brands/website-sources.json', '/assets/brands/not-a-brand.png', '/assets/brands/%2e%2e/%2e%2e/package.json']) {
    assert.equal((await fetch(f.url + route)).status, 404, route);
  }
  assert.equal(f.probeCalls, 0); assert.equal(f.systemProbeCalls, 0);
  assert.deepEqual(f.events, [], 'loading visual assets must not start or stop a proxy');
});

test('startup requires pinned IP and uses only configured port', async t => {
  const f = await fixture(t);
  assert.equal((await f.post('/api/proxy/start', { confirm: true, port: 8888 })).data.error.code, 'PROXY_PORT_INVALID');
  f.config.probe.expectedExitIps = [];
  await f.get('/api/status');
  assert.equal((await f.start()).data.error.code, 'EXPECTED_EXIT_REQUIRED');
  assert.equal(f.events.length, 0);
});

test('wrong exit stops owned proxy and redacts internal diagnostic text', async t => {
  const f = await fixture(t);
  f.probe = async () => { throw failure('EXIT_IP_MISMATCH'); };
  const response = await f.start();
  assert.equal(response.data.error.code, 'EXIT_IP_MISMATCH');
  assert.doesNotMatch(JSON.stringify(response.data), /credential/);
  assert.equal(f.running, false);
  assert.equal((await f.get('/api/status')).data.data.proxy.exitStatus, 'unverified');
});

test('startup cleanup failure preserves actual running state for retry', async t => {
  const f = await fixture(t);
  f.probe = async () => { throw failure('EXIT_IP_MISMATCH'); };
  f.stopError = failure('PROCESS_STOP_TIMEOUT');
  assert.equal((await f.start()).data.error.code, 'PROCESS_STOP_TIMEOUT');
  const status = (await f.get('/api/status')).data.data;
  assert.equal(status.proxy.running, true);
  assert.equal(status.proxy.enabled, false);
  assert.equal(status.proxy.exitStatus, 'unverified');
  assert.equal(status.blockPending, true, 'failed cleanup must block new starts until the owned core is stopped');
  f.stopError = null;
  assert.equal((await f.stop()).status, 200);
});

test('health retries failed startup cleanup even while that session is disabled', async t => {
  const f = await fixture(t, { healthIntervalMs: 20 });
  f.probe = async () => { throw failure('EXIT_IP_MISMATCH'); }; f.stopError = failure('PROCESS_STOP_TIMEOUT');
  assert.equal((await f.start()).data.error.code, 'PROCESS_STOP_TIMEOUT');
  assert.equal(f.server.state.proxy.requestedStop, true);
  f.stopError = null;
  for (let attempt = 0; attempt < 100 && f.running; attempt++) await delay(10);
  assert.equal(f.running, false, 'health must retry retained owned cleanup without a new user action');
  assert.equal((await f.get('/api/status')).data.data.blockPending, false);
});

test('successful core stop updates authoritative state before auxiliary setup cleanup can fail', async t => {
  let failCleanup = false;
  const setupVerifier = { ...createSetupVerifier({ mock: true }), recoverAndStop: async () => { if (failCleanup) throw failure('CORE_CHECK_FAILED'); } };
  const f = await fixture(t, { setupVerifier });
  await f.start(); failCleanup = true;
  assert.equal((await f.stop()).data.error.code, 'CORE_CHECK_FAILED');
  assert.equal(f.running, false); assert.equal(f.server.state.proxy.running, false); assert.equal(f.server.state.proxy.managed, false);
});

test('concurrent desktop shutdown callers share one owned-session cleanup', async t => {
  const f = await fixture(t); const entered = deferred(), release = deferred();
  f.browsers.close = async () => { f.events.push('browser-close'); entered.resolve(); await release.promise; f.browserRunning = false; };
  const first = f.server.shutdown(); await entered.promise;
  const second = f.server.shutdown(); assert.equal(first, second);
  release.resolve(); await Promise.all([first, second]);
  assert.deepEqual(f.events, ['browser-close', 'proxy-stop']);
  await f.server.shutdown(); assert.deepEqual(f.events, ['browser-close', 'proxy-stop']);
});

test('browser plan has fixed arguments and can be consumed only once', async t => {
  const f = await fixture(t, { mock: true });
  await f.start();
  assert.equal((await f.post('/api/browser/plan', { browser: 'powershell' })).data.error.code, 'BROWSER_INVALID');
  assert.equal((await f.post('/api/browser/plan', { service: 'arbitrary' })).data.error.code, 'SERVICE_INVALID');
  const plan = (await f.post('/api/browser/plan', { url: 'https://evil.example', args: ['--no-proxy-server'] })).data.data;
  assert.equal(plan.url, 'https://api.ipify.org/');
  assert.doesNotMatch(JSON.stringify(plan), /evil\.example|no-proxy-server/);
  const body = { confirm: true, token: plan.token };
  assert.equal((await f.post('/api/browser/launch', body)).status, 200);
  assert.equal((await f.post('/api/browser/launch', body)).data.error.code, 'CONFIRMATION_INVALID');
});

test('expired observations and browser plans do not authorize launch', async t => {
  const f = await fixture(t);
  await f.start(); const plan = await f.plan();
  f.clock += 301_000;
  assert.equal((await f.get('/api/status')).data.data.proxy.exitStatus, 'unverified');
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: plan.data.data.token })).data.error.code, 'CONFIRMATION_INVALID');
  assert.equal(f.browserRunning, false);
});

test('configuration changes invalidate plans and stop old managed session', async t => {
  const f = await fixture(t);
  await f.start(); const plan = await f.plan();
  f.config.probe.expectedExitIps = ['203.0.113.9'];
  const status = (await f.get('/api/status')).data.data;
  assert.equal(status.proxy.exitStatus, 'unverified');
  assert.equal(status.lastError.code, 'PROXY_CONFIG_CHANGED');
  assert.equal(f.running, false);
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: plan.data.data.token })).data.error.code, 'CONFIRMATION_INVALID');
});

test('stop invalidates an in-flight start and late probe result', async t => {
  const f = await fixture(t);
  const entered = deferred(), release = deferred();
  f.probe = async () => { entered.resolve(); await release.promise; return { ok: true, status: 'verified', exitIp: '203.0.113.8' }; };
  const starting = f.start(); await entered.promise;
  const stopping = f.stop();
  while (!f.server.state.proxy.requestedStop) await delay(5);
  release.resolve();
  assert.equal((await starting).data.error.code, 'CONNECTION_CANCELED');
  assert.equal((await stopping).status, 200);
  assert.equal(f.running, false);
  assert.equal((await f.get('/api/status')).data.data.proxy.exit, null);
});

test('safe end closes browser first; close timeout keeps proxy until retry', async t => {
  const f = await fixture(t);
  await f.start(); assert.equal((await f.launch()).status, 200);
  f.events.length = 0; f.closeError = failure('BROWSER_CLOSE_TIMEOUT');
  assert.equal((await f.stop()).data.error.code, 'BROWSER_CLOSE_TIMEOUT');
  assert.equal(f.running, true);
  assert.deepEqual(f.events, ['browser-close']);
  f.closeError = null; f.events.length = 0;
  assert.equal((await f.stop()).status, 200);
  assert.deepEqual(f.events, ['browser-close', 'proxy-stop']);
  assert.equal(f.browserRunning, false);
});

test('manual exit failure blocks active browser gateway without erasing login', async t => {
  const f = await fixture(t);
  await f.start(); await f.launch();
  f.probe = async () => { throw failure('EXIT_IP_MISMATCH'); };
  assert.equal((await f.post('/api/probes')).data.error.code, 'EXIT_IP_MISMATCH');
  assert.equal(f.running, false);
  assert.equal(f.browserRunning, true);
});

test('status read failure blocks existing gateway and does not strand health loop', async t => {
  const f = await fixture(t);
  await f.start(); await f.launch();
  f.readError = failure('CONFIG_READ_FAILED');
  const status = (await f.get('/api/status')).data.data;
  assert.equal(f.running, false);
  assert.equal(status.proxy.enabled, false);
  assert.equal(status.lastError.code, 'CONFIG_READ_FAILED');
});

test('active browser configuration failure during explicit verification also blocks', async t => {
  const f = await fixture(t);
  await f.start(); await f.launch();
  f.readError = failure('CONFIG_READ_FAILED');
  assert.equal((await f.post('/api/probes')).data.error.code, 'CONFIG_READ_FAILED');
  assert.equal(f.running, false);
});

test('configuration changed during pending probe blocks before returning a response', async t => {
  const f = await fixture(t);
  await f.start(); await f.launch();
  f.probe = async () => {
    f.config.probe.expectedExitIps = ['203.0.113.9'];
    return { ok: true, status: 'verified', exitIp: '203.0.113.8' };
  };
  assert.equal((await f.post('/api/probes')).data.error.code, 'PROXY_CONFIG_CHANGED');
  assert.equal(f.running, false);
  assert.equal(f.server.state.proxy.exit, null);
});

test('configuration already changed before explicit verification also blocks active browser', async t => {
  const f = await fixture(t);
  await f.start(); await f.launch();
  f.config.probe.expectedExitIps = ['203.0.113.9'];
  assert.equal((await f.post('/api/probes')).data.error.code, 'PROXY_CONFIG_CHANGED');
  assert.equal(f.running, false);
  assert.equal(f.browserRunning, true);
});

test('health recovers active session without GET and retries failed owned stop', async t => {
  const f = await fixture(t, { healthIntervalMs: 20, state: { running: true, browserRunning: true } });
  f.probe = async () => { throw failure('EXIT_IP_MISMATCH'); };
  f.stopError = failure('PROCESS_STOP_TIMEOUT');
  const until = async check => { for (let i = 0; i < 100; i++) { if (check()) return; await delay(10); } assert.fail('health action timed out'); };
  await until(() => f.events.includes('proxy-stop'));
  assert.equal(f.browserRunning, false);
  f.stopError = null;
  await until(() => !f.running);
  assert.ok(f.events.filter(x => x === 'proxy-stop').length >= 2);
  assert.equal((await f.get('/api/status')).data.data.blockPending, false);
});

test('cleanup requires selected browser data and one-use confirmation; retired writes return 410', async t => {
  const f = await fixture(t, { mock: true });
  assert.equal((await f.post('/api/cleanup/preview')).status, 400);
  assert.equal((await f.post('/api/cleanup/preview', { items: ['claudeData'] })).status, 410);
  assert.equal((await f.post('/api/optimization/apply', { confirm: true })).status, 410);
  const preview = (await f.post('/api/cleanup/preview', { browser: 'chrome', items: ['browserCache'] })).data.data;
  assert.ok(preview.targets.every(target => !Object.hasOwn(target, 'path')));
  assert.equal((await f.post('/api/cleanup/apply', { token: preview.token })).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/cleanup/apply', { confirm: true, token: preview.token })).status, 200);
  assert.equal((await f.post('/api/cleanup/apply', { confirm: true, token: preview.token })).data.error.code, 'CONFIRMATION_INVALID');
});

test('close timeout keeps health checks active while new operations remain blocked', async t => {
  const f = await fixture(t, { healthIntervalMs: 20 });
  await f.start(); await f.launch();
  f.closeError = failure('BROWSER_CLOSE_TIMEOUT');
  assert.equal((await f.stop()).data.error.code, 'BROWSER_CLOSE_TIMEOUT');
  f.probe = async () => { throw failure('EXIT_IP_MISMATCH'); };
  f.clock += 1000;
  for (let i = 0; i < 100 && f.running; i++) await delay(10);
  assert.equal(f.running, false);
  assert.equal(f.browserRunning, true);
  assert.equal((await f.plan()).data.error.code, 'PROXY_STOPPED');
});

test('gateway disappearance revokes verification and old browser plan', async t => {
  const f = await fixture(t);
  await f.start(); const plan = await f.plan();
  f.running = false;
  assert.equal((await f.get('/api/status')).data.data.proxy.exitStatus, 'unverified');
  assert.equal((await f.post('/api/browser/launch', { confirm: true, token: plan.data.data.token })).data.error.code, 'CONFIRMATION_INVALID');
});

test('TUN route loss blocks recovered session even before any browser is opened', async t => {
  const f = await fixture(t, { state: { running: true, mode: 'tun', tunReady: false } });
  assert.equal(f.running, false);
  const state = (await f.get('/api/status')).data.data;
  assert.equal(state.proxy.enabled, false);
  assert.equal(state.lastError.code, 'TUN_NOT_READY');
});

test('multi-source mismatch stops the session and keeps a stale failed report', async t => {
  const request = async url => {
    if (url.hostname === 'api.ipify.org') return '{"ip":"203.0.113.9"}';
    if (url.hostname === 'www.cloudflare.com') return 'ip=203.0.113.8';
    if (url.hostname === 'ipwho.is') return '{"success":true,"ip":"203.0.113.8","country_code":"JP","city":"Tokyo","timezone":{"id":"Asia/Tokyo"}}';
    return { statusCode: 200 };
  };
  const f = await fixture(t, { request });
  await f.start();
  const report = await f.post('/api/probes', { multi: true });
  assert.equal(report.data.error.code, 'MULTI_EXIT_MISMATCH');
  assert.equal(f.running, false);
  assert.equal((await f.get('/api/status')).data.data.report.stale, true);
});

test('startup collects an external network report only after explicit opt-in', async t => {
  const f = await fixture(t, { mock: true, autoReport: true });
  assert.equal((await f.start()).data.data.report, null, 'legacy autoReport cannot override the user default');
  await f.stop();
  const status = (await f.post('/api/proxy/start', { confirm: true, externalReport: true })).data.data;
  assert.equal(status.report.summary.status, 'mocked');
  assert.equal(status.report.results.length, 7);
  assert.equal(status.report.geo, null);
});

test('environment baseline rebuild requires confirmation, explicit refresh and an idle session', async t => {
  const environment = createEnvironmentManager({ mock: true });
  const calls = [];
  const check = environment.check;
  environment.check = options => { calls.push(options); return check(options); };
  const f = await fixture(t, { environment });
  const rebuild = { refreshBackup: true, rebuildBackup: true };
  assert.equal((await f.post('/api/environment/check', rebuild)).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/environment/check', { rebuildBackup: true, confirm: true })).data.error.code, 'INPUT_INVALID');
  assert.equal((await f.post('/api/environment/check', { rebuildBackup: 'true' })).data.error.code, 'INPUT_INVALID');
  assert.equal((await f.post('/api/environment/check', { unknown: true })).data.error.code, 'INPUT_INVALID');
  f.running = true;
  assert.equal((await f.post('/api/environment/check', { ...rebuild, confirm: true })).data.error.code, 'ENVIRONMENT_BACKUP_SESSION_ACTIVE');
  f.running = false; f.browserRunning = true;
  assert.equal((await f.post('/api/environment/check', { ...rebuild, confirm: true })).data.error.code, 'ENVIRONMENT_BACKUP_SESSION_ACTIVE');
  assert.equal(calls.length, 0);
  f.browserRunning = false;
  const refreshed = await f.post('/api/environment/check', { ...rebuild, confirm: true });
  assert.equal(refreshed.status, 200);
  assert.equal(refreshed.data.data.ownership, 'matched');
  assert.equal(refreshed.data.data.backupRebuilt, true);
  assert.deepEqual(calls, [{ refreshBackup: true, rebuildBackup: true }]);
});

test('adopting the current environment requires explicit confirmation and idle owned sessions', async t => {
  const environment = createEnvironmentManager({ mock: true });
  let adopts = 0;
  const adopt = environment.adoptCurrent;
  environment.adoptCurrent = () => { adopts++; return adopt(); };
  const f = await fixture(t, { environment });
  assert.equal((await f.post('/api/environment/adopt')).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/environment/adopt', { confirm: true, target: { timeZoneId: 'Tokyo Standard Time' } })).data.error.code, 'INPUT_INVALID');
  f.running = true;
  assert.equal((await f.post('/api/environment/adopt', { confirm: true })).data.error.code, 'ENVIRONMENT_BACKUP_SESSION_ACTIVE');
  f.running = false; f.browserRunning = true;
  assert.equal((await f.post('/api/environment/adopt', { confirm: true })).data.error.code, 'ENVIRONMENT_BACKUP_SESSION_ACTIVE');
  assert.equal(adopts, 0);
  f.browserRunning = false;
  const response = await f.post('/api/environment/adopt', { confirm: true });
  assert.equal(response.status, 200);
  assert.equal(response.data.data.adoptedCurrent, true);
  assert.equal(response.data.data.status, 'ready');
  assert.equal(response.data.data.backup.canRestore, true);
  assert.equal(response.data.data.backup.restoreNeeded, false);
  assert.equal((await f.get('/api/onboarding')).data.data.environment.backup.id, response.data.data.backup.id);
  assert.equal(adopts, 1);
  assert.equal(f.probeCalls + f.requestCalls, 0);
});

test('confirmed connection optimization and manual actions force drifted settings without replacing the initial backup', async t => {
  const directory = await mkdtemp(path.resolve(import.meta.dirname, '.environment-controller-adopt-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const adapter = createMockEnvironmentAdapter();
  const environment = createEnvironmentManager({ stateDir: directory, adapter });
  const first = await environment.check();
  const original = await adapter.snapshot();
  await environment.optimize({ geo: { verified: true, ip: '203.0.113.8', countryCode: 'JP', timezone: 'Asia/Tokyo' }, localize: false });
  await adapter.apply({ timeZoneId: 'Taipei Standard Time', culture: 'en-US' });
  const current = await adapter.snapshot();
  const f = await fixture(t, { mock: true, environment });
  const checked = (await f.post('/api/environment/check')).data.data;
  assert.equal(checked.status, 'conflict');
  assert.equal(checked.canAdoptCurrent, true);
  const started = await f.post('/api/proxy/start', { confirm: true, optimize: true });
  assert.equal(started.status, 200);
  assert.equal(started.data.data.proxy.running, true);
  assert.equal(started.data.data.environment.optimization.status, 'applied');
  assert.equal(started.data.data.environment.backup.id, first.backup.id);
  await adapter.apply({ culture: 'fr-FR' });
  assert.equal((await f.post('/api/environment/optimize')).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await adapter.snapshot()).culture, 'fr-FR');
  assert.equal((await f.post('/api/environment/optimize', { confirm: true })).data.data.optimization.status, 'applied');
  await adapter.apply({ culture: 'de-DE' });
  assert.equal((await f.post('/api/environment/restore-original')).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await adapter.snapshot()).culture, 'de-DE');
  assert.deepEqual((await f.post('/api/environment/restore-original', { confirm: true })).data.data.current, original);
  assert.equal(f.running, true, 'environment restore leaves the verified connection running');
  assert.equal((await environment.check()).backup.id, first.backup.id);
  await f.stop();
  await adapter.apply(current);
  const adopted = (await f.post('/api/environment/adopt', { confirm: true })).data.data;
  assert.equal(adopted.status, 'ready');
  assert.equal(adopted.optimization.status, 'not-requested');
  assert.deepEqual(adopted.current, current);
  assert.ok(adopted.archivedStatePath);
  assert.deepEqual(await adapter.snapshot(), current);
  assert.equal((await f.post('/api/environment/restore-original', { confirm: true })).data.data.noChange, true);
});

test('connection without selected environment optimization never forces drifted settings', async t => {
  const directory = await mkdtemp(path.resolve(import.meta.dirname, '.environment-controller-no-force-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const adapter = createMockEnvironmentAdapter();
  const environment = createEnvironmentManager({ stateDir: directory, adapter });
  await environment.check(); await adapter.apply({ culture: 'fr-FR' });
  let writes = 0; const apply = adapter.apply; adapter.apply = async target => { writes++; return apply(target); };
  const f = await fixture(t, { mock: true, environment });
  const started = await f.post('/api/proxy/start', { confirm: true, optimize: false });
  assert.equal(started.status, 200); assert.equal(f.running, true);
  assert.equal(writes, 0); assert.equal((await adapter.snapshot()).culture, 'fr-FR');
});

test('file-backed invalid environment record rebuilds through HTTP and survives a controller restart', async t => {
  const directory = await mkdtemp(path.resolve(import.meta.dirname, '.environment-controller-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const original = Buffer.from('{"version":2,broken\r\n');
  await writeFile(path.join(directory, 'state.json'), original);
  const adapter = createMockEnvironmentAdapter();
  let applyCalls = 0;
  adapter.apply = async () => { applyCalls++; throw new Error('snapshot must never apply Windows settings'); };
  const environment = createEnvironmentManager({ stateDir: directory, adapter });
  const f = await fixture(t, { mock: true, environment });
  const failed = (await f.get('/api/status')).data.data.environment;
  assert.equal(failed.ownership, 'invalid');
  assert.equal(failed.canRefresh, true);
  assert.equal((await f.post('/api/environment/check')).data.error.code, 'ENVIRONMENT_STATE_INVALID');
  const refreshed = await f.post('/api/environment/check', { refreshBackup: true, rebuildBackup: true, confirm: true });
  assert.equal(refreshed.status, 200);
  const baseline = refreshed.data.data;
  assert.equal(baseline.ownership, 'matched');
  assert.equal(baseline.status, 'ready');
  assert.deepEqual(await readFile(baseline.archivedStatePath), original);
  const restarted = await fixture(t, { mock: true, environment: createEnvironmentManager({ stateDir: directory, adapter }) });
  const saved = (await restarted.get('/api/onboarding')).data.data.environment;
  assert.equal(saved.ownership, 'matched');
  assert.equal(saved.backup.id, baseline.backup.id);
  assert.equal(applyCalls, 0);
});

test('live snapshot validation failures are distinct from stored-record errors and never create a baseline', async t => {
  const directory = await mkdtemp(path.resolve(import.meta.dirname, '.environment-controller-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const adapter = createMockEnvironmentAdapter();
  const snapshot = await adapter.snapshot();
  snapshot.languages[0].languageTag = 'zh-Hans-CN en-US';
  adapter.snapshot = async () => structuredClone(snapshot);
  adapter.apply = async () => { throw new Error('snapshot must never apply Windows settings'); };
  const f = await fixture(t, { mock: true, environment: createEnvironmentManager({ stateDir: directory, adapter }) });
  for (const body of [{}, { refreshBackup: true, rebuildBackup: true, confirm: true }]) {
    const result = await f.post('/api/environment/check', body);
    assert.equal(result.data.error.code, 'ENVIRONMENT_SNAPSHOT_INVALID');
    assert.match(result.data.error.message, /本机.*语言/);
    assert.doesNotMatch(result.data.error.message, /恢复记录无效|旧记录/);
    assert.deepEqual(await readdir(directory), []);
  }
});

test('environment backup, mock location optimization and exact restore are exposed separately from cleanup', async t => {
  const f = await fixture(t, { mock: true });
  assert.equal((await f.get('/api/status')).data.data.environment.backup, null);
  const before = (await f.post('/api/environment/check')).data.data;
  assert.ok(before.backup.id);
  assert.equal((await f.post('/api/environment/optimize')).data.error.code, 'CONFIRMATION_REQUIRED');
  await f.start();
  const optimized = (await f.post('/api/environment/optimize', { confirm: true })).data.data;
  assert.equal(optimized.current.timeZoneId, 'Tokyo Standard Time');
  assert.equal(optimized.current.culture, 'zh-SG');
  assert.equal((await f.post('/api/environment/restore-original')).data.error.code, 'CONFIRMATION_REQUIRED');
  const restored = (await f.post('/api/environment/restore-original', { confirm: true })).data.data;
  assert.deepEqual(restored.current, before.current);
  assert.equal(f.probeCalls + f.requestCalls, 0);
});

test('Claude Code cleanup requires a preview and a separate explicit confirmation', async t => {
  const f = await fixture(t, { mock: true });
  const plan = (await f.post('/api/claude/cleanup-plan')).data.data.plan;
  assert.ok(plan.token);
  assert.equal((await f.post('/api/claude/cleanup', { token: plan.token })).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/claude/cleanup', { token: plan.token, confirm: true })).status, 200);
  assert.notEqual((await f.post('/api/claude/cleanup', { token: plan.token, confirm: true })).status, 200);
});

test('network lock survives proxy stop; unlocking requires confirmation and all sessions closed', async t => {
  const f = await fixture(t, { lockSimulation: true, state: { networkLocked: true } });
  await f.start();
  assert.equal((await f.post('/api/network-lock/unlock', { confirm: true })).data.error.code, 'NETWORK_LOCK_ACTIVE');
  assert.equal((await f.post('/api/network-lock/unlock')).data.error.code, 'CONFIRMATION_REQUIRED');
  const ended = (await f.stop()).data.data;
  assert.equal(ended.networkLock.locked, true);
  assert.equal(f.events.includes('network-unlock'), false);
  const unlock = f.runtime.networkLock.unlock;
  f.runtime.networkLock.unlock = async input => { f.server.state.operation = { stage: 'unlocking-network' }; return unlock(input); };
  const unlocked = (await f.post('/api/network-lock/unlock', { confirm: true })).data.data;
  assert.equal(unlocked.networkLock.status, 'unlocked');
  assert.equal(f.server.state.operation, null, 'completed unlock must not block future desktop network repair');
  assert.equal(f.events.filter(event => event === 'network-unlock').length, 1);
});

test('TUN connects unlocked and manual arm requires confirmation and a verified TUN session', async t => {
  const f = await fixture(t, { lockSimulation: true, state: { mode: 'tun' } });
  assert.equal((await f.post('/api/network-lock/arm', { confirm: true })).data.error.code, 'PROXY_STOPPED');
  const connected = (await f.start()).data.data;
  assert.equal(connected.networkLock.locked, false);
  assert.equal(f.events.includes('network-arm'), false);
  assert.equal((await f.post('/api/network-lock/arm')).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/network-lock/arm', { confirm: true, endpoint: '192.0.2.99' })).data.error.code, 'INPUT_INVALID');
  const before = f.probeCalls;
  const armed = (await f.post('/api/network-lock/arm', { confirm: true })).data.data;
  assert.equal(armed.networkLock.locked, true);
  assert.equal(armed.proxy.exitStatus, 'verified');
  assert.equal(f.probeCalls, before + 1, 'pre-arm lease is reused; after policy mutation a fresh check is mandatory');
  assert.equal((await f.stop()).data.data.networkLock.locked, true);
  const g = await fixture(t, { lockSimulation: true });
  await g.start();
  assert.equal((await g.post('/api/network-lock/arm', { confirm: true })).data.error.code, 'NETWORK_LOCK_TUN_REQUIRED');
  assert.equal(g.events.includes('network-arm'), false);
});

test('TUN only reports system-network verification when default DNS and routing match the explicit proxy exit', async t => {
  const f = await fixture(t, { state: { mode: 'tun' } });
  const connected = (await f.start()).data.data;
  assert.equal(connected.proxy.systemNetwork.status, 'verified');
  assert.equal(connected.protection.systemWide, 'default-network-verified');
  assert.equal(f.systemProbeCalls, 1);
  assert.equal((await f.get('/api/diagnostics')).data.data.checks.find(check => check.name === '系统 TUN').status, 'verified');
  f.clock += 90_001;
  assert.equal((await f.get('/api/diagnostics')).data.data.checks.find(check => check.name === '系统 TUN').status, 'unverified', 'cached diagnostics cannot retain an expired verified claim');
  assert.equal(f.systemProbeCalls, 1, 'reading diagnostics does not launch a request');
  assert.equal((await f.stop()).data.data.proxy.systemNetwork.status, 'offline');
  const g = await fixture(t);
  assert.equal((await g.start()).data.data.proxy.systemNetwork.status, 'not-applicable');
  assert.equal(g.systemProbeCalls, 0);
});

test('losing the owned ready TUN during explicit-proxy verification prevents the system request', async t => {
  for (const lostState of [{ tunReady: false }, { running: false }]) {
    const f = await fixture(t, { state: { mode: 'tun' } });
    f.probe = async () => { Object.assign(f, lostState); return { ok: true, status: 'verified', exitIp: '203.0.113.8' }; };
    const response = await f.start();
    assert.equal(response.data.error.code, lostState.running === false ? 'PROXY_OFFLINE' : 'TUN_NOT_READY');
    assert.equal(f.systemProbeCalls, 0);
    assert.equal(f.running, false);
  }
});

test('matching local proxy exit cannot hide a broken system TUN DNS or a different system exit', async t => {
  for (const failureMode of ['SYSTEM_DNS_FAILED', 'SYSTEM_EXIT_MISMATCH']) {
    const diagnostics = [];
    const f = await fixture(t, { state: { mode: 'tun' }, onDiagnostic: event => diagnostics.push(event),
      systemProbe: async () => {
        if (failureMode === 'SYSTEM_DNS_FAILED') throw failure(failureMode);
        return { ok: true, status: 'verified', exitIp: '203.0.113.9' };
      } });
    const connected = await f.start();
    assert.equal(connected.data.error.code, failureMode);
    assert.equal(f.probeCalls, 1, 'the local explicit proxy exit passed first');
    assert.equal(f.running, false, 'a broken default system path cannot remain a connected TUN');
    assert.equal((await f.get('/api/status')).data.data.proxy.systemNetwork.status, 'offline');
    assert.ok(diagnostics.some(event => event.code === failureMode && event.operation === 'verifying-exit'));
    assert.doesNotMatch(JSON.stringify(diagnostics), /private credential/);
  }
});

test('a temporary manual system recheck failure preserves the existing TUN, original proof deadline and safe diagnostics', async t => {
  for (const code of ['SYSTEM_DNS_FAILED', 'SYSTEM_HTTP_STATUS']) {
    const diagnostics = [];
    const f = await fixture(t, { lockSimulation: true, state: { mode: 'tun', networkLocked: true }, onDiagnostic: event => diagnostics.push(event) });
    assert.equal((await f.start()).status, 200);
    const before = (await f.get('/api/snapshot')).data.data;
    f.systemProbe = async () => { throw Object.assign(failure(code), { diagnostic: { httpStatus: 404, message: 'private credential' } }); };
    const checked = await f.post('/api/probes');
    assert.equal(checked.data.error.code, code);
    assert.equal(f.running, true, 'A failed observation must not dismantle the still-owned TUN route');
    assert.equal(f.browserRunning, false);
    const status = (await f.get('/api/status')).data.data;
    assert.equal(status.connectionResult.status, 'connected');
    assert.equal(status.proxy.systemNetwork.status, 'verified');
    assert.deepEqual(status.proxy.exit, before.proxy.exit);
    assert.equal(status.proxy.systemNetwork.observedAt, before.proxy.systemNetwork.observedAt);
    assert.equal(status.health.state, 'degraded');
    assert.equal(status.networkLock.locked, true);
    assert.equal(diagnostics.findLast(event => event.code === code).diagnostic.httpStatus, 404);
    assert.doesNotMatch(JSON.stringify(diagnostics), /private credential/);
    f.clock += 90_001;
    const expired = (await f.get('/api/snapshot')).data.data;
    assert.equal(expired.proxy.exitStatus, 'unverified'); assert.equal(expired.proxy.systemNetwork.status, 'unverified');
    await assert.rejects(f.server.applicationProxy(), { code });
    assert.equal(f.running, true); assert.equal(f.events.includes('proxy-stop'), false);
  }
});

test('temporary status inspection failures preserve the owned TUN and original proof without hiding their safe error code', async t => {
  for (const code of ['PROCESS_QUERY_FAILED', 'TUN_STATE_UNAVAILABLE']) {
    const diagnostics = [];
    const f = await fixture(t, { state: { mode: 'tun' }, onDiagnostic: event => diagnostics.push(event) });
    assert.equal((await f.start()).status, 200);
    const original = (await f.get('/api/snapshot')).data.data;
    f.runtime.status = async () => { throw Object.assign(failure(code), { diagnostic: { command: 'powershell.exe', category: 'OperationTimeout', path: 'PRIVATE_NATIVE_PATH' } }); };
    const read = await f.get('/api/status');
    assert.equal(read.status, 200);
    assert.equal(read.data.data.proxy.running, true); assert.equal(read.data.data.proxy.exitStatus, 'verified');
    assert.deepEqual(read.data.data.proxy.exit, original.proxy.exit);
    assert.equal(read.data.data.proxy.systemNetwork.observedAt, original.proxy.systemNetwork.observedAt);
    assert.equal(read.data.data.health.state, 'degraded'); assert.equal(read.data.data.lastError.code, code);
    assert.equal(f.running, true); assert.equal(f.events.includes('proxy-stop'), false);
    assert.ok(diagnostics.some(event => event.code === code && event.operation === 'checking-local-status'));
    assert.doesNotMatch(JSON.stringify(diagnostics), /PRIVATE_NATIVE_PATH|private credential/);
    await assert.rejects(f.server.applicationProxy(), { code });
    f.clock += 90_001;
    const expired = (await f.get('/api/snapshot')).data.data;
    assert.equal(expired.proxy.exitStatus, 'unverified'); assert.equal(expired.proxy.systemNetwork.status, 'unverified');
    assert.equal(f.running, true); assert.equal(f.events.includes('proxy-stop'), false);
  }
});

test('failed manual lock blocks the session and retains safe command diagnostics', async t => {
  const diagnostics = [];
  const f = await fixture(t, { lockSimulation: true, state: { mode: 'tun' }, onDiagnostic: event => diagnostics.push(event) });
  await f.start();
  f.armError = Object.assign(failure('NETWORK_LOCK_WINDOWS_FAILED'), { diagnostic: { operation: 'add', command: 'New-NetFirewallRule', rule: 'loopback', nativeCode: 87, message: 'PRIVATE_SECRET', path: 'C:\\PRIVATE_SECRET' } });
  const failed = await f.post('/api/network-lock/arm', { confirm: true });
  assert.equal(failed.data.error.code, 'NETWORK_LOCK_WINDOWS_FAILED');
  assert.equal(f.running, false);
  assert.deepEqual(diagnostics.at(-1).diagnostic, { operation: 'add', command: 'New-NetFirewallRule', rule: 'loopback', nativeCode: 87 });
  assert.doesNotMatch(JSON.stringify(diagnostics), /PRIVATE_SECRET/);
});

test('paused lock is rejected before probing or changing the running TUN', async t => {
  const f = await fixture(t, { lockSimulation: true, state: { mode: 'tun' } });
  await f.start();
  f.runtime.networkLock.canArm = false;
  f.runtime.armNetworkLock = () => assert.fail('disabled lock must never mutate runtime');
  const probesBefore = f.probeCalls, systemBefore = f.systemProbeCalls;
  const failed = await f.post('/api/network-lock/arm', { confirm: true });
  assert.equal(failed.data.error.code, 'NETWORK_LOCK_DISABLED');
  assert.equal(f.probeCalls, probesBefore); assert.equal(f.systemProbeCalls, systemBefore);
  assert.equal(f.running, true);
  assert.equal(f.events.includes('proxy-stop'), false);
  assert.equal((await f.get('/api/status')).data.data.protection.killSwitch, false);
});

test('desktop network repair keeps the controller open and prevents operations until journal reload', async t => {
  const f = await fixture(t, { lockSimulation: true });
  f.running = true; f.browserRunning = true; f.networkLocked = true;
  await f.server.beginNetworkRepair();
  assert.equal(f.server.listening, true);
  assert.equal(f.running || f.browserRunning, false);
  assert.equal(f.networkLocked, true);
  assert.equal((await f.get('/api/status')).status, 200);
  assert.equal((await f.post('/api/proxy/start', { confirm: true })).data.error.code, 'SERVICE_REPAIRING');
  await assert.rejects(f.server.shutdown(), { code: 'SERVICE_REPAIRING' });
  f.networkLocked = false;
  await f.server.finishNetworkRepair();
  assert.equal(f.events.includes('network-reload'), true);
  assert.equal((await f.start()).status, 200);
});

test('automatic region optimization preserves full report and localizes subsequent browser plans', async t => {
  const f = await fixture(t, { mock: true, autoReport: true });
  const started = (await f.post('/api/proxy/start', { confirm: true, optimize: true, externalReport: true })).data.data;
  assert.equal(started.environment.current.culture, 'zh-SG');
  assert.equal(started.environment.optimization.status, 'applied');
  assert.equal(started.connectionResult.status, 'connected');
  assert.equal(started.report.results.length, 7);
  assert.equal((await f.plan()).data.data.language, 'ja-JP');
  await f.post('/api/environment/check');
  assert.equal((await f.plan()).data.data.language, 'ja-JP');
  f.clock += 100_000;
  assert.equal((await f.get('/api/status')).data.data.report.stale, true);
});

test('connected proxy exposes failed environment optimization without losing the failure on recheck', async t => {
  const environment = createEnvironmentManager({ mock: true });
  environment.optimize = async () => { throw failure('ENVIRONMENT_WINDOWS_FAILED'); };
  const f = await fixture(t, { mock: true, autoReport: true, environment });
  await f.post('/api/environment/check');
  const response = await f.post('/api/proxy/start', { confirm: true, optimize: true });
  assert.equal(response.status, 200);
  const started = response.data.data;
  assert.equal(started.proxy.enabled, true);
  assert.equal(started.connectionResult.status, 'connected-with-warnings');
  assert.equal(started.connectionResult.environmentStatus, 'failed');
  assert.match(started.connectionResult.message, /环境优化未完成/);
  assert.equal(started.environment.status, 'ready');
  assert.equal(started.environment.optimization.code, 'ENVIRONMENT_WINDOWS_FAILED');
  assert.equal(JSON.stringify(started).includes('private credential'), false);
  assert.equal((await f.post('/api/environment/check')).data.data.optimization.status, 'failed');
  const checked = (await f.get('/api/status')).data.data;
  assert.equal(checked.connectionResult.status, 'connected-with-warnings');
  assert.equal(checked.environment.optimization.code, 'ENVIRONMENT_WINDOWS_FAILED');
  assert.equal((await f.stop()).data.data.connectionResult.status, 'disconnected');
});

test('unverified exit geography is an explicit failed environment outcome while the proxy remains connected', async t => {
  const f = await fixture(t);
  const started = (await f.post('/api/proxy/start', { confirm: true, optimize: true })).data.data;
  assert.equal(started.proxy.enabled, true);
  assert.equal(started.environment.optimization.code, 'GEO_UNVERIFIED');
  assert.equal(started.environment.optimization.stage, 'exit-location');
  assert.equal(started.connectionResult.status, 'connected-with-warnings');
  assert.equal((await f.post('/api/environment/check')).data.data.optimization.code, 'GEO_UNVERIFIED');
  assert.equal((await f.get('/api/status')).data.data.connectionResult.status, 'connected-with-warnings');
});

test('nonmock imported global startup localizes from one verified geo request with external reports disabled', async t => {
  const requested = [];
  const f = await fixture(t, { state: { mode: 'tun' }, request: async (url, options) => {
    requested.push(url.hostname); assert.equal(url.href, 'https://ipwho.is/'); assert.equal(options.proxyPort, 17890);
    return JSON.stringify({ success: true, ip: '203.0.113.8', country_code: 'US', city: 'Phoenix', timezone: { id: 'America/Phoenix' } });
  } });
  f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) }); await f.get('/api/status');
  const result = await f.post('/api/proxy/start', { confirm: true, mode: 'tun', optimize: true, externalReport: false });
  assert.equal(result.status, 200, JSON.stringify(result.data)); const started = result.data.data;
  assert.equal(started.proxy.systemNetwork.status, 'verified'); assert.equal(started.environment.optimization.status, 'applied');
  assert.equal(started.environment.current.timeZoneId, 'US Mountain Standard Time'); assert.equal(started.environment.current.culture, 'zh-SG');
  assert.equal(started.connectionResult.status, 'connected'); assert.equal(started.report, null);
  assert.deepEqual(requested, ['ipwho.is']); assert.equal(f.probeCalls, 1); assert.equal(f.systemProbeCalls, 1);
});

test('disabled optimization and external reports make no geo or website request', async t => {
  const f = await fixture(t, { request: () => assert.fail('neither environment nor external reports were selected') });
  const started = await f.post('/api/proxy/start', { confirm: true, optimize: false, externalReport: false });
  assert.equal(started.status, 200); assert.equal(f.requestCalls, 0); assert.equal(f.probeCalls, 1);
  assert.equal(started.data.data.report, null); assert.equal(started.data.data.connectionResult.status, 'connected');
});

test('manual environment optimization reuses fresh valid report geography but expired reports do not authorize settings', async t => {
  const requested = [];
  const f = await fixture(t, { request: async url => {
    requested.push(url.hostname);
    if (url.hostname === 'api.ipify.org') return '{"ip":"203.0.113.8"}';
    if (url.hostname === 'www.cloudflare.com') return 'ip=203.0.113.8\n';
    assert.equal(url.hostname, 'ipwho.is'); return JSON.stringify({ success: true, ip: '203.0.113.8', country_code: 'JP', timezone: { id: 'Asia/Tokyo' } });
  } });
  await f.start(); assert.equal((await f.post('/api/probes', { multi: true, thirdParty: false })).status, 200);
  assert.equal((await f.post('/api/environment/optimize', { confirm: true })).status, 200); assert.equal(requested.length, 3);
  assert.equal(f.probeCalls, 2, 'manual environment action reuses the fresh exit lease');
  f.clock += 100_000;
  assert.equal((await f.post('/api/environment/optimize', { confirm: true })).status, 200); assert.equal(requested.length, 4); assert.equal(requested.at(-1), 'ipwho.is');
  assert.equal(f.probeCalls, 3); assert.equal(requested.some(host => ['cleanip.io', 'ippure.com', 'ping0.cc'].includes(host)), false);
});

test('invalid or failed location leaves the verified proxy connected and reports no private response in diagnostics', async t => {
  const valid = { success: true, ip: '203.0.113.8', country_code: 'JP', city: 'PRIVATE_CITY', timezone: { id: 'Asia/Tokyo' } };
  for (const input of ['PRIVATE_RESPONSE', '{}', { ...valid, ip: '203.0.113.9' }, { ...valid, country_code: null }, { ...valid, timezone: { id: 'Planet/Unknown' } }, null]) {
    const events = []; let applications = 0;
    const environment = createEnvironmentManager({ mock: true }); environment.optimize = () => { applications++; assert.fail('invalid geography must not change settings'); };
    const f = await fixture(t, { environment, onDiagnostic: event => events.push(event), request: async url => {
      assert.equal(url.hostname, 'ipwho.is'); if (input === null) throw new Error('PRIVATE_REQUEST_FAILURE'); return typeof input === 'string' ? input : JSON.stringify(input);
    } });
    const started = (await f.post('/api/proxy/start', { confirm: true, optimize: true, externalReport: false })).data.data;
    assert.equal(started.proxy.enabled, true); assert.equal(started.proxy.exitStatus, 'verified'); assert.equal(started.environment.optimization.code, 'GEO_UNVERIFIED');
    assert.equal(started.environment.optimization.stage, 'exit-location'); assert.equal(started.report, null); assert.equal(f.running, true); assert.equal(applications, 0); assert.equal(f.requestCalls, 1);
    assert.doesNotMatch(JSON.stringify(events), /PRIVATE_|203\.0\.113\.|ipwho\.is/);
  }
});

test('a config or core-session change during geography cannot apply the late location result', async t => {
  for (const changed of ['config', 'session', 'offline']) {
    let applies = 0; const environment = createEnvironmentManager({ mock: true }); environment.optimize = () => { applies++; assert.fail('a changed session cannot apply geography'); };
    let f;
    f = await fixture(t, { state: { sessionId: 'original-owned-core' }, environment, request: async () => {
      if (changed === 'config') f.config.upstream.port++;
      if (changed === 'session') f.sessionId = 'replacement-owned-core';
      if (changed === 'offline') { f.running = false; throw new Error('PRIVATE_FAILED_REQUEST'); }
      return JSON.stringify({ success: true, ip: '203.0.113.8', country_code: 'JP', timezone: { id: 'Asia/Tokyo' } });
    } });
    const result = await f.post('/api/proxy/start', { confirm: true, optimize: true });
    assert.equal(result.status, 409); assert.ok(['PROXY_CONFIG_CHANGED', 'SESSION_CHANGED', 'PROXY_OFFLINE'].includes(result.data.error.code), JSON.stringify(result.data));
    assert.equal(applies, 0); assert.equal(f.running, false); assert.doesNotMatch(JSON.stringify(result.data), /PRIVATE_/);
  }
});

test('an explicit stop cancels pending geography without applying settings or accepting the late response', async t => {
  const entered = deferred(), release = deferred(); let applies = 0;
  const environment = createEnvironmentManager({ mock: true }); environment.optimize = () => { applies++; assert.fail('stop cancels environment settings'); };
  const f = await fixture(t, { environment, request: async () => { entered.resolve(); await release.promise;
    return JSON.stringify({ success: true, ip: '203.0.113.8', country_code: 'JP', timezone: { id: 'Asia/Tokyo' } }); } });
  const starting = f.post('/api/proxy/start', { confirm: true, optimize: true }); await entered.promise;
  const stopping = f.stop();
  for (let i = 0; i < 20 && !f.server.state.proxy.requestedStop; i++) await delay(2);
  assert.equal(f.server.state.proxy.requestedStop, true); release.resolve();
  assert.equal((await starting).status, 409); assert.equal((await stopping).status, 200); assert.equal(applies, 0); assert.equal(f.running, false);
});

test('environment diagnostics retain fixed difference names and never log private values', async t => {
  const environment = createEnvironmentManager({ mock: true });
  const events = [];
  environment.restore = async () => {
    throw Object.assign(failure('ENVIRONMENT_VERIFY_FAILED'), { diagnostic: {
      environmentFields: ['defaultInputMethod', 'private password value', 'culture', 'culture'],
      rollbackEnvironmentFields: ['timeZoneId', 'provider-secret'], actualCulture: 'private-user-data',
    } });
  };
  const f = await fixture(t, { environment, onDiagnostic: event => events.push(event) });
  const response = await f.post('/api/environment/restore-original', { confirm: true });
  assert.equal(response.data.error.code, 'ENVIRONMENT_VERIFY_FAILED');
  assert.deepEqual(response.data.error.details, { environmentFields: ['culture', 'defaultInputMethod'], rollbackEnvironmentFields: ['timeZoneId'] });
  assert.doesNotMatch(JSON.stringify(response.data), /private|provider-secret/);
  const event = events.find(item => item.code === 'ENVIRONMENT_VERIFY_FAILED');
  assert.deepEqual(event.diagnostic.environmentFields, ['culture', 'defaultInputMethod']);
  assert.deepEqual(event.diagnostic.rollbackEnvironmentFields, ['timeZoneId']);
  assert.doesNotMatch(JSON.stringify(events), /private|provider-secret/);
});

test('manual optimization failure is redacted and remains available from status', async t => {
  const environment = createEnvironmentManager({ mock: true });
  environment.optimize = async () => { throw failure('ENVIRONMENT_BACKUP_DRIFT'); };
  const f = await fixture(t, { mock: true, environment });
  await f.start();
  const response = await f.post('/api/environment/optimize', { confirm: true });
  assert.equal(response.data.ok, false);
  assert.equal(response.data.error.code, 'ENVIRONMENT_BACKUP_DRIFT');
  assert.equal(JSON.stringify(response.data).includes('private credential'), false);
  const current = (await f.get('/api/status')).data.data;
  assert.equal(current.connectionResult.status, 'connected-with-warnings');
  assert.equal(current.environment.optimization.code, 'ENVIRONMENT_BACKUP_DRIFT');
});

test('cached progress remains readable while a network operation holds the controller queue', async t => {
  const f = await fixture(t);
  const pending = deferred();
  f.probe = async () => { await pending.promise; return { ok: true, status: 'verified', exitIp: '203.0.113.8' }; };
  const started = f.start();
  for (let attempt = 0; attempt < 30 && !f.probeCalls; attempt++) await delay(5);
  try {
    const progress = await f.get('/api/progress');
    assert.equal(progress.data.data.operation.stage, 'verifying-exit');
  } finally { pending.resolve(); await started; }
  assert.equal((await f.get('/api/progress')).data.data.operation, null);
});

test('busy status and snapshot reads return immediately without adding native inspections behind a pending probe', async t => {
  const f = await fixture(t); const pending = deferred(); let statusReads = 0;
  const status = f.runtime.status; f.runtime.status = async (...args) => { statusReads++; return status(...args); };
  f.probe = async () => { await pending.promise; return { ok: true, status: 'verified', exitIp: '203.0.113.8' }; };
  const started = f.start();
  for (let attempt = 0; attempt < 40 && !f.probeCalls; attempt++) await delay(5);
  const before = statusReads;
  try {
    const reads = await Promise.race([Promise.all(Array.from({ length: 8 }, (_, index) => f.get(index % 2 ? '/api/status' : '/api/snapshot'))),
      delay(500).then(() => assert.fail('display polls must not wait for the operation queue'))]);
    assert.equal(statusReads, before); assert.ok(reads.every(read => read.data.data.statusRead.state === 'busy'));
    assert.ok(reads.every(read => read.data.data.proxy.exitStatus === 'unverified'));
  } finally { pending.resolve(); await started; }
});

test('parallel display polls share one native status refresh while later idle reads remain fresh', async t => {
  const f = await fixture(t); const entered = deferred(), release = deferred(); let reads = 0;
  const status = f.runtime.status;
  f.runtime.status = async () => { reads++; entered.resolve(); await release.promise; return status(); };
  const first = f.get('/api/status'); await entered.promise;
  try {
    const displayed = await Promise.race([Promise.all(Array.from({ length: 8 }, () => f.get('/api/status'))), delay(500).then(() => assert.fail('duplicate polls must not await native status'))]);
    assert.equal(reads, 1); assert.ok(displayed.every(read => read.data.data.statusRead.state === 'checking'));
  } finally { release.resolve(); }
  assert.equal((await first).data.data.statusRead.state, 'fresh');
  await f.get('/api/status'); assert.equal(reads, 2, 'a completed native refresh is never an authorization cache');
});

test('a cancelled queued read is skipped while an authorized mutation still completes after its client closes', { timeout: 3000 }, async t => {
  const entered = deferred(), release = deferred(); let scans = 0;
  t.after(() => release.resolve());
  const f = await fixture(t);
  f.browsers.listBrowsers = async () => { scans++; return []; };
  f.probe = async () => { entered.resolve(); await release.promise; return { ok: true, status: 'verified', exitIp: '203.0.113.8' }; };
  const abort = new AbortController(); const starting = f.get('/api/proxy/start', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ confirm: true }), signal: abort.signal }).catch(() => null);
  await entered.promise;
  const request = http.request(f.url + '/api/diagnostics', { headers: f.server.controlHeaders() }); request.on('error', () => {}); request.end();
  await delay(20); const closed = new Promise(resolve => request.once('close', resolve)); request.destroy(); await closed; abort.abort(); await starting;
  await delay(10); release.resolve();
  for (let attempt = 0; attempt < 50 && f.server.state.operation; attempt++) await delay(5);
  const result = (await f.get('/api/status')).data.data;
  assert.equal(scans, 0); assert.equal(result.proxy.exitStatus, 'verified'); assert.equal(f.running, true);
});

test('cached readiness never authorizes a launch and firewall-read failures retain their original safe diagnostic', async t => {
  const diagnostics = []; const f = await fixture(t, { onDiagnostic: event => diagnostics.push(event), lockSimulation: true,
    state: { mode: 'tun', protections: { systemRouting: true, killSwitch: true }, networkLocked: true } });
  await f.start(); assert.equal((await f.get('/api/snapshot')).data.data.proxy.systemNetwork.status, 'verified');
  const cause = failure('NETWORK_LOCK_TIMEOUT'); cause.diagnostic = { operation: 'inspect', command: 'powershell.exe', category: 'OperationTimeout', secret: 'PRIVATE_KEY' };
  f.runtime.status = async () => { throw cause; };
  await assert.rejects(f.server.applicationProxy(), { code: 'NETWORK_LOCK_TIMEOUT' });
  const result = (await f.get('/api/status')).data.data;
  assert.equal(result.proxy.enabled, false); assert.equal(result.lastError.code, 'NETWORK_LOCK_TIMEOUT'); assert.equal(f.networkLocked, true);
  assert.equal(result.lastError.diagnostic.operation, 'inspect'); assert.equal(result.lastError.diagnostic.category, 'OperationTimeout');
  assert.match(result.lastError.stage, /^[a-z-]{1,80}$/);
  assert.ok(diagnostics.some(event => event.code === 'NETWORK_LOCK_TIMEOUT' && event.diagnostic?.operation === 'inspect'));
  assert.doesNotMatch(JSON.stringify(diagnostics), /PRIVATE_KEY|private credential/);
});

test('owned gateway authorization stays responsive while the display status read is waiting on its native inspection', async t => {
  const f = await fixture(t, { state: { mode: 'tun', protections: { systemRouting: true } } }); await f.start();
  const lease = await f.server.applicationProxy(); const status = f.runtime.status;
  const statusEntered = deferred(), releaseStatus = deferred(), ownedEntered = deferred(), releaseOwned = deferred();
  let statusReads = 0; let ownedReads = 0;
  f.runtime.status = async () => { statusReads++; statusEntered.resolve(); await releaseStatus.promise; return status(); };
  f.runtime.inspectOwnedState = async () => { ownedReads++; ownedEntered.resolve(); await releaseOwned.promise; return status(); };
  const echo = net.createServer(socket => socket.pipe(socket)); const sockets = new Set();
  echo.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  await new Promise(resolve => echo.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => echo.close(resolve)); });
  const displayed = f.get('/api/status'); await statusEntered.promise;
  try {
    const connecting = Promise.all(Array.from({ length: 8 }, () => connectTunnel({ host: 'localhost', port: echo.address().port, proxyPort: lease.port, timeoutMs: 1000 })));
    await ownedEntered.promise; await delay(20); assert.equal(ownedReads, 1); assert.equal(statusReads, 1);
    releaseOwned.resolve(); for (const client of await connecting) client.destroy();
    assert.equal(f.probeCalls, 1); assert.equal(f.systemProbeCalls, 1, 'gateway checks must not probe the ISP');
  } finally { releaseOwned.resolve(); releaseStatus.resolve(); await displayed; }
});

test('application leases expose only an opaque binding that changes when the owned core session changes', async t => {
  const f = await fixture(t, { state: { sessionId: 'synthetic-owned-session-one' } }); await f.start();
  const first = await f.server.applicationProxy(); assert.match(first.binding, /^[0-9a-f]{64}$/);
  assert.doesNotMatch(JSON.stringify(first), /synthetic-owned-session-one/);
  f.sessionId = 'synthetic-owned-session-two';
  const second = await f.server.applicationProxy(); assert.match(second.binding, /^[0-9a-f]{64}$/); assert.notEqual(second.binding, first.binding);
});

test('onboarding defers environment scan and saves first-run choices without exposing credentials', async t => {
  const f = await fixture(t, { mock: true });
  const initial = (await f.get('/api/onboarding')).data.data;
  assert.equal(initial.onboarding.firstRun, true);
  assert.equal(initial.configuration.available, false);
  assert.equal(initial.environment.backup, null);
  assert.equal((await f.post('/api/onboarding/preferences', { completed: true })).data.error.code, 'ONBOARDING_CONFIGURATION_REQUIRED');
  const saved = await f.post('/api/configuration/save', { host: '192.0.2.1', port: 443, type: 'http', username: 'test-account', password: 'test-secret', expectedExitIps: [] });
  assert.equal(saved.status, 200);
  assert.equal(saved.data.data.configuration.available, true);
  assert.equal(JSON.stringify(saved.data).includes('test-secret'), false);
  assert.equal(JSON.stringify(saved.data).includes('test-account'), false);
  assert.equal((await f.get('/api/onboarding')).data.data.environment.backup, null);
  const backup = (await f.post('/api/environment/check')).data.data.backup;
  assert.ok(backup.id);
  assert.equal((await f.post('/api/onboarding/preferences', { completed: true, browser: 'chrome', autoOptimize: true, fresh: true })).status, 200);
  const repeated = (await f.get('/api/onboarding')).data.data;
  assert.equal(repeated.onboarding.firstRun, false);
  assert.equal(repeated.onboarding.backupExists, true);
  assert.equal(repeated.environment.backup.id, backup.id);
  assert.equal(f.probeCalls + f.requestCalls, 0);
});

test('quality is explicitly requested after save and returns three readable local reports', async t => {
  const f = await fixture(t, { mock: true });
  assert.equal((await f.post('/api/quality/check')).data.error.code, 'ONBOARDING_CONFIGURATION_REQUIRED');
  await f.post('/api/configuration/save', { host: '192.0.2.1', port: 443, type: 'http', clearCredentials: true });
  const report = await f.post('/api/quality/check');
  assert.equal(report.status, 200);
  const data = report.data.data;
  assert.equal(data.maxScore, 100);
  assert.equal(data.mock, true);
  assert.equal(data.results.length, 3);
  assert.ok(data.score === null || data.score >= 0 && data.score <= 100);
  for (const item of data.results) {
    const page = await fetch(f.url + item.reportUrl);
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-type'), /text\/html/);
    const html = await page.text();
    assert.ok(html.includes(item.label));
    assert.ok(html.includes(item.sourceUrl));
  }
  assert.equal((await f.get('/api/quality/check')).status, 404);
  assert.equal((await f.get('/reports/quality/00000000-0000-4000-8000-000000000000/ping0')).status, 404);
  assert.equal(f.events.includes('proxy-start'), false);
  assert.equal(f.probeCalls + f.requestCalls, 0);
});

test('configuration and quality checks refuse a running session or a retained network lock', async t => {
  const f = await fixture(t, { lockSimulation: true });
  const input = { host: '192.0.2.1', port: 443, type: 'http', clearCredentials: true };
  assert.equal((await f.post('/api/configuration/save', input)).status, 200);
  await f.start();
  for (const route of ['/api/configuration/save', '/api/quality/check']) assert.equal((await f.post(route, input)).data.error.code, 'SETUP_SESSION_ACTIVE');
  await f.stop(); f.networkLocked = true;
  for (const route of ['/api/configuration/save', '/api/quality/check']) assert.equal((await f.post(route, input)).data.error.code, 'SETUP_NETWORK_LOCKED');
});

test('orphan TUN guard prevents unlocking even when the owned core has stopped', async t => {
  const f = await fixture(t, { lockSimulation: true, state: { networkLocked: true } });
  f.runtime.assertSafeToUnlock = async () => { throw failure('PROXY_STILL_RUNNING'); };
  assert.equal((await f.post('/api/network-lock/unlock', { confirm: true })).data.error.code, 'PROXY_STILL_RUNNING');
  assert.equal(f.events.includes('network-unlock'), false);
  assert.equal(f.networkLocked, true);
});

test('an explicit session stop cancels a pending ISP verification before saving credentials', async t => {
  const pending = deferred(); let entered = false, written = false;
  const onboarding = {
    status: async () => ({ firstRun: true }),
    configuration: async () => ({ available: false }),
    saveConfiguration: async (body, { verifyConfiguration }) => {
      await verifyConfiguration({ config: {}, secrets: {} });
      written = true;
      return { available: true };
    },
  };
  const setupVerifier = { verify: async () => { entered = true; await pending.promise; return { expectedExitIps: ['203.0.113.8'] }; } };
  const f = await fixture(t, { onboarding, setupVerifier });
  const save = f.post('/api/configuration/save', {});
  for (let attempt = 0; attempt < 50 && !entered; attempt++) await delay(5);
  assert.equal(entered, true);
  const stop = f.stop();
  for (let attempt = 0; attempt < 50 && f.server.state.revision === 0; attempt++) await delay(5);
  pending.resolve();
  assert.equal((await save).data.error.code, 'SESSION_CHANGED');
  assert.equal((await stop).status, 200);
  assert.equal(written, false);
});

function relayControllerFixture() {
  const record = { upstream: null, bindingRevision: 0, events: [], configured: true };
  const manager = {
    status: async () => ({ configured: record.configured, host: '192.0.2.50', port: 443, serverName: 'localhost', accountHint: 'te•••er', mock: false }),
    credentials: async () => { if (!record.configured) throw failure('RELAY_NOT_CONFIGURED'); return { relay: relayFixture(), secrets: { ...relaySecrets } }; },
    check: async () => { record.events.push('check'); return { ok: true, upstream: structuredClone(record.upstream), bindingRevision: record.bindingRevision, activeTunnels: 0, maxTunnels: 64 }; },
    bind: async (target, expected) => {
      record.events.push(`bind:${target.host}:${expected}`);
      if (record.bindingRevision !== expected) throw failure('RELAY_BINDING_CONFLICT');
      if (record.upstream?.host !== target.host || record.upstream?.port !== target.port) { record.upstream = structuredClone(target); record.bindingRevision++; }
      return { ok: true, upstream: structuredClone(record.upstream), bindingRevision: record.bindingRevision };
    },
    clear: async expected => { record.events.push(`clear:${expected}`); if (record.bindingRevision !== expected) throw failure('RELAY_BINDING_CONFLICT'); record.upstream = null; record.bindingRevision++; return { ok: true, upstream: null, bindingRevision: record.bindingRevision }; },
    importEnrollment: async () => { record.events.push('import'); record.configured = true; },
  };
  return { record, manager };
}

test('cancel during a slow relay preflight finishes cleanup without waiting for the late read or starting a core', { timeout: 4000 }, async t => {
  const relay = relayControllerFixture(), entered = deferred(), release = deferred();
  const f = await fixture(t, { relayManager: relay.manager, requireRelay: true, loadSecrets: async () => ({ ...relaySecrets }) });
  f.config.relay = relayFixture(); relay.record.upstream = structuredClone(f.config.upstream); await f.get('/api/status');
  const check = relay.manager.check;
  relay.manager.check = async () => { entered.resolve(); await release.promise; return check(); };
  const starting = f.start(); await entered.promise;
  assert.deepEqual((await f.get('/api/progress')).data.data.connectionCancellation, { active: true, requested: false });
  const stopped = await Promise.race([f.stop(), delay(750).then(() => { throw new Error('Relay read held cancellation'); })]);
  assert.equal(stopped.status, 200); assert.equal((await starting).data.error.code, 'CONNECTION_CANCELED');
  assert.equal(f.events.includes('proxy-start'), false); release.resolve(); await delay(10);
  assert.equal(f.running, false); assert.equal((await f.get('/api/progress')).data.data.connectionCancellation.active, false);
});

test('canceling local relay credential reads prevents the abandoned preflight from issuing a remote check', { timeout: 4000 }, async t => {
  for (const step of ['credentials', 'secrets']) {
    const relay = relayControllerFixture(), entered = deferred(), release = deferred(); let held = false;
    const credentials = relay.manager.credentials;
    relay.manager.credentials = async () => { if (held && step === 'credentials') { entered.resolve(); await release.promise; } return credentials(); };
    const f = await fixture(t, { relayManager: relay.manager, requireRelay: true, loadSecrets: async () => {
      if (held && step === 'secrets') { entered.resolve(); await release.promise; } return { ...relaySecrets };
    } });
    f.config.relay = relayFixture(); relay.record.upstream = structuredClone(f.config.upstream); await f.get('/api/status'); held = true;
    const starting = f.start(); await entered.promise;
    const stopped = await Promise.race([f.stop(), delay(750).then(() => { throw new Error(`${step} held cancellation`); })]);
    assert.equal(stopped.status, 200); assert.equal((await starting).data.error.code, 'CONNECTION_CANCELED');
    held = false; release.resolve(); await delay(10);
    assert.deepEqual(relay.record.events, []); assert.equal(f.events.includes('proxy-start'), false);
    assert.equal((await f.start()).status, 200); assert.equal(f.running, true); assert.deepEqual(relay.record.events, ['check']);
  }
});

test('failed relay checks immediately replace an earlier ready snapshot without leaking the native error', async t => {
  const relay = relayControllerFixture(); let checkStatus = 'ready', errorCode = null;
  const status = relay.manager.status;
  relay.manager.status = async () => ({ ...await status(), checkStatus, errorCode });
  const f = await fixture(t, { relayManager: relay.manager, requireRelay: true });
  assert.equal((await f.get('/api/status')).data.data.relay.checkStatus, 'ready');
  relay.manager.check = async () => { checkStatus = 'auth-failed'; errorCode = 'RELAY_AUTH_FAILED'; throw failure(errorCode); };
  const result = await f.post('/api/relay/check');
  assert.equal(result.data.error.code, 'RELAY_AUTH_FAILED'); assert.match(result.data.error.message, /已停用/);
  const snapshot = (await f.get('/api/snapshot')).data.data;
  assert.equal(snapshot.relay.checkStatus, 'auth-failed'); assert.equal(snapshot.relay.errorCode, errorCode);
  assert.equal(snapshot.relay.configured, true); assert.doesNotMatch(JSON.stringify(result), /private credential/);
});

test('required relay status remains local and import/check enforce idle, confirmation and input boundaries', async t => {
  const relay = relayControllerFixture();
  const f = await fixture(t, { relayManager: relay.manager, requireRelay: true, lockSimulation: true });
  assert.equal((await f.get('/api/status')).data.data.relay.required, true);
  assert.equal((await f.get('/api/onboarding')).data.data.relay.configured, true);
  assert.equal((await f.get('/api/relay')).data.data.accountHint, 'te•••er');
  assert.deepEqual(relay.record.events, []);
  assert.equal((await f.post('/api/relay/import', { enrollment: {} })).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/relay/import', { confirm: true, enrollment: {}, surprise: true })).status, 400);
  assert.equal((await f.post('/api/relay/check', { host: 'evil.test' })).status, 400);
  assert.equal((await f.post('/api/relay/check')).status, 200);
  f.networkLocked = true;
  assert.equal((await f.post('/api/relay/check')).data.error.code, 'SETUP_NETWORK_LOCKED');
  assert.equal((await f.post('/api/relay/import', { confirm: true, enrollment: {} })).data.error.code, 'SETUP_NETWORK_LOCKED');
  f.networkLocked = false; f.running = true;
  assert.equal((await f.post('/api/relay/check')).data.error.code, 'SETUP_SESSION_ACTIVE');
  assert.deepEqual(relay.record.events, ['check']);
});

test('VPN compatibility verifies candidate ISP paths and chooses a local SOCKS VPN without contacting the VPS', async t => {
  const diagnostics = [];
  const relay = relayControllerFixture(); relay.record.configured = false;
  const attempts = [];
  const vpnProxy = { type: 'socks', host: '127.0.0.1', port: 10808 };
  const f = await fixture(t, { requireRelay: true, relayManager: relay.manager,
    onDiagnostic: item => diagnostics.push(item),
    compatibilityRoutes: async () => [{ strategy: 'system' }, { strategy: 'socks-proxy', vpnProxy }],
    setupVerifier: { verify: async input => {
      assert.equal(input.config.relay, undefined); attempts.push(input.vpnProxy || 'system');
      if (!input.vpnProxy) throw failure('SETUP_CHECK_FAILED');
      return { expectedExitIps: ['203.0.113.8'], checks: [{ source: 'ipify', ip: '203.0.113.8' }] };
    } },
  });
  f.config.connectionMode = 'vpn-compat'; await f.get('/api/status');
  assert.equal((await f.post('/api/proxy/start', { confirm: true, mode: 'http' })).data.error.code, 'VPN_CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/proxy/start', { confirm: true, mode: 'tun', vpnConfirmed: true })).data.error.code, 'VPN_COMPAT_HTTP_ONLY');
  assert.deepEqual(attempts, []);
  const connected = await f.post('/api/proxy/start', { confirm: true, mode: 'http', vpnConfirmed: true });
  assert.equal(connected.status, 200);
  assert.deepEqual(attempts, ['system', vpnProxy]);
  assert.deepEqual(f.startInput.vpnProxy, vpnProxy);
  assert.equal(f.startInput.mode, 'http');
  assert.equal(connected.data.data.proxy.compatibility.strategy, 'socks-proxy');
  assert.equal(connected.data.data.proxy.systemNetwork.status, 'not-applicable');
  assert.equal(connected.data.data.relay.required, false);
  assert.equal(f.systemProbeCalls, 0);
  assert.deepEqual(relay.record.events, []);
  assert.ok(diagnostics.some(item => item.code === 'SETUP_CHECK_FAILED' && item.operation === 'detecting-system'));
  assert.ok(diagnostics.some(item => item.code === 'VPN_COMPAT_NETWORK_VERIFIED' && item.operation === 'detecting-socks-proxy'));
  assert.doesNotMatch(JSON.stringify(diagnostics), /private credential/);
  assert.equal((await f.post('/api/network-lock/arm', { confirm: true })).data.error.code, 'NETWORK_LOCK_TUN_REQUIRED');
});

test('VPN compatibility never probes under a retained lock and stops when every tested ISP path fails', async t => {
  let secretReads = 0, attempts = 0;
  const f = await fixture(t, { lockSimulation: true, state: { networkLocked: true }, loadSecrets: async () => { secretReads++; return {}; },
    setupVerifier: { verify: async () => { attempts++; throw failure('SETUP_CHECK_FAILED'); } } });
  f.config.connectionMode = 'vpn-compat'; await f.get('/api/status');
  assert.equal((await f.post('/api/proxy/start', { confirm: true, mode: 'http', vpnConfirmed: true })).data.error.code, 'SETUP_NETWORK_LOCKED');
  assert.equal(secretReads, 0); assert.equal(attempts, 0); assert.equal(f.networkLocked, true);
  f.networkLocked = false;
  const failed = await f.post('/api/proxy/start', { confirm: true, mode: 'http', vpnConfirmed: true });
  assert.equal(failed.data.error.code, 'VPN_COMPAT_NO_ROUTE');
  assert.equal(f.events.includes('proxy-start'), false);
  assert.equal(f.running, false);
  assert.equal((await f.get('/api/status')).data.data.compatibility.attempts[0].errorCode, 'SETUP_CHECK_FAILED');
  assert.doesNotMatch(JSON.stringify(failed.data), /private credential/);
});

test('mock compatibility keeps saved mode through start and never discovers native network settings', async t => {
  const f = await fixture(t, { mock: true, compatibilityRoutes: () => assert.fail('mock must stay offline') });
  const input = { host: '192.0.2.5', port: 1080, type: 'socks', clearCredentials: true, connectionMode: 'vpn-compat', vpnConfirmed: true };
  assert.equal((await f.post('/api/configuration/save', { ...input, vpnProxy: { type: 'http', host: '127.0.0.1', port: 443 } })).data.error.code, 'VPN_PROXY_INVALID');
  assert.equal((await f.post('/api/configuration/save', input)).status, 200);
  assert.equal((await f.get('/api/onboarding')).data.data.configuration.connectionMode, 'vpn-compat');
  const started = await f.post('/api/proxy/start', { confirm: true, mode: 'http', vpnConfirmed: true });
  assert.equal(started.status, 200, JSON.stringify(started.data)); assert.equal(started.data.data.proxy.connectionMode, 'vpn-compat');
  assert.equal(started.data.data.compatibility.status, 'mocked');
  assert.equal(f.startInput.config.connectionMode, 'vpn-compat');
  assert.equal(f.systemProbeCalls + f.probeCalls, 0);
});

test('a failed compatibility recheck stops the owned HTTP gateway without switching VPN routes', async t => {
  let detections = 0;
  const f = await fixture(t, { compatibilityRoutes: async () => { detections++; return [{ strategy: 'system' }]; } });
  f.config.connectionMode = 'vpn-compat'; await f.get('/api/status');
  assert.equal((await f.post('/api/proxy/start', { confirm: true, mode: 'http', vpnConfirmed: true })).status, 200);
  assert.equal(f.running, true); assert.equal(f.browserRunning, false);
  f.probe = async () => { throw failure('EXIT_IP_MISMATCH'); };
  const recheck = await f.post('/api/probes');
  assert.equal(recheck.data.error.code, 'EXIT_IP_MISMATCH');
  assert.equal(f.running, false); assert.equal(detections, 1);
  const status = (await f.get('/api/status')).data.data;
  assert.equal(status.proxy.exitStatus, 'unverified');
  assert.doesNotMatch(JSON.stringify(recheck.data), /private credential/);
});

test('an invalid unused relay registration does not prevent an ISP-only compatibility session', async t => {
  const relay = relayControllerFixture();
  relay.manager.status = async () => { throw failure('RELAY_ENROLLMENT_INVALID'); };
  const f = await fixture(t, { requireRelay: true, relayManager: relay.manager });
  f.config.connectionMode = 'vpn-compat';
  const initial = (await f.get('/api/status')).data.data;
  assert.equal(initial.configuration.connectionMode, 'vpn-compat');
  assert.equal(initial.relay.required, false); assert.equal(initial.relay.errorCode, 'RELAY_ENROLLMENT_INVALID');
  assert.equal((await f.post('/api/proxy/start', { confirm: true, mode: 'http', vpnConfirmed: true })).status, 200);
  assert.equal(f.running, true); assert.deepEqual(relay.record.events, []);
  f.config.connectionMode = 'relay';
  const restored = (await f.get('/api/status')).data.data;
  assert.equal(restored.proxy.enabled, false); assert.equal(restored.lastError.code, 'RELAY_ENROLLMENT_INVALID');
});

test('an orphan MC Proxy TUN rejects compatibility before route discovery or temporary verification', async t => {
  let detections = 0, checks = 0;
  const f = await fixture(t, { compatibilityRoutes: async () => { detections++; return [{ strategy: 'system' }]; },
    setupVerifier: { verify: async () => { checks++; assert.fail('orphan TUN must reject before verification'); } } });
  f.config.connectionMode = 'vpn-compat';
  f.runtime.assertCompatibilityReady = async () => { throw failure('TUN_INTERFACE_IN_USE'); };
  await f.get('/api/status');
  assert.equal((await f.post('/api/proxy/start', { confirm: true, mode: 'http', vpnConfirmed: true })).data.error.code, 'TUN_INTERFACE_IN_USE');
  assert.equal(detections + checks, 0); assert.equal(f.running, false);
});

test('switching to VPN compatibility saves verified ISP-only settings and keeps normal relay registration for switching back', async t => {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.vpn-controller-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const onboarding = createOnboardingManager({ runtimeRoot: root });
  const input = { host: 'same-isp.test', port: 1080, type: 'socks', username: 'test-isp-user', password: 'test-isp-secret', expectedExitIps: ['203.0.113.8'] };
  await onboarding.saveConfiguration(input, { prepareConfiguration: async candidate => ({ config: { ...candidate.config, relay: relayFixture() }, secrets: { ...candidate.secrets, ...relaySecrets } }) });
  const relay = relayControllerFixture();
  let failNext = true;
  const f = await fixture(t, { runtimeRoot: root, onboarding, requireRelay: true, relayManager: relay.manager,
    setupVerifier: { verify: async candidate => {
      if (failNext) throw failure('SETUP_CHECK_FAILED');
      assert.equal(candidate.secrets.ISP_PASSWORD, input.password);
      return { expectedExitIps: ['203.0.113.8'], checks: [{ source: 'ipify', ip: '203.0.113.8' }] };
    } } });
  f.config = await loadConfig(path.join(root, 'config.json'));
  const before = await readFile(path.join(root, 'config.json'), 'utf8');
  const change = { ...input, username: '', password: '', connectionMode: 'vpn-compat', vpnConfirmed: true };
  assert.equal((await f.post('/api/configuration/save', change)).data.error.code, 'VPN_COMPAT_NO_ROUTE');
  assert.equal(await readFile(path.join(root, 'config.json'), 'utf8'), before);
  failNext = false;
  const saved = await f.post('/api/configuration/save', change);
  assert.equal(saved.status, 200); assert.equal(saved.data.data.configuration.connectionMode, 'vpn-compat');
  f.config = await loadConfig(path.join(root, 'config.json'));
  assert.equal(f.config.relay, undefined);
  assert.deepEqual(await loadSecrets(path.join(root, 'upstream.secrets.env'), f.config), { ISP_USERNAME: input.username, ISP_PASSWORD: input.password });
  assert.deepEqual(relay.record.events, []);
  assert.equal((await f.get('/api/onboarding')).data.data.relay.required, false);
  const restored = await f.post('/api/configuration/save', { ...change, connectionMode: 'relay' });
  assert.equal(restored.status, 200);
  assert.deepEqual((await loadConfig(path.join(root, 'config.json'))).relay, relayFixture());
  assert.deepEqual(relay.record.events, ['check', 'bind:same-isp.test:0']);
});

const importedYaml = (count = 2) => `proxies:\n${Array.from({ length: count }, (_, offset) => `  - name: Imported ${offset + 1}\n    type: vless\n    server: fixture-node-${offset + 1}.test\n    port: 443\n    uuid: 6f2ce6f0-f610-4e74-9370-a38c746873a4\n    tls: true\n    network: tcp\n    servername: fixture-sni.test\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: '${Buffer.alloc(32, 3).toString('base64url')}'\n      short-id: 'abcd'\n`).join('')}`;

const latencyResult = latencyMs => ({ expectedExitIps: ['203.0.113.8'], checks: [{ source: 'ipify', ip: '203.0.113.8' }, { source: 'cloudflare', ip: '203.0.113.8' }], latencyMs, mock: false });

test('both VPN modes preserve local verification failures in HTTP, status, logs and share diagnostics', async t => {
  for (const mode of ['vpn-compat', 'vpn-import']) {
    for (const nativeCode of ['EACCES', 'OUTPUT_UNAVAILABLE', undefined]) {
      const diagnostics = [];
      const verifier = createSetupVerifier({ dependencies: {
        lstat: async () => { throw nativeCode ? Object.assign(new Error('PRIVATE_PATH_AND_CREDENTIAL'), { code: nativeCode }) : new TypeError('PRIVATE_PATH_AND_CREDENTIAL'); },
        createRuntime: () => assert.fail('failed local preparation must never start a core'),
      } });
      const f = await fixture(t, { onDiagnostic: event => diagnostics.push(event),
        compatibilityRoutes: async () => [{ strategy: 'system' }],
        setupVerifier: { ...verifier, recoverAndStop: async () => ({ running: false }) } });
      f.config.connectionMode = mode;
      if (mode === 'vpn-import') assert.equal((await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) })).status, 200);
      await f.get('/api/status');
      const response = await f.post('/api/proxy/start', { confirm: true, mode: 'http', vpnConfirmed: true });
      const code = nativeCode === 'OUTPUT_UNAVAILABLE' ? nativeCode : 'SETUP_VERIFICATION_FAILED';
      const details = { setupStage: 'preparing-runtime', ...(nativeCode === 'EACCES' ? { nativeCode } : {}), nativeError: nativeCode ? 'Error' : 'TypeError' };
      assert.equal(response.data.error.code, code); assert.deepEqual(response.data.error.details, details);
      const status = (await f.get('/api/status')).data.data;
      assert.equal(status.lastError.code, code); assert.deepEqual(status.lastError.diagnostic, details);
      const event = diagnostics.find(item => item.operation === (mode === 'vpn-import' ? 'checking-imported-node' : 'detecting-system') && item.code === code);
      assert.deepEqual(event?.diagnostic, details);
      const summary = (await f.get('/api/diagnostics/summary')).data.data;
      assert.equal(summary.code, code); assert.deepEqual(summary.diagnostic, details);
      assert.equal(f.running, false); assert.equal(f.events.includes('proxy-start'), false);
      assert.doesNotMatch(JSON.stringify({ response, status, diagnostics, summary }), /PRIVATE_PATH_AND_CREDENTIAL/);
    }
  }
});

async function rankImported(f) {
  // Isolated preexisting ISP fixture: preparing it makes no native/network call.
  await f.onboarding.saveConfiguration({ connectionMode: 'vpn-import', host: '192.0.2.1', port: 443, type: 'http', clearCredentials: true, expectedExitIps: ['203.0.113.8'] });
  return f.post('/api/vpn/latency');
}

test('imported connection starts after the first fully verified candidate without ranking unused nodes', async t => {
  for (const firstUnavailable of [false, true]) {
    const checked = [];
    const f = await fixture(t, { setupVerifier: { verify: async input => {
      checked.push(input.vpnNode.server);
      if (firstUnavailable && input.vpnNode.server === 'fixture-node-1.test') throw failure('SETUP_CHECK_FAILED');
      assert.notEqual(input.vpnNode.server, 'fixture-node-3.test', 'Connection must stop probing once a candidate passes both ISP checks');
      return latencyResult(30);
    } } });
    f.config.connectionMode = 'vpn-import';
    await f.post('/api/vpn/import', { confirm: true, text: importedYaml(3) }); await f.get('/api/status');
    const connected = await f.start();
    assert.equal(connected.status, 200); assert.equal(f.running, true);
    assert.deepEqual(checked, firstUnavailable ? ['fixture-node-1.test', 'fixture-node-2.test'] : ['fixture-node-1.test']);
    assert.equal(connected.data.data.compatibility.winningNodeIndex, firstUnavailable ? 2 : 1);
    assert.deepEqual([connected.data.data.vpnLatency.tested, connected.data.data.vpnLatency.total, connected.data.data.vpnLatency.verifiedEligible], [firstUnavailable ? 2 : 1, 3, 1]);
    assert.equal(connected.data.data.vpnLatency.status, 'partial', 'Untested nodes must not appear as measured or globally slower');
  }
});

test('manual latency ranking still verifies all three shortlisted candidates and chooses the fastest complete chain', async t => {
  const checked = [];
  const f = await fixture(t, { setupVerifier: { verify: async input => {
    checked.push(input.vpnNode.server);
    return latencyResult({ 'fixture-node-1.test': 70, 'fixture-node-2.test': 20, 'fixture-node-3.test': 40 }[input.vpnNode.server]);
  } } });
  f.config.connectionMode = 'vpn-import';
  await f.post('/api/vpn/import', { confirm: true, text: importedYaml(3) }); await f.get('/api/status');
  const measured = await rankImported(f);
  assert.equal(measured.status, 200); assert.equal(f.running, false, 'Manual measurement does not start the permanent proxy');
  assert.deepEqual(checked, ['fixture-node-1.test', 'fixture-node-2.test', 'fixture-node-3.test']);
  assert.deepEqual(measured.data.data.vpnLatency.results.map(item => [item.nodeIndex, item.latencyMs]), [[2, 20], [3, 40], [1, 70]]);
  assert.equal(measured.data.data.vpnLatency.recommendedNodeIndex, 2);
  assert.deepEqual([measured.data.data.vpnLatency.tested, measured.data.data.vpnLatency.total, measured.data.data.vpnLatency.verifiedEligible], [3, 3, 3]);
  assert.equal(measured.data.data.vpnLatency.status, 'complete');
});

test('large imported profiles use concurrent TCP screening and fully verify only the fastest three before cached reuse', async t => {
  let light = 0; const checked = [];
  const f = await fixture(t, { importedTcpProbe: async endpoint => {
    light++; return { status: 'reachable', tcpLatencyMs: ({ 'fixture-node-40.test': 1, 'fixture-node-30.test': 2, 'fixture-node-20.test': 3 })[endpoint.host] || 100 };
  }, setupVerifier: { verify: async input => {
    assert.equal(light, 43, 'the lightweight pass ends before any ISP verification'); checked.push(input.vpnNode.server);
    return latencyResult(({ 'fixture-node-40.test': 90, 'fixture-node-30.test': 10, 'fixture-node-20.test': 50 })[input.vpnNode.server]);
  } } });
  f.config.connectionMode = 'vpn-import';
  await f.post('/api/vpn/import', { confirm: true, text: importedYaml(43) }); await f.get('/api/status');
  const result = await rankImported(f); assert.equal(result.status, 200);
  assert.deepEqual(checked, ['fixture-node-40.test', 'fixture-node-30.test', 'fixture-node-20.test']);
  const progress = result.data.data.vpnLatency;
  assert.deepEqual([progress.candidateCount, progress.shortlistSize, progress.tested, progress.total, progress.verifiedEligible], [43, 3, 3, 3, 3]);
  assert.deepEqual(progress.shortlistedNodeIndices, [40, 30, 20]); assert.equal(progress.recommendedNodeIndex, 30); assert.equal(progress.status, 'partial');
  assert.equal(progress.screening.scope, 'local-tcp-connect'); assert.equal(progress.screening.screened, 43);
  assert.doesNotMatch(JSON.stringify(progress), /fixture-node|fixture-sni|6f2ce6f0|public_key/);
  const connected = await f.start(); assert.equal(connected.status, 200);
  assert.equal(light, 43, 'cached connection never screens the full profile again');
  assert.deepEqual(checked, ['fixture-node-40.test', 'fixture-node-30.test', 'fixture-node-20.test', 'fixture-node-30.test']);
  assert.equal(connected.data.data.vpnLatency.screening.scope, 'cached-shortlist');
});

test('shortlist bounds full attempts rather than collecting three successes or walking the remaining subscription', async t => {
  for (const allFail of [false, true]) {
    const checked = [];
    const f = await fixture(t, { setupVerifier: { verify: async input => {
      checked.push(input.vpnNode.server);
      if (allFail || input.vpnNode.server !== 'fixture-node-3.test') throw failure('SETUP_CHECK_FAILED');
      return latencyResult(60);
    } } });
    f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml(43) }); await f.get('/api/status');
    const result = await f.start();
    assert.deepEqual(checked, ['fixture-node-1.test', 'fixture-node-2.test', 'fixture-node-3.test']);
    assert.equal(result.status, allFail ? 409 : 200);
    if (allFail) assert.equal(result.data.error.code, 'VPN_IMPORT_NO_ROUTE');
    const progress = (await f.get('/api/status')).data.data.vpnLatency;
    assert.deepEqual([progress.shortlistSize, progress.tested, progress.total, progress.verifiedEligible], [3, 3, 3, allFail ? 0 : 1]);
    assert.equal(f.events.includes('proxy-start'), !allFail);
  }
});

test('manual selection skips the subscription screen and QUIC-only auto mode retains three unknown candidates without TCP', async t => {
  const manualChecks = [];
  const manual = await fixture(t, { shortlistImportedNodes: () => assert.fail('selected node must not screen the subscription'),
    setupVerifier: { verify: async input => { manualChecks.push(input.vpnNode.server); return latencyResult(20); } } });
  manual.config.connectionMode = 'vpn-import'; await manual.post('/api/vpn/import', { confirm: true, text: importedYaml(43) });
  await manual.post('/api/vpn/select', { confirm: true, nodeIndex: 40 }); await manual.get('/api/status');
  const selected = await manual.start(); assert.equal(selected.status, 200);
  assert.deepEqual(manualChecks, ['fixture-node-40.test']); assert.equal(selected.data.data.vpnLatency.total, 1);
  assert.equal(selected.data.data.vpnLatency.screening.scope, 'selected-node');
  const quicChecks = [];
  const quic = await fixture(t, { importedTcpProbe: () => assert.fail('QUIC must not be rejected through bare TCP'),
    setupVerifier: { verify: async input => { quicChecks.push(input.vpnNode.server); return latencyResult(10); } } });
  quic.config.connectionMode = 'vpn-import';
  await quic.post('/api/vpn/import', { confirm: true, text: JSON.stringify({ proxies: Array.from({ length: 43 }, (_, index) => ({
    name: 'QUIC ' + index, type: 'hysteria2', server: 'quic-' + index + '.test', port: 443, password: 'PRIVATE_QUIC', sni: 'fixture-sni.test',
  })) }) });
  await quic.get('/api/status'); const result = await rankImported(quic); assert.equal(result.status, 200);
  assert.deepEqual(quicChecks, ['quic-0.test', 'quic-1.test', 'quic-2.test']);
  assert.ok(result.data.data.vpnLatency.screening.results.every(item => item.status === 'unknown' && item.tcpLatencyMs === null));
  assert.equal(result.data.data.vpnLatency.verifiedEligible, 3); assert.doesNotMatch(JSON.stringify(result.data), /PRIVATE_QUIC|fixture-sni/);
});

test('profile replacement during lightweight screening prevents every ISP verification', async t => {
  let f, replaced = false, verified = 0;
  f = await fixture(t, { importedTcpProbe: async () => {
    if (!replaced) { replaced = true; await f.vpnConfigStore.import(importedYaml(1)); }
    return { status: 'reachable', tcpLatencyMs: 1 };
  }, setupVerifier: { verify: async () => { verified++; return latencyResult(10); } } });
  f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml(43) }); await f.get('/api/status');
  const result = await f.start(); assert.equal(result.data.error.code, 'VPN_IMPORT_CONFLICT');
  assert.equal(verified, 0); assert.equal(f.events.includes('proxy-start'), false);
});

test('automatic import ranks only valid full ISP chains and revalidates the fastest cached node before each connection', async t => {
  const checked = [];
  const f = await fixture(t, { setupVerifier: { verify: async input => {
    checked.push(input.vpnNode.server);
    return latencyResult(({ 'fixture-node-1.test': 400, 'fixture-node-2.test': 50, 'fixture-node-3.test': 110 })[input.vpnNode.server]);
  } } });
  f.config.connectionMode = 'vpn-import';
  await f.post('/api/vpn/import', { confirm: true, text: importedYaml(3) }); await f.get('/api/status');
  const first = await rankImported(f); assert.equal(first.status, 200);
  assert.equal(first.data.data.compatibility.winningNodeIndex, 2);
  assert.deepEqual(first.data.data.vpnLatency.results.map(item => [item.nodeIndex, item.latencyMs]), [[2, 50], [3, 110], [1, 400]]);
  assert.equal(first.data.data.vpnLatency.status, 'complete'); assert.equal(first.data.data.vpnLatency.stale, false);
  assert.doesNotMatch(JSON.stringify(first.data), /fixture-node|6f2ce6f0|public_key|short_id|secrets|vpnNodeHash/);
  checked.length = 0;
  assert.equal((await f.start()).status, 200);
  assert.equal(f.startInput.vpnNode.server, 'fixture-node-2.test');
  assert.deepEqual(checked, ['fixture-node-2.test'], 'cached ordering never bypasses complete ISP checks');
  await f.stop(); f.clock += 300_001; checked.length = 0;
  assert.equal((await f.get('/api/status')).data.data.vpnLatency.stale, true);
  assert.equal((await rankImported(f)).status, 200); assert.equal(checked.length, 3);
});

test('cached fastest-node failure freshly verifies the next measured node and updates the public recommendation', async t => {
  let unavailable = false; const checked = [];
  const f = await fixture(t, { setupVerifier: { verify: async input => {
    checked.push(input.vpnNode.server);
    if (unavailable && input.vpnNode.server === 'fixture-node-2.test') throw failure('SETUP_CHECK_FAILED');
    return latencyResult(input.vpnNode.server === 'fixture-node-2.test' ? 20 : 100);
  } } });
  f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml() }); await f.get('/api/status');
  assert.equal((await rankImported(f)).status, 200); unavailable = true; checked.length = 0;
  const result = await f.start(); assert.equal(result.status, 200);
  assert.deepEqual(checked, ['fixture-node-2.test', 'fixture-node-1.test']);
  assert.equal(result.data.data.vpnLatency.recommendedNodeIndex, 1);
  assert.equal(result.data.data.vpnLatency.results.find(item => item.nodeIndex === 2).status, 'failed');
  assert.equal(f.startInput.vpnNode.server, 'fixture-node-1.test');
});

test('latency budgets report a partial measured set and never describe untested nodes as successful', async t => {
  let f;
  f = await fixture(t, { importedProbeBudgetMs: 100, setupVerifier: { verify: async () => { f.clock += 101; return latencyResult(70); } } });
  f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml(3) }); await f.get('/api/status');
  const result = await f.start(); assert.equal(result.status, 200);
  assert.equal(result.data.data.vpnLatency.status, 'partial');
  assert.deepEqual([result.data.data.vpnLatency.tested, result.data.data.vpnLatency.total, result.data.data.vpnLatency.results.length], [1, 3, 1]);
  assert.equal(result.data.data.vpnLatency.recommendedNodeIndex, 1);
});

test('a fatal ownership or ISP mismatch after a fast valid node rejects the whole ranking and starts no proxy', async t => {
  for (const code of ['SETUP_EXIT_MISMATCH', 'SETUP_PROXY_STOP_FAILED', 'SETUP_PROXY_UNVERIFIED']) {
    let checks = 0;
    const f = await fixture(t, { setupVerifier: { verify: async () => { if (++checks === 1) return latencyResult(10); throw failure(code); } } });
    f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml() }); await f.get('/api/status');
    assert.equal((await rankImported(f)).data.error.code, code);
    const status = (await f.get('/api/status')).data.data;
    assert.equal(status.vpnLatency.status, 'failed'); assert.equal(status.vpnLatency.recommendedNodeIndex, null);
    assert.equal(f.events.includes('proxy-start'), false);
  }
});

test('latency cache cannot survive changed ISP configuration, credentials or explicit node selection', async t => {
  let checks = 0; let password = 'first-private-password';
  const f = await fixture(t, { loadSecrets: async () => ({ ISP_USERNAME: 'fixture-user', ISP_PASSWORD: password }), setupVerifier: { verify: async input => { checks++; return latencyResult(input.vpnNode.server === 'fixture-node-2.test' ? 20 : 80); } } });
  f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml() }); await f.get('/api/status');
  assert.equal((await rankImported(f)).status, 200); assert.equal(checks, 2);
  await f.start(); assert.equal(f.startInput.vpnNode.server, 'fixture-node-2.test'); await f.stop(); assert.equal(checks, 3);
  password = 'changed-private-password'; await f.start(); assert.equal(f.startInput.vpnNode.server, 'fixture-node-1.test'); await f.stop(); assert.equal(checks, 4);
  f.config.upstream.host = '192.0.2.2'; await f.get('/api/status');
  assert.equal((await f.get('/api/status')).data.data.vpnLatency, null);
  await f.start(); assert.equal(f.startInput.vpnNode.server, 'fixture-node-1.test'); await f.stop(); assert.equal(checks, 5);
  await f.post('/api/vpn/select', { confirm: true, nodeIndex: 2 });
  assert.equal((await f.get('/api/status')).data.data.vpnLatency, null);
  const result = await f.start(); assert.equal(checks, 6); assert.equal(f.startInput.vpnNode.server, 'fixture-node-2.test');
  assert.equal(result.data.data.vpnLatency.total, 1);
  assert.doesNotMatch(JSON.stringify(result.data), /private-password/);
});

test('latency API strictly rejects extra arguments, missing saved ISP and active sessions without probing', async t => {
  let checks = 0;
  const f = await fixture(t, { setupVerifier: { verify: async () => { checks++; return latencyResult(100); } } });
  f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) });
  assert.equal((await f.post('/api/vpn/latency', { url: 'https://private.invalid' })).status, 400);
  assert.equal((await f.post('/api/vpn/latency')).data.error.code, 'ONBOARDING_CONFIGURATION_REQUIRED');
  assert.equal(checks, 0);
  assert.equal((await f.post('/api/configuration/save', { connectionMode: 'vpn-import', host: '192.0.2.1', port: 443, type: 'http', clearCredentials: true })).status, 200);
  const beforeManual = checks;
  assert.equal((await f.post('/api/vpn/latency')).status, 200);
  assert.equal((await f.post('/api/vpn/latency')).status, 200);
  assert.equal(checks, beforeManual + 2, 'manual latency detection forces fresh verification instead of cache reuse');
  f.running = true;
  assert.equal((await f.post('/api/vpn/latency')).data.error.code, 'SETUP_SESSION_ACTIVE'); assert.equal(checks, beforeManual + 2);
});

test('latency progress remains readable mid-ranking without exposing private nodes or waiting for the next probe', async t => {
  const entered = deferred(), release = deferred();
  const f = await fixture(t, { setupVerifier: { verify: async input => {
    if (input.vpnNode.server === 'fixture-node-2.test') { entered.resolve(); await release.promise; return latencyResult(50); }
    return latencyResult(100);
  } } });
  f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml() }); await f.get('/api/status');
  const starting = rankImported(f);
  await Promise.race([entered.promise, starting.then(result => assert.fail(`Ranking ended before its gated probe: ${result.data.error?.code || result.status}`))]);
  try {
    const progress = await f.get('/api/progress');
    assert.equal(progress.data.data.vpnLatency.status, 'checking');
    assert.deepEqual(progress.data.data.vpnLatency.results, [{ nodeIndex: 1, status: 'verified', latencyMs: 100 }]);
    assert.doesNotMatch(JSON.stringify(progress.data), /fixture-node|6f2ce6f0|public_key|short_id/);
  } finally { release.resolve(); }
  assert.equal((await starting).data.data.compatibility.winningNodeIndex, 2);
});

test('YAML import is a private local operation with explicit confirmation, bounded bodies and atomic rejection', async t => {
  const f = await fixture(t);
  assert.equal((await f.post('/api/vpn/import', { text: importedYaml() })).data.error.code, 'CONFIRMATION_REQUIRED');
  assert.equal((await f.post('/api/vpn/import', { confirm: true, text: importedYaml(), path: 'other.yaml' })).status, 400);
  const text = '# '.concat('fixture'.repeat(5500), '\n', importedYaml());
  assert.ok(Buffer.byteLength(JSON.stringify({ text })) > 32_768);
  const imported = await f.post('/api/vpn/import', { confirm: true, text });
  assert.equal(imported.status, 200); const config = imported.data.data.vpnConfig;
  assert.equal(config.supported, 2); assert.equal(config.selectedIndex, null);
  assert.doesNotMatch(JSON.stringify(imported.data), /6f2ce6f0|fixture-node|fixture-sni|public-key|short-id/);
  assert.equal(config.format, 'clash-yaml');
  assert.deepEqual((await f.get('/api/vpn/config')).data.data.nodes, [{ index: 1, name: 'Imported 1', protocol: 'vless', transport: 'tcp' }, { index: 2, name: 'Imported 2', protocol: 'vless', transport: 'tcp' }]);
  assert.equal((await f.post('/api/vpn/import', { confirm: true, text: 'proxies: [' })).data.error.code, 'VPN_YAML_INVALID');
  assert.equal((await f.post('/api/vpn/import', { confirm: true, text: 'proxies: []' })).data.error.code, 'VPN_IMPORT_NO_SUPPORTED_NODES');
  assert.equal((await f.get('/api/vpn/config')).data.data.id, config.id);
  assert.equal((await f.post('/api/vpn/select', { confirm: true, nodeIndex: 2, expectedId: config.id })).data.data.vpnConfig.selectedIndex, 2);
  assert.equal((await f.post('/api/vpn/select', { confirm: true, nodeIndex: 99 })).data.error.code, 'VPN_NODE_NOT_FOUND');
  assert.equal((await f.post('/api/vpn/import', { confirm: true, text: '#'.repeat(1024 * 1024 + 1) })).data.error.code, 'VPN_YAML_SIZE_INVALID');
  assert.equal((await f.post('/api/onboarding/preferences', { extra: 'x'.repeat(33_000) })).status, 413);
  assert.equal(f.probeCalls + f.requestCalls + f.systemProbeCalls, 0);
  f.running = true;
  assert.equal((await f.post('/api/vpn/import', { confirm: true, text: importedYaml() })).status, 409);
  f.running = false; f.browserRunning = true;
  assert.equal((await f.post('/api/vpn/select', { confirm: true, nodeIndex: null })).status, 409);
});

test('failed import exposes only bounded node issue categories while preserving the existing profile', async t => {
  const f = await fixture(t);
  const imported = await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) });
  f.vpnConfigStore.import = async () => { throw Object.assign(failure('VPN_IMPORT_NO_SUPPORTED_NODES'), { unsupportedNodes: [
    { index: 1, code: 'VPN_NODE_FIELD_UNSUPPORTED', server: 'PRIVATE_ENDPOINT', password: 'PRIVATE_PASSWORD' },
    { index: 0, code: 'VPN_NODE_INVALID' }, { index: 257, code: 'VPN_NODE_INVALID' }, { index: 2, code: 'PRIVATE_PASSWORD' },
  ] }); };
  const rejected = await f.post('/api/vpn/import', { confirm: true, text: 'unsupported content' });
  assert.deepEqual(rejected.data.error.details, { unsupportedNodes: [{ index: 1, code: 'VPN_NODE_FIELD_UNSUPPORTED' }] });
  assert.doesNotMatch(JSON.stringify(rejected.data), /PRIVATE_ENDPOINT|PRIVATE_PASSWORD/);
  assert.equal((await f.get('/api/vpn/config')).data.data.id, imported.data.data.vpnConfig.id);
});

test('imported mode selects a verified node without external VPN discovery, starts HTTP and never exposes its credentials', async t => {
  const checked = [];
  const f = await fixture(t, { requireRelay: true, compatibilityRoutes: () => assert.fail('imported mode must not discover an external VPN'),
    setupVerifier: { verify: async input => {
      checked.push(input.vpnNode.server); assert.equal(input.config.relay, undefined); assert.equal(input.vpnProxy, undefined);
      if (checked.length === 1) throw failure('SETUP_CHECK_FAILED');
      return { expectedExitIps: ['203.0.113.8'], checks: [{ source: 'ipify', ip: '203.0.113.8' }, { source: 'cloudflare', ip: '203.0.113.8' }] };
    } } });
  f.config.connectionMode = 'vpn-import';
  assert.equal((await f.post('/api/vpn/import', { confirm: true, text: importedYaml() })).status, 200);
  await f.get('/api/status');
  const response = await f.post('/api/proxy/start', { confirm: true });
  assert.equal(response.status, 200);
  assert.deepEqual(checked, ['fixture-node-1.test', 'fixture-node-2.test']);
  assert.equal(f.startInput.mode, 'http'); assert.equal(f.startInput.vpnNode.server, 'fixture-node-2.test');
  assert.equal(response.data.data.proxy.connectionMode, 'vpn-import');
  assert.equal(response.data.data.compatibility.winningNodeIndex, 2);
  assert.equal(response.data.data.relay.required, false);
  assert.doesNotMatch(JSON.stringify(response.data), /6f2ce6f0|fixture-node|fixture-sni|public_key|short_id/);
  assert.equal(f.systemProbeCalls, 0);
  assert.equal((await f.get('/api/status')).data.data.proxy.enabled, true);
  const original = (await f.get('/api/snapshot')).data.data.proxy.exit;
  f.probe = async () => { throw failure('PROBE_TIMEOUT'); };
  assert.equal((await f.post('/api/probes')).status, 500);
  assert.equal(f.running, true);
  assert.deepEqual((await f.get('/api/snapshot')).data.data.proxy.exit, original);
  f.clock += 90_001;
  assert.equal((await f.get('/api/snapshot')).data.data.proxy.exitStatus, 'unverified');
  await assert.rejects(f.server.applicationProxy(), { code: 'PROBE_TIMEOUT' });
  assert.equal(f.running, true);
});

test('imported node failures and fixed ISP exit mismatches never start the owned listener or try a direct fallback', async t => {
  let checks = 0; let currentFailure = 'SETUP_CHECK_FAILED';
  const f = await fixture(t, { compatibilityRoutes: () => assert.fail('no external or system fallback'),
    setupVerifier: { verify: async () => { checks++; throw failure(currentFailure); } } });
  f.config.connectionMode = 'vpn-import';
  await f.post('/api/vpn/import', { confirm: true, text: importedYaml() });
  await f.get('/api/status');
  assert.equal((await f.start()).data.error.code, 'VPN_IMPORT_NO_ROUTE');
  assert.equal(checks, 2); assert.equal(f.events.includes('proxy-start'), false);
  currentFailure = 'SETUP_EXIT_MISMATCH'; checks = 0;
  assert.equal((await f.start()).data.error.code, 'SETUP_EXIT_MISMATCH'); assert.equal(checks, 1);
  assert.deepEqual(f.config.probe.expectedExitIps, ['203.0.113.8']);
  assert.equal((await f.post('/api/proxy/start', { confirm: true, mode: 'tun' })).data.error.code, 'SETUP_EXIT_MISMATCH');
  assert.equal((await f.post('/api/proxy/start', { confirm: true, vpnProxy: { type: 'http', host: '127.0.0.1', port: 7890 } })).data.error.code, 'VPN_PROXY_INVALID');
});

test('imported mode respects explicit selection, retained network locks and external profile replacement', async t => {
  let checked = 0;
  const f = await fixture(t, { lockSimulation: true, setupVerifier: { verify: async input => { checked++; assert.equal(input.vpnNode.server, 'fixture-node-2.test'); return { expectedExitIps: ['203.0.113.8'], checks: [{ source: 'ipify', ip: '203.0.113.8' }] }; } } });
  f.config.connectionMode = 'vpn-import';
  await f.post('/api/vpn/import', { confirm: true, text: importedYaml() });
  await f.post('/api/vpn/select', { confirm: true, nodeIndex: 2 });
  await f.get('/api/status');
  f.networkLocked = true;
  assert.equal((await f.start()).data.error.code, 'SETUP_NETWORK_LOCKED'); assert.equal(checked, 0);
  assert.equal((await f.post('/api/vpn/import', { confirm: true, text: importedYaml() })).status, 409);
  f.networkLocked = false;
  assert.equal((await f.start()).status, 200); assert.equal(checked, 1);
  await f.vpnConfigStore.import(importedYaml().replaceAll('fixture-node', 'changed-node'));
  assert.equal((await f.post('/api/probes')).data.error.code, 'VPN_IMPORT_CONFLICT');
  assert.equal(f.running, false, 'manual verification stops the old listener before another status poll');
  const status = (await f.get('/api/status')).data.data;
  assert.equal(status.proxy.running, false); assert.equal(status.lastError.code, 'VPN_IMPORT_CONFLICT');
});

test('replacing the imported profile during verification prevents starting even when node credentials are identical', async t => {
  let f;
  f = await fixture(t, { setupVerifier: { verify: async () => {
    await f.vpnConfigStore.import(importedYaml(1).replaceAll('fixture-node', 'replacement-node'));
    return { expectedExitIps: ['203.0.113.8'], checks: [{ source: 'ipify', ip: '203.0.113.8' }] };
  } } });
  f.config.connectionMode = 'vpn-import';
  await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) });
  await f.get('/api/status');
  assert.equal((await f.start()).data.error.code, 'VPN_IMPORT_CONFLICT');
  assert.equal(f.events.includes('proxy-start'), false);
});

test('a same-profile node change is refused before temporary verification contacts stale credentials', async t => {
  const f = await fixture(t, { setupVerifier: { verify: () => assert.fail('a changed node must never be contacted') } });
  f.config.connectionMode = 'vpn-import';
  await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) }); await f.get('/api/status');
  const originalCandidates = f.vpnConfigStore.candidates;
  let reads = 0;
  f.vpnConfigStore.candidates = async () => {
    const nodes = await originalCandidates();
    return ++reads === 1 ? nodes : nodes.map(node => ({ ...node, outbound: { ...node.outbound, server: 'changed-node.test' } }));
  };
  assert.equal((await f.start()).data.error.code, 'VPN_IMPORT_CONFLICT');
  assert.equal((await f.get('/api/status')).data.data.compatibility.status, 'failed');
  assert.equal(f.events.includes('proxy-start'), false);
});

test('imported ISP save and independent check reuse the same verified route and preserve existing ISP on failure', async t => {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.vpn-import-controller-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const onboarding = createOnboardingManager({ runtimeRoot: root });
  let failCheck = false; const candidates = [];
  const f = await fixture(t, { runtimeRoot: root, onboarding, requireRelay: true, setupVerifier: { verify: async input => {
    candidates.push(input); assert.equal(input.config.connectionMode, 'vpn-import'); assert.equal(input.config.relay, undefined);
    if (failCheck) throw failure('SETUP_CHECK_FAILED');
    return { expectedExitIps: ['203.0.113.8'], checks: [{ source: 'ipify', ip: '203.0.113.8' }, { source: 'cloudflare', ip: '203.0.113.8' }] };
  } } });
  await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) });
  const input = { connectionMode: 'vpn-import', host: 'imported-isp.test', port: 1080, type: 'socks', username: 'fixture-user', password: 'fixture-private-password' };
  const saved = await f.post('/api/configuration/save', input);
  assert.equal(saved.status, 200); assert.equal(saved.data.data.configuration.connectionMode, 'vpn-import');
  f.config = await loadConfig(path.join(root, 'config.json'));
  assert.equal(f.config.relay, undefined);
  assert.equal((await f.post('/api/vpn/check')).status, 200);
  assert.equal(candidates.length, 2); assert.equal(candidates[0].vpnNode.server, 'fixture-node-1.test');
  failCheck = true;
  assert.equal((await f.post('/api/configuration/save', { ...input, host: 'failed-isp.test' })).data.error.code, 'VPN_IMPORT_NO_ROUTE');
  assert.equal((await loadConfig(path.join(root, 'config.json'))).upstream.host, input.host);
  assert.doesNotMatch(JSON.stringify((await f.get('/api/onboarding')).data), /fixture-private-password|6f2ce6f0/);
});

test('required relay refuses missing registration or changed relay credentials before the core starts', async t => {
  const relay = relayControllerFixture(); relay.record.configured = false;
  const f = await fixture(t, { relayManager: relay.manager, requireRelay: true, loadSecrets: async () => ({ ...relaySecrets }) });
  f.config.relay = relayFixture(); await f.get('/api/status');
  assert.equal((await f.start()).data.error.code, 'RELAY_NOT_CONFIGURED');
  relay.record.configured = true;
  f.config.relay = { ...relayFixture(), host: '192.0.2.51' }; await f.get('/api/status');
  assert.equal((await f.start()).data.error.code, 'RELAY_CONFIGURATION_CHANGED');
  assert.equal(f.events.includes('proxy-start'), false); assert.equal(relay.record.events.length, 0);
  const g = await fixture(t, { relayManager: relay.manager, requireRelay: true, loadSecrets: async () => ({ ...relaySecrets, RELAY_PASSWORD: 'changed' }) });
  g.config.relay = relayFixture(); await g.get('/api/status');
  assert.equal((await g.start()).data.error.code, 'RELAY_CONFIGURATION_CHANGED');
});

test('unlocked start checks remote ISP binding, while retained-lock reconnect avoids every physical relay API call', async t => {
  const relay = relayControllerFixture();
  const f = await fixture(t, { relayManager: relay.manager, requireRelay: true, lockSimulation: true, loadSecrets: async () => ({ ...relaySecrets }) });
  f.config.relay = relayFixture(); await f.get('/api/status');
  assert.equal((await f.start()).data.error.code, 'RELAY_BINDING_MISMATCH');
  assert.equal(f.events.includes('proxy-start'), false);
  relay.record.events.length = 0; f.networkLocked = true;
  assert.equal((await f.start()).status, 200);
  assert.equal(f.probeCalls, 1, 'the existing ISP exit verification still gates reconnect');
  assert.deepEqual(relay.record.events, []);
});

test('quality verification rejects a changed relay account before it starts any temporary core', async t => {
  const relay = relayControllerFixture(); let verified = 0;
  const onboarding = { status: async () => ({ firstRun: false }), configuration: async () => ({ available: true }) };
  const f = await fixture(t, { onboarding, relayManager: relay.manager, requireRelay: true, loadSecrets: async () => ({ ...relaySecrets, RELAY_USERNAME: 'other-account' }),
    setupVerifier: { verify: async () => { verified++; } } });
  f.config.relay = relayFixture();
  assert.equal((await f.post('/api/quality/check')).data.error.code, 'RELAY_CONFIGURATION_CHANGED');
  assert.equal(verified, 0); assert.deepEqual(relay.record.events, []);
});

test('external enrollment changes revoke an active session locally and retain its existing network lock', async t => {
  const relay = relayControllerFixture();
  const f = await fixture(t, { relayManager: relay.manager, requireRelay: true, lockSimulation: true, loadSecrets: async () => ({ ...relaySecrets }) });
  f.config.relay = relayFixture(); f.networkLocked = true; await f.get('/api/status');
  assert.equal((await f.start()).status, 200);
  relay.manager.credentials = async () => ({ relay: relayFixture(), secrets: { ...relaySecrets, RELAY_PASSWORD: 'PRIVATE-NEW-PASSWORD' } });
  const status = (await f.get('/api/status')).data.data;
  assert.equal(status.lastError.code, 'RELAY_CONFIGURATION_CHANGED');
  assert.equal(status.proxy.running, false); assert.equal(status.networkLock.locked, true);
  assert.equal(f.events.includes('proxy-stop'), true);
  assert.deepEqual(relay.record.events, [], 'active checks and recovery never use physical Node HTTPS under the lock');
  assert.doesNotMatch(JSON.stringify(status), /PRIVATE-NEW-PASSWORD|relay-test-password|BEGIN CERTIFICATE/);
});

test('completed direct-ISP installations return to the ISP form when relay enrollment is required without losing prefill', async t => {
  const relay = relayControllerFixture();
  const configuration = { available: true, host: 'saved-isp.test', port: 1080, type: 'socks', credentialsConfigured: true, expectedExitIps: ['203.0.113.8'] };
  const onboarding = { status: async () => ({ firstRun: false, completedAt: '2026-10-01T00:00:00Z' }), configuration: async () => structuredClone(configuration) };
  const f = await fixture(t, { onboarding, relayManager: relay.manager, requireRelay: true, loadSecrets: async () => ({ ...relaySecrets }) });
  let result = (await f.get('/api/onboarding')).data.data;
  assert.equal(result.onboarding.firstRun, false);
  assert.equal(result.configuration.available, false); assert.equal(result.configuration.errorCode, 'RELAY_CONFIGURATION_CHANGED');
  assert.equal(result.configuration.host, 'saved-isp.test'); assert.equal(result.configuration.port, 1080);
  f.config.relay = relayFixture();
  result = (await f.get('/api/onboarding')).data.data;
  assert.equal(result.configuration.available, true); assert.equal(result.configuration.errorCode, undefined);
  assert.equal(configuration.available, true, 'public migration gating never modifies persisted settings');
  assert.deepEqual(relay.record.events, []);
});

async function saveThroughRelayFixture(t, { failedVerification = false, failedWrite = false, foreignRevision = false, previousBinding = null, exportDiagnostics } = {}) {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.relay-controller-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const relay = relayControllerFixture(); relay.record.upstream = previousBinding;
  let failNextSecrets = failedWrite;
  const onboarding = createOnboardingManager({ runtimeRoot: root, dependencies: { rename: async (from, to) => {
    if (failNextSecrets && from.endsWith('secrets.after')) { failNextSecrets = false; throw new Error('secret filesystem failure'); }
    return rename(from, to);
  } } });
  const setupVerifier = { verify: async candidate => {
    relay.record.events.push('verify'); assert.deepEqual(candidate.config.relay, relayFixture());
    assert.equal(candidate.secrets.RELAY_PASSWORD, relaySecrets.RELAY_PASSWORD);
    if (foreignRevision) { relay.record.upstream = { host: 'foreign.test', port: 8888 }; relay.record.bindingRevision++; }
    if (failedVerification) throw failure('SETUP_CHECK_FAILED');
    return { expectedExitIps: ['203.0.113.8'], checks: [{ source: 'ipify', ip: '203.0.113.8' }] };
  } };
  const f = await fixture(t, { onboarding, setupVerifier, relayManager: relay.manager, requireRelay: true, runtimeRoot: root, exportDiagnostics });
  const input = { host: 'new-isp.test', port: 1080, type: 'socks', username: 'new-user', password: 'new-secret' };
  return { f, relay, root, input };
}

test('ISP save enrolls and binds relay before verification then commits both credential layers privately', async t => {
  const { f, relay, root, input } = await saveThroughRelayFixture(t);
  const result = await f.post('/api/configuration/save', input);
  assert.equal(result.status, 200);
  assert.deepEqual(relay.record.events, ['check', 'bind:new-isp.test:0', 'verify']);
  assert.doesNotMatch(JSON.stringify(result.data), /new-secret|relay-test-password|BEGIN CERTIFICATE/);
  const config = await loadConfig(path.join(root, 'config.json'));
  assert.deepEqual(config.relay, relayFixture());
  assert.deepEqual(await loadSecrets(path.join(root, 'upstream.secrets.env'), config), { ISP_USERNAME: input.username, ISP_PASSWORD: input.password, ...relaySecrets });
});

test('saving ISP refreshes the credential-free offline manifest and an export failure never undoes the committed chain', async t => {
  let failExport = false;
  const { f, relay, root, input } = await saveThroughRelayFixture(t, { exportDiagnostics: async options => {
    if (failExport) throw new Error('PRIVATE-EXPORT-ERROR');
    return exportChainDiagnostics(options);
  } });
  f.runtime.readConfig = () => loadConfig(path.join(root, 'config.json'));
  const saved = await f.post('/api/configuration/save', input);
  assert.equal(saved.status, 200); assert.equal(saved.data.data.diagnosticsExported, true);
  const manifestPath = path.join(root, 'offline-diagnostics', 'manifest.json');
  const raw = await readFile(manifestPath, 'utf8'); const manifest = JSON.parse(raw);
  assert.equal(manifest.isp.configured, true); assert.equal(manifest.isp.host, input.host);
  assert.deepEqual(manifest.expectedExitIps, ['203.0.113.8']); assert.equal(manifest.relay.host, relayFixture().host);
  assert.doesNotMatch(raw, /new-secret|relay-test-password|BEGIN CERTIFICATE/);
  failExport = true;
  const next = await f.post('/api/configuration/save', { ...input, host: 'next-isp.test' });
  assert.equal(next.status, 200); assert.equal(next.data.data.configuration.available, true);
  assert.equal(next.data.data.diagnosticsExported, false); assert.equal(next.data.data.diagnosticsErrorCode, 'DIAGNOSTICS_EXPORT_FAILED');
  assert.doesNotMatch(JSON.stringify(next.data), /PRIVATE-EXPORT-ERROR/);
  assert.equal((await loadConfig(path.join(root, 'config.json'))).upstream.host, 'next-isp.test');
  assert.equal(relay.record.upstream.host, 'next-isp.test');
  assert.equal(relay.record.events.some(event => event.startsWith('clear:')), false);
});

test('relay import refreshes offline metadata after commit without treating export failure as import failure', async t => {
  const relay = relayControllerFixture(); let calls = 0;
  const f = await fixture(t, { relayManager: relay.manager, requireRelay: true, exportDiagnostics: async () => { calls++; throw new Error('PRIVATE-EXPORT-ERROR'); } });
  const result = await f.post('/api/relay/import', { confirm: true, enrollment: {} });
  assert.equal(result.status, 200); assert.equal(result.data.data.configured, true);
  assert.equal(result.data.data.diagnosticsExported, false); assert.equal(result.data.data.diagnosticsErrorCode, 'DIAGNOSTICS_EXPORT_FAILED');
  assert.equal(calls, 1); assert.deepEqual(relay.record.events, ['import']);
  assert.doesNotMatch(JSON.stringify(result.data), /PRIVATE-EXPORT-ERROR/);
});

test('verification failure restores previous remote binding or clears new enrollment by CAS', async t => {
  for (const previousBinding of [null, { host: 'old-isp.test', port: 8000 }]) {
    const { f, relay, root, input } = await saveThroughRelayFixture(t, { failedVerification: true, previousBinding });
    const response = await f.post('/api/configuration/save', input);
    assert.equal(response.data.error.code, 'SETUP_CHECK_FAILED');
    assert.deepEqual(relay.record.upstream, previousBinding);
    assert.deepEqual(relay.record.events.slice(0, 4), ['check', 'bind:new-isp.test:0', 'verify', 'check']);
    assert.equal(relay.record.events.at(-1), previousBinding ? 'bind:old-isp.test:1' : 'clear:1');
    await assert.rejects(readFile(path.join(root, 'config.json')), { code: 'ENOENT' });
  }
});

test('local commit failure rolls back the remote binding and a foreign revision is never overwritten', async t => {
  const first = await saveThroughRelayFixture(t, { failedWrite: true });
  assert.equal((await first.f.post('/api/configuration/save', first.input)).data.error.code, 'ONBOARDING_WRITE_FAILED');
  assert.equal(first.relay.record.upstream, null);
  assert.equal(first.relay.record.events.at(-1), 'clear:1');
  const second = await saveThroughRelayFixture(t, { failedVerification: true, foreignRevision: true });
  assert.equal((await second.f.post('/api/configuration/save', second.input)).data.error.code, 'RELAY_ROLLBACK_REQUIRED');
  assert.deepEqual(second.relay.record.upstream, { host: 'foreign.test', port: 8888 });
  assert.equal(second.relay.record.events.some(event => event.startsWith('clear:')), false);
  assert.equal((await second.f.get('/api/status')).data.data.lastError.code, 'RELAY_ROLLBACK_REQUIRED');
});

test('pre-ISP diagnostics export uses enrolled relay only and accepts no caller-controlled output path', async t => {
  const relay = relayControllerFixture(); let exported;
  const f = await fixture(t, { relayManager: relay.manager, requireRelay: true, recoveryAppPath: path.resolve('MC Proxy.exe'), exportDiagnostics: async input => {
    exported = input; return { directory: path.join(input.runtimeRoot, 'offline-diagnostics'), files: ['manifest.json'], manifest: createChainDiagnosticManifest(input), mock: false };
  } });
  f.readError = failure('CONFIG_READ_FAILED');
  const result = await f.post('/api/diagnostics/export');
  assert.equal(result.status, 200); assert.equal(result.data.data.manifest.isp.configured, false);
  assert.equal(result.data.data.manifest.relay.host, '192.0.2.50');
  assert.equal(exported.appPath, path.resolve('MC Proxy.exe'));
  assert.doesNotMatch(JSON.stringify(result.data), /relay-test-password|BEGIN CERTIFICATE|RELAY_PASSWORD/);
  assert.deepEqual(relay.record.events, []);
  assert.equal((await f.post('/api/diagnostics/export', { path: 'C:\\Windows' })).status, 400);
});

test('desktop shutdown drains owned sessions then closes idle and incomplete-header controller sockets promptly', { timeout: 5000 }, async t => {
  const f = await fixture(t, { lockSimulation: true });
  f.running = true; f.browserRunning = true; f.networkLocked = true;
  const sockets = [];
  for (const partial of [false, true]) {
    const socket = net.connect(f.server.address().port, '127.0.0.1'); sockets.push(socket);
    socket.on('error', () => {}); await once(socket, 'connect');
    if (partial) socket.write(`GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:${f.server.address().port}\r\n`);
  }
  let timer; let disposed = false;
  f.runtime.dispose = async () => { disposed = true; };
  try {
    await Promise.race([f.server.shutdown(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('controller shutdown exceeded two seconds')), 2000); })]);
    assert.deepEqual(f.events, ['browser-close', 'proxy-stop']);
    assert.equal(f.running, false); assert.equal(f.browserRunning, false); assert.equal(f.networkLocked, true);
    assert.equal(f.server.listening, false); assert.equal(disposed, true);
  } finally { clearTimeout(timer); for (const socket of sockets) socket.destroy(); }
});

test('failed desktop shutdown keeps the controller usable and never releases the network lock', async t => {
  const f = await fixture(t, { lockSimulation: true });
  f.running = true; f.browserRunning = true; f.networkLocked = true; f.closeError = failure('BROWSER_CLOSE_TIMEOUT');
  await assert.rejects(f.server.shutdown(), { code: 'BROWSER_CLOSE_TIMEOUT' });
  assert.equal(f.server.listening, true); assert.equal(f.running, true); assert.equal(f.networkLocked, true);
  assert.equal((await f.get('/api/status')).status, 200);
  assert.equal(f.events.includes('proxy-stop'), false); assert.equal(f.events.includes('network-unlock'), false);
  f.closeError = null; await f.server.shutdown();
  assert.equal(f.running, false); assert.equal(f.networkLocked, true);
});

test('desktop shutdown rejects waiting controller mutations before draining its own end-session operation', async t => {
  const gate = deferred(); const entered = deferred(); let calls = 0;
  const onboarding = {
    status: async () => ({ firstRun: true }), configuration: async () => ({ available: false }),
    preferences: async () => { calls++; if (calls === 1) { entered.resolve(); await gate.promise; } return {}; },
  };
  const f = await fixture(t, { onboarding });
  const first = f.post('/api/onboarding/preferences', { autoOptimize: true }).catch(() => null); await entered.promise;
  const queued = f.post('/api/onboarding/preferences', { autoOptimize: false }).catch(() => null);
  await delay(25);
  const shutdown = f.server.shutdown(); gate.resolve();
  await shutdown; await Promise.all([first, queued]);
  assert.equal(calls, 1, 'waiting mutations cannot run after shutdown begins');
  assert.deepEqual(f.events, ['browser-close', 'proxy-stop']);
});

test('application lease requires owned managed runtime and a fresh pinned exit before opening its private gateway', async t => {
  let starts = 0, running = false;
  const applicationGateway = { status: () => ({ running }), stop: async () => { running = false; },
    start: async binding => { starts++; running = true; assert.equal(binding.upstreamPort, 17890); return { port: 19001, endpoint: '127.0.0.1:19001', url: 'http://127.0.0.1:19001', policy: 'private-direct-public-isp' }; } };
  const f = await fixture(t, { applicationGateway });
  await assert.rejects(f.server.applicationProxy(), { code: 'PROXY_STOPPED' }); assert.equal(starts, 0);
  assert.equal((await f.start()).status, 200); const before = f.probeCalls;
  const lease = await f.server.applicationProxy(); assert.equal(f.probeCalls, before, 'fresh session-bound proof is reused');
  assert.deepEqual([lease.port, lease.corePort, lease.mode, lease.exitStatus], [19001, 17890, 'http', 'verified']);
  assert.equal(lease.revision, f.server.state.revision); assert.equal(starts, 1);
  assert.doesNotMatch(JSON.stringify(lease), /secrets|credentials|fingerprint|vpnNodeHash/);
  const status = f.runtime.status;
  f.runtime.status = async () => ({ ...(await status()), managed: false });
  await assert.rejects(f.server.applicationProxy(), { code: 'PROXY_OFFLINE' }); assert.equal(starts, 1);
});

test('proof expiry while the gateway starts rejects a new lease and cleans up only a newly opened gateway', async t => {
  for (const existingGateway of [false, true]) {
    let f, running = false, starts = 0, stops = 0, expireOnStart = false;
    const applicationGateway = { status: () => ({ running }), stop: async () => { stops++; running = false; },
      start: async () => { starts++; running = true; if (expireOnStart) f.clock += 90_001; return { port: 19001 }; } };
    f = await fixture(t, { applicationGateway, state: { mode: 'tun', protections: { systemRouting: true } } });
    assert.equal((await f.start()).status, 200);
    if (existingGateway) assert.equal((await f.server.applicationProxy()).exitStatus, 'verified');
    const checkedAt = f.server.state.proxy.exit.checkedAt;
    const systemCheckedAt = f.server.state.proxy.systemExit.checkedAt;
    const originalStarts = starts; stops = 0; expireOnStart = true;
    await assert.rejects(f.server.applicationProxy(), { code: 'EXIT_UNVERIFIED' });
    assert.equal(starts, originalStarts + 1);
    assert.equal(running, existingGateway, 'Expired admission preserves only a gateway that existed before this attempt');
    assert.equal(stops, existingGateway ? 0 : 1);
    const expired = (await f.get('/api/snapshot')).data.data;
    assert.equal(expired.proxy.exitStatus, 'unverified'); assert.equal(expired.proxy.systemNetwork.status, 'unverified');
    assert.equal(expired.applicationProxy.running, existingGateway);
    assert.equal(f.server.state.proxy.exit.checkedAt, checkedAt, 'A delayed startup must never renew the proof');
    assert.equal(f.server.state.proxy.systemExit.checkedAt, systemCheckedAt);
    assert.equal(f.running, true); assert.equal(f.events.includes('proxy-stop'), false);
    assert.equal(f.probeCalls, 1); assert.equal(f.systemProbeCalls, 1);
  }
});

test('proof expiry during the final configuration read rejects admission before a gateway can start', async t => {
  let starts = 0, running = false;
  const applicationGateway = { status: () => ({ running }), stop: async () => { running = false; },
    start: async () => { starts++; running = true; return { port: 19001 }; } };
  const f = await fixture(t, { applicationGateway, state: { mode: 'tun', protections: { systemRouting: true } } });
  assert.equal((await f.start()).status, 200);
  const read = f.runtime.readConfig, checkedAt = f.server.state.proxy.exit.checkedAt;
  let reads = 0;
  f.runtime.readConfig = async () => {
    const config = await read();
    if (++reads === 2) f.clock += 90_001;
    return config;
  };
  await assert.rejects(f.server.applicationProxy(), { code: 'EXIT_UNVERIFIED' });
  assert.equal(reads, 2, 'The clock advances after the reused proof, inside the final saved-configuration read');
  assert.equal(starts, 0); assert.equal(running, false);
  const expired = (await f.get('/api/snapshot')).data.data;
  assert.equal(expired.proxy.exitStatus, 'unverified'); assert.equal(expired.proxy.systemNetwork.status, 'unverified');
  assert.equal(f.server.state.proxy.exit.checkedAt, checkedAt);
  assert.equal(f.running, true); assert.equal(f.events.includes('proxy-stop'), false);
  assert.equal(f.probeCalls, 1); assert.equal(f.systemProbeCalls, 1);
});

test('parallel plans and application leases reuse a fresh owned session while manual checks and expiry revalidate', async t => {
  const f = await fixture(t); f.sessionId = 'synthetic-owned-session-1'; await f.start();
  await Promise.all([f.plan(), f.plan(), f.server.applicationProxy(), f.server.applicationProxy()]);
  assert.equal(f.probeCalls, 1, 'serialized consumers reuse the same successful session-bound lease');
  assert.equal((await f.post('/api/probes')).status, 200); assert.equal(f.probeCalls, 2);
  f.clock += 90_001; assert.equal((await f.plan()).status, 200); assert.equal(f.probeCalls, 3);
  f.sessionId = 'synthetic-owned-session-2'; assert.equal((await f.plan()).status, 200); assert.equal(f.probeCalls, 4, 'new core identity cannot borrow the previous lease');
});

test('a pending forced exit check and temporary failure preserve only the original valid application lease', async t => {
  const f = await fixture(t); await f.start(); const lease = await f.server.applicationProxy();
  const original = (await f.get('/api/snapshot')).data.data.proxy.exit;
  const echo = net.createServer(socket => socket.pipe(socket)); const sockets = new Set();
  echo.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  await new Promise(resolve => echo.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => echo.close(resolve)); });
  const entered = deferred(), release = deferred();
  f.probe = async () => { entered.resolve(); await release.promise; throw failure('PROBE_TIMEOUT'); };
  const pending = f.post('/api/probes'); await entered.promise;
  let client;
  try {
    client = await connectTunnel({ host: 'localhost', port: echo.address().port, proxyPort: lease.port, timeoutMs: 1000 });
    const echoed = once(client, 'data'); client.write('LEASE_DURING_CHECK'); assert.equal((await echoed)[0].toString(), 'LEASE_DURING_CHECK');
  } finally { release.resolve(); }
  assert.equal((await pending).data.error.code, 'PROBE_TIMEOUT');
  const retained = (await f.get('/api/status')).data.data;
  assert.equal(retained.applicationProxy.running, true); assert.equal(f.running, true);
  assert.deepEqual(retained.proxy.exit, original);
  const stillEchoed = once(client, 'data'); client.write('LEASE_AFTER_SOFT_FAILURE'); assert.equal((await stillEchoed)[0].toString(), 'LEASE_AFTER_SOFT_FAILURE');
  client.destroy();
});

test('parallel application CONNECT requests share only the in-flight owned identity check and cannot borrow its result after revocation', async t => {
  const f = await fixture(t); await f.start(); const lease = await f.server.applicationProxy();
  const echo = net.createServer(socket => socket.pipe(socket)); const sockets = new Set();
  echo.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  await new Promise(resolve => echo.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise(resolve => echo.close(resolve)); });
  const status = f.runtime.status; let reads = 0; const entered = deferred(), release = deferred();
  f.runtime.status = async () => { reads++; entered.resolve(); await release.promise; return status(); };
  const clients = Promise.all(Array.from({ length: 8 }, () => connectTunnel({ host: 'localhost', port: echo.address().port, proxyPort: lease.port, timeoutMs: 1500 })));
  await entered.promise; await delay(25); assert.equal(reads, 1, 'concurrent requests must not queue eight CIM/TUN reads'); release.resolve();
  for (const client of await clients) client.destroy(); assert.equal(reads, 1); assert.equal(f.probeCalls, 1);
  const again = await connectTunnel({ host: 'localhost', port: echo.address().port, proxyPort: lease.port, timeoutMs: 1000 }); again.destroy();
  assert.equal(reads, 2, 'completed identity results are not silently cached');
  f.runtime.status = status;
  f.clock += 90_001;
  await assert.rejects(connectTunnel({ host: 'localhost', port: echo.address().port, proxyPort: lease.port, timeoutMs: 1000 }), { code: 'PROXY_CONNECT_REJECTED' });
});

test('application target checks are fixed HEAD requests through the application gateway and cache only current successful routes', async t => {
  let gatewayRunning = false; const observed = [];
  const applicationGateway = { status: () => ({ running: gatewayRunning }), stop: async () => { gatewayRunning = false; }, start: async () => { gatewayRunning = true; return { port: 19001 }; } };
  const f = await fixture(t, { applicationGateway, request: async (url, options) => { observed.push([url.href, options]); return { statusCode: 401, body: 'PRIVATE_BODY_IGNORED' }; } });
  await f.start();
  for (const body of [{ service: 'https://private.invalid/', path: 'proxy' }, { service: 'claude', path: 'proxy', url: 'https://private.invalid/' }]) assert.equal((await f.post('/api/applications/check', body)).status, 400);
  assert.equal(observed.length, 0);
  const result = (await f.post('/api/applications/check', { service: 'claude', path: 'proxy' })).data.data;
  assert.equal(result.status, 'reachable'); assert.equal(result.checks.length, 2); assert.equal(result.coverage.systemProtected, false);
  assert.deepEqual(observed.map(([url]) => url), ['https://api.anthropic.com/', 'https://claude.ai/']);
  for (const [, options] of observed) {
    const { signal, ...requestOptions } = options;
    assert(signal instanceof AbortSignal); assert.equal(signal.aborted, false);
    assert.deepEqual(requestOptions, { proxyPort: 19001, timeoutMs: 10000, method: 'HEAD', responseDetails: true });
  }
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_BODY|Cookie|authorization/);
  assert.equal((await f.server.checkApplicationTargets({ service: 'claude', path: 'proxy', force: false })).reused, true); assert.equal(observed.length, 2);
  await f.post('/api/applications/check', { service: 'claude', path: 'proxy' }); assert.equal(observed.length, 4, 'manual button checks afresh');
  f.clock += 60_001; await f.server.checkApplicationTargets({ service: 'claude', path: 'proxy', force: false }); assert.equal(observed.length, 6);
  assert.equal(f.probeCalls, 1, 'business checks do not repeat ISP verification within its lease');
});

test('system application checks require genuine fresh TUN and keep optional kill-switch coverage separate', async t => {
  for (const options of [{}, { state: { mode: 'tun' } }]) {
    const f = await fixture(t, options); await f.start();
    const response = await f.post('/api/applications/check', { service: 'claude', path: 'system' });
    assert.equal(response.data.error.code, 'APPLICATION_SYSTEM_UNVERIFIED');
    assert.equal((await f.get('/api/status')).data.data.applicationProxy.coverage.systemProtected, false);
  }
  const simulated = await fixture(t, { mock: true, state: { mode: 'tun', protections: { systemRouting: true, killSwitch: true } } }); await simulated.start();
  assert.equal((await simulated.post('/api/applications/check', { service: 'claude', path: 'system' })).data.data.status, 'mocked');
  assert.equal(simulated.requestCalls, 0); assert.equal(simulated.systemProbeCalls, 0);
  const requests = [];
  const f = await fixture(t, { state: { mode: 'tun', protections: { systemRouting: true, killSwitch: true }, networkLocked: true }, lockSimulation: true,
    directHttpsRequest: async (url, options) => { requests.push([url.href, options]); return { statusCode: 403, body: 'PRIVATE_RESTRICTION' }; } });
  await f.start(); assert.equal((await f.get('/api/status')).data.data.applicationProxy.coverage.systemProtected, true);
  const result = (await f.post('/api/applications/check', { service: 'codex', path: 'system' })).data.data;
  assert.equal(result.status, 'failed'); assert.equal(result.checks[0].code, 'TARGET_HTTP_RESTRICTED');
  assert.equal(requests.length, 2); assert.equal(requests[0][1].proxyPort, undefined); assert.equal(requests[0][1].method, 'HEAD');
  f.networkLocked = false;
  const unlocked = (await f.post('/api/applications/check', { service: 'codex', path: 'system' })).data.data;
  assert.equal(unlocked.transportReady, true); assert.equal(unlocked.coverage.systemExitVerified, true);
  assert.equal(unlocked.coverage.systemProtected, false); assert.equal(requests.length, 4);
});

test('DNS startup failure is a fixed public error and application routing keeps the optional-lock wording', async t => {
  const f = await fixture(t);
  f.runtime.start = async () => { throw failure('DNS_CACHE_CLEAR_FAILED'); };
  const response = await f.start();
  assert.equal(response.data.error.code, 'DNS_CACHE_CLEAR_FAILED'); assert.match(response.data.error.message, /DNS.*缓存/);
  assert.doesNotMatch(JSON.stringify(response.data), /private credential/);
  assert.equal(f.server.state.lastError.code, 'DNS_CACHE_CLEAR_FAILED');
  f.config.connectionMode = 'vpn-import';
  const status = (await f.get('/api/status')).data.data;
  assert.match(status.protection.statement, /需要已核验的全局 TUN；断网锁可选/);
});

test('application target failures are diagnostic only and never change a verified exit into a business success', async t => {
  const diagnostics = [];
  const f = await fixture(t, { request: async () => { throw failure('PROXY_CONNECT_REJECTED'); }, onDiagnostic: event => diagnostics.push(event) }); await f.start();
  const result = (await f.post('/api/applications/check', { service: 'claude', path: 'proxy' })).data.data;
  assert.equal(result.status, 'failed'); assert.equal(result.checks[0].code, 'PROXY_CONNECT_REJECTED'); assert.equal(f.running, true);
  assert.equal(result.transportReady, false); assert.equal(result.checks[0].transportReachable, false);
  assert.equal((await f.get('/api/status')).data.data.proxy.exitStatus, 'verified');
  assert.doesNotMatch(JSON.stringify([result, diagnostics]), /private credential/);
});

test('verified TLS with HTTP 403 or 421 is transport ready while retaining the business restriction and failure states', async t => {
  const f = await fixture(t, { request: async url => ({ statusCode: url.hostname === 'api.openai.com' ? 421 : 403, body: 'PRIVATE_WAF_RESPONSE' }) }); await f.start();
  const result = (await f.post('/api/applications/check', { service: 'codex', path: 'proxy' })).data.data;
  assert.equal(result.transportReady, true); assert.equal(result.status, 'failed'); assert.equal(result.code, 'APPLICATION_TARGETS_FAILED');
  assert.deepEqual(result.checks.map(check => [check.httpStatus, check.transportReachable, check.status, check.code]), [[421, true, 'failed', 'TARGET_HTTP_FAILED'], [403, true, 'failed', 'TARGET_HTTP_RESTRICTED']]);
  assert.equal((await f.server.checkApplicationTargets({ service: 'codex', path: 'proxy', force: false })).reused, true);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_WAF_RESPONSE/);
});

test('a CONNECT 502 or TLS failure never claims target transport readiness', async t => {
  for (const code of ['PROXY_CONNECT_REJECTED', 'PROBE_TLS_OR_SOCKET_FAILED']) {
    const f = await fixture(t, { request: async () => { throw Object.assign(failure(code), { diagnostic: { httpStatus: 502 } }); } }); await f.start();
    const result = (await f.post('/api/applications/check', { service: 'claude', path: 'proxy' })).data.data;
    assert.equal(result.transportReady, false); assert.equal(result.status, 'failed'); assert.ok(result.checks.every(check => check.transportReachable === false && check.code === code));
  }
});

test('trusted TUN application leases force local protection reads and stop when the actual TUN readiness disappeared', async t => {
  const f = await fixture(t, { state: { mode: 'tun', protections: { systemRouting: true, killSwitch: true }, networkLocked: true }, lockSimulation: true }); await f.start();
  const read = f.runtime.status; let forced = 0;
  f.runtime.status = async options => { if (options?.force) forced++; return { ...(await read()), tunReady: !options?.force }; };
  await assert.rejects(f.server.applicationProxy(), { code: 'TUN_NOT_READY' });
  assert.ok(forced > 0); assert.equal(f.running, false); assert.equal(f.networkLocked, true); assert.equal(f.server.state.proxy.requestedStop, true);
});

test('system target checks use force TUN reads instead of accepting the displayed cached readiness', async t => {
  const f = await fixture(t, { state: { mode: 'tun', protections: { systemRouting: true, killSwitch: true }, networkLocked: true }, lockSimulation: true }); await f.start();
  let forced = 0;
  const read = f.runtime.status;
  f.runtime.status = async options => { if (options?.force) forced++; return { ...(await read()), tunReady: !options?.force }; };
  assert.equal((await f.post('/api/applications/check', { service: 'claude', path: 'system' })).data.error.code, 'TUN_NOT_READY');
  assert.ok(forced > 0); assert.equal(f.requestCalls, 0);
});

test('a superseded system-target protection read cannot stop the current core or alter a resumed network proof', { timeout: 3000 }, async t => {
  for (const resumeBeforeRelease of [false, true]) {
    let targets = 0, gatewayRunning = false;
    const gateway = { status: () => ({ running: gatewayRunning }), stop: async () => { gatewayRunning = false; },
      start: async () => { gatewayRunning = true; return { port: 19001 }; } };
    const f = await fixture(t, { state: { mode: 'tun', protections: { systemRouting: true } }, applicationGateway: gateway,
      directHttpsRequest: () => { targets++; assert.fail('A superseded protection read must not send a target request'); } });
    assert.equal((await f.start()).status, 200);
    const original = structuredClone(f.server.state.proxy.exit);
    const read = f.runtime.status, entered = deferred(), release = deferred();
    // Separate the lease's lightweight identity check from the force read that
    // belongs to the system-target protection helper under review.
    f.runtime.inspectOwnedState = () => read();
    f.runtime.status = async options => {
      assert.equal(options?.force, true);
      entered.resolve(); await release.promise;
      return read();
    };
    t.after(() => release.resolve());
    const pending = f.post('/api/applications/check', { service: 'claude', path: 'system' });
    await entered.promise;
    f.server.suspendNetwork();
    const suspended = (await f.get('/api/snapshot')).data.data;
    assert.equal(suspended.networkLifecycle.state, 'suspended'); assert.equal(suspended.proxy.exitStatus, 'unverified');
    assert.equal(suspended.proxy.exit, null); assert.equal(f.running, true);
    f.clock += 50;
    const resumed = resumeBeforeRelease ? f.server.networkChanged('resume') : null;
    release.resolve();
    assert.equal((await pending).data.error.code, 'SESSION_CHANGED');
    assert.equal(f.events.includes('proxy-stop'), false, 'The old force-read catch must ignore SESSION_CHANGED');
    assert.equal(f.running, true); assert.equal(targets, 0);
    if (!resumeBeforeRelease) {
      const afterOld = (await f.get('/api/snapshot')).data.data;
      assert.equal(afterOld.networkLifecycle.state, 'suspended'); assert.equal(afterOld.proxy.exitStatus, 'unverified');
      assert.equal(afterOld.lastError, null, 'The obsolete check must not overwrite current diagnostic state');
    }
    const restored = await (resumed || f.server.networkChanged('resume'));
    assert.equal(restored.networkLifecycle.state, 'stable'); assert.equal(restored.proxy.exitStatus, 'verified');
    assert.equal(restored.proxy.systemNetwork.status, 'verified'); assert.equal(restored.lastError, null);
    assert.equal(f.server.state.proxy.exit.checkedAt, f.clock); assert.notEqual(f.server.state.proxy.exit.binding, original.binding);
    assert.equal(f.probeCalls, 2); assert.equal(f.systemProbeCalls, 2);
    assert.equal(f.running, true); assert.equal(f.events.includes('proxy-stop'), false);
  }
});

test('explicit environment optimization requests only geography and never opts into external website reports', async t => {
  const requested = [];
  const f = await fixture(t, { autoReport: true, request: async (url, options) => { requested.push(url.hostname); assert.equal(url.hostname, 'ipwho.is'); assert.equal(options.proxyPort, 17890);
    return JSON.stringify({ success: true, ip: '203.0.113.8', country_code: 'JP', timezone: { id: 'Asia/Tokyo' }, city: 'Tokyo' }); } });
  assert.equal((await f.post('/api/proxy/start', { confirm: true, externalReport: 'yes' })).status, 400);
  assert.equal((await f.post('/api/proxy/start', { confirm: true, optimize: true })).status, 200);
  assert.equal(f.requestCalls, 1); assert.equal(f.probeCalls, 1); assert.equal(f.running, true);
  assert.equal((await f.post('/api/environment/optimize', { confirm: true })).status, 200);
  assert.deepEqual(requested, ['ipwho.is', 'ipwho.is']); assert.equal(f.probeCalls, 1);
  assert.equal((await f.get('/api/status')).data.data.report, null);
});

test('fixed quality links launch only the selected managed browser and reuse a fresh ISP lease', async t => {
  const f = await fixture(t); await f.start();
  const originalPlan = f.browsers.plan; const choices = [];
  f.browsers.plan = async options => { choices.push(options); const planned = await originalPlan(options);
    assert.equal(planned.url, { ping0: 'https://ping0.cc/', cleanip: 'https://cleanip.io/claude', claude: 'https://claude.ai/', tiktok: 'https://www.tiktok.com/' }[options.service]); return planned; };
  assert.equal((await f.server.openWebsite('ping0')).launched, true); assert.equal(choices[0].service, 'ping0'); assert.equal(f.probeCalls, 1);
  await assert.rejects(f.server.openWebsite('https://unknown.invalid/'), { code: 'SERVICE_INVALID' });
  await assert.rejects(f.server.openWebsite('cleanip'), { code: 'BROWSER_ALREADY_RUNNING' });
  for (const service of ['claude', 'tiktok']) {
    await f.post('/api/browser/close', { confirm: true });
    assert.equal((await f.server.openWebsite(service)).launched, true); assert.equal(choices.at(-1).service, service);
  }
  assert.equal(f.probeCalls, 1, 'all fixed website services reuse the fresh owned session');
  for (const service of ['https://claude.ai/', 'https://www.tiktok.com/', 'https://unknown.invalid/', 'unknown']) await assert.rejects(f.server.openWebsite(service), { code: 'SERVICE_INVALID' });
  assert.equal(choices[0].browser, 'chrome'); assert.equal(choices[0].fresh, false, 'new default keeps a retained Chrome profile in tray/IPC website entry');
  await f.post('/api/browser/close', { confirm: true });
  await f.post('/api/onboarding/preferences', { browser: 'fingerprint', fingerprintFresh: true });
  await f.server.openWebsite('claude'); assert.equal(choices.at(-1).fresh, true, 'tray/IPC honors the fingerprint pure-profile preference');
  await f.post('/api/browser/close', { confirm: true });
  await f.post('/api/onboarding/preferences', { browser: 'chrome', fresh: true });
  await f.server.openWebsite('claude'); assert.equal(choices.at(-1).browser, 'chrome'); assert.equal(choices.at(-1).fresh, true, 'explicit compatibility browser keeps its independent preference');
});

test('soft failure and proof expiry preserve existing HTTP streams while denying new ones; a real mismatch still closes the gateway', async t => {
  const f = await fixture(t); assert.equal((await f.start()).status, 200);
  assert.equal(f.server.state.proxy.mode, 'http');
  const echoSockets = new Set();
  const echo = net.createServer(socket => { echoSockets.add(socket); socket.once('close', () => echoSockets.delete(socket)); socket.pipe(socket); });
  await new Promise(resolve => echo.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const socket of echoSockets) socket.destroy(); await new Promise(resolve => echo.close(resolve)); });
  const lease = await f.server.applicationProxy();
  const client = await connectTunnel({ host: 'localhost', port: echo.address().port, proxyPort: lease.port, timeoutMs: 1000 });
  t.after(() => client.destroy());
  const payload = once(client, 'data'); client.write('LOCAL_MCP_FIXTURE'); assert.equal((await payload)[0].toString(), 'LOCAL_MCP_FIXTURE');
  const original = (await f.get('/api/snapshot')).data.data.proxy.exit;
  f.probe = async () => { throw failure('PROBE_TIMEOUT'); };
  const result = await f.post('/api/probes'); assert.equal(result.data.error.code, 'PROBE_TIMEOUT');
  const retained = (await f.get('/api/snapshot')).data.data;
  assert.equal(retained.applicationProxy.running, true); assert.equal(f.running, true);
  assert.deepEqual(retained.proxy.exit, original);
  f.clock += 90_001;
  assert.equal((await f.get('/api/snapshot')).data.data.proxy.exitStatus, 'unverified');
  await assert.rejects(connectTunnel({ host: 'localhost', port: echo.address().port, proxyPort: lease.port, timeoutMs: 1000 }));
  await assert.rejects(f.server.applicationProxy(), { code: 'PROBE_TIMEOUT' });
  const stillEchoed = once(client, 'data'); client.write('LOCAL_MCP_EXISTING_STREAM'); assert.equal((await stillEchoed)[0].toString(), 'LOCAL_MCP_EXISTING_STREAM');
  assert.equal(f.running, true);
  const closed = once(client, 'close');
  f.probe = async () => { throw failure('EXIT_IP_MISMATCH'); };
  assert.equal((await f.post('/api/probes')).data.error.code, 'EXIT_IP_MISMATCH');
  let timer;
  try { await Promise.race([closed, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('revoked application socket stayed open')), 500); })]); }
  finally { clearTimeout(timer); }
  const status = (await f.get('/api/status')).data.data;
  assert.equal(status.applicationProxy.running, true); assert.equal(status.applicationProxy.accepting, false); assert.equal(status.proxy.running, false); assert.equal(status.proxy.requestedStop, true);
});

test('late application-gateway startup is revoked when shutdown changes the lease revision while it waits', async t => {
  const entered = deferred(), release = deferred(), cleaning = deferred(), cleanupRelease = deferred();
  let running = false, stoppedAfterStart = false, settled = false;
  const gateway = { status: () => ({ running }), start: async () => { entered.resolve(); await release.promise; running = true; return { port: 19001 }; },
    stop: async () => { if (running) { cleaning.resolve(); await cleanupRelease.promise; stoppedAfterStart = true; } running = false; } };
  const f = await fixture(t, { applicationGateway: gateway }); assert.equal((await f.start()).status, 200);
  const granting = f.server.applicationProxy(); await entered.promise;
  void granting.then(() => { settled = true; }, () => { settled = true; });
  const shutdown = f.server.shutdown(); release.resolve();
  await cleaning.promise;
  try { await delay(5); assert.equal(settled, false, 'failed lease grant must finish its gateway cleanup before rejecting'); }
  finally { cleanupRelease.resolve(); }
  await assert.rejects(granting, { code: 'SESSION_CHANGED' }); await shutdown;
  assert.equal(stoppedAfterStart, true); assert.equal(running, false);
  await assert.rejects(f.server.applicationProxy(), { code: 'SERVICE_STOPPING' });
});

test('application gateway is stopped before core on explicit end and repair, while mock grants create no native gateway', async t => {
  let running = false, starts = 0;
  const gateway = { status: () => ({ running }), start: async () => { starts++; running = true; return { port: 19001 }; }, stop: async () => { running = false; } };
  const f = await fixture(t, { applicationGateway: gateway });
  const stopCore = f.runtime.stop;
  f.runtime.stop = async () => { assert.equal(running, false, 'application sockets must close before their owned core'); await stopCore(); };
  assert.equal((await f.start()).status, 200); await f.server.applicationProxy(); await f.stop(); assert.equal(running, false);
  assert.equal((await f.start()).status, 200); await f.server.applicationProxy(); await f.server.beginNetworkRepair();
  await assert.rejects(f.server.applicationProxy(), { code: 'SERVICE_REPAIRING' }); assert.equal(starts, 2); await f.server.finishNetworkRepair();
  const mock = await fixture(t, { mock: true, applicationGateway: { status: () => ({ running: false }), stop: async () => {}, start: () => assert.fail('mock must not open a native proxy') } });
  assert.equal((await mock.start()).status, 200); const lease = await mock.server.applicationProxy();
  assert.equal(lease.mock, true); assert.equal(lease.exitStatus, 'mocked');
});

test('imported global preflight rejects external VPN or unavailable interface state before screening, ISP or core work', async t => {
  for (const code of ['GLOBAL_VPN_CONFLICT', 'VPN_INTERFACE_STATE_UNAVAILABLE']) {
    let guarded = 0, verified = 0;
    const f = await fixture(t, { shortlistImportedNodes: () => assert.fail('global conflict must precede any endpoint screen'),
      setupVerifier: { verify: async () => { verified++; return latencyResult(10); } } });
    f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) }); await f.get('/api/status');
    f.runtime.assertGlobalReady = async () => { guarded++; throw failure(code); };
    const before = f.server.state.revision;
    const result = await f.post('/api/proxy/start', { confirm: true, mode: 'tun' });
    assert.equal(result.data.error.code, code); assert.equal(guarded, 1); assert.equal(verified, 0);
    assert.equal(f.events.includes('proxy-start'), false); assert.equal(f.probeCalls, 0); assert.equal(f.systemProbeCalls, 0);
    assert.equal(f.server.state.revision, before, 'a rejected preflight cannot mutate session identity');
    assert.doesNotMatch(JSON.stringify(result.data), /private credential/);
  }
});

test('imported global mode forwards the validated node to TUN and requires a matching live system exit', async t => {
  let guards = 0, verified = 0;
  const f = await fixture(t, { setupVerifier: { verify: async input => { verified++; assert.equal(input.vpnNode.server, 'fixture-node-1.test'); return latencyResult(20); } } });
  f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) }); await f.get('/api/status');
  f.runtime.assertGlobalReady = async () => { guards++; return { ready: true }; };
  const start = f.runtime.start;
  f.runtime.start = async input => { f.mode = input.mode; return start(input); };
  const result = await f.post('/api/proxy/start', { confirm: true, mode: 'tun' }); assert.equal(result.status, 200);
  assert.equal(guards, 1); assert.equal(verified, 1); assert.equal(f.startInput.mode, 'tun'); assert.ok(f.startInput.vpnNode);
  assert.equal(f.startInput.vpnProxy, undefined); assert.equal(f.systemProbeCalls, 1); assert.equal(result.data.data.proxy.systemNetwork.status, 'verified');
  await f.stop(); guards = 0; f.mode = 'http';
  assert.equal((await f.start()).status, 200); assert.equal(guards, 0, 'HTTP import leaves external VPN interfaces alone');
});

test('locked imported TUN reconnect selects only the protected saved node without temporary checks, DNS or credential discovery', async t => {
  const f = await fixture(t, { lockSimulation: true, state: { mode: 'tun' },
    setupVerifier: { verify: () => assert.fail('locked reconnect must not launch a temporary HTTP core'), recoverAndStop: async () => ({ stopped: true }) },
    importedTcpProbe: () => assert.fail('locked reconnect must not perform physical endpoint probes'), loadSecrets: () => assert.fail('controller must not discover credentials on a locked reconnect') });
  f.config.connectionMode = 'vpn-import'; await f.post('/api/vpn/import', { confirm: true, text: importedYaml(1) }); await f.get('/api/status');
  f.networkLocked = true; let resumed = 0;
  f.runtime.resumeImportedNode = async ({ config, nodes }) => { resumed++; assert.equal(config.connectionMode, 'vpn-import'); assert.equal(nodes.length, 1); return nodes[0].outbound; };
  const result = await f.post('/api/proxy/start', { confirm: true, mode: 'tun' });
  assert.equal(result.status, 200, JSON.stringify(result.data)); assert.equal(resumed, 1); assert.equal(result.data.data.proxy.systemNetwork.status, 'verified');
  assert.equal(f.networkLocked, true); assert.equal(f.events.includes('network-unlock'), false); assert.equal(f.probeCalls, 1); assert.equal(f.systemProbeCalls, 1);
});
