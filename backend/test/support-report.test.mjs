import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, readFile, readdir, rm, symlink } from 'node:fs/promises';
import { createSupportReport, writeSupportReport } from '../src/support-report.mjs';

const now = () => Date.parse('2026-10-13T00:00:00.000Z');
const leak = 'PRIVATE_TOKEN_198.51.100.27_https://secret.fixture/C:\\private\\profile';
const status = () => ({ service: { mock: false }, configuration: { connectionMode: 'vpn-import', upstream: { password: leak } },
  proxy: { running: true, managed: true, requestedStop: false, exitStatus: 'verified', mode: 'tun', routingMode: 'global', systemNetwork: { status: 'verified', ip: leak }, exitIp: leak },
  license: { required: true, allowed: true, state: 'active', licenseId: leak, deviceId: leak },
  lastError: { code: 'CHAIN_TIMEOUT', message: leak, diagnostic: { url: leak, password: leak } },
  browserObservation: { status: 'completed', session: leak, report: { checks: [{ id: 'https-exit', status: 'verified', value: leak }, { id: 'webrtc', status: 'unverified', candidates: [leak] }] } },
  workspaces: { count: 2, phase: 'ready', items: [{ name: leak, seed: leak, path: leak }] } });

test('one report preserves layered evidence and explicit untested checks without any raw customer material or mutation', () => {
  const input = status(), before = structuredClone(input);
  const report = createSupportReport({ version: '1.6.2', status: input, now, targetCheck: { status: 'failed', checks: [{ transportReachable: false, url: leak, message: leak }] } });
  assert.equal(report.createdAt, '2026-10-13T00:00:00.000Z'); assert.equal(report.summary.version, '1.6.2');
  assert.equal(report.summary.code, 'CHAIN_TIMEOUT'); assert.equal(report.summary.connectionMode, 'vpn-import');
  assert.equal(report.diagnosis.layers.find(row => row.id === 'isp').status, 'verified');
  assert.equal(report.diagnosis.layers.find(row => row.id === 'browser').status, 'unverified');
  assert.equal(report.diagnosis.layers.find(row => row.id === 'target').status, 'failed');
  assert.match(report.diagnosis.layers.find(row => row.id === 'target').detail, /无法独立区分/);
  assert.equal(report.privacy.redacted, true); assert.equal(report.privacy.uploaded, false);
  assert.ok(report.untested.includes('browser:dns')); assert.ok(report.untested.includes('account-login'));
  assert.ok(report.untested.includes('provider-account-status')); assert.ok(report.untested.includes('continuous-connection-stability'));
  assert.deepEqual(input, before);
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE|198\.51|https?:\/\/|C:\\|licenseId|deviceId|password|seed|"candidates":\[|session|userAgent/);
});

test('unknown enums, arbitrary error text, null checks and invalid shapes cannot be exported as strings or masquerade as passed', () => {
  const report = createSupportReport({ version: leak, now, status: { phase: leak, proxy: { running: leak, managed: leak, mode: leak },
    license: { state: leak }, lastError: { code: leak, message: leak }, browserObservation: { status: 'completed', report: { checks: [null, { id: leak, status: leak }] } }, workspaces: { phase: leak } },
    targetCheck: { status: leak, checks: [null, { targetHttpStatus: leak, transportReachable: leak }] } });
  assert.equal(report.summary.version, 'unknown'); assert.equal(report.summary.code, 'OPERATION_FAILED');
  assert.equal(report.diagnosis.layers.find(row => row.id === 'isp').status, 'unverified');
  assert.equal(report.diagnosis.layers.find(row => row.id === 'target').status, 'failed');
  assert.equal(report.license.state, 'unknown'); assert.doesNotMatch(JSON.stringify(report), /PRIVATE|secret\.fixture|198\.51/);
  assert.doesNotThrow(() => createSupportReport({ status: null }));
});

test('HTTP restriction remains a target restriction, and mocked evidence is never promoted to a real pass', () => {
  const restricted = createSupportReport({ now, status: status(), targetCheck: { status: 'reachable', checks: [{ transportReachable: true, httpStatus: 403 }] } });
  assert.equal(restricted.diagnosis.layers.find(row => row.id === 'target').status, 'restricted');
  const mocked = createSupportReport({ now, status: { ...status(), service: { mock: true } }, targetCheck: { status: 'mocked', checks: [{ transportReachable: true, httpStatus: 200 }] } });
  assert.equal(mocked.summary.simulation, true); assert.equal(mocked.diagnosis.layers.every(row => row.status === 'mocked'), true);
});

test('local export writes a unique readable sanitized JSON with no overwrite and refuses junction destinations', async t => {
  const root = await mkdtemp(path.resolve(import.meta.dirname, '.support-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const first = await writeSupportReport({ directory: root, version: '1.6.2', status: status(), now });
  const second = await writeSupportReport({ directory: root, version: '1.6.2', status: status(), now });
  assert.notEqual(first.path, second.path); assert.equal(path.dirname(first.path), root);
  assert.deepEqual(JSON.parse(await readFile(first.path, 'utf8')), first.report);
  assert.doesNotMatch(await readFile(first.path, 'utf8'), /PRIVATE|https?:\/\/|198\.51/);
  assert.equal((await readdir(root)).filter(name => name.endsWith('.json')).length, 2);
  const link = path.join(root, 'linked'); await symlink(root, link, process.platform === 'win32' ? 'junction' : 'dir');
  await assert.rejects(writeSupportReport({ directory: link, status: status(), now }), { code: 'SUPPORT_REPORT_WRITE_FAILED' });
  await assert.rejects(writeSupportReport({ directory: 'relative-path', now }), { code: 'SUPPORT_REPORT_WRITE_FAILED' });
});
