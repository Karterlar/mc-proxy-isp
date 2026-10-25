import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createLicensePage, licenseView, validateLicenseImport, MAX_LICENSE_IMPORT_BYTES } from '../../frontend/license-page.js';

const html = await readFile(new URL('../../frontend/index.html', import.meta.url), 'utf8');
const active = { mode: 'required', status: 'active', allowed: true, licenseId: 'customer-01', deviceId: 'device-01',
  expiresAt: '2026-11-05T00:00:00Z', offlineUntil: '2026-10-09T00:00:00Z', ispExpiresAt: '2026-11-04T00:00:00Z' };

function fixture(implementation = async () => active, clipboard) {
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => [id, {
    value: '', textContent: '', hidden: false, disabled: false, dataset: {}, listeners: {},
    setAttribute(name, value) { this[name] = value; },
    addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); },
    async dispatch(type, event = {}) { for (const listener of this.listeners[type] || []) await listener({ preventDefault() {}, ...event }); },
    click() { return this.dispatch('click'); }, focus() { this.focused = true; }, select() { this.selected = true; },
  }]));
  const calls = [], updates = [];
  const node = id => { assert.ok(nodes.has(id), `Missing markup for ${id}`); return nodes.get(id); };
  const page = createLicensePage({ root: { querySelector: selector => node(selector.slice(1)) },
    request: async (...args) => { calls.push(args); return implementation(...args); }, onStatus: status => updates.push(status), clipboard });
  return { page, node, calls, updates };
}

test('only an explicit development mode is unrestricted; unknown and initializing licenses await confirmation', () => {
  for (const input of [undefined, {}, { status: 'active' }, { mode: 'future', status: 'active' }, { mode: 'required', status: 'initializing' }, { mode: 'required', status: 'development' }]) {
    const view = licenseView(input);
    assert.equal(view.title, '授权状态待确认');
    assert.equal(view.development, false);
    assert.equal(view.confirmed, false);
    assert.equal(view.onlineAvailable, false);
    assert.match(view.termExplanation, /信息待确认/);
  }
  assert.equal(licenseView({ mode: 'development' }).title, '开发者版 · 无授权限制');
  const view = licenseView(active);
  assert.equal(view.state, 'active');
  assert.equal(view.licenseId, 'customer-01');
  assert.notEqual(view.offlineUntil, view.expiresAt);
  assert.notEqual(view.ispExpiresAt, view.expiresAt);
  assert.equal(view.vpsExpiresAt, '未使用或尚未登记');
  assert.equal(licenseView({ mode: 'required', status: 'offline-expired' }).title, '离线许可已到期');
});

test('license import limits actual UTF-8 bytes and accepts only a JSON object', () => {
  const exact = `{"v":"${'a'.repeat(MAX_LICENSE_IMPORT_BYTES - 8)}"}`;
  assert.equal(new TextEncoder().encode(exact).byteLength, MAX_LICENSE_IMPORT_BYTES);
  assert.equal(validateLicenseImport(exact), exact);
  assert.equal(validateLicenseImport('\uFEFF{"signature":"fixture"}'), '\uFEFF{"signature":"fixture"}');
  assert.throws(() => validateLicenseImport(`{"v":"${'界'.repeat(12000)}"}`), /32 KiB/);
  for (const value of ['', 'not-json', 'null', '[]', '"text"']) assert.throws(() => validateLicenseImport(value));
});

test('v2 software access and customer-maintained resources have separate labels while v1 explains its original limit', () => {
  const customer = licenseView({ ...active, licenseVersion: 2, resourcesMode: 'customer', ispExpiresAt: null, vpsExpiresAt: null });
  assert.equal(customer.ispExpiresAt, '客户自备 · 自行维护'); assert.match(customer.termExplanation, /不限制软件授权期限/);
  assert.equal(customer.vpsExpiresAt, '免费可选中转 · 独立维护'); assert.match(customer.termExplanation, /免费可选入口/);
  const included = licenseView({ ...active, licenseVersion: 2, resourcesMode: 'included' });
  assert.match(included.termExplanation, /仅作资源提醒/); assert.match(included.termExplanation, /不会截短软件使用权/);
  const expired = licenseView({ ...active, licenseVersion: 2, resourcesMode: 'included', status: 'expired' });
  assert.equal(expired.title, '软件授权已到期'); assert.match(expired.detail, /独立维护/);
  const legacy = licenseView({ ...active, licenseVersion: 1 });
  assert.match(legacy.termExplanation, /原有线路期限限制/); assert.match(legacy.termExplanation, /免费重签/);
});

test('protocol epoch milliseconds and error code strings display alongside older ISO fixtures', () => {
  const timestamp = Date.parse(active.expiresAt);
  const numeric = licenseView({ ...active, expiresAt: timestamp, ispExpiresAt: timestamp + 86400000, lastCheckedAt: 0, lastError: 'LICENSE_TIMEOUT' });
  assert.equal(numeric.expiresAt, licenseView(active).expiresAt);
  assert.notEqual(numeric.ispExpiresAt, numeric.expiresAt);
  assert.equal(numeric.checked, `最近检查：${new Date(0).toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })}`);
  assert.match(numeric.error, /LICENSE_TIMEOUT/);
  assert.match(licenseView({ ...active, lastError: { code: 'LICENSE_TIMEOUT' } }).error, /LICENSE_TIMEOUT/);
  for (const expiresAt of [null, undefined, -1, 1.5, Number.MAX_SAFE_INTEGER, NaN, {}, 'invalid date']) assert.equal(licenseView({ ...active, expiresAt }).expiresAt, '尚未登记');
  assert.equal(licenseView({ ...active, status: 'expired' }).title, '授权或线路已到期');
});

test('rendering snapshots sends no requests; opening reads local state only', async () => {
  const f = fixture();
  for (let index = 0; index < 30; index++) f.page.render(active);
  assert.equal(f.calls.length, 0);
  await f.page.open();
  assert.deepEqual(f.calls.map(([endpoint]) => endpoint), ['/api/license/status']);
  assert.equal(f.updates[0], active);
  assert.match(f.node('licenseOperationResult').textContent, /未发起云端刷新/);
});

test('card clears before the request settles and authorization busy leaves navigation and connection alone', async () => {
  let resolve;
  const f = fixture(() => new Promise(done => { resolve = done; }));
  f.page.render({ mode: 'required', status: 'unactivated' });
  f.node('licenseCard').value = 'private-card-123';
  const pending = f.node('licenseActivationForm').dispatch('submit');
  assert.equal(f.node('licenseCard').value, '');
  assert.equal(f.node('licenseActivateButton').disabled, true);
  for (const id of ['connectButton', 'safeQuitButton', 'licenseBackButton', 'networkRepairButton']) assert.equal(f.node(id).disabled, false);
  assert.deepEqual(f.calls[0].slice(0, 2), ['/api/license/activate', { card: 'private-card-123' }]);
  f.node('licenseCard').value = 'second-card';
  await f.node('licenseActivationForm').dispatch('submit');
  assert.equal(f.calls.length, 1);
  assert.equal(f.node('licenseCard').value, '');
  resolve(active); await pending;
  assert.equal(f.node('licenseActivateButton').disabled, false);
});

test('failed mutations display safe fixed text without echoed card or license contents', async () => {
  const secret = 'never-display-secret-card';
  const f = fixture(async () => { throw Object.assign(new Error(secret), { code: 'LICENSE_CARD_INVALID' }); });
  f.page.render(active); f.node('licenseCard').value = secret;
  await f.node('licenseActivationForm').dispatch('submit');
  assert.equal(f.node('licenseCard').value, '');
  assert.ok(!f.node('licenseOperationResult').textContent.includes(secret));
  assert.match(f.node('licenseOperationResult').textContent, /LICENSE_CARD_INVALID/);
});

test('device application is read-only and copying uses only the returned public application', async () => {
  const application = { deviceId: 'device-01', publicKey: 'fixture-public-key', format: 'mc-proxy-device' }, copied = [];
  const f = fixture(async endpoint => endpoint === '/api/license/device' ? { application } : active, { writeText: async text => copied.push(text) });
  f.page.render(active);
  await f.node('licenseDeviceButton').click();
  await f.node('licenseCopyDeviceButton').click();
  assert.deepEqual(JSON.parse(copied[0]), application);
  assert.deepEqual(f.calls.map(([endpoint]) => endpoint), ['/api/license/device']);
  assert.match(html, /id="licenseDeviceApplication"[^>]*readonly/);
});

test('invalid or oversized files never reach the controller; paste clears immediately', async () => {
  const f = fixture(); f.page.render(active);
  for (const file of [{ name: 'permit.txt', size: 4 }, { name: 'permit.json', size: MAX_LICENSE_IMPORT_BYTES + 1 }]) {
    f.node('licenseImportFile').files = [file]; await f.node('licenseImportFile').dispatch('change');
  }
  assert.equal(f.calls.length, 0);
  f.node('licenseImportText').value = 'invalid JSON'; await f.node('licenseImportButton').click();
  assert.equal(f.node('licenseImportText').value, ''); assert.equal(f.calls.length, 0);
  const text = '{"signature":"fixture"}';
  f.node('licenseImportText').value = text; await f.node('licenseImportButton').click();
  assert.equal(f.node('licenseImportText').value, '');
  assert.deepEqual(f.calls[0].slice(0, 2), ['/api/license/import', { text }]);
});

test('explicit refresh is separate; development controls cannot submit a card', async () => {
  const f = fixture(); f.page.render(active);
  await f.node('licenseRefreshButton').click();
  assert.deepEqual(f.calls[0].slice(0, 2), ['/api/license/refresh', {}]);
  f.page.render({ mode: 'development' }); f.node('licenseCard').value = 'private-card';
  await f.node('licenseActivationForm').dispatch('submit');
  assert.equal(f.node('licenseCard').value, ''); assert.equal(f.calls.length, 1);
});

test('offline-only delivery blocks online activation and refresh without reporting a generic error', async () => {
  const f = fixture();
  f.page.render({ mode: 'required', status: 'unactivated', onlineAvailable: false });
  assert.equal(f.node('licenseOnlineNotice').hidden, false);
  assert.match(f.node('licenseStateDetail').textContent, /设备的申请/);
  assert.equal(f.node('licenseActivationForm')['aria-disabled'], 'true');
  for (const id of ['licenseCard', 'licenseActivateButton', 'licenseRefreshButton']) assert.equal(f.node(id).disabled, true);
  f.node('licenseCard').value = 'never-submit-offline-card';
  await f.node('licenseActivationForm').dispatch('submit');
  await f.node('licenseRefreshButton').click();
  assert.equal(f.node('licenseCard').value, '');
  assert.equal(f.calls.length, 0);
  assert.equal(f.node('licenseOperationResult').textContent, '在线卡密激活待服务上线；当前使用设备申请与签名许可导入');
  assert.equal(f.node('licenseOperationResult').dataset.error, 'false');
  assert.equal(f.node('licenseLastError').hidden, true);
  f.page.render({ ...active, onlineAvailable: true });
  for (const id of ['licenseCard', 'licenseActivateButton', 'licenseRefreshButton']) assert.equal(f.node(id).disabled, false);
  assert.equal(f.node('licenseOnlineNotice').hidden, true);
  assert.equal(f.node('licenseActivationForm')['aria-disabled'], 'false');
  f.page.render(active);
  assert.equal(f.node('licenseRefreshButton').disabled, false);
  f.page.render({ mode: 'development', onlineAvailable: false });
  assert.equal(f.node('licenseState').textContent, '开发者版 · 无授权限制');
  assert.equal(f.node('licenseOnlineNotice').hidden, true);
});

test('offline-only device application and imports remain available through expiry and keep recovery independent', async () => {
  const offline = { ...active, onlineAvailable: false };
  const application = { deviceId: 'device-01', publicKey: 'fixture-public-key' };
  let resolveImport;
  const copied = [];
  const f = fixture(async endpoint => endpoint === '/api/license/device' ? { application } : new Promise(resolve => { resolveImport = resolve; }), { writeText: async text => copied.push(text) });
  for (const status of ['unactivated', 'active', 'expired', 'offline-expired', 'revoked']) {
    f.page.render({ ...offline, status });
    for (const id of ['licenseDeviceButton', 'licenseImportFileButton', 'licenseImportButton', 'licenseImportText', 'licenseImportFile']) assert.equal(f.node(id).disabled, false);
  }
  await f.node('licenseDeviceButton').click();
  await f.node('licenseCopyDeviceButton').click();
  assert.deepEqual(JSON.parse(copied[0]), application);
  const text = '{"signature":"offline-fixture"}';
  f.node('licenseImportFile').files = [{ name: 'permit.json', size: text.length, text: async () => text }];
  const pending = f.node('licenseImportFile').dispatch('change');
  await new Promise(resolve => setImmediate(resolve));
  for (const id of ['connectButton', 'safeQuitButton', 'licenseBackButton', 'networkRepairButton']) assert.equal(f.node(id).disabled, false);
  assert.equal(f.node('licenseImportButton').disabled, true);
  resolveImport(offline); await pending;
  assert.equal(f.node('licenseImportButton').disabled, false);
  assert.equal(f.node('licenseRefreshButton').disabled, true);
  assert.deepEqual(f.calls.map(([endpoint]) => endpoint), ['/api/license/device', '/api/license/import']);
  assert.deepEqual(f.calls[1][1], { text });
  assert.match(html, /实际截止时间以签名许可为准；授权期限内由管理员免费重签离线许可，无需重复付费/);
});

test('signed trial and paid terms are displayed without a hardcoded offline duration', () => {
  const f = fixture();
  f.page.render({ ...active, plan: 'trial-1d-single' });
  assert.match(f.node('licenseTermExplanation').textContent, /1 天试用/);
  assert.match(f.node('licenseTermExplanation').textContent, /同一客户编号/);
  f.page.render({ ...active, plan: 'isp-30d-single' });
  assert.match(f.node('licenseTermExplanation').textContent, /30 天/);
  assert.match(f.node('licenseTermExplanation').textContent, /以签名许可为准/);
  f.page.render({ mode: 'development' });
  assert.match(f.node('licenseTermExplanation').textContent, /无卡密、试用或付费期限限制/);
  const customerPageHtml = html.split('id="screen-license"')[1].split('id="screen-licensing-admin"')[0];
  assert.ok(!customerPageHtml.includes('72 小时'));
});

test('initial license state allows local retry without treating a missing route as an unrestricted edition', async () => {
  let available = false;
  const f = fixture(async () => {
    if (!available) throw Object.assign(new Error('private-service-detail'), { code: 'NOT_FOUND' });
    return { ...active, onlineAvailable: false };
  });
  assert.equal(f.node('licenseState').textContent, '授权状态待确认');
  assert.equal(f.node('licenseReadButton').disabled, false);
  for (const id of ['licenseActivateButton', 'licenseRefreshButton', 'licenseDeviceButton', 'licenseImportButton', 'licenseImportFileButton']) assert.equal(f.node(id).disabled, true);
  f.node('licenseCard').value = 'not-to-send';
  f.node('licenseImportText').value = '{"signature":"not-to-send"}';
  await f.node('licenseActivationForm').dispatch('submit');
  await f.node('licenseRefreshButton').click();
  await f.node('licenseDeviceButton').click();
  await f.node('licenseImportButton').click();
  assert.equal(f.calls.length, 0);
  assert.equal(await f.page.open(), false);
  assert.equal(f.node('licenseState').textContent, '授权状态待确认');
  assert.match(f.node('licenseOperationResult').textContent, /NOT_FOUND/);
  assert.ok(!f.node('licenseOperationResult').textContent.includes('private-service-detail'));
  assert.equal(f.node('licenseReadButton').disabled, false);
  available = true; assert.equal(await f.page.open(), true);
  assert.equal(f.node('licenseState').textContent, '授权有效');
  assert.equal(f.node('licenseDeviceButton').disabled, false);
  assert.deepEqual(f.calls.map(([endpoint]) => endpoint), ['/api/license/status', '/api/license/status']);
});

test('a slow local license file read prevents a second import and leaves navigation and recovery available', async () => {
  const f = fixture(); f.page.render(active);
  let resolveFile;
  f.node('licenseImportFile').files = [{ name: 'permit.json', size: 24, text: () => new Promise(resolve => { resolveFile = resolve; }) }];
  const pending = f.node('licenseImportFile').dispatch('change');
  assert.equal(f.node('licenseImportButton').disabled, true);
  assert.equal(f.calls.length, 0);
  for (const id of ['connectButton', 'safeQuitButton', 'licenseBackButton', 'networkRepairButton']) assert.equal(f.node(id).disabled, false);
  f.node('licenseImportText').value = '{"signature":"second"}'; await f.node('licenseImportButton').click();
  await f.node('licenseRefreshButton').click();
  assert.equal(f.calls.length, 0);
  resolveFile('{"signature":"first"}'); await pending;
  assert.deepEqual(f.calls.map(([endpoint]) => endpoint), ['/api/license/import']);
  assert.deepEqual(f.calls[0][1], { text: '{"signature":"first"}' });
  assert.equal(f.node('licenseImportButton').disabled, false);
});
