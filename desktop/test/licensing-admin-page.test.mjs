import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { adminTermPreview, buildAdminPayload, createLicensingAdminPage, licensingAdminAvailable, MAX_DEVICE_APPLICATION_BYTES } from '../../frontend/licensing-admin-page.js';

const html = await readFile(new URL('../../frontend/index.html', import.meta.url), 'utf8');
const app = await readFile(new URL('../../frontend/app.js', import.meta.url), 'utf8');
const applicationText = '{"deviceId":"fixture-device","publicKey":"fixture-public-key"}';
const customer = { licenseId: '1d6657b2-88ee-4a79-b984-05ed03b3f647', deviceId: 'fixture-device', plan: 'isp-1d-trial', status: 'active', expiresAt: 1791288000000, offlineUntil: 1791288000000, ispExpiresAt: 1791288000000, generation: 1 };
const trialResources = { resourcesReady: true, ispExpiresAt: '2026-11-06T12:30' };
const status = { enabled: true, configured: true, directory: 'fixture-directory', keyId: 'fixture-key', publicKeyFingerprint: 'fixture-fingerprint', customers: [customer], orders: [], summary: { licenseCount: 1, trialCount: 1, paidLicenseCount: 0, totalReceivedFen: 0, totalIspCostFen: 0 } };
const fixedNow = Date.UTC(2026, 9, 7);

function fixture(overrides = {}) {
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(([, id]) => [id, {
    value: '', textContent: '', innerHTML: '', hidden: false, disabled: false, checked: false, dataset: {}, listeners: {},
    setAttribute(name, value) { this[name] = value; },
    addEventListener(type, listener) { (this.listeners[type] ||= []).push(listener); },
    async dispatch(type, event = {}) { for (const listener of this.listeners[type] || []) await listener({ preventDefault() {}, ...event }); },
    click() { return this.dispatch('click'); },
    focus() { this.focused = true; },
    querySelector(selector) { return selector === 'span' ? this.label ||= { textContent: '' } : null; },
  }]));
  for (const item of nodes.values()) {
    item.writes = { textContent: 0, innerHTML: 0 };
    for (const key of ['textContent', 'innerHTML']) {
      let value = '';
      Object.defineProperty(item, key, { get: () => value, set: next => { value = String(next); item.writes[key]++; }, configurable: true });
    }
  }
  const node = id => { assert.ok(nodes.has(id), `Missing markup for ${id}`); return nodes.get(id); };
  node('adminAction').value = 'trial'; node('adminOfflineDays').value = '1';
  node('adminResourcesReady').checked = true; node('adminIspExpiresAt').value = trialResources.ispExpiresAt;
  const calls = [], desktop = {};
  for (const method of ['licenseAdminStatus', 'licenseAdminSelectStore', 'licenseAdminCreateStore', 'licenseAdminGenerate']) desktop[method] = async payload => {
    calls.push({ method, payload });
    return overrides[method] ? overrides[method](payload) : method === 'licenseAdminGenerate' ? { saved: true, filePath: 'fixture-permit.json', licenseId: customer.licenseId, plan: customer.plan, license: customer } : status;
  };
  let suggestedOrders = 0;
  const copied = [];
  const page = createLicensingAdminPage({ root: { querySelector: selector => node(selector.slice(1)) }, desktop, now: () => fixedNow, orderIdFactory: () => `MC-SUGGESTED-${++suggestedOrders}`, clipboard: overrides.clipboard || { writeText: async text => copied.push(text) } });
  return { page, node, calls, copied };
}

test('developer gate hides native admin by default and customer edition cannot open or issue', async () => {
  assert.equal(licensingAdminAvailable(), false);
  assert.equal(licensingAdminAvailable({ edition: 'licensed' }), false);
  assert.equal(licensingAdminAvailable({ edition: 'licensed', mock: true }, true), false);
  assert.equal(licensingAdminAvailable({ edition: 'developer', mock: true }), false);
  assert.equal(licensingAdminAvailable({ edition: 'developer', mock: false }), true);
  assert.equal(licensingAdminAvailable({}, true), false);
  assert.equal(licensingAdminAvailable({ edition: 'developer', mock: true }, true), true);
  assert.match(html, /id="openLicensingAdminButton"[^>]*hidden/);
  assert.match(app, /if\(page==='licensing-admin'&&!adminAvailable\(\)\)return/);
  assert.match(app, /if\(step==='licensing-admin'&&!adminAvailable\(\)\)return/);
  const f = fixture();
  await f.page.open(); await f.node('adminCreateStoreButton').click();
  f.node('adminApplicationText').value = applicationText; await f.node('adminGenerateForm').dispatch('submit');
  assert.equal(f.calls.length, 0);
  assert.equal(f.node('adminGenerateButton').disabled, true);
  assert.equal(f.node('adminStoreDetails').open, true);
});

test('trial always signs one day with no payment order and validates actual UTF-8 request size', () => {
  const payload = buildAdminPayload({ action: 'trial', applicationText, offlineDays: 30, orderId: 'must-not-be-ledgered', paidConfirmed: true, ...trialResources });
  assert.equal(payload.offlineDays, 1);
  assert.ok(!Object.hasOwn(payload, 'orderId'));
  assert.ok(!Object.hasOwn(payload, 'paidConfirmed'));
  const exact = `{"v":"${'a'.repeat(MAX_DEVICE_APPLICATION_BYTES - 8)}"}`;
  assert.equal(new TextEncoder().encode(exact).byteLength, MAX_DEVICE_APPLICATION_BYTES);
  assert.equal(buildAdminPayload({ action: 'trial', applicationText: exact, ...trialResources }).applicationText, exact);
  assert.throws(() => buildAdminPayload({ action: 'trial', applicationText }), /线路资源可用/);
  for (const value of ['', 'not-json', 'null', '[]', `{"v":"${'界'.repeat(3000)}"}`]) assert.throws(() => buildAdminPayload({ action: 'trial', applicationText: value }));
});

test('paid activation requires confirmed money and resources; renew converts trial without device request', () => {
  const values = { action: 'activate', applicationText, orderId: 'order-unique', paidConfirmed: true, resourcesReady: true, ispExpiresAt: '2026-11-06T12:30', offlineDays: 30 };
  for (const patch of [{ paidConfirmed: false }, { resourcesReady: false }, { orderId: '' }, { ispExpiresAt: '' }]) assert.throws(() => buildAdminPayload({ ...values, ...patch }));
  const payload = buildAdminPayload(values);
  assert.equal(payload.ispExpiresAt, new Date(values.ispExpiresAt).toISOString());
  assert.equal(payload.vpsExpiresAt, null);
  assert.equal(payload.offlineDays, 30);
  const renewal = buildAdminPayload({ ...values, action: 'renew', licenseId: customer.licenseId, applicationText: '' });
  assert.equal(renewal.licenseId, customer.licenseId);
  assert.ok(!Object.hasOwn(renewal, 'applicationText'));
});

test('customer-provided resources hide supplier inputs and keep full software/offline preview without changing the price', async () => {
  const values = { action: 'activate', applicationText, orderId: 'self-paid', paidConfirmed: true, resourcesMode: 'customer', offlineDays: 30, ispExpiresAt: 'bad-date', resourcesReady: false };
  const payload = buildAdminPayload(values);
  assert.equal(payload.resourcesMode, 'customer'); assert.equal(payload.ispExpiresAt, null); assert.equal(payload.vpsExpiresAt, null);
  assert.equal(payload.paidConfirmed, true);
  assert.equal(adminTermPreview(values, [], [], fixedNow).offlineUntil, fixedNow + 30 * 86400000);
  assert.equal(adminTermPreview(values, [], [], fixedNow).blocked, false);
  assert.throws(() => buildAdminPayload({ ...values, paidConfirmed: false }), /¥100/);
  assert.throws(() => buildAdminPayload({ ...values, resourcesMode: 'invalid' }), /供应方式/);
  const f = fixture(); f.page.setEnabled(true); f.page.render(status);
  f.node('adminResourcesMode').value = 'customer'; await f.node('adminResourcesMode').dispatch('change');
  assert.equal(f.node('adminResourceFields').hidden, true);
  f.node('adminApplicationText').value = applicationText; f.node('adminResourcesReady').checked = false; f.node('adminIspExpiresAt').value = '';
  await f.node('adminGenerateForm').dispatch('submit');
  assert.equal(f.calls.find(call => call.method === 'licenseAdminGenerate').payload.resourcesMode, 'customer');
});

test('free refresh ignores payment and resource inputs; rebind and revoke have separate requirements', () => {
  assert.deepEqual(buildAdminPayload({ action: 'refresh', licenseId: customer.licenseId, offlineDays: 15, orderId: 'stale-order', paidConfirmed: true, resourcesReady: true, ispExpiresAt: 'bad-date' }), { action: 'refresh', licenseId: customer.licenseId, offlineDays: 15 });
  assert.throws(() => buildAdminPayload({ action: 'rebind', licenseId: customer.licenseId }));
  assert.equal(buildAdminPayload({ action: 'rebind', licenseId: customer.licenseId, applicationText }).offlineDays, 30);
  assert.throws(() => buildAdminPayload({ action: 'revoke', licenseId: customer.licenseId }));
  assert.deepEqual(buildAdminPayload({ action: 'revoke', licenseId: customer.licenseId, revokeConfirmed: true }), { action: 'revoke', licenseId: customer.licenseId });
  assert.deepEqual(buildAdminPayload({ action: 'resources', licenseId: customer.licenseId, resourcesReady: false }), { action: 'resources', resourcesMode: 'included', licenseId: customer.licenseId, resourcesReady: false, ispExpiresAt: null, vpsExpiresAt: null });
});

test('native status is read only on explicit open; no automatic store creation or controller requests', async () => {
  const f = fixture(); f.page.setEnabled(true);
  for (let index = 0; index < 30; index++) f.page.updateControls();
  assert.equal(f.calls.length, 0);
  await f.page.open();
  assert.deepEqual(f.calls.map(call => call.method), ['licenseAdminStatus']);
  assert.equal(f.node('adminCustomerCount').textContent, '1');
  assert.equal(f.node('adminTrialCount').textContent, '1');
  assert.equal(f.node('adminRevenue').textContent, '¥0.00');
  assert.match(f.node('adminStoreFingerprint').textContent, /fixture-fingerprint/);
  assert.equal(f.node('adminStoreDetails').open, false);
  assert.match(html, /现有正式安装包不会信任它/);
  assert.ok(!app.includes("api('/api/license-admin"));
});

test('unchanged admin updates preserve issue buttons, options, review and live text', () => {
  const f = fixture(); f.page.setEnabled(true); f.page.render(status);
  const watched = ['adminMissingList', 'adminProgressList', 'adminReviewSummary', 'adminCustomer', 'adminCustomerList', 'adminOrderList', 'adminNextStep', 'adminTermPreview'];
  const before = new Map(watched.map(id => [id, { ...f.node(id).writes }]));
  for (let index = 0; index < 30; index++) f.page.setEnabled(true);
  f.page.render(structuredClone(status));
  for (const id of watched) assert.deepEqual(f.node(id).writes, before.get(id), id);
  f.node('adminApplicationText').value = applicationText;
  f.page.updateControls();
  assert.ok(f.node('adminMissingList').writes.innerHTML > before.get('adminMissingList').innerHTML);
  assert.match(f.node('adminNextStep').textContent, /条件已齐/);
});

test('a blocking term expands details only on a new block and respects a manual close', async () => {
  const f = fixture(); f.page.setEnabled(true); f.page.render(status);
  const details = { open: false };
  f.node('adminTermPreview').closest = () => details;
  await f.node('adminActivateButton').click();
  f.node('adminApplicationText').value = applicationText;
  f.node('adminIspExpiresAt').value = '2026-10-08T00:00';
  f.page.updateControls();
  assert.equal(details.open, true);
  details.open = false;
  for (let index = 0; index < 30; index++) f.page.setEnabled(true);
  assert.equal(details.open, false);
  f.node('adminIspExpiresAt').value = '2026-12-08T00:00'; f.page.updateControls();
  f.node('adminIspExpiresAt').value = '2026-10-08T00:00'; f.page.updateControls();
  assert.equal(details.open, true);
  const store = f.node('adminStoreDetails');
  f.page.render({ enabled: true, configured: false }); assert.equal(store.open, true);
  store.open = false;
  f.page.render({ enabled: true, configured: false }); assert.equal(store.open, false);
});

test('selecting an existing trial pre-fills renewal without requesting the device again', async () => {
  const f = fixture(); f.page.setEnabled(true); f.page.render(status);
  f.node('adminCustomer').value = customer.licenseId; await f.node('adminCustomer').dispatch('change');
  assert.equal(f.node('adminLicenseId').value, customer.licenseId);
  assert.equal(f.node('adminAction').value, 'renew');
  assert.equal(f.node('adminApplicationFields').hidden, true);
  assert.equal(f.node('adminOfflineDays').value, '30');
  assert.equal(f.node('adminPaidConfirmed').checked, false);
  assert.equal(f.node('adminResourcesReady').checked, false);
  assert.equal(f.node('adminIspExpiresAt').value.length, 16);
  assert.equal(f.calls.length, 0);
});

test('trial refresh and rebind keep one day while conversion and paid renewal keep thirty', async () => {
  const paidCustomer = { ...customer, licenseId: '42f52c5e-22b5-4d4c-81bf-daa994dc6191', plan: 'isp-30d-single' };
  const f = fixture(); f.page.setEnabled(true); f.page.render({ ...status, customers: [customer, paidCustomer] });
  f.node('adminCustomer').value = customer.licenseId; await f.node('adminCustomer').dispatch('change');
  for (const action of ['refresh', 'rebind']) {
    f.node('adminAction').value = action; await f.node('adminAction').dispatch('change');
    assert.equal(f.node('adminOfflineDays').value, '1');
    assert.equal(f.node('adminOfflineDays').disabled, true);
    assert.equal(buildAdminPayload({ action, plan: customer.plan, licenseId: customer.licenseId, applicationText, offlineDays: 30 }).offlineDays, 1);
  }
  f.node('adminAction').value = 'renew'; await f.node('adminAction').dispatch('change');
  assert.equal(f.node('adminOfflineDays').value, '30'); assert.equal(f.node('adminOfflineDays').disabled, false);
  f.node('adminCustomer').value = paidCustomer.licenseId; await f.node('adminCustomer').dispatch('change');
  assert.equal(f.node('adminAction').value, 'renew');
  assert.equal(f.node('adminOfflineDays').value, '30'); assert.equal(f.node('adminOfflineDays').disabled, false);
  await f.node('adminRefreshButton').click();
  f.node('adminLicenseId').value = customer.licenseId; await f.node('adminLicenseId').dispatch('input');
  assert.equal(f.node('adminOfflineDays').value, '1'); assert.equal(f.node('adminOfflineDays').disabled, true);
  await f.node('adminGenerateForm').dispatch('submit');
  assert.deepEqual(f.calls.find(call => call.method === 'licenseAdminGenerate').payload, { action: 'refresh', licenseId: customer.licenseId, offlineDays: 1 });
});

test('a completed trial conversion switches the same customer to paid refresh without retaining payment confirmation', async () => {
  const paidCustomer = { ...customer, plan: 'isp-30d-single', generation: 2 };
  const f = fixture({ licenseAdminGenerate: async () => ({ saved: true, filePath: 'paid-permit.json', licenseId: customer.licenseId, plan: paidCustomer.plan, license: paidCustomer, customers: [paidCustomer], summary: { ...status.summary, trialCount: 0, paidLicenseCount: 1, totalReceivedFen: 10000 } }) });
  f.page.setEnabled(true); f.page.render(status);
  f.node('adminCustomer').value = customer.licenseId; await f.node('adminCustomer').dispatch('change');
  f.node('adminOrderId').value = 'CUSTOMER-PAID-001'; f.node('adminPaidConfirmed').checked = true; f.node('adminResourcesReady').checked = true;
  f.node('adminIspExpiresAt').value = '2026-12-01T00:00';
  await f.node('adminGenerateForm').dispatch('submit');
  const { payload } = f.calls.find(call => call.method === 'licenseAdminGenerate');
  assert.equal(payload.action, 'renew'); assert.equal(payload.offlineDays, 30); assert.equal(payload.licenseId, customer.licenseId);
  assert.equal(f.node('adminCustomer').value, customer.licenseId); assert.equal(f.node('adminAction').value, 'refresh');
  assert.equal(f.node('adminOfflineDays').value, '30'); assert.equal(f.node('adminOfflineDays').disabled, false);
  assert.equal(f.node('adminOrderId').value, 'CUSTOMER-PAID-001'); assert.equal(f.node('adminPaidConfirmed').checked, false);
  assert.equal(f.node('adminSavedFile').hidden, false); assert.match(f.node('adminSavedFile').textContent, /paid-permit.json/);
});

test('native generation busy leaves connection, quit and recovery independent and blocks a second submission', async () => {
  let resolve;
  const f = fixture({ licenseAdminGenerate: () => new Promise(done => { resolve = done; }) });
  f.page.setEnabled(true); f.page.render(status); f.node('adminApplicationText').value = applicationText;
  const pending = f.node('adminGenerateForm').dispatch('submit');
  assert.equal(f.node('adminGenerateButton').disabled, true);
  for (const id of ['connectButton', 'safeQuitButton', 'networkRepairButton', 'adminBackButton']) assert.equal(f.node(id).disabled, false);
  f.page.updateControls(); assert.equal(f.node('adminApplicationText').disabled, true);
  await f.node('adminGenerateForm').dispatch('submit'); assert.equal(f.calls.length, 1);
  resolve({ saved: true, filePath: 'fixture-permit.json', licenseId: customer.licenseId }); await pending;
  assert.deepEqual(f.calls.map(call => call.method), ['licenseAdminGenerate', 'licenseAdminStatus']);
  assert.equal(f.node('adminApplicationText').value, '');
  assert.match(f.node('adminOperationResult').textContent, /无付费订单/);
  assert.equal(f.node('adminGenerateButton').disabled, true);
  assert.equal(f.node('adminCustomer').value, customer.licenseId);
  assert.equal(f.node('adminAction').value, 'renew');
  assert.equal(f.node('adminOfflineDays').value, '30');
  assert.equal(f.node('adminResourcesReady').checked, false);
});

test('canceling save records no success, and native errors never echo private contents', async () => {
  const f = fixture({ licenseAdminGenerate: async () => ({ canceled: true }) });
  f.page.setEnabled(true); f.page.render(status); f.node('adminApplicationText').value = applicationText;
  f.node('adminSavedFile').hidden = false; f.node('adminSavedFile').textContent = 'previous-customer-file.json';
  await f.node('adminApplicationText').dispatch('input');
  await f.node('adminGenerateForm').dispatch('submit');
  assert.deepEqual(f.calls.map(call => call.method), ['licenseAdminGenerate']);
  assert.match(f.node('adminOperationResult').textContent, /未生成本次许可或收款记录/);
  assert.equal(f.node('adminApplicationText').value, applicationText);
  assert.equal(f.node('adminSavedFile').hidden, true);
  const failed = fixture({ licenseAdminGenerate: async () => { throw Object.assign(new Error('private-key-secret'), { code: 'LICENSE_ADMIN_SIGN_FAILED' }); } });
  failed.page.setEnabled(true); failed.page.render(status); failed.node('adminApplicationText').value = applicationText;
  await failed.node('adminGenerateForm').dispatch('submit');
  assert.ok(!failed.node('adminOperationResult').textContent.includes('private-key-secret'));
  assert.match(failed.node('adminOperationResult').textContent, /LICENSE_ADMIN_SIGN_FAILED/);
});

test('device file reads serialize with signing and clear-on-navigation discards a stale read', async () => {
  const f = fixture(); f.page.setEnabled(true); f.page.render(status);
  let resolveFile;
  f.node('adminApplicationFile').files = [{ name: 'request.json', size: applicationText.length, text: () => new Promise(resolve => { resolveFile = resolve; }) }];
  const pending = f.node('adminApplicationFile').dispatch('change');
  assert.equal(f.node('adminGenerateButton').disabled, true);
  for (const id of ['connectButton', 'safeQuitButton', 'networkRepairButton', 'adminBackButton']) assert.equal(f.node(id).disabled, false);
  f.node('adminApplicationText').value = applicationText;
  await f.node('adminGenerateForm').dispatch('submit'); assert.equal(f.calls.length, 0);
  f.page.clearInputs(); resolveFile(applicationText); await pending;
  assert.equal(f.node('adminApplicationText').value, '');
  assert.equal(f.node('adminGenerateButton').disabled, true);
  assert.equal(f.calls.length, 0);
});

test('device file rejects oversized and invalid contents, and safe records cannot inject markup', async () => {
  const f = fixture(); f.page.setEnabled(true); f.page.render(status);
  for (const file of [{ name: 'device.txt', size: 1 }, { name: 'device.json', size: MAX_DEVICE_APPLICATION_BYTES + 1 }, { name: 'device.json', size: 4, text: async () => 'null' }]) {
    f.node('adminApplicationFile').files = [file]; await f.node('adminApplicationFile').dispatch('change');
  }
  assert.equal(f.node('adminApplicationText').value, ''); assert.equal(f.calls.length, 0);
  f.node('adminApplicationFile').files = [{ name: 'device.json', size: applicationText.length, text: async () => applicationText }];
  await f.node('adminApplicationFile').dispatch('change'); assert.equal(f.node('adminApplicationText').value, applicationText);
  f.page.render({ ...status, customers: [{ ...customer, licenseId: '<script>fixture</script>' }], orders: [{ orderId: '<img>', licenseId: '<script>', amountFen: 10000, ispCostFen: 3500, paidAt: 1791288000000 }] });
  assert.ok(!f.node('adminCustomerList').innerHTML.includes('<script>'));
  assert.match(f.node('adminCustomerList').innerHTML, /&lt;script&gt;/);
  assert.ok(!f.node('adminOrderList').innerHTML.includes('<img>'));
  assert.equal(f.node('adminPaidOrders').textContent, '1 笔付费订单');
});

test('saved license remains successful when post-commit customer statistics cannot refresh', async () => {
  for (const summaryUnavailable of [false, true]) {
    const f = fixture({ licenseAdminGenerate: async () => ({ saved: true, licenseId: customer.licenseId, filePath: 'already-saved.json', summaryUnavailable }), licenseAdminStatus: async () => { throw new Error('private-summary-error'); } });
    f.page.setEnabled(true); f.page.render(status); f.node('adminApplicationText').value = applicationText;
    const oldList = f.node('adminCustomerList').innerHTML;
    await f.node('adminGenerateForm').dispatch('submit');
    assert.match(f.node('adminSavedFile').textContent, /already-saved.json/);
    assert.equal(f.node('adminSavedFile').hidden, false);
    assert.equal(f.node('adminCustomerList').innerHTML, oldList);
    assert.match(f.node('adminOperationResult').textContent, /许可已保存/);
    assert.match(f.node('adminOperationResult').textContent, /不要重复记收款/);
    assert.equal(f.node('adminOperationResult').dataset.error, 'false');
    assert.ok(!f.node('adminOperationResult').textContent.includes('private-summary-error'));
    assert.equal(f.calls.filter(call => call.method === 'licenseAdminGenerate').length, 1);
  }
});

test('paid term preview includes carried time and all resource cutoffs; shorter offline windows cannot bypass it', () => {
  const paid = { ...customer, plan: 'isp-30d-single', expiresAt: fixedNow + 20 * 86400000, vpsExpiresAt: fixedNow + 40 * 86400000 };
  const values = { action: 'renew', licenseId: paid.licenseId, ispExpiresAt: new Date(fixedNow + 40 * 86400000).toISOString(), vpsExpiresAt: new Date(fixedNow + 60 * 86400000).toISOString(), offlineDays: 1 };
  const short = adminTermPreview(values, [paid], [], fixedNow);
  assert.equal(short.expiresAt, fixedNow + 50 * 86400000); assert.equal(short.blocked, true);
  assert.match(short.text, /拟软件截止/); assert.match(short.text, /ISP 资源提醒/); assert.match(short.text, /VPS 资源提醒/); assert.match(short.text, /拟离线许可截止/); assert.match(short.text, /缩短离线许可天数不会/);
  const covered = { ...values, ispExpiresAt: new Date(fixedNow + 50 * 86400000).toISOString(), vpsExpiresAt: new Date(fixedNow + 50 * 86400000).toISOString() };
  assert.equal(adminTermPreview(covered, [paid], [], fixedNow).blocked, false);
  assert.equal(adminTermPreview({ ...covered, vpsExpiresAt: '' }, [paid], [], fixedNow).blocked, false);
  assert.equal(adminTermPreview({ ...covered, action: 'resources', resourcesReady: true, ispExpiresAt: new Date(fixedNow + 10 * 86400000).toISOString() }, [paid], [], fixedNow).blocked, false);
  assert.equal(adminTermPreview({ ...values, action: 'refresh' }, [paid], [], fixedNow).blocked, false);
  assert.equal(adminTermPreview(values, [], [], fixedNow).blocked, true);
  const activation = adminTermPreview({ ...values, action: 'activate', applicationText: JSON.stringify({ request: { deviceId: paid.deviceId } }) }, [paid], [], fixedNow);
  assert.equal(activation.expiresAt, short.expiresAt); assert.equal(activation.blocked, true);
  const recorded = adminTermPreview({ ...values, orderId: 'existing-renew' }, [paid], [{ orderId: 'existing-renew', kind: 'renew', licenseId: paid.licenseId }], fixedNow);
  assert.equal(recorded.blocked, false); assert.match(recorded.text, /已成功记账/); assert.match(recorded.text, /不重复收费/);
  assert.ok(!recorded.text.includes('不会新增收款记录'));
});

test('trial conversion shows insufficient resources and blocks save until the actual ISP covers thirty paid days', async () => {
  const f = fixture(); f.page.setEnabled(true); f.page.render(status);
  f.node('adminCustomer').value = customer.licenseId; await f.node('adminCustomer').dispatch('change');
  f.node('adminOrderId').value = 'covered-conversion'; f.node('adminPaidConfirmed').checked = true; f.node('adminResourcesReady').checked = true;
  f.node('adminOfflineDays').value = '1'; await f.node('adminOfflineDays').dispatch('change');
  assert.equal(f.node('adminGenerateButton').disabled, true); assert.match(f.node('adminTermPreview').textContent, /线路不足/);
  await f.node('adminGenerateForm').dispatch('submit'); assert.equal(f.calls.length, 0); assert.match(f.node('adminOperationResult').textContent, /不会新增收款记录/);
  f.node('adminIspExpiresAt').value = '2026-12-01T00:00'; await f.node('adminIspExpiresAt').dispatch('input');
  assert.equal(f.node('adminGenerateButton').disabled, false); assert.match(f.node('adminTermPreview').textContent, /线路已覆盖完整/);
  await f.node('adminGenerateForm').dispatch('submit');
  assert.equal(f.calls.filter(call => call.method === 'licenseAdminGenerate').length, 1);
});

test('a native coverage rejection explicitly reports no new ledger entry or delivery', async () => {
  const f = fixture({ licenseAdminGenerate: async () => { throw Object.assign(new Error('secret-resource-detail'), { code: 'RESOURCE_TERM_TOO_SHORT' }); } });
  f.page.setEnabled(true); f.page.render(status);
  f.node('adminAction').value = 'activate'; f.node('adminApplicationText').value = applicationText; f.node('adminOrderId').value = 'rejected'; f.node('adminPaidConfirmed').checked = true;
  f.node('adminIspExpiresAt').value = '2026-12-01T00:00';
  await f.node('adminGenerateForm').dispatch('submit');
  assert.match(f.node('adminOperationResult').textContent, /未新增收款记录、未延期、未保存许可/);
  assert.ok(!f.node('adminOperationResult').textContent.includes('secret-resource-detail')); assert.equal(f.node('adminSavedFile').hidden, true);
});

test('the page can save an already completed order without repeating payment or resource confirmation', async () => {
  const paid = { ...customer, plan: 'isp-30d-single' }, recorded = { ...status, customers: [paid], orders: [{ orderId: 'retry-paid', kind: 'renew', licenseId: paid.licenseId }] };
  const f = fixture(); f.page.setEnabled(true); f.page.render(recorded);
  f.node('adminCustomer').value = paid.licenseId; await f.node('adminCustomer').dispatch('change');
  f.node('adminAction').value = 'renew'; await f.node('adminAction').dispatch('change');
  f.node('adminOrderId').value = 'retry-paid'; f.node('adminIspExpiresAt').value = ''; f.node('adminVpsExpiresAt').value = '';
  await f.node('adminOrderId').dispatch('input');
  assert.equal(f.node('adminGenerateButton').disabled, false); assert.match(f.node('adminTermPreview').textContent, /已成功记账/);
  await f.node('adminGenerateForm').dispatch('submit');
  const generated = f.calls.find(call => call.method === 'licenseAdminGenerate'); assert.ok(generated);
  assert.equal(generated.payload.paidConfirmed, false); assert.equal(generated.payload.resourcesReady, false); assert.equal(generated.payload.ispExpiresAt, null);
});

test('daily shortcuts prepare the right duration without fabricating dates or confirmations', async () => {
  const paid = { ...customer, plan: 'isp-30d-single', resourcesMode: 'customer', expiresAt: fixedNow + 12 * 86400000, ispExpiresAt: null };
  const f = fixture(); f.page.setEnabled(true); f.page.render({ ...status, customers: [paid] });
  await f.node('adminActivateButton').click();
  assert.equal(f.node('adminAction').value, 'activate'); assert.equal(f.node('adminOfflineDays').value, '30');
  assert.equal(f.node('adminOrderId').value, 'MC-SUGGESTED-1');
  assert.equal(f.node('adminOrderId').disabled, true); assert.equal(f.node('adminResourcesMode').disabled, true);
  assert.equal(f.node('adminIspExpiresAt').value, ''); assert.equal(f.node('adminVpsExpiresAt').value, '');
  assert.equal(f.node('adminResourcesReady').checked, false); assert.equal(f.node('adminPaidConfirmed').checked, false);
  assert.equal(f.node('adminActivateButton')['aria-pressed'], 'true');
  await f.node('adminTrialButton').click();
  assert.equal(f.node('adminAction').value, 'trial'); assert.equal(f.node('adminOfflineDays').value, '1');
  assert.equal(f.node('adminOfflineDays').disabled, true); assert.equal(f.node('adminOrderFields').hidden, true);
  await f.node('adminRenewButton').click();
  assert.equal(f.node('adminCustomerField').hidden, false); assert.equal(f.node('adminGenerateButton').disabled, true);
  f.node('adminCustomer').value = paid.licenseId; await f.node('adminCustomer').dispatch('change');
  assert.equal(f.node('adminAction').value, 'renew'); assert.equal(f.node('adminLicenseId').value, paid.licenseId);
  assert.equal(f.node('adminResourcesMode').value, 'customer'); assert.equal(f.node('adminResourceFields').hidden, true);
  assert.equal(f.node('adminPaidConfirmed').checked, false); assert.equal(f.node('adminResourcesReady').checked, false);
  assert.equal(adminTermPreview({ action: 'renew', licenseId: paid.licenseId, resourcesMode: 'customer', offlineDays: 30 }, [paid], [], fixedNow).expiresAt, fixedNow + 42 * 86400000);
  assert.match(f.node('adminRecipient').textContent, new RegExp(paid.licenseId));
  await f.node('adminRefreshButton').click();
  const refresh = buildAdminPayload({ action: f.node('adminAction').value, licenseId: f.node('adminLicenseId').value, plan: paid.plan, offlineDays: f.node('adminOfflineDays').value });
  assert.deepEqual(refresh, { action: 'refresh', licenseId: paid.licenseId, offlineDays: 30 });
  assert.match(f.node('adminActionHelp').textContent, /不延长/); assert.equal(f.node('adminOrderFields').hidden, true);
});

test('preparation lists all unpaid included-resource conditions and self ISP alone removes supplier gates', async () => {
  const f = fixture(); f.page.setEnabled(true); f.page.render(status); await f.node('adminActivateButton').click();
  assert.match(f.node('adminMissingList').innerHTML, /完整设备申请/);
  f.node('adminApplicationText').value = applicationText; await f.node('adminApplicationText').dispatch('input');
  assert.equal(f.node('adminPaidConfirmed').disabled, false); assert.equal(f.node('adminResourcesMode').disabled, false);
  assert.match(f.node('adminMissingList').innerHTML, /实际收到本次¥100/);
  assert.match(f.node('adminMissingList').innerHTML, /线路可用/);
  assert.match(f.node('adminMissingList').innerHTML, /真实ISP到期时间/);
  assert.equal(f.node('adminGenerateButton').disabled, true);
  assert.equal((f.node('adminProgressList').innerHTML.match(/data-state="done"/g) || []).length, 2);
  f.node('adminResourcesMode').value = 'customer'; await f.node('adminResourcesMode').dispatch('change');
  assert.ok(!f.node('adminMissingList').innerHTML.includes('真实ISP到期时间'));
  assert.equal(f.node('adminGenerateButton').disabled, true);
  f.node('adminPaidConfirmed').checked = true; await f.node('adminPaidConfirmed').dispatch('change');
  assert.equal(f.node('adminGenerateButton').disabled, false); assert.equal(f.node('adminMissingList').hidden, true);
  assert.equal((f.node('adminProgressList').innerHTML.match(/data-state="done"/g) || []).length, 3);
  assert.equal(f.calls.length, 0);
});

test('request metadata matches the original customer without overwriting later edits or claiming signature approval', async () => {
  const paid = { ...customer, plan: 'isp-30d-single', resourcesMode: 'customer', expiresAt: fixedNow + 20 * 86400000, ispExpiresAt: null, vpsExpiresAt: null };
  const f = fixture(); f.page.setEnabled(true); f.page.render({ ...status, customers: [paid] }); await f.node('adminActivateButton').click();
  f.node('adminApplicationText').value = JSON.stringify({ request: { licenseId: paid.licenseId, deviceId: paid.deviceId } });
  await f.node('adminApplicationText').dispatch('input');
  assert.equal(f.node('adminLicenseId').value, paid.licenseId); assert.equal(f.node('adminCustomer').value, paid.licenseId);
  assert.equal(f.node('adminResourcesMode').value, 'customer'); assert.equal(f.node('adminIspExpiresAt').value, '');
  assert.equal(f.node('adminPaidConfirmed').checked, false); assert.equal(f.node('adminResourcesReady').checked, false);
  f.node('adminResourcesMode').value = 'included'; await f.node('adminResourcesMode').dispatch('change');
  f.node('adminIspExpiresAt').value = '2027-01-01T12:30'; await f.node('adminIspExpiresAt').dispatch('input');
  f.node('adminPaidConfirmed').checked = true; await f.node('adminPaidConfirmed').dispatch('change');
  f.page.render({ ...status, customers: [paid] });
  assert.equal(f.node('adminResourcesMode').value, 'included'); assert.equal(f.node('adminIspExpiresAt').value, '2027-01-01T12:30');
  assert.equal(f.node('adminPaidConfirmed').checked, true);
  assert.equal(f.node('adminAction').value, 'activate'); assert.equal(f.calls.length, 0);
  f.node('adminApplicationText').value = JSON.stringify({ request: { deviceId: 'another-customer' } });
  await f.node('adminApplicationText').dispatch('input');
  assert.equal(f.node('adminLicenseId').value, ''); assert.equal(f.node('adminCustomer').value, '');
  assert.equal(f.node('adminIspExpiresAt').value, ''); assert.equal(f.node('adminPaidConfirmed').checked, false);
  assert.match(f.node('adminRecipient').textContent, /仍须在本机签发时核验/);
  f.node('adminApplicationFile').files = [{ name: 'request.json', size: 100, text: async () => JSON.stringify({ request: { deviceId: paid.deviceId } }) }];
  await f.node('adminApplicationFile').dispatch('change');
  assert.equal(f.node('adminLicenseId').value, paid.licenseId); assert.equal(f.node('adminResourcesMode').value, 'customer');
  assert.match(f.node('adminOperationResult').textContent, /仍须在签发时核验/);
});

test('order suggestion is editable and stable through refresh, cancel, failure and same-payment success', async () => {
  let attempt = 0;
  const f = fixture({ licenseAdminGenerate: async () => {
    if (++attempt === 1) return { canceled: true };
    if (attempt === 2) throw Object.assign(new Error('private-ledger-detail'), { code: 'LICENSE_ADMIN_SIGN_FAILED' });
    return { saved: true, filePath: 'stable-order-permit.json', licenseId: customer.licenseId };
  } });
  f.page.setEnabled(true); f.page.render(status); await f.node('adminActivateButton').click();
  f.node('adminApplicationText').value = applicationText; await f.node('adminApplicationText').dispatch('input');
  f.node('adminResourcesMode').value = 'customer'; await f.node('adminResourcesMode').dispatch('change');
  assert.equal(f.node('adminOrderId').value, 'MC-SUGGESTED-1');
  f.node('adminOrderId').value = 'REAL-INVOICE-001'; await f.node('adminOrderId').dispatch('input');
  f.node('adminPaidConfirmed').checked = true; await f.node('adminPaidConfirmed').dispatch('change');
  await f.node('adminReadButton').click();
  assert.equal(f.node('adminOrderId').value, 'REAL-INVOICE-001'); assert.equal(f.node('adminPaidConfirmed').checked, true);
  for (let index = 0; index < 3; index++) {
    await f.node('adminGenerateForm').dispatch('submit');
    assert.equal(f.node('adminOrderId').value, 'REAL-INVOICE-001');
    if (index < 2) assert.equal(f.node('adminDeliveryPanel').hidden, true);
  }
  assert.deepEqual(f.calls.filter(call => call.method === 'licenseAdminGenerate').map(call => call.payload.orderId), ['REAL-INVOICE-001', 'REAL-INVOICE-001', 'REAL-INVOICE-001']);
  assert.equal(f.node('adminDeliveryPanel').hidden, false); assert.match(f.node('adminDeliveryInstructions').textContent, /REAL-INVOICE-001/);
  await f.node('adminRenewButton').click();
  assert.equal(f.node('adminOrderId').value, 'REAL-INVOICE-001');
  await f.node('adminNewOrderButton').click();
  assert.equal(f.node('adminOrderId').value, 'MC-SUGGESTED-2'); assert.equal(f.node('adminPaidConfirmed').checked, false);
  assert.equal(f.node('adminDeliveryPanel').hidden, true);
});

test('only a saved native result provides the precise software delivery steps, separate VPS file and route verification caveat', async () => {
  const f = fixture(); f.page.setEnabled(true); f.page.render(status); f.node('adminApplicationText').value = applicationText;
  await f.node('adminGenerateForm').dispatch('submit');
  assert.equal(f.node('adminDeliveryPanel').hidden, false); assert.equal(f.node('adminSavedFile').hidden, false);
  assert.match(f.node('adminDeliveryInstructions').textContent, /软件许可JSON/);
  assert.match(f.node('adminDeliveryInstructions').textContent, /设置 → 授权与续费 → 选择签名许可文件/);
  assert.match(f.node('adminDeliveryInstructions').textContent, /1\.6\.1/);
  assert.match(f.node('adminDeliveryInstructions').textContent, /另发该客户独立中转注册JSON/);
  assert.match(f.node('adminDeliveryInstructions').textContent, /仅保存软件许可不代表线路已开通或完整连接已通过/);
  assert.match(f.node('adminProgressList').innerHTML, /保存许可<small>已保存/);
  f.node('adminOfflineDays').value = '15'; await f.node('adminOfflineDays').dispatch('change');
  assert.equal(f.node('adminDeliveryPanel').hidden, true); assert.equal(f.node('adminSavedFile').hidden, true);
  for (const result of [{ canceled: true }, { saved: false }]) {
    const failed = fixture({ licenseAdminGenerate: async () => result }); failed.page.setEnabled(true); failed.page.render(status); failed.node('adminApplicationText').value = applicationText;
    await failed.node('adminGenerateForm').dispatch('submit');
    assert.equal(failed.node('adminDeliveryPanel').hidden, true); assert.equal(failed.node('adminSavedFile').hidden, true);
    assert.ok(!failed.node('adminOperationResult').textContent.includes('交付完成'));
  }
});

test('a previously issued trial preview retains its real deadline and an expired or paid device is directed to the original customer renewal', async () => {
  const live = { ...customer, expiresAt: fixedNow + 3600000, resourcesMode: 'customer', ispExpiresAt: null };
  const trial = adminTermPreview({ action: 'trial', licenseId: live.licenseId, resourcesMode: 'customer', offlineDays: 1 }, [live], [], fixedNow);
  assert.equal(trial.expiresAt, live.expiresAt); assert.equal(trial.offlineUntil, live.expiresAt);
  assert.match(trial.text, /重复签发沿用原截止/);
  for (const existing of [customer, { ...live, plan: 'isp-30d-single' }]) {
    const f = fixture(); f.page.setEnabled(true); f.page.render({ ...status, customers: [existing] });
    await f.node('adminTrialButton').click(); f.node('adminApplicationText').value = JSON.stringify({ request: { licenseId: existing.licenseId, deviceId: existing.deviceId } });
    await f.node('adminApplicationText').dispatch('input');
    assert.equal(f.node('adminGenerateButton').disabled, true);
    assert.match(f.node('adminMissingList').innerHTML, /转正式 \/ 续费/);
    await f.node('adminGenerateForm').dispatch('submit'); assert.equal(f.calls.length, 0);
  }
});

test('choosing a customer after a maintenance shortcut keeps that explicit free or destructive action', async () => {
  const f = fixture(); f.page.setEnabled(true); f.page.render(status);
  for (const [button, action] of [['adminRefreshButton', 'refresh'], ['adminRebindButton', 'rebind'], ['adminResourcesButton', 'resources'], ['adminRevokeButton', 'revoke']]) {
    await f.node(button).click(); f.node('adminCustomer').value = customer.licenseId; await f.node('adminCustomer').dispatch('change');
    assert.equal(f.node('adminAction').value, action); assert.equal(f.node('adminLicenseId').value, customer.licenseId);
    assert.equal(f.node('adminPaidConfirmed').checked, false); assert.equal(f.node('adminRevokeConfirmed').checked, false);
    if (['refresh', 'rebind'].includes(action)) assert.equal(f.node('adminOfflineDays').value, '1');
    assert.equal(f.node('adminOrderFields').hidden, true);
  }
  assert.equal(f.calls.length, 0);
});

test('search preserves the selected customer, pending payment and renewal when it finds no matches', async () => {
  const other = { ...customer, licenseId: '42f52c5e-22b5-4d4c-81bf-daa994dc6191', deviceId: 'another-device' };
  const f = fixture(); f.page.setEnabled(true); f.page.render({ ...status, customers: [customer, other] });
  await f.node('adminRenewButton').click();
  f.node('adminCustomerSearch').value = 'ANOTHER-DEVICE'; await f.node('adminCustomerSearch').dispatch('input');
  assert.ok(f.node('adminCustomer').innerHTML.includes(other.licenseId));
  assert.ok(!f.node('adminCustomer').innerHTML.includes(customer.licenseId));
  f.node('adminCustomer').value = other.licenseId; await f.node('adminCustomer').dispatch('change');
  f.node('adminOrderId').value = 'PENDING-RENEWAL'; f.node('adminPaidConfirmed').checked = true;
  f.node('adminCustomerSearch').value = 'no-such-device'; await f.node('adminCustomerSearch').dispatch('input');
  assert.match(f.node('adminCustomerSearchStatus').textContent, /找到 0 位客户/);
  assert.equal(f.node('adminCustomer').value, other.licenseId); assert.equal(f.node('adminLicenseId').value, other.licenseId);
  assert.equal(f.node('adminAction').value, 'renew'); assert.equal(f.node('adminOrderId').value, 'PENDING-RENEWAL');
  assert.equal(f.node('adminPaidConfirmed').checked, true); assert.equal(f.calls.length, 0);
});

test('matched legacy customer is explicit and only switches to renewal when chosen, retaining the payment reference', async () => {
  const legacy = { ...customer, version: 1, plan: 'isp-30d-single', expiresAt: fixedNow + 20 * 86400000, resourcesMode: 'customer' };
  const f = fixture(); f.page.setEnabled(true); f.page.render({ ...status, customers: [legacy] });
  await f.node('adminActivateButton').click(); f.node('adminOrderId').value = 'PENDING-OLD-CUSTOMER';
  f.node('adminApplicationText').value = JSON.stringify({ request: { licenseId: legacy.licenseId, deviceId: legacy.deviceId } });
  await f.node('adminApplicationText').dispatch('input');
  assert.equal(f.node('adminAction').value, 'activate'); assert.equal(f.node('adminMatchedCustomerNotice').hidden, false);
  assert.match(f.node('adminMatchedCustomerText').textContent, /原期限基础上续期/);
  assert.match(f.node('adminRecipient').textContent, /1\.6\.1/);
  f.node('adminPaidConfirmed').checked = true;
  await f.node('adminUseExistingCustomerButton').click();
  assert.equal(f.node('adminAction').value, 'renew'); assert.equal(f.node('adminLicenseId').value, legacy.licenseId);
  assert.equal(f.node('adminApplicationFields').hidden, true); assert.equal(f.node('adminMatchedCustomerNotice').hidden, true);
  assert.equal(f.node('adminOrderId').value, 'PENDING-OLD-CUSTOMER'); assert.equal(f.node('adminPaidConfirmed').checked, false);
  assert.equal(f.calls.length, 0);
});

test('recognized customer with a recorded activation order keeps the original action for idempotent re-save', async () => {
  const paid = { ...customer, plan: 'isp-30d-single', resourcesMode: 'customer', expiresAt: fixedNow + 20 * 86400000 };
  const orders = [{ orderId: 'ORIGINAL-ACTIVATION', kind: 'offline', licenseId: paid.licenseId }];
  const f = fixture(); f.page.setEnabled(true); f.page.render({ ...status, customers: [paid], orders });
  await f.node('adminActivateButton').click();
  f.node('adminApplicationText').value = JSON.stringify({ request: { licenseId: paid.licenseId } });
  await f.node('adminApplicationText').dispatch('input');
  f.node('adminOrderId').value = orders[0].orderId; await f.node('adminOrderId').dispatch('input');
  assert.equal(f.node('adminUseExistingCustomerButton').hidden, true);
  assert.match(f.node('adminReviewSummary').innerHTML, /不重复收款/);
  await f.node('adminUseExistingCustomerButton').click();
  assert.equal(f.node('adminAction').value, 'activate'); assert.equal(f.node('adminOrderId').value, orders[0].orderId);
  await f.node('adminGenerateForm').dispatch('submit');
  assert.equal(f.calls.find(call => call.method === 'licenseAdminGenerate').payload.action, 'activate');
});

test('missing-field navigation focuses the input without confirming payment or signing', async () => {
  const f = fixture(); f.page.setEnabled(true); f.page.render(status);
  await f.node('adminActivateButton').click(); await f.node('adminContinueButton').click();
  assert.equal(f.node('adminApplicationText').focused, true); assert.match(f.node('adminProgressList').innerHTML, /aria-current="step"/);
  f.node('adminApplicationText').value = applicationText; await f.node('adminApplicationText').dispatch('input');
  await f.node('adminContinueButton').click(); assert.equal(f.node('adminPaidConfirmed').focused, true);
  const target = { closest: () => ({ dataset: { focusField: 'adminIspExpiresAt' } }) };
  await f.node('adminMissingList').dispatch('click', { target }); assert.equal(f.node('adminIspExpiresAt').focused, true);
  assert.equal(f.node('adminPaidConfirmed').checked, false); assert.equal(f.calls.length, 0);
});

test('expired and revoked customers receive accurate free-refresh guidance without appearing restored', async () => {
  for (const selected of [{ ...customer, expiresAt: fixedNow - 1000 }, { ...customer, status: 'revoked' }]) {
    const f = fixture(); f.page.setEnabled(true); f.page.render({ ...status, customers: [selected] });
    await f.node('adminRefreshButton').click(); f.node('adminCustomer').value = selected.licenseId;
    await f.node('adminCustomer').dispatch('change');
    assert.match(f.node('adminRecipient').textContent, selected.status === 'revoked' ? /不会恢复使用权/ : /免费重签不能延期/);
    assert.match(f.node('adminRecipient').textContent, /离线文件至/);
    assert.equal(f.calls.length, 0);
  }
});

test('saved review retains the issued operation and actual deadlines while customer copy excludes internal payment instructions', async () => {
  const paid = { ...customer, plan: 'isp-30d-single', expiresAt: fixedNow + 30 * 86400000, offlineUntil: fixedNow + 30 * 86400000 };
  const f = fixture({ licenseAdminGenerate: async () => ({ saved: true, filePath: 'paid.json', licenseId: customer.licenseId, license: paid, customers: [paid], summary: status.summary }) });
  f.page.setEnabled(true); f.page.render(status); await f.node('adminActivateButton').click();
  f.node('adminApplicationText').value = applicationText; await f.node('adminApplicationText').dispatch('input');
  f.node('adminResourcesMode').value = 'customer'; f.node('adminPaidConfirmed').checked = true;
  await f.node('adminGenerateForm').dispatch('submit');
  assert.equal(f.node('adminAction').value, 'refresh');
  assert.match(f.node('adminReviewSummary').innerHTML, /30 天正式开通/);
  assert.match(f.node('adminReviewSummary').innerHTML, /已确认收款/);
  assert.equal(f.node('adminGenerateButton').disabled, true);
  await f.node('adminGenerateForm').dispatch('submit');
  assert.equal(f.calls.filter(call => call.method === 'licenseAdminGenerate').length, 1);
  assert.equal((f.node('adminProgressList').innerHTML.match(/data-state="done"/g) || []).length, 4);
  assert.equal(f.node('adminMissingList').hidden, true);
  await f.node('adminCopyDeliveryButton').click(); assert.equal(f.copied.length, 1);
  assert.match(f.copied[0], /选择签名许可文件/); assert.ok(!f.copied[0].includes('MC-SUGGESTED'));
  assert.ok(!f.copied[0].includes('登记另一笔收款')); assert.ok(!f.copied[0].includes('paid.json'));
  f.node('adminOfflineDays').value = '7'; await f.node('adminOfflineDays').dispatch('change');
  assert.match(f.node('adminReviewSummary').innerHTML, /免费重签/);
  assert.equal(f.node('adminGenerateButton').disabled, false);
  await f.node('adminCopyDeliveryButton').click(); assert.equal(f.copied.length, 1);
});

test('refreshing records preserves expanded signing information and clipboard failure never changes saved status', async () => {
  const f = fixture({ clipboard: { writeText: async () => { throw new Error('denied'); } } });
  f.page.setEnabled(true); f.page.render(status); f.node('adminStoreDetails').open = true;
  await f.node('adminReadButton').click(); assert.equal(f.node('adminStoreDetails').open, true);
  f.node('adminApplicationText').value = applicationText; await f.node('adminGenerateForm').dispatch('submit');
  await f.node('adminCopyDeliveryButton').click();
  assert.equal(f.node('adminSavedFile').hidden, false); assert.match(f.node('adminOperationResult').textContent, /许可文件已保存/);
  assert.equal(f.calls.filter(call => call.method === 'licenseAdminGenerate').length, 1);
});

test('free reissue of a revoked license cannot be described as restored service in customer instructions', async () => {
  const revoked = { ...customer, status: 'revoked' };
  const f = fixture({ licenseAdminGenerate: async () => ({ saved: true, filePath: 'revoked.json', licenseId: customer.licenseId, license: revoked, customers: [revoked], summary: status.summary }) });
  f.page.setEnabled(true); f.page.render({ ...status, customers: [revoked] });
  await f.node('adminRefreshButton').click(); f.node('adminCustomer').value = customer.licenseId;
  await f.node('adminCustomer').dispatch('change'); await f.node('adminGenerateForm').dispatch('submit');
  assert.match(f.node('adminOperationResult').textContent, /撤销许可已保存，不会恢复使用权/);
  await f.node('adminCopyDeliveryButton').click();
  assert.match(f.copied[0], /本文件用于撤销授权，不会恢复软件使用权/);
  assert.ok(!f.copied[0].includes('核验真实出口'));
});
