import { setText, setHtml } from './dom-updates.js';

export const MAX_DEVICE_APPLICATION_BYTES = 8192;
const actions = {
  trial: { application: true, resources: true, offline: true, label: '生成 1 天试用许可', help: '免费试用1天，不记收款；相同设备重复签发不延长试用。' },
  activate: { application: true, paid: true, resources: true, offline: true, label: '保存 30 天正式许可', help: '新客户正式开通：确认已收 ¥100 且线路就绪后，签发 30 天许可。' },
  renew: { id: true, paid: true, resources: true, offline: true, label: '保存 30 天正式许可', help: '试用转正式或续费，沿用同一客户编号。确认本次收款与线路；不需要重新提供设备申请。' },
  refresh: { id: true, offline: true, label: '免费重签并保存许可', help: '仅更新离线许可，不延长授权或线路期限，也不新增收款订单。' },
  rebind: { id: true, application: true, offline: true, label: '保存换机许可', help: '保留原授权期限并绑定新设备。旧设备已经收到的离线许可在剩余期限内无法远程即时停用。' },
  resources: { id: true, resources: true, label: '保存资源提醒及许可', help: '登记资源供应方式、ISP / VPS 提醒日期或待开通状态，不延长软件授权，也不因资源到期截短许可。线路实际撤销须在供应商处单独处理。' },
  revoke: { id: true, label: '保存撤销许可', help: '撤销此客户授权。已有离线许可在剩余期限内无法远程即时停用；ISP / VPS 资源须另外撤销。' },
};
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const safeCode = error => /^[A-Z][A-Z0-9_]{0,79}$/.test(error?.code || '') ? `（${error.code}）` : '';
const stamp = value => typeof value === 'number' ? Number.isSafeInteger(value) && value >= 0 ? value : NaN : typeof value === 'string' ? Date.parse(value) : NaN;
const dateLabel = value => { const date = new Date(stamp(value)); return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '尚未登记'; };
const localDate = value => {
  const date = new Date(stamp(value));
  return Number.isFinite(date.getTime()) ? new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '';
};
const money = value => `¥${(Number.isSafeInteger(value) && value >= 0 ? value / 100 : 0).toFixed(2)}`;
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const planLabel = value => /trial/i.test(value || '') ? '1 天试用' : value === 'isp-30d-single' ? '30 天正式' : '许可';
const stateLabel = value => ({ active: '有效', trial: '试用', expired: '已到期', revoked: '已撤销', 'pending-resource': '线路待开通', 'offline-expired': '离线到期' }[value] || '待核验');
const fixedTrialWindow = (action, plan) => action === 'trial' || ['refresh', 'rebind'].includes(action) && plan === 'isp-1d-trial';
const DAY = 86400000;
const validLicenseId = value => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(String(value || '').trim());
const requestCustomer = (text, customers) => {
  let request;
  try { request = JSON.parse(String(text || '').replace(/^\uFEFF/, '')).request; } catch { return null; }
  if (!request || typeof request !== 'object') return null;
  return request.licenseId ? customers.find(item => item.licenseId === request.licenseId) : customers.findLast(item => item.deviceId === request.deviceId && item.status !== 'revoked');
};

export function adminTermPreview(values, customers = [], orders = [], now = Date.now()) {
  const action = values.action;
  let customer = customers.find(item => item.licenseId === String(values.licenseId || '').trim());
  if (action === 'activate') {
    customer = requestCustomer(values.applicationText, customers);
  }
  if (!['trial', 'activate', 'renew', 'resources', 'refresh', 'rebind'].includes(action)) return { blocked: false, text: '' };
  if (actions[action].id && !customer) return { blocked: ['renew', 'resources'].includes(action), text: '请先读取客户记录并选择已登记客户，确认原软件与线路期限。' };
  const completed = orders.find(order => order.orderId === String(values.orderId || '').trim() && order.kind === (action === 'renew' ? 'renew' : 'offline') && order.licenseId === customer?.licenseId);
  if (['activate', 'renew'].includes(action) && completed) return { blocked: false, completedOrder: true, text: '此订单已成功记账。本次只重新保存现有许可，不重复收费或延长软件期限。' };
  const mode = values.resourcesMode ?? customer?.resourcesMode ?? 'included';
  const paid = ['activate', 'renew'].includes(action), usesInputs = actions[action].resources && (action !== 'resources' || values.resourcesReady === true);
  const repeatedTrial = action === 'trial' && customer?.plan === 'isp-1d-trial';
  const expiresAt = paid ? (customer?.plan === 'isp-30d-single' ? Math.max(now, stamp(customer.expiresAt)) : now) + 30 * DAY : action === 'trial' && !repeatedTrial ? now + DAY : stamp(customer?.expiresAt);
  const ispExpiresAt = stamp(usesInputs ? values.ispExpiresAt : customer?.ispExpiresAt);
  const vpsValue = usesInputs ? values.vpsExpiresAt : customer?.vpsExpiresAt;
  const vpsExpiresAt = vpsValue ? stamp(vpsValue) : null;
  const requiresCoverage = paid && mode === 'included';
  const short = requiresCoverage && (!Number.isFinite(ispExpiresAt) || ispExpiresAt < expiresAt);
  const days = fixedTrialWindow(action, customer?.plan) ? 1 : Number(values.offlineDays || customer?.offlineDays || 30);
  const offlineUntil = Math.min(now + days * DAY, expiresAt);
  const resourceText = mode === 'customer' ? '客户自带 ISP，无需填写供应商日期；仍可选择默认免费 VPS 中转。' : `ISP 资源提醒：${dateLabel(ispExpiresAt)}；免费可选 VPS 资源提醒：${vpsExpiresAt === null ? '未登记' : dateLabel(vpsExpiresAt)}。`;
  const text = `拟软件截止：${dateLabel(expiresAt)}；拟离线许可截止：${dateLabel(offlineUntil)}。${resourceText}${repeatedTrial ? ' 此设备已领试用，重复签发沿用原截止，不会重新起算1天。' : ''}`;
  return { blocked: short, expiresAt, offlineUntil, text: text + (short ? ' 线路不足以覆盖完整软件期限，无法提交；请先在供应商处延长资源。缩短离线许可天数不会减少应交付的付费期限。本次不会新增收款记录或延期。' : requiresCoverage ? ' 线路已覆盖完整软件期限；最终签发仍以本机授权库核验为准。' : '') };
}

export const licensingAdminAvailable = (info, mock = false) => info?.edition === 'developer' && (mock === true || info?.mock !== true);

function deviceApplicationText(text) {
  if (typeof text !== 'string' || !text.trim() || new TextEncoder().encode(text).byteLength > MAX_DEVICE_APPLICATION_BYTES) throw new Error('请提供不超过 8 KiB 的设备申请 JSON。');
  let application;
  try { application = JSON.parse(text.replace(/^\uFEFF/, '')); } catch { throw new Error('设备申请须为有效 JSON。'); }
  if (!application || typeof application !== 'object' || Array.isArray(application)) throw new Error('设备申请须为 JSON 对象。');
  return text;
}

export function buildAdminPayload(values, { completedOrder = false } = {}) {
  const action = values.action, rule = actions[action];
  if (!rule) throw new Error('请选择有效操作。');
  const payload = { action };
  const mode = values.resourcesMode ?? 'included';
  if (!['included', 'customer'].includes(mode)) throw new Error('请选择有效的资源供应方式。');
  if (rule.resources) payload.resourcesMode = mode;
  if (rule.id) {
    payload.licenseId = String(values.licenseId || '').trim();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(payload.licenseId)) throw new Error('请先选择客户或填写有效授权编号。');
  }
  if (rule.application) {
    payload.applicationText = deviceApplicationText(values.applicationText || '');
  }
  if (rule.paid) {
    payload.orderId = String(values.orderId || '').trim();
    if (!/^[A-Za-z0-9_-]{1,100}$/.test(payload.orderId)) throw new Error('请填写本次唯一收款订单编号，仅用英数字、下划线或短横线，最多 100 字符。');
    if (!completedOrder && values.paidConfirmed !== true) throw new Error('请先确认已收到 ¥100。');
    if (!completedOrder && mode === 'included' && values.resourcesReady !== true) throw new Error('包含 ISP 的正式开通或续费前，请确认线路资源可用。');
    payload.paidConfirmed = values.paidConfirmed === true;
  }
  if (rule.resources) {
    payload.resourcesReady = mode === 'customer' || values.resourcesReady === true;
    if (action === 'trial' && !payload.resourcesReady) throw new Error('试用签发前，请确认线路资源可用。');
    for (const key of ['ispExpiresAt', 'vpsExpiresAt']) {
      const value = mode === 'customer' ? null : values[key];
      if (!value) { payload[key] = null; continue; }
      const date = new Date(value);
      if (!Number.isFinite(date.getTime())) throw new Error('请填写有效的线路到期时间。');
      payload[key] = date.toISOString();
    }
    if (!completedOrder && mode === 'included' && payload.resourcesReady && !payload.ispExpiresAt) throw new Error('线路资源就绪时，请填写 ISP 到期时间。');
  }
  if (rule.offline) {
    payload.offlineDays = fixedTrialWindow(action, values.plan) ? 1 : Number(values.offlineDays || 30);
    if (![1, 3, 7, 15, 30].includes(payload.offlineDays)) throw new Error('请选择有效的离线许可期限。');
  }
  if (action === 'revoke' && values.revokeConfirmed !== true) throw new Error('请先确认撤销与离线许可的剩余期限。');
  return payload;
}

export function createLicensingAdminPage({ root = document, desktop = globalThis.window?.mcDesktop, now = Date.now, orderIdFactory = () => `MC-${globalThis.crypto.randomUUID()}`, clipboard = globalThis.navigator?.clipboard } = {}) {
  const find = id => root.querySelector(`#${id}`);
  const page = find('screen-licensing-admin');
  let enabled = false, busy = false, status = {}, customers = [], inputRevision = 0, matchedApplicationId = '';
  let savedReview = '', customerDeliveryText = '', termBlockKey = '', storeRendered = false;
  const controls = ['adminSelectStoreButton', 'adminCreateStoreButton', 'adminReadButton', 'adminCustomer', 'adminAction', 'adminLicenseId', 'adminApplicationFileButton', 'adminApplicationFile', 'adminApplicationText', 'adminOrderId', 'adminPaidConfirmed', 'adminResourcesMode', 'adminResourcesReady', 'adminIspExpiresAt', 'adminVpsExpiresAt', 'adminOfflineDays', 'adminRevokeConfirmed', 'adminGenerateButton', 'adminTrialButton', 'adminActivateButton', 'adminRenewButton', 'adminRefreshButton', 'adminRebindButton', 'adminResourcesButton', 'adminRevokeButton', 'adminNewOrderButton'];
  controls.push('adminCustomerSearch', 'adminContinueButton', 'adminUseExistingCustomerButton', 'adminCopyDeliveryButton');
  const message = (text, error = false) => { find('adminOperationResult').textContent = text; find('adminOperationResult').dataset.error = String(error); };
  const bridge = async (method, payload) => {
    if (typeof desktop?.[method] !== 'function') throw Object.assign(new Error('Unavailable'), { code: 'LICENSE_ADMIN_UNAVAILABLE' });
    return desktop[method](payload);
  };
  const currentCustomer = () => customers.find(customer => customer.licenseId === find('adminLicenseId').value.trim());
  const formValues = () => ({ action: find('adminAction').value, plan: currentCustomer()?.plan, licenseId: find('adminLicenseId').value, applicationText: find('adminApplicationText').value, orderId: find('adminOrderId').value, paidConfirmed: find('adminPaidConfirmed').checked, resourcesMode: find('adminResourcesMode').value || 'included', resourcesReady: find('adminResourcesReady').checked, ispExpiresAt: find('adminIspExpiresAt').value, vpsExpiresAt: find('adminVpsExpiresAt').value, offlineDays: find('adminOfflineDays').value, revokeConfirmed: find('adminRevokeConfirmed').checked });
  const preview = () => adminTermPreview(formValues(), customers, Array.isArray(status.orders) ? status.orders : [], now());
  const resetSavedFile = () => { find('adminSavedFile').hidden = true; find('adminSavedFile').textContent = ''; find('adminDeliveryPanel').hidden = true; savedReview = ''; customerDeliveryText = ''; };
  function renderCustomerOptions() {
    const selection = find('adminLicenseId').value || find('adminCustomer').value;
    const query = find('adminCustomerSearch').value.trim().toLowerCase();
    const matches = customers.filter(customer => [customer.licenseId, customer.deviceId, planLabel(customer.plan), stateLabel(customer.status)].some(value => String(value || '').toLowerCase().includes(query)));
    const selected = customers.find(customer => customer.licenseId === selection);
    const visible = selected && !matches.includes(selected) ? [selected, ...matches] : matches;
    setHtml(find('adminCustomer'), '<option value="">请选择已有客户</option>' + visible.map(customer => `<option value="${esc(customer.licenseId)}">${customer === selected && !matches.includes(customer) ? '已选择 · ' : ''}${esc(customer.licenseId)} · ${esc(planLabel(customer.plan))} · ${esc(stateLabel(customer.status))}</option>`).join(''));
    find('adminCustomer').value = selected?.licenseId || '';
    setText(find('adminCustomerSearchStatus'), !customers.length ? '此授权库暂无客户。如曾经签发过，请核对是否选择了原授权库。' : query ? `找到 ${matches.length} 位客户。${matches.length ? '从下方选择本次客户。' : '换一段客户编号或设备编号试试。'}${selected && !matches.includes(selected) ? ' 当前已选客户保留，搜索不会切换客户。' : ''}` : `共 ${customers.length} 位客户，可按客户编号或设备编号查找。`);
  }
  function focusField(id) {
    if (!id) return;
    const field = find(id);
    if (!field || field.disabled) return;
    let detail = field.closest?.('details');
    while (detail) { detail.open = true; detail = detail.parentElement?.closest('details'); }
    field.scrollIntoView?.({ block: 'center' }); field.focus?.({ preventScroll: true });
  }
  function reviewMarkup(check, license) {
    const { values, rule, term, identityReady } = check, selected = currentCustomer();
    const labels = { trial: '1 天试用', activate: selected ? '原客户正式开通 / 延期' : '30 天正式开通', renew: selected?.plan === 'isp-1d-trial' ? '试用转正式' : '正式续费 30 天', refresh: '免费重签', rebind: '原客户换机', resources: '更新资源提醒', revoke: '撤销许可' };
    const rows = [['本次办理', term.completedOrder ? '原订单重新保存' : labels[values.action]], ['客户编号', license?.licenseId || selected?.licenseId || (identityReady ? '新客户 · 签发后生成' : '等待客户资料')], ['收款', term.completedOrder ? '原订单已记账 · 不重复收款' : rule.paid ? `¥100 · ${license || values.paidConfirmed ? '已确认收款' : '待确认到账'}` : '¥0 · 不新增收款']];
    if (rule.paid) rows.push(['付款订单', values.orderId || '等待填写']);
    if (values.action !== 'revoke' && identityReady) {
      rows.push(['软件授权至', dateLabel(license?.expiresAt ?? (term.completedOrder ? selected?.expiresAt : term.expiresAt))]);
      if (rule.offline || license) rows.push(['离线文件至', dateLabel(license?.offlineUntil ?? (term.completedOrder ? selected?.offlineUntil : term.offlineUntil))]);
    }
    return rows.map(([label, value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('');
  }
  function suggestOrder() {
    if (!actions[find('adminAction').value]?.paid || find('adminOrderId').value.trim()) return;
    try { find('adminOrderId').value = orderIdFactory(); }
    catch { message('无法自动建议订单编号，请手动填写本次收款的唯一编号。', true); }
  }
  function matchApplicationCustomer() {
    if (!['trial', 'activate'].includes(find('adminAction').value)) return;
    const customer = requestCustomer(find('adminApplicationText').value, customers);
    const id = customer?.licenseId || '';
    if (id === matchedApplicationId) return;
    matchedApplicationId = id;
    find('adminLicenseId').value = id; find('adminCustomer').value = id;
    renderCustomerOptions();
    find('adminResourcesMode').value = customer?.resourcesMode || 'included';
    find('adminIspExpiresAt').value = customer ? localDate(customer.ispExpiresAt) : '';
    find('adminVpsExpiresAt').value = customer ? localDate(customer.vpsExpiresAt) : '';
    find('adminResourcesReady').checked = false; find('adminPaidConfirmed').checked = false;
  }
  function readiness() {
    const values = formValues(), rule = actions[values.action] || actions.trial, term = preview(), issues = [];
    const add = (text, target) => { if (!issues.some(issue => issue.text === text)) issues.push({ text, target }); };
    const customer = currentCustomer();
    if (!status.configured) add('先选择正式安装包信任的现有授权库。', 'adminSelectStoreButton');
    let identityReady = true;
    if (rule.id && (!validLicenseId(values.licenseId) || !customer)) { identityReady = false; add('刷新客户记录并选择本次客户；续费无需重新提供申请。', 'adminCustomer'); }
    if (rule.application) {
      try { deviceApplicationText(values.applicationText); }
      catch (error) { identityReady = false; add(values.applicationText.trim() ? error.message : '粘贴客户从“授权与续费”复制的完整设备申请，或读取申请JSON文件。', 'adminApplicationText'); }
    }
    if (values.action === 'trial' && customer) {
      if (customer.plan !== 'isp-1d-trial') add('此设备已有正式授权，不能再次试用；选择“转正式 / 续费”及原客户。', 'adminUseExistingCustomerButton');
      else if (stamp(customer.expiresAt) <= now()) add('此设备的1天试用已结束，重复签发不会延期；选择“转正式 / 续费”及原客户。', 'adminUseExistingCustomerButton');
    }
    const matchingOrder = (status.orders || []).find(order => order.orderId === values.orderId.trim());
    if (rule.paid && matchingOrder && !term.completedOrder) add('此订单已用于另一客户或操作；核对原记录，不要用它登记另一笔付款。', 'adminOrderId');
    if (identityReady && status.configured) {
      if (rule.paid) {
        if (!/^[A-Za-z0-9_-]{1,100}$/.test(values.orderId.trim())) add('填写本次唯一付款订单编号，只用英数字、下划线或短横线，最多100字符。', 'adminOrderId');
        if (!term.completedOrder && values.paidConfirmed !== true) add('实际收到本次¥100后，勾选收款确认；未收款请用1天试用。', 'adminPaidConfirmed');
      }
      if (rule.resources && values.resourcesMode === 'included' && !term.completedOrder) {
        if ((rule.paid || values.action === 'trial') && !values.resourcesReady) add('核对本客户的独立ISP线路可用，再勾选线路就绪。', 'adminResourcesReady');
        if ((rule.paid || values.action === 'trial' || values.resourcesReady) && !values.ispExpiresAt) add('填写供应商提供的真实ISP到期时间；客户自带ISP可更改供应方式。', 'adminIspExpiresAt');
        if (term.blocked && values.ispExpiresAt) add(`ISP须完整覆盖软件至${dateLabel(term.expiresAt)}；先在供应商处延长，再填真实日期。`, 'adminIspExpiresAt');
      }
      if (values.action === 'revoke' && !values.revokeConfirmed) add('核对原客户后勾选撤销确认，已有离线许可在剩余期限内无法即时停用。', 'adminRevokeConfirmed');
      if (!issues.length) {
        try { buildAdminPayload(values, term); }
        catch (error) { add(error.message, 'adminConditionsSection'); }
      }
      if (values.action === 'trial' && values.resourcesMode !== 'customer' && Number.isFinite(stamp(values.ispExpiresAt)) && stamp(values.ispExpiresAt) <= now()) add('试用ISP日期已到期，请填写供应商真实的未来到期时间。', 'adminIspExpiresAt');
    }
    return { values, rule, term, identityReady, issues, missing: issues.map(issue => issue.text), ready: status.configured && identityReady && !issues.length };
  }
  function updateControls() {
    const rule = actions[find('adminAction').value] || actions.trial;
    const trialWindow = fixedTrialWindow(find('adminAction').value, currentCustomer()?.plan);
    page.setAttribute('aria-busy', String(busy));
    controls.forEach(id => { find(id).disabled = busy || !enabled || status.enabled === false || !status.configured && !['adminSelectStoreButton', 'adminCreateStoreButton', 'adminReadButton', 'adminContinueButton'].includes(id); });
    if (trialWindow) find('adminOfflineDays').value = '1';
    find('adminOfflineDays').disabled ||= trialWindow;
    find('adminLicenseIdField').hidden = !rule.id;
    find('adminApplicationFields').hidden = !rule.application;
    find('adminOrderFields').hidden = !rule.paid;
    find('adminResourcesModeField').hidden = !rule.resources;
    find('adminResourceFields').hidden = !rule.resources || find('adminResourcesMode').value === 'customer';
    find('adminOfflineDaysField').hidden = !rule.offline;
    find('adminRevokeField').hidden = find('adminAction').value !== 'revoke';
    const check = readiness(), { term } = check;
    const laterControls = ['adminOrderId', 'adminPaidConfirmed', 'adminResourcesMode', 'adminResourcesReady', 'adminIspExpiresAt', 'adminVpsExpiresAt', 'adminOfflineDays', 'adminRevokeConfirmed', 'adminNewOrderButton'];
    if (!check.identityReady) laterControls.forEach(id => { find(id).disabled = true; });
    find('adminCustomerField').hidden = !rule.id;
    find('adminLicenseIdField').hidden = true;
    setText(find('adminActionHelp'), rule.help);
    setText(find('adminTermPreview'), term.text);
    find('adminTermPreview').hidden = !check.identityReady;
    find('adminTermPreview').dataset.error = String(term.blocked);
    const nextTermBlockKey = term.blocked && check.identityReady && check.values.ispExpiresAt
      ? `${check.values.action}:${check.values.licenseId}:${check.values.ispExpiresAt}` : '';
    if (nextTermBlockKey && nextTermBlockKey !== termBlockKey) {
      const detail = find('adminTermPreview').closest?.('details');
      if (detail) detail.open = true;
    }
    termBlockKey = nextTermBlockKey;
    const selected = currentCustomer() || (find('adminAction').value === 'activate' ? requestCustomer(find('adminApplicationText').value, customers) : null);
    const action = check.values.action;
    let customerHint = '';
    if (selected?.status === 'revoked') customerHint = ' 此客户已撤销；免费重签只会补发撤销文件，不会恢复使用权。';
    else if (selected && action === 'refresh' && stamp(selected.expiresAt) <= now()) customerHint = ' 软件期限已到，免费重签不能延期。请回到“转正式 / 续费”。';
    else if (selected?.version === 1) customerHint = ' 原客户编号继续沿用；本次新许可导入前，客户软件须升级至 1.6.1 或更高版本。';
    setText(find('adminRecipient'), selected ? `当前客户：${selected.licenseId} · ${planLabel(selected.plan)} · 软件至 ${dateLabel(selected.expiresAt)} · 离线文件至 ${dateLabel(selected.offlineUntil)}。${customerHint}` : rule.application ? '申请签名与设备身份仍须在本机签发时核验。' : '选择原客户，沿用编号、ISP供应方式与软件期限。');
    const matched = selected && ['trial', 'activate'].includes(action);
    const recordedOrder = rule.paid && (status.orders || []).some(order => order.orderId === check.values.orderId.trim());
    find('adminMatchedCustomerNotice').hidden = !matched;
    setText(find('adminMatchedCustomerText'), matched ? `申请信息对应原客户 ${selected.licenseId}。${term.completedOrder ? '本次只重新保存现有许可，不再延期或记账。' : action === 'activate' ? '本次将沿用原编号办理正式许可；已有正式客户会在原期限基础上续期。' : '重复试用沿用原截止，不重新起算。'}${recordedOrder ? '此订单已有记录，请保持当前办理方式和订单号重试。' : '也可直接沿用此客户进入“转正式 / 续费”，无需再次申请。'}申请签名仍须在签发时核验。` : '');
    find('adminUseExistingCustomerButton').hidden = !!recordedOrder;
    const saved = !find('adminSavedFile').hidden;
    page.dataset.deliverySaved = String(saved);
    const currentStep = !status.configured ? 0 : !check.identityReady ? 1 : !check.ready ? 2 : 3;
    setHtml(find('adminProgressList'), ['授权库', rule.id ? '选择客户' : '客户申请', '交付条件', '保存许可'].map((label, index) => {
      const done = saved || index < currentStep, current = !saved && index === currentStep;
      return `<li data-state="${done ? 'done' : current ? 'current' : 'waiting'}"${current ? ' aria-current="step"' : ''}><span>${index + 1}</span>${label}<small>${done ? index === 3 ? '已保存' : '已具备' : current ? busy ? '处理中' : '当前步骤' : '待完成'}</small></li>`;
    }).join(''));
    setHtml(find('adminMissingList'), check.issues.map(issue => `<li><button type="button" data-focus-field="${esc(issue.target)}"${busy || !enabled || status.enabled === false ? ' disabled' : ''}>${esc(issue.text)}</button></li>`).join(''));
    find('adminMissingList').hidden = saved || !check.missing.length;
    setText(find('adminNextStep'), saved ? '本次文件已保存，请按下方交付说明发送给对应客户。补发用“免费重签”，新的付款才办理续费。' : busy ? '正在处理本机操作；若系统对话框已打开，请在其中完成选择。' : check.ready ? term.completedOrder ? '原订单已记账，可以重新保存；不会再次收款或延期。' : '条件已齐，核对期限后选择新的软件JSON保存位置。' : !status.configured ? '第一步：选择原签发授权库。' : !check.identityReady ? rule.id ? '第二步：选择本次客户。' : '第二步：提供完整客户申请。' : '点击下方待补项，即可定位到对应位置。');
    find('adminContinueButton').hidden = saved || check.ready;
    setText(find('adminContinueButton').querySelector('span'), !status.configured ? '选择已有授权库' : '定位下一处待补项');
    setHtml(find('adminReviewSummary'), savedReview || reviewMarkup(check));
    find('adminCopyDeliveryButton').disabled ||= !saved;
    for (const [id, action] of [['adminTrialButton', 'trial'], ['adminActivateButton', 'activate'], ['adminRenewButton', 'renew'], ['adminRefreshButton', 'refresh'], ['adminRebindButton', 'rebind'], ['adminResourcesButton', 'resources'], ['adminRevokeButton', 'revoke']]) find(id).setAttribute('aria-pressed', String(find('adminAction').value === action));
    find('adminActionHelp').dataset.error = String(term.blocked);
    find('adminGenerateButton').disabled ||= saved || !check.ready;
    setText(find('adminGenerateButton'), saved ? '本次许可已保存' : term.completedOrder ? '重新保存原订单许可' : rule.label);
  }
  function render(data = {}) {
    const storeChanged = !storeRendered || status.configured !== data.configured;
    storeRendered = true;
    status = data;
    customers = Array.isArray(data.customers) ? data.customers : [];
    const orders = Array.isArray(data.orders) ? data.orders : [], summary = data.summary || {};
    setText(find('adminStoreState'), data.configured ? '已选择' : '未配置');
    if (storeChanged) find('adminStoreDetails').open = !data.configured;
    setText(find('adminStoreDirectory'), data.directory || '选择包含 server-config.json 的原授权库文件夹。');
    find('adminStoreDirectory').title = find('adminStoreDirectory').textContent;
    setText(find('adminStoreHint'), data.configured ? '已连接原签发库。老客户续费、转正式和补发，均沿用下方现有记录。' : '为已有客户继续授权，请先选择原签发库；新建库无法替代原来的签名身份。');
    setText(find('adminStoreFingerprint'), data.publicKeyFingerprint ? `公钥指纹：${data.publicKeyFingerprint}${data.keyId ? ` · ${data.keyId}` : ''}` : '签名公钥指纹尚未读取');
    setText(find('adminCustomerCount'), count(summary.licenseCount ?? summary.customers));
    setText(find('adminTrialCount'), count(summary.trialCount ?? summary.trial));
    setText(find('adminActiveCount'), count(summary.paidLicenseCount ?? summary.active));
    setText(find('adminRevenue'), money(summary.totalReceivedFen ?? summary.revenueFen));
    setText(find('adminPaidOrders'), `${count(summary.paidOrders ?? orders.filter(order => order.amountFen > 0).length)} 笔付费订单`);
    renderCustomerOptions();
    setHtml(find('adminCustomerList'), customers.length ? customers.map(customer => `<article class="admin-record"><strong class="license-identifier">${esc(customer.licenseId)}</strong><span>${esc(planLabel(customer.plan))} · ${esc(stateLabel(customer.status))}</span><small>${customer.resourcesMode === 'customer' ? '客户自带 ISP · 可选免费 VPS' : `包含 ISP · 资源${({ active: '可用', pending: '待开通', expired: '已到期' }[customer.resourceStatus] || '待确认')}`}${customer.version === 1 ? ' · 旧许可可免费重签升级' : ''}</small><small>设备 ${esc(customer.deviceId || '尚未绑定')}</small><small>授权至 ${esc(dateLabel(customer.expiresAt))}</small><small>离线至 ${esc(dateLabel(customer.offlineUntil))} · 第 ${count(customer.generation)} 版</small></article>`).join('') : '<p class="empty-state">暂无客户。先生成一份 1 天试用许可。</p>');
    setHtml(find('adminOrderList'), orders.length ? orders.map(order => `<article class="admin-record"><strong class="license-identifier">${esc(order.orderId)}</strong><span>${esc(order.licenseId)} · ${esc(money(order.amountFen))}</span><small>${esc(order.kind === 'renew' ? '正式续费 / 转正式' : '正式开通')} · ${esc(dateLabel(order.paidAt))}</small><small>${order.resourcesMode === 'customer' ? '客户自带 ISP · ISP 成本 ¥0.00' : `包含 ISP · ISP 成本 ${esc(money(order.ispCostFen))}`}</small></article>`).join('') : '<p class="empty-state">暂无付费订单。</p>');
    matchApplicationCustomer(); updateControls();
  }
  async function operation(progress, run) {
    if (busy || !enabled || status.enabled === false) return false;
    busy = true; updateControls(); message(progress);
    try { await run(); return true; }
    catch (error) {
      const guidance = {
        RESOURCE_TERM_TOO_SHORT: '套餐 ISP 未完整覆盖软件授权截止；本次未新增收款记录、未延期、未保存许可。请先延长 ISP，再刷新记录重试。免费可选 VPS 不限制许可期限。',
        RESOURCE_NOT_READY: '核对ISP供应方式。包含ISP时须填写真实未来到期时间并确认线路可用；客户自带ISP无需日期。',
        PAYMENT_NOT_CONFIRMED: '确认实际收到本次¥100后勾选收款；未收到款请用1天试用。',
        ORDER_CONFLICT: '此订单号属于其他操作或客户。核对付款记录；同笔付款重试须使用原订单号。',
        ORDER_EXISTS: '订单已记账，请刷新记录并按原客户、原操作和原订单重新保存；不要再登记收款。',
        INVALID_REQUEST: '请客户重新从“授权与续费”生成完整设备申请，原样复制或导出JSON；不要编辑其中内容。',
        LICENSE_ADMIN_APPLICATION_INVALID: '请客户重新从“授权与续费”生成完整设备申请，原样复制或导出JSON；不要编辑其中内容。',
        INVALID_SIGNATURE: '设备申请签名未通过，请重新获取完整申请；不要手动改申请字段。',
        DEVICE_MISMATCH: '申请属于另一设备。核对当前客户；换电脑请用维护中的“换机”。',
        TRIAL_UNAVAILABLE: '该设备已有正式授权，请选择原客户续费；不能重新领取试用。',
        LICENSE_REVOKED: '客户已撤销，请先核对原订单和设备记录；不能直接续费。',
        LICENSE_NOT_FOUND: '原客户不在此授权库中。选择原签发库并刷新客户记录，不能用新库替代原客户。',
        LICENSE_EXPIRED: '软件付费期已到期；免费重签不能延期。选择“转正式 / 续费”，收到本次款后续期。',
        INVALID_ORDER: '付款订单须使用英数字、下划线或短横线，最多100字符；同笔付款重试保留原编号。',
        INVALID_OFFLINE_WINDOW: '请选择1、3、7、15或30天；1天试用只能签发1天。',
        TRIAL_WINDOW_FIXED: '试用的离线期限固定1天；满意后选择原客户转正式。',
        LICENSE_ADMIN_STORE_REQUIRED: '先选择原签发授权库，再准备客户资料。',
        LICENSE_ADMIN_SETTINGS_INVALID: '授权库配置无法读取。重新选择完整的原授权库目录，核对私有备份与文件权限。',
        LICENSE_ADMIN_SIGN_FAILED: '签发未完成，请检查原授权库权限与私有备份，按原订单重试；不要更换付款编号。',
        LICENSE_ADMIN_STORE_CHANGED: '授权库公钥已改变，请重新选择原签发库并核对安装包信任的指纹。',
        SIGNING_KEY_UNAVAILABLE: '无法读取签发私钥，请检查原授权库权限或恢复私有备份；不要创建新库替代原签名根。',
        UNSAFE_FILE: '文件或目录包含链接等不安全路径，请选普通私有目录及新的JSON文件名。',
        OUTPUT_EXISTS: '文件已存在，请选新的JSON文件名；原订单编号保持不变。',
        SERVER_CLOCK_INVALID: '本机时间早于台账，请校准管理员电脑时间后按原订单重试。',
      };
      message(`${guidance[error?.code] || '本机授权操作未完成。检查授权库与客户申请后按原订单重试；错误详情可用于诊断。'}${safeCode(error)}`, true); return false;
    }
    finally { busy = false; updateControls(); }
  }
  async function readStatus() {
    return operation('正在读取本机客户记录…', async () => { render(await bridge('licenseAdminStatus')); message('客户记录已读取；未访问在线授权服务。'); });
  }
  function clearInputs() {
    inputRevision++; matchedApplicationId = '';
    find('adminApplicationText').value = ''; find('adminApplicationFile').value = ''; find('adminOrderId').value = '';
    find('adminPaidConfirmed').checked = false; find('adminRevokeConfirmed').checked = false;
  }
  function selectCustomer(customer, preserveSavedFile = false, requestedAction) {
    const savedOrder = preserveSavedFile ? find('adminOrderId').value : '';
    clearInputs();
    if (!preserveSavedFile) resetSavedFile();
    find('adminLicenseId').value = customer?.licenseId || '';
    find('adminCustomer').value = customer?.licenseId || '';
    find('adminResourcesMode').value = customer?.resourcesMode || 'included';
    find('adminIspExpiresAt').value = customer ? localDate(customer.ispExpiresAt) : '';
    find('adminVpsExpiresAt').value = customer ? localDate(customer.vpsExpiresAt) : '';
    find('adminResourcesReady').checked = false;
    find('adminAction').value = requestedAction || (customer ? customer.plan === 'isp-1d-trial' ? 'renew' : 'refresh' : 'trial');
    find('adminOfflineDays').value = fixedTrialWindow(find('adminAction').value, customer?.plan) ? '1' : '30';
    if (savedOrder) find('adminOrderId').value = savedOrder;
    suggestOrder();
    renderCustomerOptions();
    updateControls();
  }
  find('adminReadButton').addEventListener('click', readStatus);
  for (const [id, method] of [['adminSelectStoreButton', 'licenseAdminSelectStore'], ['adminCreateStoreButton', 'licenseAdminCreateStore']]) {
    find(id).addEventListener('click', () => operation('正在等待本机授权库对话框…', async () => {
      const result = await bridge(method);
      if (result?.canceled) { message('已取消选择，授权库保持原状。'); return; }
      find('adminCustomerSearch').value = '';
      render(await bridge('licenseAdminStatus')); find('adminCustomer').value = ''; selectCustomer(); message('已读取所选授权库。请核对公钥指纹与正式安装包一致。');
    }));
  }
  find('adminCustomer').addEventListener('change', () => {
    if (busy || !enabled) return;
    const action = find('adminAction').value;
    selectCustomer(customers.find(item => item.licenseId === find('adminCustomer').value), false, actions[action]?.id ? action : undefined);
  });
  find('adminCustomerSearch').addEventListener('input', () => { if (!busy && enabled) renderCustomerOptions(); });
  find('adminContinueButton').addEventListener('click', () => {
    if (busy || !enabled || status.enabled === false) return;
    if (!status.configured) { find('adminSelectStoreButton').click(); return; }
    focusField(readiness().issues[0]?.target || 'adminGenerateButton');
  });
  find('adminMissingList').addEventListener('click', event => {
    if (busy || !enabled || status.enabled === false) return;
    const target = event.target?.closest?.('button[data-focus-field]')?.dataset.focusField;
    if (readiness().issues.some(issue => issue.target === target)) focusField(target);
  });
  find('adminUseExistingCustomerButton').addEventListener('click', () => {
    if (busy || !enabled || !status.configured || find('adminUseExistingCustomerButton').hidden) return;
    const customer = requestCustomer(find('adminApplicationText').value, customers);
    if (!customer || !['trial', 'activate'].includes(find('adminAction').value)) return;
    const orderId = find('adminOrderId').value;
    selectCustomer(customer, false, 'renew');
    if (orderId) find('adminOrderId').value = orderId;
    updateControls(); focusField('adminConditionsSection');
    message('已沿用原客户办理转正式 / 续费，客户编号保持不变。请核对本次收款与期限。');
  });
  find('adminCopyDeliveryButton').addEventListener('click', async () => {
    if (busy || !enabled || find('adminDeliveryPanel').hidden || !customerDeliveryText) return;
    const text = customerDeliveryText;
    try {
      if (!clipboard?.writeText) throw new Error('Clipboard unavailable');
      await clipboard.writeText(text);
      if (text === customerDeliveryText) message('客户导入步骤已复制；请连同上面的许可文件发送给对应客户。');
    } catch { if (text === customerDeliveryText) message('无法写入剪贴板；许可文件已保存，可手动复制下方交付说明。', true); }
  });
  const draftChanged = () => { if (busy) return; resetSavedFile(); matchApplicationCustomer(); updateControls(); };
  find('adminLicenseId').addEventListener('input', draftChanged);
  for (const id of ['adminApplicationText', 'adminOrderId', 'adminResourcesMode', 'adminIspExpiresAt', 'adminVpsExpiresAt', 'adminOfflineDays', 'adminResourcesReady', 'adminPaidConfirmed', 'adminRevokeConfirmed']) {
    find(id).addEventListener('input', draftChanged);
    find(id).addEventListener('change', draftChanged);
  }
  find('adminAction').addEventListener('change', () => {
    find('adminOfflineDays').value = fixedTrialWindow(find('adminAction').value, currentCustomer()?.plan) ? '1' : '30';
    resetSavedFile();
    find('adminPaidConfirmed').checked = false; find('adminRevokeConfirmed').checked = false; suggestOrder(); updateControls();
  });
  for (const [id, action] of [['adminTrialButton', 'trial'], ['adminActivateButton', 'activate'], ['adminRenewButton', 'renew'], ['adminRefreshButton', 'refresh'], ['adminRebindButton', 'rebind'], ['adminResourcesButton', 'resources'], ['adminRevokeButton', 'revoke']]) find(id).addEventListener('click', () => {
    if (busy || !enabled || !status.configured) return;
    if (['trial', 'activate'].includes(action)) { find('adminCustomer').value = ''; selectCustomer(null, false, action); }
    else {
      find('adminAction').value = action; find('adminOfflineDays').value = fixedTrialWindow(action, currentCustomer()?.plan) ? '1' : '30';
      find('adminPaidConfirmed').checked = false; find('adminRevokeConfirmed').checked = false; resetSavedFile(); suggestOrder(); updateControls();
    }
    message(actions[action].help);
  });
  find('adminNewOrderButton').addEventListener('click', () => {
    if (busy || !enabled || !status.configured || !actions[find('adminAction').value]?.paid) return;
    find('adminOrderId').value = ''; find('adminPaidConfirmed').checked = false; suggestOrder(); resetSavedFile(); updateControls();
    message('已建议另一笔收款的新订单号。仅用于新付款；同笔付款重新保存须填回原订单号。');
  });
  find('adminApplicationFileButton').addEventListener('click', () => { if (!busy && enabled && status.configured) find('adminApplicationFile').click(); });
  find('adminApplicationFile').addEventListener('change', async () => {
    const file = find('adminApplicationFile').files?.[0]; find('adminApplicationFile').value = '';
    if (!file || busy || !enabled || !status.configured) return;
    if (!/\.json$/i.test(file.name) || file.size > MAX_DEVICE_APPLICATION_BYTES) { message('请选择不超过 8 KiB 的设备申请 .json 文件。', true); return; }
    const revision = inputRevision;
    return operation('正在读取设备申请文件…', async () => {
      try {
        const text = deviceApplicationText(await file.text());
        if (revision !== inputRevision) return;
        find('adminApplicationText').value = text; resetSavedFile(); matchApplicationCustomer(); message('设备申请已读取；签名与设备身份仍须在签发时核验。');
      } catch { message('设备申请文件无法读取，请核验 JSON 与大小。', true); }
    });
  });
  find('adminGenerateForm').addEventListener('submit', event => {
    event.preventDefault();
    if (busy || !enabled || status.enabled === false || !status.configured || !find('adminSavedFile').hidden) return;
    let payload;
    try {
      const term = preview();
      payload = buildAdminPayload(formValues(), term);
      if (term.blocked) throw new Error(term.text);
      const check = readiness();
      if (!check.ready) throw new Error(check.missing[0]);
    }
    catch (error) { message(error.message, true); focusField(readiness().issues[0]?.target); return; }
    return operation('正在等待本机许可保存对话框…', async () => {
      resetSavedFile();
      const submittedCheck = readiness();
      const result = await bridge('licenseAdminGenerate', payload);
      if (result?.canceled) { message('已取消保存，未生成本次许可或收款记录。'); return; }
      if (result?.saved !== true) throw Object.assign(new Error('Not saved'), { code: 'LICENSE_ADMIN_NOT_SAVED' });
      savedReview = reviewMarkup(submittedCheck, { ...result.license, licenseId: result.licenseId });
      const paidOrder = payload.orderId || '';
      clearInputs(); if (paidOrder) find('adminOrderId').value = paidOrder; find('adminLicenseId').value = result.licenseId || '';
      find('adminSavedFile').textContent = `许可文件已保存：${result.filePath || '请查看所选目录'}`; find('adminSavedFile').hidden = false;
      find('adminDeliveryPanel').hidden = false;
      const revoked = payload.action === 'revoke' || result.license?.status === 'revoked';
      customerDeliveryText = `1. 请使用 MC Proxy 正式版 1.6.1 或更高版本。\n2. 在“设置 → 授权与续费 → 选择签名许可文件”中导入随附的软件许可JSON。${revoked ? '本文件用于撤销授权，不会恢复软件使用权。' : '已有客户在原软件中导入即可，无需重新建档。'}\n3. ${revoked ? '如需停止线路服务，还须由管理员单独处理 ISP / VPS 账号。' : '使用免费可选VPS时，还须另发该客户独立中转注册JSON，在“连接设置 → VPS中转”导入，再配置ISP并核验真实出口。仅保存软件许可不代表线路已开通或完整连接已通过。'}`;
      setText(find('adminDeliveryInstructions'), `对应客户：${result.licenseId || '本次申请的设备'}\n${customerDeliveryText}${paidOrder ? `\n管理员核对：本次付款订单 ${paidOrder} 已记账。需要补发文件时选择“免费重签”；不要重复登记这笔付款。下一笔付款先选“转正式 / 续费”，再点“登记另一笔收款”。` : ''}`);
      const success = revoked ? '撤销许可已保存，不会恢复使用权。剩余离线许可无法即时远程停用；请另行撤销供应商资源。' : payload.action === 'trial' ? '1 天试用许可已保存，无付费订单。交付客户导入，满意后再收款转正式。' : payload.action === 'refresh' ? '离线许可已免费重签；原授权期限与收款记录保持不变。' : '许可文件已保存，请交付对应客户导入，并核对授权与线路期限。';
      message(success);
      let listFailed = result.summaryUnavailable === true;
      if (!listFailed) {
        try {
          if (Array.isArray(result.customers) && result.summary) render({ ...status, ...result, configured: true });
          else render(await bridge('licenseAdminStatus'));
          find('adminCustomer').value = result.licenseId || '';
          const customer = customers.find(item => item.licenseId === result.licenseId);
          if (customer) selectCustomer(customer, true);
        } catch { listFailed = true; }
      }
      if (listFailed) message(`${success} 客户列表刷新失败，可手动刷新；不要重复记收款。`);
      find('adminDeliveryPanel').scrollIntoView?.({ block: 'nearest' });
    });
  });
  resetSavedFile(); render();
  return { render, open: readStatus, clearInputs, updateControls, setEnabled(value) { enabled = value === true; updateControls(); } };
}
