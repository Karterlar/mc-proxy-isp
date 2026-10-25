export const MAX_LICENSE_IMPORT_BYTES = 32 * 1024;
const ONLINE_UNAVAILABLE_NOTICE = '在线卡密激活待服务上线；当前使用设备申请与签名许可导入';

const states = {
  development: ['开发者版 · 无授权限制', '可真实连接代理，无需卡密、续费或限时授权。网络核验与恢复功能正常保留。'],
  unactivated: ['尚未激活', '输入已付款订单的初次激活卡密，或导入管理员签发的设备许可。'],
  active: ['授权有效', '连接启动使用本机有效许可。后台刷新超时不会立即断开已有连接。'],
  expired: ['授权或线路已到期', '软件、ISP 与 VPS 期限分别计算。请由原订单交付方核验并人工续费；网络修复与环境恢复仍可使用。'],
  'offline-expired': ['离线许可已到期', '付费期限与离线许可分别计算。请刷新许可，或导入管理员重新签发的许可。'],
  revoked: ['授权已撤销', '请由原订单交付方核验订单与设备。诊断、断开和恢复入口仍可使用。'],
  'pending-resource': ['线路待开通', '软件、ISP 与 VPS 分别确认开通和期限。软件授权有效不表示线路已交付。'],
  error: ['授权状态待确认', '请读取本机状态，或联系原订单交付方核验。恢复功能保持可用。'],
};

const dateLabel = value => {
  const timestamp = typeof value === 'number' ? Number.isSafeInteger(value) && value >= 0 ? value : NaN : typeof value === 'string' ? Date.parse(value) : NaN;
  const date = new Date(timestamp);
  return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }) : '尚未登记';
};
const identifier = value => typeof value === 'string' && value.trim() ? value.slice(0, 256) : '尚未分配';
const errorCode = error => { const code = typeof error === 'string' ? error : error?.code; return /^[A-Z][A-Z0-9_]{0,79}$/.test(code || '') ? `（${code}）` : ''; };

export function licenseView(input) {
  const data = input && typeof input === 'object' ? input : {};
  const development = data.mode === 'development';
  const confirmed = development || ['required', 'mock'].includes(data.mode) && data.status !== 'development' && Object.hasOwn(states, data.status);
  const onlineAvailable = confirmed && !development && data.onlineAvailable !== false;
  const state = development ? 'development' : confirmed ? data.status : 'error';
  const independent = data.licenseVersion === 2;
  const customerResources = independent && data.resourcesMode === 'customer';
  const [title, detail] = independent && state === 'expired'
    ? ['软件授权已到期', '请续费软件使用权。ISP 与 VPS 由线路提供方独立维护；网络修复与环境恢复仍可使用。'] : states[state];
  const term = development ? '开发者版可真实连接代理，无卡密、试用或付费期限限制。' : !confirmed ? '授权信息待确认，请读取本机状态后查看套餐与许可期限。' : /trial/i.test(data.plan || '') ? '当前为 1 天试用。软件与离线许可截止时间以签名许可为准；满意后可沿用同一客户编号开通 30 天正式套餐。' : data.plan === 'isp-30d-single' ? '正式套餐为 30 天。实际软件与离线许可截止时间以签名许可为准；授权期限内免费重签不会新增收款或延长套餐。' : '先领取 1 天试用，满意后开通 30 天正式套餐。实际期限以导入并通过校验的签名许可为准。';
  return {
    state, development, confirmed, onlineAvailable, mode: ['required', 'mock', 'development'].includes(data.mode) ? data.mode : 'unknown',
    title: data.mode === 'mock' ? `演示 · ${title}` : title,
    detail: !onlineAvailable && state === 'unactivated' ? '生成这台设备的申请，由管理员签发许可后导入激活。' : !onlineAvailable && state === 'offline-expired' ? '付费期限与离线许可分别计算。请向管理员申请重新签发离线许可，再导入本机。' : detail,
    licenseId: identifier(data.licenseId), deviceId: identifier(data.deviceId),
    termExplanation: term + (independent ? customerResources ? ' 当前使用客户自备 ISP，其可用性与续费由客户维护，不限制软件授权期限。VPS 中转仍为免费可选入口。' : ' ISP / VPS 日期仅作资源提醒，不会截短软件使用权；ISP 到期须单独处理，VPS 中转为免费可选入口。' : data.licenseVersion === 1 ? ' 当前为旧版许可，仍保留其原有线路期限限制；升级客户端后请管理员免费重签以采用独立软件授权。' : ''),
    expiresAt: dateLabel(data.expiresAt), offlineUntil: dateLabel(data.offlineUntil),
    ispExpiresAt: customerResources ? '客户自备 · 自行维护' : dateLabel(data.ispExpiresAt), vpsExpiresAt: customerResources ? '免费可选中转 · 独立维护' : data.vpsExpiresAt ? dateLabel(data.vpsExpiresAt) : independent ? '免费可选中转 · 未登记期限' : '未使用或尚未登记',
    checked: data.refreshing ? '后台正在刷新许可' : data.lastCheckedAt != null ? `最近检查：${dateLabel(data.lastCheckedAt)}` : '尚未刷新许可',
    error: data.lastError ? `最近许可检查未完成${errorCode(data.lastError)}。请以当前许可状态为准。` : '',
  };
}

export function validateLicenseImport(text) {
  if (typeof text !== 'string' || !text.trim()) throw new Error('请先选择或粘贴签名许可 JSON。');
  if (new TextEncoder().encode(text).byteLength > MAX_LICENSE_IMPORT_BYTES) throw new Error('签名许可不能超过 32 KiB。');
  let data;
  try { data = JSON.parse(text.replace(/^\uFEFF/, '')); } catch { throw new Error('签名许可须为有效 JSON。'); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('签名许可须为 JSON 对象。');
  return text;
}

export function createLicensePage({ root = document, request, onStatus = () => {}, clipboard = globalThis.navigator?.clipboard } = {}) {
  const find = id => root.querySelector(`#${id}`);
  const page = find('screen-license');
  let busy = false, status, applicationText = '';
  const buttons = ['licenseReadButton', 'licenseRefreshButton', 'licenseActivateButton', 'licenseDeviceButton', 'licenseImportFileButton', 'licenseImportButton'];
  const inputs = ['licenseCard', 'licenseImportText', 'licenseImportFile'];
  const customerReady = () => { const view = licenseView(status); return view.confirmed && !view.development; };
  const message = (text, failed = false) => {
    find('licenseOperationResult').textContent = text;
    find('licenseOperationResult').dataset.error = String(failed);
  };

  function updateControls() {
    const view = licenseView(status);
    const blocked = view.development || !view.confirmed;
    page.setAttribute('aria-busy', String(busy));
    buttons.forEach(id => { find(id).disabled = busy || blocked && id !== 'licenseReadButton' || !view.onlineAvailable && ['licenseRefreshButton', 'licenseActivateButton'].includes(id); });
    inputs.forEach(id => { find(id).disabled = busy || blocked || !view.onlineAvailable && id === 'licenseCard'; });
    find('licenseActivationForm').setAttribute('aria-disabled', String(busy || blocked || !view.onlineAvailable));
    find('licenseCopyDeviceButton').disabled = busy || blocked || !applicationText;
  }
  function render(data) {
    status = data;
    const view = licenseView(data);
    page.dataset.licenseState = view.state;
    page.dataset.licenseMode = view.mode;
    for (const [id, value] of Object.entries({ licenseState: view.title, licenseStateDetail: view.detail,
      licenseId: view.licenseId, licenseDeviceId: view.deviceId, licenseExpiresAt: view.expiresAt,
      licenseOfflineUntil: view.offlineUntil, licenseIspExpiresAt: view.ispExpiresAt, licenseVpsExpiresAt: view.vpsExpiresAt,
      licenseTermExplanation: view.termExplanation,
      licenseLastChecked: view.checked, licenseLastError: view.error })) find(id).textContent = value;
    find('licenseLastError').hidden = !view.error;
    find('licenseOnlineNotice').hidden = !view.confirmed || view.development || view.onlineAvailable;
    updateControls();
  }
  function accept(data) {
    const next = data?.license && typeof data.license === 'object' ? data.license : data;
    render(next); onStatus(next);
  }
  async function operation(progress, run, failure = '授权操作未完成，请读取本机状态后再决定是否重试。') {
    if (busy) return false;
    busy = true; updateControls(); message(progress);
    try { await run(); return true; }
    catch (error) { message(`${failure}${errorCode(error)}`, true); return false; }
    finally { busy = false; updateControls(); }
  }
  async function readLocal() {
    return operation('正在读取本机授权状态…', async () => {
      try { accept(await request('/api/license/status', undefined, { timeoutMs: 5000 })); }
      catch (error) { if (licenseView(status).development && error?.code === 'NOT_FOUND') { render(status); message('开发者版 · 无授权限制'); return; } throw error; }
      message('已读取本机状态；未发起云端刷新。');
    }, '本机授权状态暂时无法读取，请稍后重试。');
  }

  find('licenseReadButton').addEventListener('click', readLocal);
  find('licenseRefreshButton').addEventListener('click', () => {
    const view = licenseView(status);
    if (busy || !customerReady()) return;
    if (!view.onlineAvailable) { message(ONLINE_UNAVAILABLE_NOTICE); return; }
    return operation('正在请求后台刷新许可…', async () => {
      accept(await request('/api/license/refresh', {}, { timeoutMs: 20000 }));
      message('刷新请求已完成，请查看当前许可与线路期限。');
    }, '许可刷新未完成；未失效的本机许可继续按其期限使用。');
  });
  find('licenseActivationForm').addEventListener('submit', event => {
    event.preventDefault();
    const card = find('licenseCard').value.trim();
    find('licenseCard').value = '';
    const view = licenseView(status);
    if (busy || !customerReady()) return;
    if (!view.onlineAvailable) { message(ONLINE_UNAVAILABLE_NOTICE); return; }
    if (!card || card.length > 256) { message('请输入有效的初次激活卡密。', true); return; }
    return operation('正在提交初次激活卡密…', async () => {
      accept(await request('/api/license/activate', { card }, { timeoutMs: 20000 }));
      message('激活请求已完成，请查看当前授权状态。');
    }, '激活结果尚未确认，请先读取本机状态；卡密已从输入框清空。');
  });
  find('licenseDeviceButton').addEventListener('click', () => {
    if (!customerReady()) return;
    return operation('正在读取本机设备申请…', async () => {
      const data = await request('/api/license/device', undefined, { timeoutMs: 5000 });
      if (!data.application || typeof data.application !== 'object' || Array.isArray(data.application)) throw new Error('Invalid device application');
      applicationText = JSON.stringify(data.application, null, 2);
      find('licenseDeviceApplication').value = applicationText;
      find('licenseDeviceApplicationPanel').hidden = false;
      message('设备申请已生成，可交给原订单管理员签发许可。');
    }, '设备申请暂时无法读取，请重试。');
  });
  find('licenseCopyDeviceButton').addEventListener('click', async () => {
    if (busy || !customerReady() || !applicationText) return;
    try { if (!clipboard?.writeText) throw new Error('Clipboard unavailable'); await clipboard.writeText(applicationText); message('已复制设备申请。'); }
    catch { find('licenseDeviceApplication').focus(); find('licenseDeviceApplication').select(); message('设备申请已选中，请按 Ctrl+C 复制。'); }
  });
  async function submitImport(text) {
    accept(await request('/api/license/import', { text }, { timeoutMs: 5000 }));
    message('签名许可已提交并完成校验，请查看授权状态。');
  }
  async function importText(text) {
    if (busy || !customerReady()) return false;
    try { validateLicenseImport(text); } catch (error) { message(error.message, true); return false; }
    return operation('正在校验并导入签名许可…', () => submitImport(text), '许可导入未完成。请核对设备申请与管理员签发的文件，再读取本机状态。');
  }
  find('licenseImportButton').addEventListener('click', () => {
    const text = find('licenseImportText').value;
    find('licenseImportText').value = '';
    return importText(text);
  });
  find('licenseImportFileButton').addEventListener('click', () => { if (!busy && customerReady()) find('licenseImportFile').click(); });
  find('licenseImportFile').addEventListener('change', async () => {
    const file = find('licenseImportFile').files?.[0];
    find('licenseImportFile').value = '';
    if (!file || busy || !customerReady()) return;
    if (!/\.json$/i.test(file.name) || file.size > MAX_LICENSE_IMPORT_BYTES) { message('请选择不超过 32 KiB 的 .json 签名许可文件。', true); return; }
    return operation('正在读取并校验签名许可文件…', async () => {
      const text = await file.text();
      validateLicenseImport(text);
      if (!customerReady()) { message('本机授权状态待确认，请重新读取后再导入。', true); return; }
      await submitImport(text);
    }, '签名许可文件读取或导入未完成，请核对文件后重试。');
  });
  render();
  return { render, open: readLocal, updateControls, clearInputs() { find('licenseCard').value = ''; find('licenseImportText').value = ''; find('licenseImportFile').value = ''; } };
}
