import test from 'node:test';
import assert from 'node:assert/strict';
import { createControllerClient, consumeControlToken } from '../../frontend/controller-client.js';
import { environmentDiagnosticText, sanitizeEnvironmentFeedback, environmentOutcomeNotice, environmentSettingRows, environmentVerificationView } from '../../frontend/environment-feedback.js';

const ok = data => ({ ok: true, json: async () => ({ ok: true, data }) });

test('partial environment results preserve successful-item messaging and never claim a complete restore', () => {
  const environment = { optimization: { status: 'partial', operation: 'restore', differingFields: ['languages', 'private-data'] } };
  const notice = environmentOutcomeNotice(environment, { operation: 'restore' });
  assert.equal(notice.partial, true);
  assert.match(notice.text, /部分设置已复原.*成功项目已保留/);
  assert.match(notice.text, /尚未匹配：语言与输入法列表/);
  assert.doesNotMatch(notice.text, /系统环境已复原|自动回滚|private-data/);
  assert.match(environmentOutcomeNotice(environment, { mock: true }).text, /模拟结果/);
  assert.equal(sanitizeEnvironmentFeedback({ environmentFields: ['timeZoneId', 'daylightSavingDisabled', 'culture', 'uiLanguageOverride', 'languages', 'defaultInputMethod', 'cultureFromLanguageListOptOut', 'homeGeoId'] }).environmentFields.length, 8);
});

test('environment rows show actual and intended settings, missing targets and retained country state distinctly', () => {
  const environment = { current: { timeZoneId: 'Tokyo Standard Time', homeGeoId: 122, homeCountryCode: 'JP', culture: 'zh-SG', languages: [{ languageTag: 'en-US' }] }, optimization: { operation: 'optimize', status: 'partial', target: { timeZoneId: 'Tokyo Standard Time', homeGeoId: 122, homeCountryCode: 'JP', culture: 'zh-SG', languages: [{ languageTag: 'ja-JP' }] }, fieldResults: [{ field: 'languages', status: 'unmatched' }, { field: 'culture', status: 'matched' }, { field: 'homeGeoId', status: 'matched' }] } };
  const rows = environmentSettingRows(environment);
  assert.equal(rows.length, 4);
  assert.match(rows[1].current, /en-US/); assert.match(rows[1].target, /ja-JP/); assert.equal(rows[1].status, 'unmatched');
  assert.match(rows[2].current, /日本/); assert.match(rows[3].target, /中文（简体，新加坡）/); assert.equal(rows[3].status, 'matched');
  assert.ok(environmentSettingRows({ current: environment.current }).every(row => row.target === '未记录' && row.status === 'unknown'));
  assert.ok(environmentSettingRows({ ...environment, snapshotSource: 'saved', ownership: 'foreign' }).every(row => row.current === '未记录'));
});

test('language details distinguish preferred order, missing languages and input method differences without replacing backend status', () => {
  const entry = (languageTag, inputMethodTips = [], handwriting = false) => ({ languageTag, inputMethodTips, handwriting });
  const row = (current, target, fieldResults = []) => environmentSettingRows({ current: { languages: current }, optimization: { target: { languages: target }, fieldResults: [{ field: 'languages', status: 'unmatched' }, ...fieldResults] } }).find(item => item.field === 'languages');
  const english = entry('en-US', ['0409:00000409']), chinese = entry('zh-CN', ['0804:00000804']);
  const preferred = row([chinese, english], [english, chinese]);
  assert.match(preferred.detail, /首选语言未切换至.*en-US/);
  assert.doesNotMatch(preferred.detail, /目标语言尚未加入|输入法条目尚未匹配/);
  const missing = row([chinese], [english, chinese]);
  assert.match(missing.detail, /目标语言尚未加入：.*en-US/);
  assert.doesNotMatch(missing.detail, /输入法条目尚未匹配/);
  const input = row([english, entry('zh-SG', ['0804:00000804'])], [english, entry('zh-SG', ['1004:00001004'])], [{ field: 'defaultInputMethod', status: 'matched' }]);
  assert.match(input.detail, /输入法条目尚未匹配；默认输入法已匹配/);
  assert.doesNotMatch(input.detail, /首选语言未切换|目标语言尚未加入|0804|1004/);
  assert.equal(input.status, 'unmatched');
  const normalized = row([entry('zh-Hans-CN', ['ABCD:00000804', '0804:00000804'])], [entry('zh-CN', ['0804:00000804', 'abcd:00000804', '0804:00000804'])]);
  assert.match(normalized.detail, /上次语言列表核验未通过，需重新核验/);
  assert.doesNotMatch(normalized.detail, /首选语言未切换|目标语言尚未加入|输入法条目尚未匹配/);
  assert.equal(normalized.status, 'unmatched');
  const handwriting = row([entry('en-US', [], false)], [entry('en-US', [], true)]);
  assert.match(handwriting.detail, /手写输入设置尚未匹配/);
  const matched = environmentSettingRows({ current: { languages: [english] }, optimization: { target: { languages: [english] }, fieldResults: [{ field: 'languages', status: 'matched' }] } }).find(item => item.field === 'languages');
  assert.equal(matched.detail, ''); assert.equal(matched.status, 'matched');
});

test('current verification replaces historical failures while saved and unknown results never claim a fresh success', () => {
  const language = { languageTag: 'en-US', inputMethodTips: ['0409:00000409'], handwriting: false };
  const env = { status: 'optimized', current: { languages: [language] }, optimization: { status: 'partial', message: 'OLD_PARTIAL_ERROR', target: { languages: [language] }, fieldResults: [{ field: 'languages', status: 'unmatched' }] }, verification: { status: 'matched', source: 'live', fieldResults: [{ field: 'languages', status: 'matched' }] } };
  const row = value => environmentSettingRows(value).find(item => item.field === 'languages');
  assert.equal(row(env).status, 'matched'); assert.equal(row(env).detail, '');
  assert.equal(environmentVerificationView(env).needsReview, false);
  assert.match(environmentVerificationView(env).summary, /当前设置.*目标匹配.*上次操作记录保留/);
  assert.doesNotMatch(environmentVerificationView(env).summary, /OLD_PARTIAL_ERROR|未匹配|失败/);
  const saved = { ...env, verification: { ...env.verification, source: 'saved' } };
  assert.equal(row(saved).currentLabel, '上次记录'); assert.equal(row(saved).statusLabel, '上次已匹配');
  assert.match(environmentVerificationView(saved).summary, /本次尚未重新读取 Windows/);
  assert.equal(environmentVerificationView(saved).needsReview, true);
  const unknown = { ...env, optimization: { ...env.optimization, fieldResults: [{ field: 'languages', status: 'matched' }] }, verification: { status: 'unverified', source: 'live', fieldResults: [{ field: 'languages', status: 'unknown' }] } };
  assert.equal(row(unknown).status, 'unknown'); assert.equal(row(unknown).statusLabel, '待核验');
  assert.equal(environmentVerificationView(unknown).status, 'unverified');
  assert.equal(environmentVerificationView({ ...unknown, verification: { ...unknown.verification, status: 'matched' } }).status, 'unverified');
  assert.equal(environmentVerificationView({ ...env, verification: { ...env.verification, fieldResults: [] } }), null);
  assert.equal(row({ ...env, verification: undefined }).status, 'unmatched');
});

test('no environment target stays neutral and matching external changes retain their history notice', () => {
  const initial = { status: 'ready', optimization: { status: 'not-requested' }, verification: { status: 'unverified', source: 'live', fieldResults: [] } };
  assert.equal(environmentVerificationView(initial), null);
  assert.ok(environmentSettingRows(initial).every(row => row.status === 'unknown'));
  for (const changed of [{ status: 'conflict' }, { backup: { drifted: true } }]) {
    const env = { ...changed, optimization: { status: 'partial' }, verification: { status: 'matched', source: 'live', fieldResults: [{ field: 'languages', status: 'matched' }] } };
    const view = environmentVerificationView(env);
    assert.equal(view.status, 'matched'); assert.equal(view.needsReview, true); assert.equal(view.changed, true);
    assert.match(view.summary, /当前设置.*目标匹配.*上次操作后设置有变化/);
    assert.doesNotMatch(view.summary, /未匹配|必须重试|失败/);
    assert.equal(environmentSettingRows(env).find(row => row.field === 'languages').status, 'matched');
  }
});

test('environment failures retain only fixed field names and display useful recovery details', async () => {
  const client = createControllerClient({ fetchImpl: async () => ({ ok: false, status: 500, json: async () => ({ ok: false, error: {
    code: 'ENVIRONMENT_VERIFY_FAILED', message: '环境设置未完整生效', details: {
      environmentStage: 'apply-culture', environmentFields: ['culture', 'culture', 'password'],
      rollbackEnvironmentFields: ['languages', 'private path'], actualCulture: 'private-user-data',
    },
  } }) }) });
  await assert.rejects(client.request('/api/environment/restore', { confirm: true }), error => {
    assert.deepEqual(error.diagnostic, { environmentStage: 'apply-culture', environmentFields: ['culture'], rollbackEnvironmentFields: ['languages'] });
    assert.equal(environmentDiagnosticText(error.diagnostic), '失败步骤：写入区域格式；尚未匹配：区域格式；自动回滚尚未匹配：语言与输入法列表');
    assert.doesNotMatch(JSON.stringify(error), /private|password/);
    return true;
  });
});

test('automatic display reads use memory snapshots; explicit inspection replaces a pending snapshot', async () => {
  const requests = [];
  const client = createControllerClient({ fetchImpl: (endpoint, options) => new Promise(resolve => requests.push({ endpoint, options, resolve })) });
  const pending = client.readStatus();
  assert.equal(requests[0].endpoint, '/api/snapshot');
  const manual = client.readStatus({ inspect: true });
  assert.equal(requests[0].options.signal.aborted, true);
  assert.equal(requests[1].endpoint, '/api/status');
  assert.equal(client.readStatus({ inspect: true }), manual);
  requests[1].resolve(ok({ revision: 2 }));
  assert.deepEqual(await manual, { revision: 2 });
  requests[0].resolve(ok({ revision: 1 }));
  assert.equal(await pending, null);
});

test('console owner token is consumed from the fragment and sent only to relative controller APIs', async () => {
  const token = 'a'.repeat(64), replacements = [], requests = [];
  assert.equal(consumeControlToken({ location: { hash: `#control_token=${token}&screen=connection`, pathname: '/', search: '' }, history: { replaceState: (...args) => replacements.push(args) } }), token);
  assert.equal(replacements[0][2], '/#screen=connection');
  const client = createControllerClient({ controlToken: token, fetchImpl: async (...args) => { requests.push(args); return ok({ done: true }); } });
  await client.request('/api/status'); assert.equal(requests[0][1].headers['x-mc-control-token'], token);
  for (const endpoint of ['https://evil.example/api/status', '//evil.example/api/status', '/api/../other']) await assert.rejects(client.request(endpoint), { code: 'CONTROLLER_ENDPOINT_INVALID' });
  assert.equal(requests.length, 1);
});

test('status reads coalesce, and a response begun before a mutation cannot overwrite the new state', async () => {
  const pending = [];
  const client = createControllerClient({ fetchImpl: () => new Promise(resolve => pending.push(resolve)) });
  const first = client.readStatus();
  assert.equal(client.readStatus(), first);
  client.invalidateStatus();
  const current = client.readStatus();
  pending[1](ok({ proxy: { running: false } }));
  assert.deepEqual(await current, { proxy: { running: false } });
  pending[0](ok({ proxy: { running: true } }));
  assert.equal(await first, null);
  assert.equal(pending.length, 2);
});

test('profile history reads allow only the exact browser query and retain same-origin token handling', async () => {
  const requests = [], token = 'b'.repeat(64);
  const client = createControllerClient({ controlToken: token, fetchImpl: async (endpoint, options) => { requests.push({ endpoint, options }); return ok({ archives: [] }); } });
  for (const browser of ['chrome', 'edge', 'fingerprint']) {
    await client.request(`/api/browser/profiles?browser=${browser}`);
    const { endpoint, options } = requests.at(-1);
    assert.equal(endpoint, `/api/browser/profiles?browser=${browser}`);
    assert.equal(options.method, 'GET');
    assert.equal(options.mode, 'same-origin');
    assert.equal(options.headers['x-mc-control-token'], token);
  }
  for (const endpoint of [
    '/api/status?browser=chrome', '/api/browser/profiles?browser=other',
    '/api/browser/profiles?browser=chrome&browser=edge', '/api/browser/profiles?browser=chrome&path=/other',
    '/api/browser/profiles?browser=chrome#fragment', '/api/browser/profiles?browser=%63hrome',
    '//other.example/api/browser/profiles?browser=chrome',
    'https://other.example/api/browser/profiles?browser=chrome', null, Symbol('invalid'),
  ]) await assert.rejects(client.request(endpoint), { code: 'CONTROLLER_ENDPOINT_INVALID' });
  await assert.rejects(client.request('/api/browser/profiles?browser=chrome', { confirm: true }), { code: 'CONTROLLER_ENDPOINT_INVALID' });
  assert.equal(requests.length, 3);
});

test('a late failed status read is also discarded after invalidation', async () => {
  let reject;
  const client = createControllerClient({ fetchImpl: () => new Promise((resolve, fail) => { reject = fail; }) });
  const pending = client.readStatus();
  client.invalidateStatus();
  reject(new TypeError('old connection closed'));
  assert.equal(await pending, null);
});

test('timeout on a mutation reports uncertain outcome and never retries it', async () => {
  let calls = 0;
  const client = createControllerClient({ operationTimeoutMs: 10, fetchImpl: (_, { signal }) => {
    calls++;
    return new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true }));
  } });
  await assert.rejects(client.request('/api/proxy/start', { confirm: true }), error => error.code === 'CONTROLLER_REQUEST_TIMEOUT' && error.message.includes('结果尚未确认'));
  assert.equal(calls, 1);
});

test('controller errors retain safe public code and bounded import diagnostics', async () => {
  const client = createControllerClient({ fetchImpl: async () => ({ ok: false, status: 409, json: async () => ({ ok: false, error: {
    code: 'VPN_IMPORT_INVALID', message: '配置无法导入', details: { unsupportedNodes: [{ index: 2, code: 'VPN_NODE_INVALID', password: 'secret' }, { index: 999, code: 'BAD' }] },
  } }) }) });
  await assert.rejects(client.request('/api/vpn/import', { text: 'invalid' }), error => {
    assert.equal(error.code, 'VPN_IMPORT_INVALID');
    assert.deepEqual(error.unsupportedNodes, [{ index: 2, code: 'VPN_NODE_INVALID' }]);
    return true;
  });
});
