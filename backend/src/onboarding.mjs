import path from 'node:path';
import { lstat, readFile, realpath, rename, rm, rmdir, open } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { validateConfig, validateSecrets, parseSecrets, UserError } from './config.mjs';
import { createPrivateDirectory, writePrivate } from './private-files.mjs';
import { equalIp } from './network-report.mjs';

const defaults = Object.freeze({ autoOptimize: true, browser: 'chrome', fresh: false, externalReport: false, takeoverMode: 'global', relayRoutingMode: 'global', fingerprintLanguage: 'auto', fingerprintTimezone: 'auto', fingerprintNativeGraphics: false, fingerprintFresh: false });
const takeoverModes = ['global', 'smart', 'application'];
const relayRoutingModes = ['global', 'smart'];
const browserIds = ['chrome', 'edge', 'fingerprint'];
const validFingerprintLanguage = value => {
  if (value === undefined || value === 'auto') return true;
  try { return typeof value === 'string' && value.length <= 64 && Intl.getCanonicalLocales(value)[0] === value; } catch { return false; }
};
const validFingerprintTimezone = value => {
  if (value === undefined || value === 'auto') return true;
  try { return typeof value === 'string' && value.length <= 100 && !/[\x00-\x20\x7f]/.test(value) && Boolean(new Intl.DateTimeFormat('en', { timeZone: value }).resolvedOptions().timeZone); } catch { return false; }
};
const clone = value => structuredClone(value);
const digest = value => value === null ? null : createHash('sha256').update(value).digest('hex');
const fail = (code, message) => { throw new UserError(code, message); };
const normalize = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
const idPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const baselineConfig = () => ({ version: 1, listen: { host: '127.0.0.1', port: 17890 }, upstream: { type: 'socks', host: '127.0.0.1', port: 1080, auth: 'none' }, probe: { exitUrl: 'https://api.ipify.org?format=json', expectedExitIps: [], timeoutMs: 10000 } });

export function createOnboardingManager({ runtimeRoot, configPath, secretsPath, mock = false, now = Date.now, dependencies = {} } = {}) {
  if (!mock && (!runtimeRoot || !path.isAbsolute(runtimeRoot))) fail('ONBOARDING_PATH_INVALID', '首次设置需要绝对运行目录');
  const root = path.resolve(runtimeRoot || '.mock-onboarding');
  const directory = path.join(root, '.onboarding');
  const preferencesPath = path.join(directory, 'preferences.json');
  const journalPath = path.join(directory, 'pending.json');
  const configurationPath = path.resolve(configPath || path.join(root, 'config.json'));
  const credentialsPath = path.resolve(secretsPath || path.join(root, 'upstream.secrets.env'));
  const within = (parent, target) => { const relative = path.relative(parent, target); return !relative.startsWith('..') && !path.isAbsolute(relative); };
  const readOnly = !within(root, configurationPath) || !within(root, credentialsPath);
  if (within(directory, configurationPath) || within(directory, credentialsPath) || normalize(configurationPath) === normalize(credentialsPath)) fail('ONBOARDING_PATH_INVALID', '配置与凭据必须分别保存在独立文件中，且不得覆盖设置恢复记录');
  const fs = { lstat, readFile, realpath, rename, rm, rmdir, open, createPrivateDirectory, writePrivate, ...dependencies };
  let mockPreferences = { version: 1, preferences: { ...defaults }, completedAt: null };
  let mockConfig = null; let mockSecrets = null;
  let serial = Promise.resolve();
  const locked = action => { const work = serial.then(action, action); serial = work.catch(() => {}); return work; };

  async function safe(file) {
    const absolute = path.resolve(file);
    // Explicit launcher paths remain readable for legacy installations. They
    // are exact file targets, never additional writable roots or ACL targets.
    const explicitExternalRead = readOnly && [configurationPath, credentialsPath].some(target => normalize(target) === normalize(absolute));
    if (!within(root, absolute) && !explicitExternalRead) fail('ONBOARDING_PATH_INVALID', '设置文件超出运行目录');
    let cursor = path.parse(absolute).root;
    for (const segment of absolute.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, segment);
      let info;
      try { info = await fs.lstat(cursor); } catch (error) { if (error.code === 'ENOENT') break; throw error; }
      if (info.isSymbolicLink() || normalize(await fs.realpath(cursor)) !== normalize(cursor)) fail('ONBOARDING_PATH_INVALID', '设置文件或其父目录包含链接，操作已拒绝');
    }
    return absolute;
  }
  async function ensureDirectory(target) {
    await safe(target);
    try { if (!(await fs.lstat(target)).isDirectory()) fail('ONBOARDING_PATH_INVALID', '设置存储位置不是目录'); }
    catch (error) {
      if (error.code !== 'ENOENT') throw error;
      if (normalize(target) !== normalize(root)) await ensureDirectory(path.dirname(target));
      await fs.createPrivateDirectory(target);
    }
  }
  async function readOptional(file, maxSize = 1024 * 1024) {
    await safe(file);
    try {
      const info = await fs.lstat(file);
      if (!info.isFile() || info.size > maxSize) fail('ONBOARDING_STATE_INVALID', '设置文件类型或大小不符合要求');
      return await fs.readFile(file, 'utf8');
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async function durable(file, content) {
    await safe(file);
    await fs.writePrivate(file, content);
    const handle = await fs.open(file, 'r+');
    try { await handle.sync(); } finally { await handle.close(); }
  }
  async function atomic(file, content) {
    await ensureDirectory(path.dirname(file));
    const temporary = path.join(directory, `.atomic-${randomUUID()}.tmp`);
    try {
      await durable(temporary, content);
      await safe(file);
      await fs.rename(temporary, file);
    } finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
  }
  const targetBinding = digest(`${normalize(configurationPath)}\n${normalize(credentialsPath)}`);
  function validateJournal(record) {
    if (!record || record.version !== 1 || !idPattern.test(record.id || '') || record.binding !== targetBinding || !['prepared', 'committed'].includes(record.phase)) fail('ONBOARDING_RECOVERY_REQUIRED', '配置保存恢复记录无效，原有配置未覆盖');
    for (const group of ['before', 'after']) for (const key of ['config', 'secrets']) if (record[group]?.[key] !== null && !/^[a-f0-9]{64}$/.test(record[group]?.[key] || '')) fail('ONBOARDING_RECOVERY_REQUIRED', '配置保存恢复记录无效，原有配置未覆盖');
    if (!record.after.config || !record.after.secrets) fail('ONBOARDING_RECOVERY_REQUIRED', '待保存的配置记录不完整');
    return record;
  }
  async function cleanupTransaction(record) {
    const transaction = path.join(directory, record.id);
    for (const name of ['config.before', 'secrets.before', 'config.after', 'secrets.after', '.gitignore']) {
      const file = path.join(transaction, name);
      await safe(file);
      await fs.rm(file, { force: true });
    }
    await safe(transaction);
    await fs.rmdir(transaction).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
  async function recover() {
    if (mock || readOnly) return;
    const raw = await readOptional(journalPath, 16384);
    if (raw === null) return;
    let record;
    try { record = validateJournal(JSON.parse(raw)); } catch { fail('ONBOARDING_RECOVERY_REQUIRED', '配置保存曾被中断，恢复记录需要人工检查；未覆盖配置'); }
    const files = { config: configurationPath, secrets: credentialsPath };
    const current = {};
    for (const [key, file] of Object.entries(files)) {
      current[key] = await readOptional(file);
      if (![record.before[key], record.after[key]].includes(digest(current[key]))) fail('ONBOARDING_CONFIG_CONFLICT', '配置文件在保存期间被其他程序修改，未自动覆盖；请检查本地恢复记录');
    }
    if (record.phase === 'committed') {
      if (Object.keys(files).some(key => digest(current[key]) !== record.after[key])) fail('ONBOARDING_RECOVERY_REQUIRED', '已提交配置与恢复记录不一致，请人工检查');
    } else {
      const originals = {};
      for (const key of Object.keys(files)) {
        originals[key] = record.before[key] === null ? null : await readOptional(path.join(directory, record.id, `${key}.before`));
        if (digest(originals[key]) !== record.before[key]) fail('ONBOARDING_RECOVERY_REQUIRED', '配置原始备份已改变，未自动复原');
      }
      for (const [key, file] of Object.entries(files)) {
        if (digest(current[key]) === record.before[key]) continue;
        // Recheck before each replacement, including recovery after partial rollback.
        if (![record.before[key], record.after[key]].includes(digest(await readOptional(file)))) fail('ONBOARDING_CONFIG_CONFLICT', '配置文件在复原期间被其他程序修改，未覆盖新设置');
        if (originals[key] === null) { await safe(file); await fs.rm(file, { force: true }); }
        else await atomic(file, originals[key]);
      }
    }
    await safe(journalPath);
    await fs.rm(journalPath, { force: true });
    await cleanupTransaction(record).catch(() => {});
  }
  async function readPreferences() {
    if (mock) return clone(mockPreferences);
    const raw = await readOptional(preferencesPath, 16384);
    if (raw === null) return { version: 1, preferences: { ...defaults }, completedAt: null };
    let value;
    try { value = JSON.parse(raw); } catch { fail('ONBOARDING_STATE_INVALID', '首次设置记录无法解析，请保留文件后检查'); }
    if (!value || value.version !== 1 || Object.keys(value).some(key => !['version', 'preferences', 'completedAt'].includes(key)) || typeof value.preferences?.autoOptimize !== 'boolean' || typeof value.preferences?.fresh !== 'boolean' || value.preferences.externalReport !== undefined && typeof value.preferences.externalReport !== 'boolean' || value.preferences.takeoverMode !== undefined && !takeoverModes.includes(value.preferences.takeoverMode) || value.preferences.relayRoutingMode !== undefined && !relayRoutingModes.includes(value.preferences.relayRoutingMode) || !browserIds.includes(value.preferences?.browser) || !validFingerprintLanguage(value.preferences.fingerprintLanguage) || !validFingerprintTimezone(value.preferences.fingerprintTimezone) || value.preferences.fingerprintNativeGraphics !== undefined && typeof value.preferences.fingerprintNativeGraphics !== 'boolean' || Object.keys(value.preferences).some(key => !Object.hasOwn(defaults, key)) || (value.completedAt !== null && (typeof value.completedAt !== 'string' || !Number.isFinite(Date.parse(value.completedAt))))) fail('ONBOARDING_STATE_INVALID', '首次设置偏好无效，请保留文件后检查');
    if (value.preferences.fingerprintFresh !== undefined && typeof value.preferences.fingerprintFresh !== 'boolean') fail('ONBOARDING_STATE_INVALID', '指纹浏览器资料偏好无效，请保留文件后检查');
    // A release default never overrides a saved browser or profile choice.
    // Old browser-default receipts are retired and remain untouched on disk.
    return value;
  }
  const publicPreferences = record => ({ firstRun: !record.completedAt, preferences: { ...defaults, ...clone(record.preferences) }, completedAt: record.completedAt, mock });
  async function readConfiguration() {
    if (mock) return { config: clone(mockConfig), secrets: clone(mockSecrets), rawConfig: null, rawSecrets: null };
    const rawConfig = await readOptional(configurationPath);
    const rawSecrets = await readOptional(credentialsPath, 65536);
    let config = null; let secrets = null; let errorCode = null;
    if (rawConfig !== null) {
      try { config = validateConfig(JSON.parse(rawConfig.replace(/^\uFEFF/, ''))); } catch { errorCode = 'ONBOARDING_CONFIG_INVALID'; }
      if (config && rawSecrets !== null) {
        try { secrets = validateSecrets(config, parseSecrets(rawSecrets)); } catch { errorCode = 'ONBOARDING_CREDENTIALS_INVALID'; }
      } else if (config?.upstream.auth === 'password') errorCode = 'ONBOARDING_CREDENTIALS_INVALID';
    } else if (rawSecrets !== null && rawSecrets.trim()) {
      errorCode = 'ONBOARDING_CONFIG_INVALID';
    }
    return { config, secrets, rawConfig, rawSecrets, errorCode };
  }
  const publicConfiguration = ({ config, secrets, errorCode }) => ({ connectionMode: config?.connectionMode || 'relay', ...(config ? { available: Boolean(secrets) && config.probe.expectedExitIps.length > 0, type: config.upstream.type, host: config.upstream.host, port: config.upstream.port, auth: config.upstream.auth, credentialsConfigured: config.upstream.auth === 'none' ? Boolean(secrets) : Boolean(secrets?.ISP_USERNAME && secrets?.ISP_PASSWORD), expectedExitIps: [...config.probe.expectedExitIps], pinned: config.probe.expectedExitIps.length > 0, ...(config.upstream.tls ? { tls: clone(config.upstream.tls) } : {}), ...(config.relay ? { relay: { host: config.relay.host, port: config.relay.port, serverName: config.relay.tls.serverName } } : {}) } : { available: false, credentialsConfigured: false, expectedExitIps: [], pinned: false }), ...(errorCode ? { errorCode } : {}), readOnly, mock });
  async function transaction(config, secrets, previous) {
    const newConfig = `${JSON.stringify(config, null, 2)}\n`;
    const newSecrets = (config.upstream.auth === 'password' ? `ISP_USERNAME=${JSON.stringify(secrets.ISP_USERNAME)}\nISP_PASSWORD=${JSON.stringify(secrets.ISP_PASSWORD)}\n` : '# No ISP authentication configured\n')
      + (config.relay ? `RELAY_USERNAME=${JSON.stringify(secrets.RELAY_USERNAME)}\nRELAY_PASSWORD=${JSON.stringify(secrets.RELAY_PASSWORD)}\n` : '');
    await ensureDirectory(directory);
    await ensureDirectory(path.dirname(configurationPath));
    await ensureDirectory(path.dirname(credentialsPath));
    const id = randomUUID();
    const transactionDirectory = path.join(directory, id);
    await fs.createPrivateDirectory(transactionDirectory);
    const record = { version: 1, id, binding: targetBinding, phase: 'prepared', createdAt: new Date(now()).toISOString(), before: { config: digest(previous.rawConfig), secrets: digest(previous.rawSecrets) }, after: { config: digest(newConfig), secrets: digest(newSecrets) } };
    let journalWritten = false;
    try {
      if (previous.rawConfig !== null) await durable(path.join(transactionDirectory, 'config.before'), previous.rawConfig);
      if (previous.rawSecrets !== null) await durable(path.join(transactionDirectory, 'secrets.before'), previous.rawSecrets);
      await durable(path.join(transactionDirectory, 'config.after'), newConfig);
      await durable(path.join(transactionDirectory, 'secrets.after'), newSecrets);
      await atomic(journalPath, JSON.stringify(record)); journalWritten = true;
      for (const [key, target] of [['config', configurationPath], ['secrets', credentialsPath]]) {
        if (digest(await readOptional(target)) !== record.before[key]) fail('ONBOARDING_CONFIG_CONFLICT', '保存期间配置文件发生外部变更，未覆盖新设置');
        await safe(target);
        await fs.rename(path.join(transactionDirectory, `${key}.after`), target);
      }
      await atomic(journalPath, JSON.stringify({ ...record, phase: 'committed' }));
      await recover();
    } catch (cause) {
      if (journalWritten) {
        try { await recover(); } catch { fail('ONBOARDING_RECOVERY_REQUIRED', '配置保存未完整完成，恢复备份已保留；请重新启动后检查配置，暂勿启动代理'); }
      } else await cleanupTransaction(record).catch(() => {});
      if (cause instanceof UserError) throw cause;
      fail('ONBOARDING_WRITE_FAILED', '代理配置保存失败，已保留或复原此前配置');
    }
  }
  return {
    status: () => locked(async () => { await recover(); return publicPreferences(await readPreferences()); }),
    preferences: (changes = {}) => locked(async () => {
      await recover();
      if (!changes || typeof changes !== 'object' || Array.isArray(changes) || Object.keys(changes).some(key => !Object.hasOwn(defaults, key) && key !== 'completed')) fail('ONBOARDING_PREFERENCES_INVALID', '首次设置偏好包含未知选项');
      for (const key of ['autoOptimize', 'fresh', 'externalReport', 'completed', 'fingerprintNativeGraphics', 'fingerprintFresh']) if (changes[key] !== undefined && typeof changes[key] !== 'boolean') fail('ONBOARDING_PREFERENCES_INVALID', '首次设置开关必须为布尔值');
      if (changes.browser !== undefined && !browserIds.includes(changes.browser)) fail('ONBOARDING_PREFERENCES_INVALID', '请选择 Chrome、Edge 或独立指纹浏览器');
      if (!validFingerprintLanguage(changes.fingerprintLanguage) || !validFingerprintTimezone(changes.fingerprintTimezone)) fail('ONBOARDING_PREFERENCES_INVALID', '指纹浏览器语言或时区无效');
      if (changes.takeoverMode !== undefined && !takeoverModes.includes(changes.takeoverMode)) fail('ONBOARDING_PREFERENCES_INVALID', '导入配置接管方式无效');
      if (changes.relayRoutingMode !== undefined && !relayRoutingModes.includes(changes.relayRoutingMode)) fail('ONBOARDING_PREFERENCES_INVALID', 'VPS 接管方式无效');
      const current = await readPreferences();
      if (changes.completed === true && !publicConfiguration(await readConfiguration()).available) fail('ONBOARDING_CONFIGURATION_REQUIRED', '请先保存可用的 ISP 代理配置，再完成首次设置');
      const next = { version: 1, preferences: { ...defaults, ...current.preferences, ...Object.fromEntries(Object.keys(defaults).filter(key => changes[key] !== undefined).map(key => [key, changes[key]])) }, completedAt: changes.completed === true ? current.completedAt || new Date(now()).toISOString() : changes.completed === false ? null : current.completedAt };
      if (mock) mockPreferences = next;
      else {
        await atomic(preferencesPath, JSON.stringify(next));
      }
      return publicPreferences(next);
    }),
    configuration: () => locked(async () => { await recover(); return publicConfiguration(await readConfiguration()); }),
    saveConfiguration: (input = {}, { prepareConfiguration, verifyConfiguration } = {}) => locked(async () => {
      if (readOnly) fail('ONBOARDING_CONFIG_READONLY', '当前启动器使用运行目录外的配置或凭据，仍可读取并连接；网页不会修改外部文件。请在原位置编辑，或使用默认运行目录后再保存');
      await recover();
      if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !['host', 'port', 'type', 'username', 'password', 'expectedExitIps', 'clearCredentials', 'connectionMode', 'vpnConfirmed'].includes(key))) fail('ONBOARDING_CONFIG_INVALID', '代理设置包含未知选项');
      if (input.clearCredentials !== undefined && typeof input.clearCredentials !== 'boolean') fail('ONBOARDING_CONFIG_INVALID', '清除凭据选项必须为布尔值');
      if (input.connectionMode !== undefined && !['relay', 'vpn-compat', 'vpn-import'].includes(input.connectionMode)) fail('ONBOARDING_CONFIG_INVALID', '连接模式必须为中转、VPN 兼容或导入 VPN 模式');
      if (input.vpnConfirmed !== undefined && typeof input.vpnConfirmed !== 'boolean') fail('ONBOARDING_CONFIG_INVALID', 'VPN 确认选项必须为布尔值');
      for (const key of ['username', 'password']) if (input[key] !== undefined && (typeof input[key] !== 'string' || input[key].length > 8192 || /[\x00-\x1f\x7f]/.test(input[key]))) fail('ONBOARDING_CREDENTIALS_INVALID', '账号或密码包含非法字符或超过长度限制');
      const previous = await readConfiguration();
      const connectionMode = input.connectionMode || previous.config?.connectionMode || 'relay';
      if (connectionMode === 'vpn-compat' && input.vpnConfirmed !== true) fail('VPN_CONFIRMATION_REQUIRED', '请先开启外部 VPN，并明确确认后再保存 VPN 兼容模式');
      const host = typeof input.host === 'string' ? input.host.trim() : input.host;
      const sameEndpoint = Boolean(previous.config && previous.config.upstream.host.toLowerCase() === String(host).toLowerCase() && previous.config.upstream.port === input.port && previous.config.upstream.type === input.type);
      const retainedPins = sameEndpoint && connectionMode !== (previous.config.connectionMode || 'relay') && previous.config.probe.expectedExitIps.length ? [...previous.config.probe.expectedExitIps] : null;
      if (!sameEndpoint && previous.config?.upstream.auth === 'password' && !input.clearCredentials && (!input.username || !input.password)) fail('ONBOARDING_NEW_CREDENTIALS_REQUIRED', '切换代理地址、端口或协议时，请重新输入账号和密码；不会将原凭据发送到新地址');
      if (previous.errorCode && !input.clearCredentials && (!input.username || !input.password)) fail('ONBOARDING_NEW_CREDENTIALS_REQUIRED', '原配置或凭据无法读取，请重新填写完整账号密码，或明确选择无账号验证；不会复用未知凭据');
      if (input.clearCredentials && (input.username || input.password)) fail('ONBOARDING_CREDENTIALS_INVALID', '清除凭据时不能同时填写新的账号或密码');
      const prior = sameEndpoint ? previous.secrets : null;
      const username = input.clearCredentials ? '' : input.username || prior?.ISP_USERNAME || '';
      const password = input.clearCredentials ? '' : input.password || (username === prior?.ISP_USERNAME ? prior?.ISP_PASSWORD || '' : '');
      const auth = username || password ? 'password' : 'none';
      let config = clone(previous.config || baselineConfig());
      config.connectionMode = connectionMode;
      if (['vpn-compat', 'vpn-import'].includes(connectionMode)) delete config.relay;
      config.upstream = { type: input.type, host, port: input.port, auth, ...(input.type === 'http' && previous.config?.upstream.tls ? { tls: clone(previous.config.upstream.tls) } : {}) };
      if (input.expectedExitIps !== undefined) {
        if (!Array.isArray(input.expectedExitIps) || input.expectedExitIps.length > 32) fail('ONBOARDING_CONFIG_INVALID', '预期出口 IP 必须为最多 32 项的列表');
        config.probe.expectedExitIps = [...new Set(input.expectedExitIps)];
      } else if (!sameEndpoint) config.probe.expectedExitIps = [];
      if (retainedPins) config.probe.expectedExitIps = [...retainedPins];
      let secrets = { ...(auth === 'password' ? { ISP_USERNAME: username, ISP_PASSWORD: password } : {}),
        ...(config.relay && previous.secrets ? Object.fromEntries(['RELAY_USERNAME', 'RELAY_PASSWORD'].filter(key => previous.secrets[key] !== undefined).map(key => [key, previous.secrets[key]])) : {}) };
      if (prepareConfiguration !== undefined) {
        if (typeof prepareConfiguration !== 'function') fail('ONBOARDING_CONFIG_INVALID', '代理配置准备器无效');
        const prepared = await prepareConfiguration({ config: clone(config), secrets: clone(secrets) });
        if (!prepared || typeof prepared !== 'object') fail('ONBOARDING_CONFIG_INVALID', '代理配置准备结果无效');
        config = clone(prepared.config); secrets = clone(prepared.secrets);
      }
      if (config?.connectionMode !== connectionMode) fail('ONBOARDING_CONFIG_INVALID', '代理配置准备器改变了连接模式，原配置未更改');
      try { validateConfig(config); validateSecrets(config, secrets); } catch { fail('ONBOARDING_CONFIG_INVALID', '请检查代理协议、地址、端口、账号密码和出口 IP；原配置未更改'); }
      if (retainedPins) config.probe.expectedExitIps = [...retainedPins];
      let verification;
      if (verifyConfiguration !== undefined) {
        if (typeof verifyConfiguration !== 'function') fail('ONBOARDING_CONFIG_INVALID', '代理配置核验器无效');
        const result = mock ? { expectedExitIps: ['203.0.113.8'], checks: [], mock: true } : await verifyConfiguration({ config: clone(config), secrets: clone(secrets) });
        if (!result || !Array.isArray(result.expectedExitIps) || !result.expectedExitIps.length || result.expectedExitIps.length > 32 || result.expectedExitIps.some(ip => typeof ip !== 'string' || !isIP(ip))) fail('ONBOARDING_VERIFICATION_INVALID', 'ISP 核验未返回有效的已确认出口 IP，配置未保存');
        const checks = result.checks === undefined ? [] : result.checks;
        if (!Array.isArray(checks) || checks.length > 16 || checks.some(check => !check || typeof check.source !== 'string' || !/^[a-z0-9_-]{1,64}$/i.test(check.source) || !isIP(check.ip || ''))) fail('ONBOARDING_VERIFICATION_INVALID', 'ISP 核验报告格式无效，配置未保存');
        if (retainedPins && [...result.expectedExitIps, ...checks.map(check => check.ip)].some(ip => !retainedPins.some(pin => equalIp(pin, ip)))) fail('SETUP_EXIT_MISMATCH', '切换连接模式后的 ISP 出口不匹配已固定的 IP，原配置未更改');
        config.probe.expectedExitIps = retainedPins ? [...retainedPins] : [...new Set(result.expectedExitIps)];
        verification = { expectedExitIps: [...config.probe.expectedExitIps], checks: checks.map(({ source, ip }) => ({ source, ip })), mock };
      }
      if (mock) { mockConfig = clone(config); mockSecrets = clone(secrets); }
      else await transaction(config, secrets, previous);
      return { ...publicConfiguration({ config, secrets }), ...(verification ? { verification } : {}) };
    }),
  };
}
