import path from 'node:path';
import { lstat, readFile, realpath, rm } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { UserError, validateConfig } from './config.mjs';
import { createPrivateDirectory, writePrivate } from './private-files.mjs';
import { createOnboardingManager } from './onboarding.mjs';
import { createImportedVpnStore } from './imported-vpn-store.mjs';
import { shortlistImportedNodes } from './imported-node-shortlist.mjs';
import { createCustomerDeliveryTransaction, parseCustomerDelivery, customerDeliveryPreview, customerDeliveryConfiguration,
  verifyCustomerDeliveryLicense } from './customer-delivery.mjs';

const fail = code => { throw new UserError(code, '交付文件未能安全导入，原有连接配置和授权已保留。'); };
const digest = value => value === null ? null : createHash('sha256').update(value).digest('hex');
const normalize = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
const within = (root, file) => { const relative = path.relative(root, file); return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative); };

// The controller owns confirmation tokens and the routing/setup serialization.
// This importer only probes an isolated HTTP proxy, then commits prepared files;
// it never starts TUN, changes the firewall, or connects the user's session.
export function createCustomerDeliveryImporter({ runtimeRoot, configPath, secretsPath, licenseClient, licenseConfig, onboarding, setupVerifier,
  vpnConfigStore, now = Date.now, mock = false, assertIdle = async () => {}, assertCurrent = () => {}, onProgress = () => {}, dependencies = {} } = {}) {
  const root = path.resolve(runtimeRoot || '.mock-delivery'), directory = path.join(root, '.customer-delivery');
  const paths = { config: path.resolve(configPath || path.join(root, 'config.json')), secrets: path.resolve(secretsPath || path.join(root, 'upstream.secrets.env')),
    vpn: path.join(root, '.vpn-config', 'nodes.json'), preferences: path.join(root, '.onboarding', 'preferences.json'),
    browserMigration: path.join(root, '.onboarding', 'fingerprint-default-1.6.2.json') };
  const fs = { lstat, readFile, realpath, rm, createPrivateDirectory, writePrivate, ...dependencies };
  // Existing launchers can legitimately use external read-only configuration.
  // Merely adding this optional feature must not reject those installations.
  let transaction;
  const getTransaction = () => transaction ??= createCustomerDeliveryTransaction({ runtimeRoot: root, configPath, secretsPath, dependencies });
  const progress = (stage, message) => { try { onProgress({ stage, message }); } catch {} };
  let busy = false;
  function preflight(input) {
    const delivery = parseCustomerDelivery(typeof input === 'string' ? input : JSON.stringify(input));
    if (delivery.connectionMode !== 'vpn-import') fail('DELIVERY_MODE_UNSUPPORTED');
    const status = licenseClient?.status();
    const required = status?.required !== false;
    if (!mock && required) {
      if (!status?.deviceId || !status?.deviceKeyHash || ['LICENSE_STATE_INVALID', 'LICENSE_CONFIG_INVALID', 'LICENSE_PATH_INVALID', 'LICENSE_STATE_CONFLICT', 'LICENSE_CLOCK_ROLLBACK', 'LICENSE_DEVICE_UNAVAILABLE'].includes(status.reason)) fail(status?.reason || 'DELIVERY_DEVICE_INVALID');
      const claims = verifyCustomerDeliveryLicense(delivery, { publicKeys: licenseConfig?.publicKeys, deviceId: status.deviceId, deviceKeyHash: status.deviceKeyHash, now: now() });
      if (claims.licenseId === status.licenseId && claims.generation < status.generation) fail('LICENSE_REPLAY');
    }
    return { delivery, required };
  }
  async function safe(file) {
    if (!within(root, file)) fail('DELIVERY_PATH_INVALID');
    let cursor = path.parse(file).root;
    for (const part of file.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, part);
      try { const info = await fs.lstat(cursor); if (info.isSymbolicLink() || normalize(await fs.realpath(cursor)) !== normalize(cursor)) fail('DELIVERY_PATH_INVALID'); }
      catch (error) { if (error.code === 'ENOENT') break; throw error; }
    }
  }
  async function readOptional(file) {
    await safe(file);
    try {
      const info = await fs.lstat(file);
      if (!info.isFile() || info.nlink !== 1 || info.size > 1024 * 1024) fail('DELIVERY_STATE_INVALID');
      const value = await fs.readFile(file, 'utf8');
      if (Buffer.byteLength(value) > 1024 * 1024) fail('DELIVERY_STATE_INVALID');
      return value;
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  }
  async function ensure(target) {
    await safe(target);
    try { if (!(await fs.lstat(target)).isDirectory()) fail('DELIVERY_PATH_INVALID'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; if (target !== root) await ensure(path.dirname(target)); await fs.createPrivateDirectory(target); }
  }
  async function recover() {
    if (mock) return { recovered: false, mock: true };
    const journal = path.join(directory, 'pending.json'); await safe(journal);
    try { await fs.lstat(journal); } catch (cause) { if (cause.code === 'ENOENT') return { recovered: false }; throw cause; }
    await licenseClient?.initialize?.();
    const status = licenseClient?.status();
    if (status?.required && ['LICENSE_STATE_INVALID', 'LICENSE_CONFIG_INVALID', 'LICENSE_PATH_INVALID', 'LICENSE_STATE_CONFLICT', 'LICENSE_DEVICE_UNAVAILABLE'].includes(status.reason)) fail('DELIVERY_RECOVERY_REQUIRED');
    return getTransaction().recover();
  }
  return {
    recover,
    preview: input => {
      const { delivery, required } = preflight(input), preview = customerDeliveryPreview(delivery);
      return { ...preview, license: { ...preview.license, verified: required && !mock, required },
        ...(delivery.reminders && Object.keys(delivery.reminders).length ? { remindersNotice: '交付文件中的资源日期仅供参考，导入后请在到期提醒中确认登记。' } : {}), mock };
    },
    import: async (input, { signal } = {}) => {
      if (busy) fail('DELIVERY_BUSY'); busy = true;
      let stage, abort, timer, detach;
      try {
        await assertIdle(); await assertCurrent();
        const { delivery, required } = preflight(input);
        if (mock) return { imported: false, mock: true, preview: customerDeliveryPreview(delivery), code: 'DELIVERY_MOCK_PREVIEW_ONLY' };
        getTransaction();
        await recover();
        // Let the original onboarding owner resolve its own pending journal first.
        await onboarding.configuration(); await onboarding.status();
        const before = Object.fromEntries(await Promise.all(Object.entries(paths).map(async ([key, file]) => [key, await readOptional(file)])));
        const configuration = customerDeliveryConfiguration(delivery);
        if (before.config !== null) {
          let previous; try { previous = validateConfig(JSON.parse(before.config.replace(/^\uFEFF/, ''))); } catch { fail('DELIVERY_STATE_INVALID'); }
          configuration.config.listen = { ...previous.listen };
          configuration.config.probe.exitUrl = previous.probe.exitUrl;
          configuration.config.probe.timeoutMs = previous.probe.timeoutMs;
        }
        await ensure(directory); stage = path.join(directory, `stage-${randomUUID()}`); await fs.createPrivateDirectory(stage);
        const stagedOnboarding = createOnboardingManager({ runtimeRoot: stage, now, dependencies });
        const stagedVpn = createImportedVpnStore({ stateDir: path.join(stage, '.vpn-config'), dependencies });
        await ensure(path.join(stage, '.onboarding'));
        for (const [key, file] of [['preferences', 'preferences.json'], ['browserMigration', 'fingerprint-default-1.6.2.json']]) {
          if (before[key] !== null) await fs.writePrivate(path.join(stage, '.onboarding', file), before[key]);
        }
        const imported = await stagedVpn.import(delivery.vpnText), candidates = await stagedVpn.candidates();
        abort = new AbortController(); detach = () => abort.abort(); signal?.addEventListener('abort', detach, { once: true });
        if (signal?.aborted) abort.abort();
        timer = setTimeout(() => abort.abort(), 180000); timer.unref?.();
        const current = async () => { if (abort.signal.aborted) fail('CONNECTION_CANCELED'); await assertCurrent(); };
        progress('delivery-screening', '正在筛选 VPN 入口，随后验证 VPN → ISP → HTTPS 完整链路');
        const shortlist = await (dependencies.shortlistImportedNodes || shortlistImportedNodes)(candidates, { listenPort: configuration.config.listen.port, signal: abort.signal });
        await current();
        let winner = null; const attempts = [];
        for (const node of shortlist.nodes) {
          await current();
          progress('delivery-verifying', `正在验证候选 ${attempts.length + 1}/${shortlist.nodes.length} 的 ISP 出口`);
          try {
            const verification = await setupVerifier.verify({ ...configuration, vpnNode: node.outbound, signal: abort.signal });
            await current();
            if (verification.mock) fail('DELIVERY_VERIFICATION_MOCKED');
            winner = { node, verification }; attempts.push({ nodeIndex: node.index, status: 'verified' }); break;
          } catch (cause) {
            await current();
            const retryable = ['SETUP_CHECK_FAILED', 'VPN_NODE_RESOLVE_FAILED', 'CORE_START_FAILED'];
            attempts.push({ nodeIndex: node.index, status: 'failed', code: retryable.includes(cause.code) ? cause.code : 'DELIVERY_VERIFICATION_FAILED' });
            if (!retryable.includes(cause.code)) throw cause;
          }
        }
        if (!winner) fail('VPN_IMPORT_NO_ROUTE');
        await stagedVpn.select(winner.node.index, { expectedId: imported.id });
        const { type, host, port, username, password, expectedExitIps } = delivery.isp;
        await stagedOnboarding.saveConfiguration({ type, host, port, username, password, expectedExitIps, clearCredentials: !username && !password, connectionMode: 'vpn-import' }, {
          prepareConfiguration: async () => configuration, verifyConfiguration: async () => winner.verification,
        });
        await stagedOnboarding.preferences({ takeoverMode: delivery.takeoverMode, completed: true });
        const stagePaths = { config: 'config.json', secrets: 'upstream.secrets.env', vpn: '.vpn-config/nodes.json', preferences: '.onboarding/preferences.json' };
        // The old browser-default receipt is retired. Preserve an existing one
        // transactionally, but its absence must not block import or create one.
        if (before.browserMigration !== null) stagePaths.browserMigration = '.onboarding/fingerprint-default-1.6.2.json';
        const files = Object.fromEntries(await Promise.all(Object.entries(stagePaths).map(async ([key, file]) => [key, await readOptional(path.join(stage, file))])));
        if (Object.values(files).some(value => value === null)) fail('DELIVERY_STATE_INVALID');
        const expected = Object.fromEntries(Object.keys(files).map(key => [key, digest(before[key])]));
        const stagedResult = { configuration: await stagedOnboarding.configuration(), onboarding: await stagedOnboarding.status(), vpn: await stagedVpn.status() };
        await current(); await assertIdle(); preflight(delivery);
        progress('delivery-saving', '完整链路验证通过，正在保存配置与原签发许可');
        const committed = await getTransaction().commit({ files, expected, ...(required ? { licenseText: delivery.licenseText } : {}), finalize: async () => {
          await current(); preflight(delivery);
          if (!required) return;
          const status = await licenseClient.importLicense(delivery.licenseText);
          if (!status.allowed) fail(status.reason || 'DELIVERY_LICENSE_INACTIVE');
        } });
        // Use the public result captured before commit. A later status read must
        // never turn a successfully committed license/configuration into a false
        // "import failed and old state preserved" response.
        return { imported: true, mock: false, cleanupPending: committed.cleanupPending, refreshRequired: committed.cleanupPending, ...stagedResult,
          verification: { nodeIndex: winner.node.index, attempts, expectedExitIps: winner.verification.expectedExitIps, checks: winner.verification.checks, tested: attempts.length, candidates: candidates.length },
          ...(delivery.reminders && Object.keys(delivery.reminders).length ? { remindersNotice: '资源日期仅供参考，请在到期提醒中确认登记。' } : {}) };
      } finally {
        clearTimeout(timer); if (detach) signal?.removeEventListener('abort', detach);
        if (stage) {
          // Only this invocation's generated staging folder is removable.
          if (path.dirname(stage) !== directory || !/^stage-[0-9a-f-]{36}$/.test(path.basename(stage))) fail('DELIVERY_PATH_INVALID');
          try { await safe(stage); await fs.rm(stage, { recursive: true, force: true }); } catch { /* private staging remains isolated for explicit cleanup */ }
        }
        busy = false;
      }
    },
  };
}
