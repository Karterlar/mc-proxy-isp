import path from 'node:path';
import { lstat, readFile, realpath, rm, open } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { UserError, TUN_NETWORK } from './config.mjs';
import { createPrivateDirectory, writePrivate, renamePrivate } from './private-files.mjs';
import { createWindowsWfpLockAdapter, normalizeWfpLockInput, validateWfpInspection, sanitizeWfpLockDiagnostic } from './windows-wfp-lock.mjs';

const phases = new Set(['arming', 'armed', 'attaching', 'active', 'unlocking', 'unlocked']);
const HEX = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const copy = value => structuredClone(value);
const fail = (code, message) => { throw new UserError(code, message); };
const samePolicy = (a, b) => a?.binding === b?.binding && a?.corePath?.toLowerCase() === b?.corePath?.toLowerCase()
  && a?.endpoint?.ip.toLowerCase() === b?.endpoint?.ip.toLowerCase()
  && a?.endpoint?.port === b?.endpoint?.port && a?.endpoint?.protocol === b?.endpoint?.protocol;

// All rule writes belong to one native transaction. The journal contains only
// this product's policy identity; it never snapshots or restores another firewall.
export function createWfpNetworkLockManager({ stateDir, adapter, now = Date.now, dependencies = {}, onProgress = () => {}, helperPath } = {}) {
  if (typeof stateDir !== 'string' || !path.isAbsolute(stateDir)) fail('NETWORK_LOCK_PATH_INVALID', 'The WFP lock requires an absolute private recovery directory');
  const directory = path.resolve(stateDir), journalPath = path.join(directory, 'journal.json');
  const fs = { lstat, readFile, realpath, rm, open, createPrivateDirectory, writePrivate, renamePrivate, ...dependencies };
  const windows = adapter || createWindowsWfpLockAdapter({ ...(helperPath ? { helperPath } : {}) });
  let record = null, legacy = null, loaded = false, serial = Promise.resolve(), cachedAt = null, last = null;
  let cached = { engine: 'wfp', state: 'unknown', status: 'unknown', locked: false, persistent: true, bootProtected: false,
    canUnlock: false, mock: false, allowedEndpoint: null, binding: null, tunAllowed: false, observedAt: null, verifiedAt: null, journalPath };
  const locked = work => { const task = serial.then(work, work); serial = task.catch(() => {}); return task; };
  const progress = (stage, message) => { try { onProgress({ stage, message }); } catch {} };
  async function safe(file) {
    if (file !== directory && !file.startsWith(directory + path.sep)) fail('NETWORK_LOCK_PATH_INVALID', 'The WFP recovery path is outside its private directory');
    let current = path.parse(file).root;
    for (const segment of file.slice(current.length).split(path.sep).filter(Boolean)) {
      current = path.join(current, segment);
      let info;
      try { info = await fs.lstat(current); } catch (cause) { if (cause.code === 'ENOENT') break; throw cause; }
      if (info.isSymbolicLink() || path.resolve(await fs.realpath(current)).toLowerCase() !== current.toLowerCase()) fail('NETWORK_LOCK_PATH_INVALID', 'WFP recovery paths cannot contain links or junctions');
    }
  }
  async function atomicWrite(file, content) {
    await safe(file);
    const temporary = path.join(directory, `${randomUUID()}.tmp`);
    try {
      await fs.writePrivate(temporary, content);
      const handle = await fs.open(temporary, 'r+');
      try { await handle.sync(); } finally { await handle.close(); }
      await safe(file);
      await fs.renamePrivate(temporary, file);
    } finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
  }
  async function save(value) {
    // An explicitly restored v1 record is archived before its replacement.
    // Active v1 policies stay with the legacy recovery-only manager.
    if (legacy) {
      const archive = path.join(directory, `legacy-v1-${randomUUID()}.json`);
      await atomicWrite(archive, JSON.stringify(legacy));
      legacy = null;
    }
    const next = { ...value, updatedAt: new Date(now()).toISOString() };
    await atomicWrite(journalPath, JSON.stringify(next));
    record = copy(next);
  }
  async function load() {
    if (loaded) return;
    await safe(directory);
    try { if (!(await fs.lstat(directory)).isDirectory()) fail('NETWORK_LOCK_PATH_INVALID', 'The WFP recovery path must be a directory'); }
    catch (cause) { if (cause.code !== 'ENOENT') throw cause; await fs.createPrivateDirectory(directory); }
    await safe(journalPath);
    let value;
    try {
      const info = await fs.lstat(journalPath);
      if (!info.isFile() || info.size > 65536) fail('NETWORK_LOCK_STATE_INVALID', 'The WFP recovery journal has an invalid size or type');
      value = JSON.parse(await fs.readFile(journalPath, 'utf8'));
    } catch (cause) { if (cause.code !== 'ENOENT') fail('NETWORK_LOCK_STATE_INVALID', 'The WFP recovery journal is unreadable; no network rules were changed'); }
    if (value !== undefined) {
      if (value?.version === 1) {
        if (value.phase !== 'unlocked') fail('NETWORK_LOCK_LEGACY_RECOVERY_REQUIRED', 'Restore the previous firewall lock before enabling the WFP lock');
        legacy = value;
      } else {
        if (!value || value.version !== 2 || value.engine !== 'wfp' || !UUID.test(value.id || '') || !phases.has(value.phase)
          || (value.fingerprint !== null && !HEX.test(value.fingerprint || '')) || typeof value.includeTun !== 'boolean'
          || (value.fingerprint === null && !['arming', 'unlocked'].includes(value.phase))
          || !Number.isFinite(Date.parse(value.createdAt))) fail('NETWORK_LOCK_STATE_INVALID', 'The WFP recovery journal is invalid; no network rules were changed');
        try { normalizeWfpLockInput(value); } catch { fail('NETWORK_LOCK_STATE_INVALID', 'The WFP recovery policy is invalid; no network rules were changed'); }
        record = value;
      }
    }
    loaded = true;
  }
  function publish(state, reason, observation = last, extra = {}) {
    cachedAt = now();
    const present = Boolean(observation?.present);
    const nativeIdentity = UUID.test(observation?.id || '') && HEX.test(observation?.fingerprint || '');
    cached = { engine: 'wfp', state, status: state, locked: state === 'locked', persistent: true,
      // Persistence after BFE starts is not protection before BFE starts.
      bootProtected: observation?.bootProtected === true, serviceReady: observation?.serviceReady === true,
      policyPresent: observation?.present === true, absenceVerified: observation?.present === false && observation?.verified === true,
      canUnlock: present && nativeIdentity && Boolean((record && record.phase !== 'unlocked') || observation?.binding), mock: false,
      tunAllowed: state === 'locked' && observation?.tunLuid != null && observation?.tunCurrent === true,
      allowedEndpoint: record && record.phase !== 'unlocked' ? copy(record.endpoint) : null,
      binding: record && record.phase !== 'unlocked' ? record.binding : null, journalPath,
      observedAt: observation ? new Date(cachedAt).toISOString() : null,
      verifiedAt: observation?.verified === true ? new Date(cachedAt).toISOString() : null,
      ...(reason ? { reason } : {}), ...extra };
    return copy(cached);
  }
  function snapshot() {
    if (cachedAt !== null && now() - cachedAt > 15000 && cached.locked) return { ...copy(cached), state: 'unknown', status: 'unknown', locked: false,
      tunAllowed: false, reason: 'The WFP protection observation is stale; a fresh check is required', errorCode: 'NETWORK_LOCK_RECHECK_REQUIRED' };
    return copy(cached);
  }
  async function inspectStatus({ force = false } = {}) {
    await load();
    if (!force && cachedAt !== null && now() - cachedAt < 3000) return snapshot();
    let observed;
    try { observed = validateWfpInspection(await windows.inspect()); }
    catch (cause) {
      last = null;
      return publish(record && record.phase !== 'unlocked' ? 'recovery-required' : 'unknown', 'The owned WFP rules could not be read', null,
        { errorCode: cause instanceof UserError ? cause.code : 'NETWORK_LOCK_INSPECTION_FAILED', inspectionFailed: true,
          diagnostic: sanitizeWfpLockDiagnostic(cause?.diagnostic, 'inspect') });
    }
    last = observed;
    if (!observed.present) {
      if (!observed.verified) return publish('unknown', 'The absence of WFP rules could not be verified');
      if (record && record.phase !== 'unlocked') {
        if (record.phase === 'unlocking') { await save({ ...record, phase: 'unlocked', fingerprint: null, includeTun: false }); return publish('unlocked'); }
        return publish('recovery-required', 'The recorded WFP protection is absent; explicitly clear the recovery record', observed,
          { errorCode: 'NETWORK_LOCK_RECOVERY_REQUIRED', canUnlock: true });
      }
      return publish('unlocked');
    }
    if (!observed.verified) return publish('recovery-required', 'The owned WFP policy is incomplete, disabled or inconsistent', observed,
      { errorCode: 'NETWORK_LOCK_VERIFY_FAILED' });
    if (!record || record.phase === 'unlocked') return publish('conflict', 'Owned WFP rules exist without an active recovery record', observed,
      { errorCode: 'NETWORK_LOCK_ORPHANED' });
    if (observed.id !== record.id || !samePolicy(observed, record)) return publish('conflict', 'The owned WFP policy differs from the recovery record', observed,
      { errorCode: 'NETWORK_LOCK_CONFLICT', canUnlock: false });
    if (['arming', 'attaching'].includes(record.phase)) {
      await save({ ...record, phase: observed.tunLuid === null ? 'armed' : 'active', includeTun: observed.tunLuid !== null, fingerprint: observed.fingerprint });
    } else if (record.fingerprint !== observed.fingerprint) return publish('conflict', 'The owned WFP policy changed outside the pending transaction', observed,
      { errorCode: 'NETWORK_LOCK_CONFLICT', canUnlock: false });
    if (record.phase === 'unlocking') return publish('recovery-required', 'Explicit WFP unlock was interrupted; retry it using the retained record');
    return publish('locked');
  }
  function request(includeTun, expectedFingerprint) {
    return { id: record.id, binding: record.binding, corePath: record.corePath, endpoint: copy(record.endpoint), includeTun,
      ...(includeTun ? { tunAlias: TUN_NETWORK.interfaceName } : {}), ...(expectedFingerprint ? { expectedFingerprint } : {}) };
  }
  async function apply(includeTun, expectedFingerprint) {
    await save({ ...record, phase: record.fingerprint ? 'attaching' : 'arming', includeTun });
    let cause;
    try { await windows.apply(request(includeTun, expectedFingerprint)); }
    catch (error) { cause = error; }
    // The helper may commit before its response is lost. Read-back is the
    // authority; neither timeout nor malformed output triggers an automatic clear.
    const current = await inspectStatus({ force: true });
    if (current.locked && (!includeTun || current.tunAllowed)) return current;
    if (expectedFingerprint === undefined && current.absenceVerified) {
      // A fresh empty namespace proves the initial transaction did not leave
      // protection behind. Roll back only our journal so the existing connected
      // TUN session can continue. Never infer this from a timeout alone.
      await save({ ...record, phase: 'unlocked', fingerprint: null, includeTun: false });
      publish('unlocked');
    }
    if (cause instanceof UserError) throw cause;
    fail(cause ? 'NETWORK_LOCK_RECOVERY_REQUIRED' : 'NETWORK_LOCK_VERIFY_FAILED', 'The WFP transaction could not be confirmed; recovery state is retained');
  }
  return {
    snapshot,
    status: options => locked(() => inspectStatus(options)),
    reload: () => locked(async () => { record = null; legacy = null; loaded = false; cachedAt = null; last = null; return inspectStatus({ force: true }); }),
    arm: input => locked(async () => {
      const normalized = normalizeWfpLockInput(input);
      await load();
      progress('checking-firewall', '正在核验 MC Proxy 自有连接保护规则');
      const current = await inspectStatus({ force: true });
      if (record && record.phase !== 'unlocked') {
        if (!samePolicy(normalized, record)) fail('NETWORK_LOCK_ENDPOINT_CHANGED', 'Explicitly unlock before changing the pinned node, protocol or core');
        if (!current.locked) fail('NETWORK_LOCK_RECOVERY_REQUIRED', 'Complete the existing WFP recovery before enabling another lock');
        // Resolve and compare the current TUN LUID in the helper. A matching
        // policy is a no-op, avoiding unnecessary ALE flow reauthorization.
        return apply(true, last.fingerprint);
      }
      if (current.state !== 'unlocked') fail('NETWORK_LOCK_RECOVERY_REQUIRED', 'The owned WFP namespace must be verified empty before activation');
      record = { version: 2, engine: 'wfp', id: randomUUID(), ...normalized, phase: 'arming', fingerprint: null,
        includeTun: true, createdAt: new Date(now()).toISOString() };
      progress('locking-network', '正在事务启用独立断网保护，并保留系统原有防火墙规则');
      return apply(true);
    }),
    attachTun: () => locked(async () => {
      progress('verifying-tun', '正在核验专属 TUN 网卡和连接保护');
      const current = await inspectStatus({ force: true });
      if (!current.locked || !record) fail('NETWORK_LOCK_RECOVERY_REQUIRED', 'A verified owned WFP policy is required before attaching TUN');
      return apply(true, last.fingerprint);
    }),
    unlock: ({ confirm = false } = {}) => locked(async () => {
      if (confirm !== true) fail('CONFIRMATION_REQUIRED', 'Explicit confirmation is required to remove the network lock');
      await load();
      const current = await inspectStatus({ force: true });
      if (current.inspectionFailed || current.state === 'unknown') fail('NETWORK_LOCK_INSPECTION_FAILED', 'The owned WFP namespace could not be inspected; no rules were removed');
      if (!last.present) {
        if (record && record.phase !== 'unlocked') await save({ ...record, phase: 'unlocked', fingerprint: null, includeTun: false });
        return publish('unlocked');
      }
      if (!current.canUnlock || (record && record.phase !== 'unlocked' && record.id !== last.id)) fail('NETWORK_LOCK_CONFLICT', 'The current owned policy identity does not match; no rules were removed');
      const identity = { id: last.id, expectedFingerprint: last.fingerprint };
      if (record && record.phase !== 'unlocked') await save({ ...record, phase: 'unlocking' });
      else await save({ version: 2, engine: 'wfp', id: last.id, ...normalizeWfpLockInput(last), phase: 'unlocking',
        fingerprint: last.fingerprint, includeTun: last.tunLuid != null, createdAt: new Date(now()).toISOString() });
      progress('unlocking-network', '正在事务移除 MC Proxy 自有断网规则');
      let cause;
      try { await windows.clear(identity); } catch (error) { cause = error; }
      const observed = await inspectStatus({ force: true });
      if (observed.state === 'unlocked') return observed;
      if (cause instanceof UserError) throw cause;
      fail('NETWORK_LOCK_RESTORE_FAILED', 'Owned WFP rule removal was not confirmed; recovery state is retained');
    }),
  };
}
