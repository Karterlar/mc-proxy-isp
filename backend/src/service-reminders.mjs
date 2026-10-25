import path from 'node:path';
import { readFile, lstat, realpath, open, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { createPrivateDirectory, writePrivate, renamePrivate } from './private-files.mjs';
import { UserError } from './config.mjs';

const DAY = 86_400_000;
const bindingPattern = /^[a-f0-9]{64}$/;
const normalize = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
const fail = code => { throw new UserError(code, '到期提醒未能安全读取或保存；现有连接和授权不受影响。'); };
const epoch = value => Number.isSafeInteger(value) && value > 0 && value <= 253_402_300_799_999 ? value : null;
const validDate = value => typeof value === 'string' && /^\d{4}-\d\d-\d\d$/.test(value)
  && value >= '2000-01-01' && value <= '9999-12-31' && Number.isFinite(Date.parse(`${value}T00:00:00.000Z`))
  && new Date(`${value}T00:00:00.000Z`).toISOString().slice(0, 10) === value;
const manualDeadline = value => {
  if (!validDate(value)) return null;
  const [year, month, day] = value.split('-').map(Number);
  // A hand-entered date means the end of that day in this computer's timezone.
  return new Date(year, month - 1, day, 23, 59, 59, 999).getTime();
};
const due = (expiresAt, now) => expiresAt === null ? { expiresAt: null, daysRemaining: null, state: 'unknown' }
  : { expiresAt, daysRemaining: Math.max(0, Math.ceil((expiresAt - now) / DAY)), state: expiresAt <= now ? 'expired' : expiresAt - now <= 7 * DAY ? 'due-soon' : 'active' };

// Metadata, never an authorization decision. This module cannot call the core,
// change routes, stop connections, mutate a license, or infer expiry from errors.
export function createServiceReminderManager({ runtimeRoot, mock = false, now = Date.now, dependencies = {} } = {}) {
  if (!mock && (!runtimeRoot || !path.isAbsolute(runtimeRoot))) fail('REMINDERS_PATH_INVALID');
  const root = path.resolve(runtimeRoot || '.mock-reminders'), directory = path.join(root, '.service-reminders'), file = path.join(directory, 'reminders.json');
  const fs = { readFile, lstat, realpath, open, rm, createPrivateDirectory, writePrivate, renamePrivate, ...dependencies };
  let memory = { version: 1, revision: 0, vpn: null, isp: null }, serial = Promise.resolve();
  const locked = action => { const result = serial.then(action, action); serial = result.catch(() => {}); return result; };
  function validate(record) {
    if (!record || record.version !== 1 || !Number.isSafeInteger(record.revision) || record.revision < 0 || Object.keys(record).sort().join(',') !== 'isp,revision,version,vpn') fail('REMINDERS_STATE_INVALID');
    for (const kind of ['vpn', 'isp']) if (record[kind] !== null && (!record[kind] || Object.keys(record[kind]).sort().join(',') !== 'binding,expiresOn'
      || !bindingPattern.test(record[kind].binding) || !validDate(record[kind].expiresOn))) fail('REMINDERS_STATE_INVALID');
    return record;
  }
  async function safe(target) {
    let cursor = path.parse(target).root;
    for (const part of target.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, part);
      try {
        const info = await fs.lstat(cursor);
        if (info.isSymbolicLink() || normalize(await fs.realpath(cursor)) !== normalize(cursor)) fail('REMINDERS_PATH_INVALID');
      } catch (cause) { if (cause.code === 'ENOENT') break; throw cause; }
    }
  }
  async function read() {
    if (mock) return structuredClone(memory);
    try {
      await safe(file);
      const stat = await fs.lstat(file);
      if (!stat.isFile() || stat.size > 8192) fail('REMINDERS_STATE_INVALID');
      return validate(JSON.parse(await fs.readFile(file, 'utf8')));
    } catch (cause) {
      if (cause.code === 'ENOENT') return { version: 1, revision: 0, vpn: null, isp: null };
      if (cause instanceof UserError) throw cause;
      fail('REMINDERS_STATE_INVALID');
    }
  }
  async function ensure(target) {
    await safe(target);
    try { if (!(await fs.lstat(target)).isDirectory()) fail('REMINDERS_PATH_INVALID'); }
    catch (cause) {
      if (cause.code !== 'ENOENT') throw cause;
      if (normalize(target) !== normalize(root)) await ensure(path.dirname(target));
      await fs.createPrivateDirectory(target);
    }
  }
  return {
    status: (context = {}) => locked(async () => {
      const record = await read(), clock = epoch(now()) ?? Date.now(), license = context.license || {}, subscription = context.subscription || {};
      const items = [];
      for (const [kind, label, field] of [['license', '软件使用权', 'expiresAt'], ['license-offline', '离线许可', 'offlineUntil']]) {
        const deadline = epoch(license[field]);
        items.push({ kind, label, source: license.required === false ? 'not-required' : deadline === null ? 'unknown' : 'license',
          ...due(deadline, clock), ...(license.required === false ? { state: 'not-required', expiresAt: null, daysRemaining: null } : {}), editable: false });
      }
      for (const [kind, label] of [['vpn', 'VPN 套餐'], ['isp', 'ISP 服务']]) {
        const manual = bindingPattern.test(context.bindings?.[kind] || '') && record[kind]?.binding === context.bindings[kind] ? record[kind] : null;
        const usage = kind === 'vpn' && subscription.configured === true ? subscription.usage : null;
        const providerExpiry = epoch(Number.isSafeInteger(usage?.expire) && usage.expire > 0 ? usage.expire * 1000 : null);
        const provider = providerExpiry !== null;
        const item = { kind, label, source: provider ? 'provider' : manual ? 'manual' : 'unknown', ...due(provider ? providerExpiry : manualDeadline(manual?.expiresOn), clock),
          expiresOn: manual?.expiresOn || null, editable: bindingPattern.test(context.bindings?.[kind] || ''), reminderOnly: true };
        if (usage && typeof usage === 'object') {
          const publicUsage = {};
          for (const key of ['upload', 'download', 'total']) if (Number.isSafeInteger(usage[key]) && usage[key] >= 0) publicUsage[key] = usage[key];
          if (Object.keys(publicUsage).length) {
            item.usage = publicUsage;
            const used = publicUsage.upload + publicUsage.download;
            if (Number.isSafeInteger(used) && Number.isSafeInteger(publicUsage.total)) item.usage.remaining = Math.max(0, publicUsage.total - used);
            if (publicUsage.total > 0 && Number.isSafeInteger(used) && used >= publicUsage.total) item.usage.exhausted = true;
          }
          if (typeof subscription.lastUpdatedAt === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(subscription.lastUpdatedAt) && Number.isFinite(Date.parse(subscription.lastUpdatedAt))) item.observedAt = subscription.lastUpdatedAt;
        }
        items.push(item);
      }
      return { revision: record.revision, items, noticeCount: items.filter(item => ['due-soon', 'expired'].includes(item.state) || item.usage?.exhausted).length };
    }),
    save: (input = {}) => locked(async () => {
      if (!input || Object.keys(input).some(key => !['kind', 'expiresOn', 'binding', 'expectedRevision'].includes(key)) || !['vpn', 'isp'].includes(input.kind)
        || !bindingPattern.test(input.binding || '') || input.expiresOn !== null && !validDate(input.expiresOn)) fail('REMINDERS_INPUT_INVALID');
      const record = await read();
      if (input.expectedRevision !== undefined && input.expectedRevision !== record.revision) fail('REMINDERS_CONFLICT');
      const next = validate({ ...record, revision: record.revision + 1, [input.kind]: input.expiresOn === null ? null : { binding: input.binding, expiresOn: input.expiresOn } });
      if (mock) { memory = next; return { saved: true, revision: next.revision }; }
      const temporary = path.join(directory, `.reminder-${randomUUID()}.tmp`);
      try {
        await ensure(directory); await safe(temporary); await fs.writePrivate(temporary, `${JSON.stringify(next)}\n`);
        const handle = await fs.open(temporary, 'r+'); try { await handle.sync(); } finally { await handle.close(); }
        await safe(file);
        if ((await read()).revision !== record.revision) fail('REMINDERS_CONFLICT');
        await fs.renamePrivate(temporary, file);
        return { saved: true, revision: next.revision };
      } catch (cause) { if (cause instanceof UserError) throw cause; fail('REMINDERS_WRITE_FAILED'); }
      finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
    }),
  };
}
