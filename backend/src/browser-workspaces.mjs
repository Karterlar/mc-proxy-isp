import path from 'node:path';
import { lstat, realpath, readFile, rm, open } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { createPrivateDirectory, writePrivate, renamePrivate } from './private-files.mjs';

export const BROWSER_WORKSPACE_SERVICES = Object.freeze(['chatgpt', 'claude', 'google', 'wikipedia', 'github', 'youtube', 'tiktok', 'ping0', 'cleanip', 'ippure', 'exit']);
export const validBrowserWorkspaceId = id => typeof id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id);
export const workspaceBrowser = item => item.browser ?? 'fingerprint';
const validBrowser = browser => ['chrome', 'edge', 'fingerprint'].includes(browser);
const fail = (code, message, status = 400) => { throw Object.assign(new Error(message), { code, status }); };
const normalize = value => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
const validBinding = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const validDate = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const keys = (value, allowed) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => allowed.includes(key));
const MAX_ACTIVE_WORKSPACES = 24, MAX_WORKSPACES = 96, MAX_STATE_BYTES = 262144;
const DEFAULT_IDENTITY = Object.freeze({ version: 1, language: 'auto', timezone: 'auto', nativeGraphics: false });

export function validateWorkspaceIdentity(identity) {
  if (!keys(identity, ['version', 'language', 'timezone', 'nativeGraphics']) || identity.version !== 1 || typeof identity.nativeGraphics !== 'boolean' || typeof identity.language !== 'string' || identity.language.length > 85 || typeof identity.timezone !== 'string' || identity.timezone.length > 100) fail('WORKSPACE_IDENTITY_INVALID', '浏览器身份设置无效');
  let language = identity.language, timezone = identity.timezone;
  try {
    if (language !== 'auto') {
      if (!language) throw new Error();
      language = Intl.getCanonicalLocales(language)[0];
    }
    if (timezone !== 'auto') {
      if (!/^[A-Za-z][A-Za-z0-9._+-]*(?:\/[A-Za-z0-9._+-]+)*$/.test(timezone)) throw new Error();
      timezone = new Intl.DateTimeFormat('en', { timeZone: timezone }).resolvedOptions().timeZone;
    }
  } catch { fail('WORKSPACE_IDENTITY_INVALID', '请选择有效的语言和 IANA 时区'); }
  return { version: 1, language, timezone, nativeGraphics: identity.nativeGraphics };
}

export function validateWorkspaceServices(services) {
  if (!Array.isArray(services) || !services.length || services.length > BROWSER_WORKSPACE_SERVICES.length || services.some(service => !BROWSER_WORKSPACE_SERVICES.includes(service)) || new Set(services).size !== services.length) fail('WORKSPACE_SERVICES_INVALID', '请选择至少一个受支持的网站，每个网站只选一次');
  return [...services];
}

function validateName(name) {
  if (typeof name !== 'string' || !name.trim() || [...name.trim()].length > 40 || /[\x00-\x1f\x7f]/.test(name)) fail('WORKSPACE_NAME_INVALID', '工作区名称需要 1–40 个字符，且不能含控制字符');
  return name.trim();
}

export function createBrowserWorkspaceManager({ runtimeRoot, mock = false, now = Date.now, dependencies = {} } = {}) {
  if (!runtimeRoot || !path.isAbsolute(runtimeRoot)) fail('WORKSPACE_PATH_INVALID', '工作区需要绝对运行目录');
  const root = path.resolve(runtimeRoot), directory = path.join(root, '.browser-workspaces'), file = path.join(directory, 'workspaces.json'), legacyBackup = path.join(directory, 'workspaces.pre-fingerprint-p0.json');
  const fs = { lstat, realpath, readFile, rm, open, createPrivateDirectory, writePrivate, renamePrivate, ...dependencies };
  const legacySnapshots = new WeakMap();
  let memory = { version: 1, items: [] }, serial = Promise.resolve();
  const locked = action => { const next = serial.then(action, action); serial = next.catch(() => {}); return next; };
  async function safe(target) {
    const relative = path.relative(root, target);
    if (relative.startsWith('..') || path.isAbsolute(relative)) fail('WORKSPACE_PATH_INVALID', '工作区路径超出运行目录');
    let cursor = path.parse(target).root;
    for (const segment of target.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, segment);
      let info; try { info = await fs.lstat(cursor); } catch (cause) { if (cause.code === 'ENOENT') break; throw cause; }
      if (info.isSymbolicLink() || normalize(await fs.realpath(cursor)) !== normalize(cursor)) fail('WORKSPACE_PATH_INVALID', '工作区路径含链接或目录联接，操作已拒绝');
    }
  }
  async function ensure(target) {
    await safe(target);
    try { if (!(await fs.lstat(target)).isDirectory()) fail('WORKSPACE_PATH_INVALID', '工作区存储位置不是目录'); }
    catch (cause) { if (cause.code !== 'ENOENT') throw cause; if (target !== root) await ensure(path.dirname(target)); await fs.createPrivateDirectory(target); }
  }
  function validateState(state) {
    if (!keys(state, ['version', 'items']) || state.version !== 1 || !Array.isArray(state.items) || state.items.length > MAX_WORKSPACES) fail('WORKSPACE_STATE_INVALID', '工作区记录损坏，原记录已保留', 409);
    const ids = new Set();
    const items = state.items.map(saved => {
      const item = { ...saved, archivedAt: saved?.archivedAt ?? null, replacesId: saved?.replacesId ?? null };
      if (!keys(saved, ['id', 'name', 'services', 'binding', 'browser', 'createdAt', 'updatedAt', 'lastOpenedAt', 'identity', 'archivedAt', 'replacesId']) || !validBrowserWorkspaceId(item.id) || ids.has(item.id) || !validBinding(item.binding) || Object.hasOwn(item, 'browser') && !validBrowser(item.browser) || !validDate(item.createdAt) || !validDate(item.updatedAt) || item.lastOpenedAt !== null && !validDate(item.lastOpenedAt) || item.archivedAt !== null && !validDate(item.archivedAt) || item.replacesId !== null && (!validBrowserWorkspaceId(item.replacesId) || item.replacesId === item.id)) fail('WORKSPACE_STATE_INVALID', '工作区记录损坏，原记录已保留', 409);
      try {
        if (validateName(item.name) !== item.name) throw new Error();
        validateWorkspaceServices(item.services);
        if (Object.hasOwn(item, 'identity')) item.identity = validateWorkspaceIdentity(item.identity);
      } catch { fail('WORKSPACE_STATE_INVALID', '工作区记录损坏，原记录已保留', 409); }
      ids.add(item.id);
      return item;
    });
    if (items.filter(item => !item.archivedAt).length > MAX_ACTIVE_WORKSPACES) fail('WORKSPACE_STATE_INVALID', '活动工作区记录数量无效，原记录已保留', 409);
    return { version: 1, items };
  }
  const legacy = state => state.items.every(item => ['identity', 'archivedAt', 'replacesId'].every(key => !Object.hasOwn(item, key)));
  async function preserveLegacy(bytes) {
    async function existing() {
      await safe(legacyBackup);
      const info = await fs.lstat(legacyBackup);
      if (!info.isFile() || info.size > MAX_STATE_BYTES) fail('WORKSPACE_PATH_INVALID', '旧版用户环境备份位置无效，原记录未更改', 409);
      const saved = await fs.readFile(legacyBackup);
      try {
        if (!saved.length || saved.length > MAX_STATE_BYTES) throw new Error();
        const state = JSON.parse(saved.toString('utf8')); validateState(state);
        if (!legacy(state)) throw new Error();
      } catch { fail('WORKSPACE_BACKUP_INVALID', '旧版用户环境备份无法核验，原记录未更改，请保留备份并联系支持', 409); }
    }
    await safe(legacyBackup);
    try { await existing(); return; } catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
    try { await fs.writePrivate(legacyBackup, bytes); }
    catch (cause) { if (cause.code !== 'EEXIST') throw cause; await existing(); return; }
    // A failed/partial backup never permits publishing the migrated metadata.
    // Keep it for diagnosis; a future attempt must validate it, never overwrite it.
    await safe(legacyBackup);
    const handle = await fs.open(legacyBackup, 'r+'); try { await handle.sync(); } finally { await handle.close(); }
  }
  async function read() {
    if (mock) return structuredClone(memory);
    await safe(file);
    try {
      const info = await fs.lstat(file);
      if (!info.isFile() || info.size > MAX_STATE_BYTES) fail('WORKSPACE_STATE_INVALID', '工作区记录类型或大小无效，原记录已保留', 409);
      const bytes = await fs.readFile(file);
      if (bytes.length > MAX_STATE_BYTES) fail('WORKSPACE_STATE_INVALID', '工作区记录大小无效，原记录已保留', 409);
      let state; try { state = JSON.parse(bytes.toString('utf8')); } catch (cause) { if (cause instanceof SyntaxError) fail('WORKSPACE_STATE_INVALID', '工作区记录无法解析，原记录已保留', 409); throw cause; }
      const normalized = validateState(state);
      if (legacy(state)) legacySnapshots.set(normalized, bytes);
      return normalized;
    } catch (cause) { if (cause.code === 'ENOENT') return { version: 1, items: [] }; throw cause; }
  }
  async function write(state) {
    const previous = legacySnapshots.get(state);
    state = validateState(state);
    const serialized = `${JSON.stringify(state, null, 2)}\n`;
    if (Buffer.byteLength(serialized) > MAX_STATE_BYTES) fail('WORKSPACE_STATE_INVALID', '工作区记录大小无效，原记录已保留', 409);
    if (mock) { memory = structuredClone(state); return; }
    await ensure(directory);
    if (previous) await preserveLegacy(previous);
    const temporary = path.join(directory, `.atomic-${randomUUID()}.tmp`);
    try {
      await fs.writePrivate(temporary, serialized);
      const handle = await fs.open(temporary, 'r+'); try { await handle.sync(); } finally { await handle.close(); }
      await safe(file); await fs.renamePrivate(temporary, file);
    } finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
  }
  function find(state, id) {
    if (!validBrowserWorkspaceId(id)) fail('WORKSPACE_ID_INVALID', '工作区标识无效');
    const item = state.items.find(item => item.id === id);
    if (!item) fail('WORKSPACE_NOT_FOUND', '工作区不存在，请刷新列表', 404);
    return item;
  }
  function fields(input, partial) {
    if (!keys(input, ['name', 'services', 'binding', 'browser', 'identity']) || partial && !Object.keys(input).length) fail('WORKSPACE_INPUT_INVALID', '工作区设置包含无效字段');
    const result = {};
    if (!partial || Object.hasOwn(input, 'browser')) {
      const browser = Object.hasOwn(input, 'browser') ? input.browser : 'chrome';
      if (!validBrowser(browser)) fail('WORKSPACE_BROWSER_INVALID', '请选择 Chrome、Edge 或指纹浏览器');
      result.browser = browser;
    }
    if (!partial || Object.hasOwn(input, 'name')) result.name = validateName(input.name);
    if (!partial || Object.hasOwn(input, 'services')) result.services = validateWorkspaceServices(input.services);
    if (!partial || Object.hasOwn(input, 'binding')) { if (!validBinding(input.binding)) fail('WORKSPACE_BINDING_INVALID', '请先核验当前 ISP 配置后绑定工作区'); result.binding = input.binding; }
    if (Object.hasOwn(input, 'identity')) result.identity = validateWorkspaceIdentity(input.identity);
    else if (!partial) result.identity = { ...DEFAULT_IDENTITY };
    return result;
  }
  function active(item) { if (item.archivedAt) fail('WORKSPACE_ARCHIVED', '此用户环境已归档，请先恢复或创建替代环境', 409); return item; }
  function capacity(state, additional = 1) {
    if (state.items.length + additional > MAX_WORKSPACES) fail('WORKSPACE_LIMIT_REACHED', '最多可保存 96 个用户环境（包括归档）', 409);
    if (state.items.filter(item => !item.archivedAt).length >= MAX_ACTIVE_WORKSPACES) fail('WORKSPACE_LIMIT_REACHED', '最多可同时保留 24 个活动用户环境，请先归档不再使用的环境', 409);
  }
  return {
    list: () => locked(read),
    get: id => locked(async () => structuredClone(find(await read(), id))),
    create: input => locked(async () => {
      const selected = fields(input, false), state = await read();
      capacity(state);
      const date = new Date(now()).toISOString(), item = { id: randomUUID(), ...selected, createdAt: date, updatedAt: date, lastOpenedAt: null, archivedAt: null, replacesId: null };
      state.items.push(item); await write(state); return structuredClone(item);
    }),
    update: (id, input) => locked(async () => {
      const selected = fields(input, true), state = await read(), item = find(state, id);
      if (Object.hasOwn(selected, 'browser') && selected.browser !== workspaceBrowser(item)) fail('WORKSPACE_BROWSER_IMMUTABLE', '此工作区的浏览器已固定，请新建工作区，原登录资料会保留', 409);
      // An unchanged legacy choice must not turn a read/edit into a migration.
      if (!Object.hasOwn(item, 'browser')) delete selected.browser;
      Object.assign(item, selected, { updatedAt: new Date(now()).toISOString() }); await write(state); return structuredClone(item);
    }),
    ensureIdentity: (id, defaults) => locked(async () => {
      const identity = validateWorkspaceIdentity(defaults), state = await read(), item = find(state, id);
      if (!Object.hasOwn(item, 'identity')) { item.identity = identity; item.updatedAt = new Date(now()).toISOString(); await write(state); }
      return structuredClone(item);
    }),
    archive: id => locked(async () => {
      const state = await read(), item = find(state, id);
      if (!item.archivedAt) { item.archivedAt = item.updatedAt = new Date(now()).toISOString(); await write(state); }
      return structuredClone(item);
    }),
    restore: id => locked(async () => {
      const state = await read(), item = find(state, id);
      if (item.archivedAt) { capacity(state, 0); item.archivedAt = null; item.updatedAt = new Date(now()).toISOString(); await write(state); }
      return structuredClone(item);
    }),
    replace: (id, input = {}) => locked(async () => {
      if (!keys(input, ['name'])) fail('WORKSPACE_INPUT_INVALID', '替代环境设置包含无效字段');
      const state = await read(), previous = active(find(state, id));
      if (state.items.length >= MAX_WORKSPACES) fail('WORKSPACE_LIMIT_REACHED', '最多可保存 96 个用户环境（包括归档）', 409);
      const date = new Date(now()).toISOString(), item = {
        id: randomUUID(), name: Object.hasOwn(input, 'name') ? validateName(input.name) : previous.name,
        services: [...previous.services], binding: previous.binding, browser: workspaceBrowser(previous), identity: structuredClone(previous.identity ?? DEFAULT_IDENTITY),
        createdAt: date, updatedAt: date, lastOpenedAt: null, archivedAt: null, replacesId: previous.id,
      };
      previous.archivedAt = previous.updatedAt = date; state.items.push(item); await write(state);
      return structuredClone({ previous, item });
    }),
    remove: id => locked(async () => {
      const state = await read(); find(state, id); state.items = state.items.filter(item => item.id !== id); await write(state);
      // Browser profile trees are deliberately retained; removal only hides the saved card.
      return { removed: true, id, profilePreserved: true };
    }),
    assertBinding: (id, binding) => locked(async () => {
      const item = active(find(await read(), id));
      if (!validBinding(binding) || item.binding !== binding) fail('WORKSPACE_BINDING_MISMATCH', '当前 ISP 配置与工作区绑定不同，请核验配置后明确重新绑定', 409);
      return structuredClone(item);
    }),
    touch: id => locked(async () => {
      const state = await read(), item = active(find(state, id)); item.lastOpenedAt = new Date(now()).toISOString(); await write(state); return structuredClone(item);
    }),
  };
}
