import path from 'node:path';
import { lstat, readdir, rename, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

const fail = (code, message, status = 409) => Object.assign(new Error(message), { code, status });
const validId = value => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value);
const validDate = value => typeof value === 'string' && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;

export const BROWSER_PROFILE_ERROR_MESSAGES = Object.freeze({
  BROWSER_PROFILE_SCOPE_INVALID: '此操作只用于默认保留资料，请在用户环境中管理独立资料',
  BROWSER_PROFILE_FRESH_RUNNING: '当前运行的是纯净空间；此操作只管理默认保留资料，请先关闭纯净窗口。纯净资料不会归档到默认历史。',
  BROWSER_PROFILE_ARCHIVE_INVALID: '请选择有效的历史资料',
  BROWSER_PROFILE_ARCHIVE_NOT_FOUND: '所选历史资料已不存在，未修改当前资料',
  BROWSER_PROFILE_UPDATE_FAILED: '资料切换未完成，原资料或恢复记录已保留，请关闭浏览器后重试',
});

// Profiles stay at their original paths. A same-volume rename preserves all
// browser databases without copying or reading their contents.
export function createBrowserProfileArchives({ profileRoot, browsers, safePath, readJson, writeJson, assertClosed, beforeChange = async () => {}, onChanged = () => {}, move = rename, mock = false } = {}) {
  const archiveRoot = path.join(profileRoot, 'archive');
  const journalFile = path.join(profileRoot, '.profile-change.json');
  const profile = browser => path.join(profileRoot, browser);
  const entry = (browser, id) => path.join(archiveRoot, browser, id);
  const storedProfile = (browser, id) => path.join(entry(browser, id), 'profile');
  const metadata = (browser, id) => path.join(entry(browser, id), 'archive.json');
  const modeled = new Map(browsers.map(browser => [browser, { current: false, archives: [] }]));

  function input(value, allowed) {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) throw fail('BROWSER_PROFILE_SCOPE_INVALID', '此操作只用于默认保留资料，请在用户环境中管理独立资料', 400);
    const browser = value.browser === undefined ? 'chrome' : value.browser;
    if (!browsers.includes(browser)) throw fail('BROWSER_INVALID', '请选择受支持的受管浏览器', 400);
    return browser;
  }

  async function stat(file) {
    await safePath(file);
    try { return await lstat(file); } catch (cause) { if (cause.code === 'ENOENT') return null; throw cause; }
  }

  async function directory(file) {
    const found = await stat(file);
    if (found && !found.isDirectory()) throw fail('BROWSER_PATH_UNSAFE', '浏览器资料目录类型异常，未移动任何资料');
    return Boolean(found);
  }

  async function tree(file) {
    if (!await directory(file)) return false;
    const visit = async target => {
      const found = await stat(target);
      if (!found || found.isSymbolicLink() || !found.isDirectory() && (!found.isFile() || found.nlink > 1)) throw fail('BROWSER_PATH_UNSAFE', '浏览器资料包含链接或非普通文件，未移动任何资料');
      if (found.isDirectory()) for (const name of await readdir(target)) await visit(path.join(target, name));
    };
    await visit(file);
    return true;
  }

  async function document(file) {
    const found = await stat(file);
    if (!found) return undefined;
    if (!found.isFile() || found.nlink > 1 || found.size > 16384) throw fail('BROWSER_STATE_INVALID', '浏览器资料恢复记录类型或大小异常，原资料保留');
    return readJson(file);
  }

  async function readMetadata(browser, id) {
    const data = await document(metadata(browser, id));
    if (!data || data.version !== 1 || data.browser !== browser || data.id !== id || !validDate(data.createdAt)) throw fail('BROWSER_STATE_INVALID', '浏览器历史资料记录无效，原资料保留');
    return { id, createdAt: data.createdAt };
  }

  async function prepareArchive(browser, id, createdAt) {
    await safePath(entry(browser, id));
    if (await directory(storedProfile(browser, id))) throw fail('BROWSER_STATE_INVALID', '历史资料目标已存在，未覆盖任何资料');
    const found = await document(metadata(browser, id));
    if (found !== undefined) {
      const expected = { version: 1, browser, id, createdAt };
      if (JSON.stringify(found) !== JSON.stringify(expected)) throw fail('BROWSER_STATE_INVALID', '历史资料记录与待恢复操作不一致');
    } else await writeJson(metadata(browser, id), { version: 1, browser, id, createdAt });
  }

  async function removeJournal() { await safePath(journalFile); await rm(journalFile, { force: true }); }

  function validateJournal(data) {
    if (data?.version !== 1 || !browsers.includes(data.browser) || !['refresh', 'restore'].includes(data.operation)
      || data.currentId !== null && !validId(data.currentId) || !validDate(data.createdAt)
      || data.operation === 'refresh' && !data.currentId
      || data.operation === 'restore' && (!validId(data.restoreId) || data.restoreId === data.currentId)) throw fail('BROWSER_STATE_INVALID', '浏览器资料切换记录无效，未新建或覆盖任何资料');
    return data;
  }

  async function complete(data) {
    validateJournal(data);
    const { browser, currentId, createdAt } = data;
    const canonical = profile(browser), archived = currentId && storedProfile(browser, currentId);
    const canonicalPresent = await tree(canonical);
    const archivedPresent = archived && await tree(archived);
    if (archivedPresent && (await readMetadata(browser, currentId)).createdAt !== createdAt) throw fail('BROWSER_STATE_INVALID', '当前资料归档时间与恢复记录不一致，未覆盖任何资料');
    if (data.operation === 'refresh') {
      if (canonicalPresent && archivedPresent || !canonicalPresent && !archivedPresent) throw fail('BROWSER_STATE_INVALID', '浏览器资料刷新状态不一致，原资料和恢复记录保留');
      if (canonicalPresent) {
        await prepareArchive(browser, currentId, createdAt);
        await assertClosed();
        await safePath(canonical); await safePath(archived);
        await move(canonical, archived);
      }
    } else {
      const target = storedProfile(browser, data.restoreId);
      const targetPresent = await tree(target);
      if (targetPresent) {
        await readMetadata(browser, data.restoreId);
        if (canonicalPresent) {
          if (!currentId || archivedPresent) throw fail('BROWSER_STATE_INVALID', '恢复目标与现有资料冲突，未覆盖任何资料');
          await prepareArchive(browser, currentId, createdAt);
          await assertClosed();
          await safePath(canonical); await safePath(archived);
          await move(canonical, archived);
        } else if (currentId && !archivedPresent) throw fail('BROWSER_STATE_INVALID', '待保存的当前资料缺失，恢复记录保留');
        await assertClosed();
        await safePath(target); await safePath(canonical);
        // Never let rename replace a canonical directory created by another process.
        if (await stat(canonical)) throw fail('BROWSER_STATE_INVALID', '资料目录在恢复期间发生变化，未覆盖任何资料');
        await move(target, canonical);
      } else if (!canonicalPresent || currentId && !archivedPresent) throw fail('BROWSER_STATE_INVALID', '待恢复资料缺失，未新建空白资料');
    }
    await onChanged(browser);
    await removeJournal();
  }

  async function recover() {
    if (mock) return;
    const pending = await document(journalFile);
    if (pending === undefined) return;
    validateJournal(pending);
    await assertClosed();
    await complete(pending);
  }

  async function list(value = {}) {
    const browser = input(value, ['browser']);
    if (mock) return { browser, currentAvailable: modeled.get(browser).current, archives: modeled.get(browser).archives.map(item => ({ ...item })) };
    await recover();
    const archives = [], base = path.join(archiveRoot, browser);
    if (await directory(base)) for (const candidate of await readdir(base, { withFileTypes: true })) {
      if (!validId(candidate.name) || !candidate.isDirectory()) throw fail('BROWSER_PATH_UNSAFE', '历史资料目录包含非预期项目，原资料保留');
      if (await directory(storedProfile(browser, candidate.name))) archives.push(await readMetadata(browser, candidate.name));
    }
    archives.sort((a, b) => b.createdAt.localeCompare(a.createdAt) || a.id.localeCompare(b.id));
    return { browser, currentAvailable: await directory(profile(browser)), archives };
  }

  async function rollback(data) {
    // If the selected history has already become canonical, the transaction
    // committed. Leave its journal for recovery rather than undoing success.
    if (data.operation === 'restore' && !await directory(storedProfile(data.browser, data.restoreId))) return;
    const canonical = profile(data.browser), archived = data.currentId && storedProfile(data.browser, data.currentId);
    if (!await directory(canonical) && archived && await tree(archived)) {
      await assertClosed(); await safePath(canonical); await safePath(archived);
      await move(archived, canonical);
    }
    if (await directory(canonical) || data.currentId === null) await removeJournal();
  }

  async function run(data) {
    await writeJson(journalFile, data);
    try { await complete(data); }
    catch (cause) {
      try { await rollback(data); } catch { /* Keep the journal until a later safe recovery. */ }
      if (/^(?:BROWSER_|PROCESS_)/.test(cause.code || '')) throw cause;
      throw fail('BROWSER_PROFILE_UPDATE_FAILED', BROWSER_PROFILE_ERROR_MESSAGES.BROWSER_PROFILE_UPDATE_FAILED);
    }
  }

  async function refresh(value = {}) {
    const browser = input(value, ['browser', 'confirm']);
    if (value.confirm !== true) throw fail('CONFIRMATION_REQUIRED', '刷新资料需要明确确认，旧登录资料将保留在历史中', 400);
    await recover();
    if (!mock) await assertClosed();
    if (!mock) await tree(profile(browser));
    await beforeChange();
    const existing = await list({ browser });
    if (!existing.currentAvailable) { await onChanged(browser); return { changed: false, archiveId: null, mode: mock ? 'mocked' : 'applied', archives: existing.archives }; }
    const archiveId = randomUUID(), createdAt = new Date().toISOString();
    if (mock) { const state = modeled.get(browser); state.current = false; state.archives.unshift({ id: archiveId, createdAt }); }
    else {
      await run({ version: 1, browser, operation: 'refresh', currentId: archiveId, createdAt });
    }
    return { changed: true, archiveId, mode: mock ? 'mocked' : 'applied', archives: (await list({ browser })).archives };
  }

  async function restore(value = {}) {
    const browser = input(value, ['browser', 'archiveId', 'confirm']);
    if (value.confirm !== true) throw fail('CONFIRMATION_REQUIRED', '恢复历史资料需要明确确认，当前资料会先保存到历史', 400);
    if (!validId(value.archiveId)) throw fail('BROWSER_PROFILE_ARCHIVE_INVALID', '请选择有效的历史资料', 400);
    await recover();
    if (!mock) await assertClosed();
    const existing = await list({ browser });
    if (!existing.archives.some(item => item.id === value.archiveId)) throw fail('BROWSER_PROFILE_ARCHIVE_NOT_FOUND', '所选历史资料已不存在，未修改当前资料', 404);
    if (!mock) { await tree(profile(browser)); await tree(storedProfile(browser, value.archiveId)); }
    await beforeChange();
    const archivedCurrentId = existing.currentAvailable ? randomUUID() : null, createdAt = new Date().toISOString();
    if (mock) {
      const state = modeled.get(browser); state.archives = state.archives.filter(item => item.id !== value.archiveId);
      if (archivedCurrentId) state.archives.unshift({ id: archivedCurrentId, createdAt }); state.current = true;
    } else {
      await run({ version: 1, browser, operation: 'restore', restoreId: value.archiveId, currentId: archivedCurrentId, createdAt });
    }
    return { restored: true, archivedCurrentId, mode: mock ? 'mocked' : 'applied', archives: (await list({ browser })).archives };
  }

  return { list, refresh, restore, recover, markMockCurrent: browser => { if (mock) modeled.get(browser).current = true; } };
}
