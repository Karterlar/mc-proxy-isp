import path from 'node:path';
import { readFile, lstat, realpath, open, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { createPrivateDirectory, writePrivate, renamePrivate } from './private-files.mjs';
import { parseVpnConfig, validateVpnOutbound, vpnNodeMetadata, vpnOutboundIdentity, deduplicateVpnNodes, VPN_NODE_ERROR_CODES } from './vpn-yaml.mjs';
import { UserError } from './config.mjs';
import { validateSubscriptionUrl } from './vpn-subscription.mjs';

const clone = value => structuredClone(value);
const fail = code => { throw new UserError(code, 'Imported VPN configuration could not be safely read or saved'); };
const formats = ['clash-yaml', 'sing-box', 'share-uri', 'base64-subscription', 'surge-ini', 'v2ray-json'];
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;

export function createImportedVpnStore({ stateDir, mock = false, dependencies = {} } = {}) {
  if (!mock && (!stateDir || !path.isAbsolute(stateDir))) fail('VPN_IMPORT_INVALID');
  const root = stateDir && path.resolve(stateDir); const file = root && path.join(root, 'nodes.json');
  const fs = { readFile, lstat, realpath, open, rm, createPrivateDirectory, writePrivate, rename: renamePrivate, ...dependencies };
  let mockRecord = null; let serial = Promise.resolve();
  const locked = action => { const task = serial.then(action, action); serial = task.catch(() => {}); return task; };
  async function safe(target) {
    let cursor = path.parse(target).root;
    for (const part of target.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, part);
      try {
        const stat = await fs.lstat(cursor);
        if (stat.isSymbolicLink() || path.resolve(await fs.realpath(cursor)).toLowerCase() !== cursor.toLowerCase()) fail('VPN_IMPORT_INVALID');
      } catch (cause) { if (cause.code === 'ENOENT') break; throw cause; }
    }
  }
  function validate(record) {
    if (record && record.duplicates === undefined) record.duplicates = [];
    if (!record || record.version !== 1 || !uuid.test(record.id || '') || !Number.isInteger(record.total) || record.total < 1 || record.total > 256
      || !Array.isArray(record.nodes) || !record.nodes.length || !Array.isArray(record.unsupported) || !Array.isArray(record.duplicates) || record.nodes.length + record.unsupported.length + record.duplicates.length !== record.total
      || Object.keys(record).some(key => !['version', 'id', 'selectedIndex', 'total', 'nodes', 'unsupported', 'duplicates', 'format', 'changeSummary', 'subscription'].includes(key)) || record.format !== undefined && !formats.includes(record.format)) fail('VPN_IMPORT_INVALID');
    record.format ??= 'clash-yaml';
    const indexes = new Set();
    for (const node of [...record.nodes, ...record.unsupported, ...record.duplicates]) {
      if (!Number.isInteger(node?.index) || node.index < 1 || node.index > record.total || indexes.has(node.index)) fail('VPN_IMPORT_INVALID');
      indexes.add(node.index);
    }
    for (const node of record.nodes) {
      if (Object.keys(node).some(key => !['index', 'name', 'outbound', 'protocol', 'transport'].includes(key)) || typeof node.name !== 'string' || !node.name.length || node.name.length > 120
        || /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/.test(node.name)) fail('VPN_IMPORT_INVALID');
      try { node.outbound = validateVpnOutbound(node.outbound); } catch { fail('VPN_IMPORT_INVALID'); }
      const metadata = vpnNodeMetadata(node.outbound);
      if (node.protocol !== undefined && node.protocol !== metadata.protocol || node.transport !== undefined && node.transport !== metadata.transport) fail('VPN_IMPORT_INVALID');
      Object.assign(node, metadata);
    }
    if (record.unsupported.some(node => Object.keys(node).some(key => !['index', 'code'].includes(key)) || !VPN_NODE_ERROR_CODES.includes(node.code))) fail('VPN_IMPORT_INVALID');
    if (record.duplicates.some(node => Object.keys(node).some(key => !['index', 'duplicateOf', 'code'].includes(key)) || node.code !== 'VPN_NODE_DUPLICATE'
      || !record.nodes.some(first => first.index === node.duplicateOf) || node.duplicateOf >= node.index)) fail('VPN_IMPORT_INVALID');
    if (record.selectedIndex !== null && !record.nodes.some(node => node.index === record.selectedIndex)) fail('VPN_IMPORT_INVALID');
    const deduplicated = deduplicateVpnNodes(record.nodes);
    record.selectedIndex = deduplicated.duplicates.find(node => node.index === record.selectedIndex)?.duplicateOf ?? record.selectedIndex;
    record.nodes = deduplicated.nodes;
    record.duplicates = [...record.duplicates, ...deduplicated.duplicates].map(node => ({ ...node, duplicateOf: deduplicated.duplicates.find(alias => alias.index === node.duplicateOf)?.duplicateOf ?? node.duplicateOf })).sort((a, b) => a.index - b.index);
    if (record.changeSummary !== undefined && (!record.changeSummary || Object.keys(record.changeSummary).sort().join(',') !== 'added,kept,removed,renamed,unchanged'
      || ['added', 'kept', 'removed', 'renamed'].some(key => !Number.isInteger(record.changeSummary[key]) || record.changeSummary[key] < 0 || record.changeSummary[key] > 256)
      || typeof record.changeSummary.unchanged !== 'boolean')) fail('VPN_IMPORT_INVALID');
    if (record.subscription !== undefined && (!record.subscription || Object.keys(record.subscription).some(key => !['lastUpdatedAt', 'url', 'usage'].includes(key))
      || typeof record.subscription.lastUpdatedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(record.subscription.lastUpdatedAt))) fail('VPN_IMPORT_INVALID');
    if (record.subscription !== undefined) {
      try { if (validateSubscriptionUrl(record.subscription.url) !== record.subscription.url || !Number.isFinite(Date.parse(record.subscription.lastUpdatedAt))) fail('VPN_IMPORT_INVALID'); }
      catch { fail('VPN_IMPORT_INVALID'); }
      if (record.subscription.usage !== undefined) {
        const usage = record.subscription.usage;
        if (!usage || typeof usage !== 'object' || Array.isArray(usage) || !Object.keys(usage).length || Object.keys(usage).some(key => !['upload', 'download', 'total', 'expire'].includes(key))
          || Object.entries(usage).some(([key, value]) => !Number.isSafeInteger(value) || value < 0 || key === 'expire' && value > 253_402_300_799)) fail('VPN_IMPORT_INVALID');
      }
    }
    return record;
  }
  async function read({ allowInvalid = false } = {}) {
    if (mock) return { record: clone(mockRecord), bytes: null };
    try {
      await safe(file);
      const stat = await fs.lstat(file);
      if (!stat.isFile() || stat.size > 1024 * 1024 || (process.platform !== 'win32' && (stat.mode & 0o077))) fail('VPN_IMPORT_INVALID');
      const bytes = await fs.readFile(file);
      if (bytes.length > 1024 * 1024) fail('VPN_IMPORT_INVALID');
      let record;
      try { record = validate(JSON.parse(bytes.toString('utf8'))); }
      catch {
        if (allowInvalid) return { record: null, bytes, invalid: true };
        fail('VPN_IMPORT_INVALID');
      }
      return { record, bytes };
    } catch (cause) {
      if (cause.code === 'ENOENT') return { record: null, bytes: null };
      if (cause instanceof UserError) throw cause;
      fail('VPN_IMPORT_READ_FAILED');
    }
  }
  function publicStatus(record) {
    return { available: Boolean(record), id: record?.id || null, selectedIndex: record?.selectedIndex ?? null, format: record?.format || null,
      total: record?.total || 0, supported: record?.nodes.length || 0, unsupported: record?.unsupported.length || 0,
      duplicates: record?.duplicates?.length || 0, duplicateNodes: clone(record?.duplicates || []), changeSummary: clone(record?.changeSummary || null),
      subscription: { configured: Boolean(record?.subscription), lastUpdatedAt: record?.subscription?.lastUpdatedAt || null, ...(record?.subscription?.usage ? { usage: clone(record.subscription.usage) } : {}) },
      nodes: (record?.nodes || []).map(({ index, name, outbound }) => ({ index, name, ...vpnNodeMetadata(outbound) })), unsupportedNodes: clone(record?.unsupported || []), mock };
  }
  async function save(record, previous) {
    const serialized = `${JSON.stringify(record)}\n`;
    if (Buffer.byteLength(serialized, 'utf8') > 1024 * 1024) fail('VPN_YAML_SIZE_INVALID');
    if (mock) { mockRecord = clone(record); return publicStatus(record); }
    let temporary;
    try {
      await safe(root);
      try { if (!(await fs.lstat(root)).isDirectory()) fail('VPN_IMPORT_INVALID'); }
      catch (cause) { if (cause.code !== 'ENOENT') throw cause; await fs.createPrivateDirectory(root); }
      if (previous.invalid) {
        const archive = path.join(root, `nodes-archive-${randomUUID()}.json`);
        await safe(archive);
        await fs.writePrivate(archive, previous.bytes);
        const handle = await fs.open(archive, 'r+'); try { await handle.sync(); } finally { await handle.close(); }
        if (!previous.bytes.equals(await fs.readFile(archive))) fail('VPN_IMPORT_WRITE_FAILED');
      }
      temporary = path.join(root, `${randomUUID()}.tmp`);
      await fs.writePrivate(temporary, serialized);
      const handle = await fs.open(temporary, 'r+'); try { await handle.sync(); } finally { await handle.close(); }
      const latest = await read({ allowInvalid: true });
      if ((previous.bytes === null) !== (latest.bytes === null) || (previous.bytes && !previous.bytes.equals(latest.bytes))) fail('VPN_IMPORT_CONFLICT');
      await fs.rename(temporary, file);
      return publicStatus(record);
    } catch (cause) { if (cause instanceof UserError) throw cause; fail('VPN_IMPORT_WRITE_FAILED'); }
    finally { if (temporary) await fs.rm(temporary, { force: true }).catch(() => {}); }
  }
  function expected(previous, expectedId) {
    if (expectedId !== undefined && (previous.record?.id || null) !== expectedId) fail('VPN_IMPORT_CONFLICT');
  }
  return {
    status: () => locked(async () => publicStatus((await read()).record)),
    load: () => locked(async () => clone((await read()).record)),
    candidates: () => locked(async () => { const { record } = await read(); return clone((record?.nodes || []).filter(node => record.selectedIndex === null || node.index === record.selectedIndex)); }),
    import: (text, { expectedId, subscription, expectedContent } = {}) => locked(async () => {
      const parsed = parseVpnConfig(text);
      if (!parsed.nodes.length) {
        const cause = new UserError('VPN_IMPORT_NO_SUPPORTED_NODES', 'Imported VPN configuration contains no supported nodes');
        cause.unsupportedNodes = clone(parsed.unsupported); throw cause;
      }
      const previous = await read({ allowInvalid: true }); expected(previous, expectedId);
      if (expectedContent !== undefined && vpnOutboundIdentity(previous.record) !== expectedContent) fail('VPN_IMPORT_CONFLICT');
      const oldNodes = new Map((previous.record?.nodes || []).map(node => [vpnOutboundIdentity(node.outbound), node]));
      const currentNodes = new Map(parsed.nodes.map(node => [vpnOutboundIdentity(node.outbound), node]));
      const comparable = record => ({ format: record.format, total: record.total, nodes: record.nodes, unsupported: record.unsupported, duplicates: record.duplicates });
      const unchanged = Boolean(previous.record && vpnOutboundIdentity(comparable(previous.record)) === vpnOutboundIdentity(comparable(parsed)));
      const selected = previous.record?.nodes.find(node => node.index === previous.record.selectedIndex);
      const selectedIndex = selected ? currentNodes.get(vpnOutboundIdentity(selected.outbound))?.index ?? null : null;
      const changeSummary = { added: [...currentNodes.keys()].filter(id => !oldNodes.has(id)).length, removed: [...oldNodes.keys()].filter(id => !currentNodes.has(id)).length,
        kept: [...currentNodes.keys()].filter(id => oldNodes.has(id)).length, renamed: [...currentNodes].filter(([id, node]) => oldNodes.has(id) && oldNodes.get(id).name !== node.name).length, unchanged };
      const record = validate({ version: 1, id: unchanged ? previous.record.id : randomUUID(), selectedIndex, ...parsed, changeSummary,
        ...(subscription ? { subscription } : unchanged && previous.record?.subscription ? { subscription: previous.record.subscription } : {}) });
      if (previous.record && vpnOutboundIdentity(record) === vpnOutboundIdentity(previous.record)) return publicStatus(previous.record);
      return save(record, previous);
    }),
    clearSubscription: ({ expectedId } = {}) => locked(async () => {
      const previous = await read(); expected(previous, expectedId);
      if (!previous.record?.subscription) return publicStatus(previous.record);
      const record = { ...previous.record }; delete record.subscription; return save(record, previous);
    }),
    select: (index, { expectedId } = {}) => locked(async () => {
      const previous = await read(); expected(previous, expectedId);
      if (!previous.record || (index !== null && (!Number.isInteger(index) || !previous.record.nodes.some(node => node.index === index)))) fail('VPN_NODE_NOT_FOUND');
      return save({ ...previous.record, selectedIndex: index }, previous);
    }),
  };
}
