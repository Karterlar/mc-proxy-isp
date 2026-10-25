import path from 'node:path';
import { lstat, realpath, readFile, rename, rm, open } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createPrivateDirectory, writePrivate } from './private-files.mjs';
import { createChainDiagnosticManifest } from './chain-diagnostics.mjs';
import { UserError } from './config.mjs';

const FILES = Object.freeze(['Transport.cs', 'Test-ChainReadiness.ps1', 'Run-Recovery.cmd', 'Repair-Network.cmd', 'Repair-Network.ps1', 'run-preflight.cmd', 'run-connected-test.cmd', 'README.zh-CN.txt']);
const IMPORTED_INSTRUCTIONS = Buffer.from('本诊断包用于 YAML VPN → ISP 导入线路。\r\n无需运行外部 VPN；在 MC Proxy 内检测所选节点和固定 ISP 出口。\r\n本线路仅提供本地 HTTP 代理。下列 TUN 预检脚本返回“不适用”，不测试导入节点。\r\n导入节点、凭据及原始 YAML 不在本包中；请勿另行加入私有运行目录。\r\n\r\n');
const normalize = target => process.platform === 'win32' ? path.resolve(target).toLowerCase() : path.resolve(target);
const fail = message => { throw new UserError('DIAGNOSTICS_EXPORT_FAILED', message); };

export async function exportChainDiagnostics({ runtimeRoot, sourceDirectory = fileURLToPath(new URL('../../tools/offline-chain-test/', import.meta.url)), config, corePath, appPath, lastFailure, mock = false } = {}) {
  if (!runtimeRoot || !path.isAbsolute(runtimeRoot)) fail('离线诊断运行目录必须为绝对路径。');
  const root = path.resolve(runtimeRoot); const directory = path.join(root, 'offline-diagnostics');
  const manifest = createChainDiagnosticManifest({ config, corePath, runtimeRoot: root, appPath, lastFailure });
  if (mock) return { directory: null, files: [...FILES, 'manifest.json'], manifest, mock: true };
  async function safe(target) {
    let cursor = path.parse(target).root;
    for (const part of target.slice(cursor.length).split(path.sep).filter(Boolean)) {
      cursor = path.join(cursor, part);
      let stat; try { stat = await lstat(cursor); } catch (cause) { if (cause.code === 'ENOENT') break; throw cause; }
      if (stat.isSymbolicLink() || normalize(await realpath(cursor)) !== normalize(cursor)) fail('诊断路径包含链接，未导出文件。');
    }
  }
  async function ensure(target) {
    await safe(target);
    try { if (!(await lstat(target)).isDirectory()) fail('诊断存储位置不是目录。'); }
    catch (cause) {
      if (cause.code !== 'ENOENT') throw cause;
      if (normalize(target) !== normalize(root)) await ensure(path.dirname(target));
      await createPrivateDirectory(target);
    }
  }
  try {
    const sources = [];
    for (const name of FILES) {
      const source = path.join(path.resolve(sourceDirectory), name); await safe(source);
      const info = await lstat(source);
      if (!info.isFile() || info.size > 2 * 1024 * 1024) fail('离线诊断程序缺失或大小异常。');
      const data = await readFile(source);
      sources.push([name, name === 'README.zh-CN.txt' && manifest.connectionMode === 'vpn-import' ? Buffer.concat([IMPORTED_INSTRUCTIONS, data]) : data]);
    }
    sources.push(['manifest.json', Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`)]);
    await ensure(directory);
    for (const [name, data] of sources) {
      const target = path.join(directory, name); const temporary = path.join(directory, `.export-${randomUUID()}.tmp`);
      try {
        await safe(target); await safe(temporary); await writePrivate(temporary, data);
        const handle = await open(temporary, 'r+'); try { await handle.sync(); } finally { await handle.close(); }
        await safe(target); await rename(temporary, target);
      } finally { await safe(temporary).then(() => rm(temporary, { force: true })).catch(() => {}); }
    }
    return { directory, files: sources.map(([name]) => name), manifest, mock: false };
  } catch (cause) {
    if (cause instanceof UserError) throw cause;
    fail('离线诊断导出失败，请检查诊断程序和私有运行目录权限。');
  }
}
