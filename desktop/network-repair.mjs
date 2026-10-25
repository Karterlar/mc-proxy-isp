import path from 'node:path';
import { lstat, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { spawn } from 'node:child_process';

// The renderer supplies no paths or commands. The offline helper owns UAC,
// journal validation and restoration. A fresh request links readiness and the
// final result, so an OS spawn or an earlier report can never claim repair.
export async function launchNetworkRepair({ scriptPath, runtimeRoot, waitForPid, mock = false, stopSessions,
  spawnProcess = spawn, readyTimeoutMs = 120_000, completionTimeoutMs = 30_000, cancelTimeoutMs = 5000, systemRoot = process.env.SystemRoot || 'C:\\Windows' } = {}) {
  if (mock) return { launched: false, mock: true };
  if (!path.isAbsolute(scriptPath || '') || !path.isAbsolute(runtimeRoot || '')
    || !Number.isSafeInteger(waitForPid) || waitForPid <= 0 || waitForPid > 2_147_483_647 || typeof stopSessions !== 'function'
    || !Number.isInteger(readyTimeoutMs) || readyTimeoutMs <= 0 || readyTimeoutMs > 600_000
    || !Number.isInteger(completionTimeoutMs) || completionTimeoutMs <= 0 || completionTimeoutMs > 600_000
    || !Number.isInteger(cancelTimeoutMs) || cancelTimeoutMs <= 0 || cancelTimeoutMs > 60_000) {
    throw new Error('网络修复路径或会话信息无效。');
  }
  for (const target of [scriptPath, runtimeRoot]) {
    const actual = await realpath(target);
    const stat = await lstat(target);
    if (stat.isSymbolicLink() || actual.toLowerCase() !== path.resolve(target).toLowerCase()
      || (target === scriptPath ? !stat.isFile() : !stat.isDirectory())) {
      throw new Error('网络修复文件或运行目录包含链接，已停止。');
    }
  }
  const directory = path.join(runtimeRoot, 'network-repair');
  await mkdir(directory, { recursive: true });
  async function assertDirectory() {
    const stat = await lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (await realpath(directory)).toLowerCase() !== directory.toLowerCase()) throw new Error('网络修复报告目录包含链接，已停止。');
  }
  await assertDirectory();
  const requestId = randomUUID();
  const requestFile = suffix => path.join(directory, `desktop-${requestId}.${suffix}`);
  async function release(value) {
    await assertDirectory();
    const temporary = requestFile(`${randomUUID()}.tmp`);
    try { await writeFile(temporary, value, { flag: 'wx' }); await rename(temporary, requestFile('continue')); }
    finally { await rm(temporary, { force: true }).catch(() => {}); }
  }
  let child;
  try { child = spawnProcess(path.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'), [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath,
    '-RuntimeRoot', runtimeRoot, '-Confirmed', '-DesktopRequestId', requestId, '-DesktopPid', String(waitForPid), '-PreserveChangedRules',
  ], { windowsHide: true, stdio: 'ignore' }); }
  catch { throw new Error('无法启动离线修复工具，请使用发行目录中的 Repair-Network.cmd。'); }
  let closed;
  const completion = new Promise(resolve => {
    child.once('error', error => { closed = { error }; resolve(closed); });
    child.once('close', code => { closed ||= { code }; resolve(closed); });
  });
  async function result() {
    if (closed?.error) throw new Error('无法启动离线修复工具，请使用发行目录中的 Repair-Network.cmd。');
    let report;
    try {
      await assertDirectory();
      const file = requestFile('result.json');
      const stat = await lstat(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 8 * 1024 * 1024) throw new Error();
      report = JSON.parse(await readFile(file, 'utf8'));
      if (report.desktopRequestId !== requestId || typeof report.success !== 'boolean'
        || typeof report.lockReleased !== 'boolean' || !/^[A-Z][A-Z_]{1,79}$/.test(report.code || '')
        || !Number.isInteger(report.exitCode) || report.exitCode !== closed?.code
        || report.skippedAllowRules !== undefined && (!Number.isInteger(report.skippedAllowRules) || report.skippedAllowRules < 0 || report.skippedAllowRules > 1_000_000)) throw new Error();
      if (report.success && !['LOCAL_FIREWALL_RESTORED', 'LOCAL_LOCK_RELEASED_WITH_PRESERVED_RULES', 'LOCAL_WFP_LOCK_RELEASED'].includes(report.code)) throw new Error();
    } catch {
      throw new Error('修复工具未返回本次修复结果。请查看运行目录 network-repair 中的报告，或运行 Repair-Network.cmd。');
    }
    if (!report.success || report.exitCode !== 0 || report.lockReleased !== true) {
      const message = report.code === 'UAC_CANCELED_OR_ELEVATION_FAILED'
        ? '管理员授权被取消或失败，网络修复未执行。'
        : `网络修复未完成：${report.code}。恢复记录已保留，请查看修复报告。`;
      const error = new Error(message); error.code = report.code; error.reportPath = requestFile('result.json'); throw error;
    }
    return { launched: true, mock: false, completed: true, success: true, requestId, code: report.code,
      skippedAllowRules: report.skippedAllowRules || 0, reportPath: requestFile('result.json') };
  }
  let released = false;
  try {
    const deadline = Date.now() + readyTimeoutMs;
    for (;;) {
      if (closed) { await result(); throw new Error('修复工具未等待代理会话停止，修复结果未被采纳。'); }
      try {
        await assertDirectory();
        const ready = requestFile('ready');
        const stat = await lstat(ready);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== requestId.length) throw new Error('修复工具就绪记录无效或包含链接。');
        if (await readFile(ready, 'utf8') !== requestId) throw new Error('修复工具就绪记录无效。');
        break;
      } catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
      if (Date.now() >= deadline) throw new Error('等待管理员授权或修复工具就绪超时，客户端已继续运行。');
      await delay(100);
    }
    await stopSessions();
    await release(requestId);
    released = true;
    const finished = completion.then(result);
    // Restoration has already been authorized. A slow native helper must keep
    // running; release the UI wait while its owner retains the mutation gate.
    void finished.catch(() => {});
    let timer;
    try {
      return await Promise.race([finished, new Promise(resolve => { timer = setTimeout(() => resolve({ launched: true, mock: false, completed: false, pending: true,
        requestId, reportPath: requestFile('result.json'), completion: finished }), completionTimeoutMs); })]);
    } finally { clearTimeout(timer); }
  } finally {
    if (!released && !closed) {
      await release('cancel').catch(() => {});
      // Cancel is published before any mutation authorization. Wait briefly for
      // acknowledgment; never terminate a helper performing firewall restoration.
      let timer;
      await Promise.race([completion, new Promise(resolve => { timer = setTimeout(resolve, cancelTimeoutMs); })]);
      clearTimeout(timer);
    }
    const cleanup = async () => {
      try { await assertDirectory(); await Promise.allSettled([rm(requestFile('ready'), { force: true }), rm(requestFile('continue'), { force: true })]); }
      catch { /* Preserve the outcome and recovery records when cleanup is denied. */ }
    };
    if (closed) await cleanup();
    else void completion.then(cleanup).catch(() => {});
  }
}
