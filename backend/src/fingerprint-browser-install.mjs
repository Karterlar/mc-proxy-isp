import path from 'node:path';
import { createReadStream, createWriteStream } from 'node:fs';
import { lstat, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { execFile } from 'node:child_process';
import { FINGERPRINT_BROWSER_RELEASE as release, FINGERPRINT_RECEIPT, fingerprintInventoryHash, inspectFingerprintRuntime } from './fingerprint-browser-runtime.mjs';

async function run(program, args, options = {}) {
  let outcome;
  const child = execFile(program, args, { windowsHide: true, timeout: 120000, maxBuffer: 65536, ...options }, (error, stdout) => { outcome = { error, stdout }; });
  // AbortSignal can report an error before process exit. Await this exact child
  // handle's close before deleting its component staging directory.
  await new Promise(resolve => child.once('close', resolve));
  if (outcome?.error) throw outcome.error;
  return String(outcome?.stdout || '').replace(/^\uFEFF/, '').trim();
}
async function ensureReadPermissions(root, signal) {
  // The Windows renderer sandbox needs read/execute permission for its public
  // runtime. Grant it only to this already verified component, never to the
  // user's profiles, credentials, application data or project directory.
  await run('icacls.exe', [root, '/grant', '*S-1-15-2-1:(OI)(CI)RX', '*S-1-15-2-2:(OI)(CI)RX', '/T', '/C'], { signal });
}
async function canonicalBundleDirectory(directory) {
  // NSIS portable extraction inherits the Windows 8.3 spelling of %TEMP%
  // (for example ADMINI~1). Expand only a real short-name component in the
  // same already checked parent. Links/junctions and parent changes are still
  // rejected before the ordinary runtime verifier sees the canonical path.
  let cursor = path.parse(directory).root;
  const equal = (left, right) => path.resolve(left).replace(/[\\/]+$/, '').toLowerCase() === path.resolve(right).replace(/[\\/]+$/, '').toLowerCase();
  for (const segment of directory.slice(cursor.length).split(path.sep).filter(Boolean)) {
    const candidate = path.join(cursor, segment);
    const stat = await lstat(candidate);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw Object.assign(new Error('Linked bundled component directories are forbidden.'), { code: 'BROWSER_FINGERPRINT_PATH_UNSAFE', status: 409 });
    const expanded = path.resolve(await realpath(candidate));
    if (!equal(expanded, candidate) && (process.platform !== 'win32' || !/^[A-Za-z0-9_!#$%&'()@^`{}-]{1,6}~[1-9][0-9]{0,5}(?:\.[A-Za-z0-9_!#$%&'()@^`{}-]{1,3})?$/.test(segment)
      || !equal(path.dirname(expanded), cursor))) throw Object.assign(new Error('Bundled component path changed its verified parent.'), { code: 'BROWSER_FINGERPRINT_PATH_UNSAFE', status: 409 });
    cursor = expanded;
  }
  return cursor;
}

// Packaged clients carry the exact public engine resources. Keep the installed
// copy outside the uninstall directory so removal of the application cannot
// remove browser profiles, and do not overwrite an already valid component.
export async function prepareFingerprintBrowserFromBundle(source, target, { onProgress = () => {}, signal, release: pinnedRelease = release } = {}) {
  const progress = (status, receivedBytes = 0, totalBytes = pinnedRelease.archiveBytes) => {
    try { onProgress({ status, receivedBytes, totalBytes, version: pinnedRelease.version }); } catch {}
  };
  const cancelled = () => {
    if (signal?.aborted) throw Object.assign(new Error('指纹浏览器组件准备已取消。'), { code: 'BROWSER_FINGERPRINT_INSTALL_CANCELLED', status: 409 });
  };
  const local = directory => {
    if (!path.isAbsolute(directory) || /^[\\/]{2}/.test(directory) || /[\x00-\x1f\x7f]/.test(directory)) throw new Error('Use an absolute local component directory.');
    return path.resolve(directory);
  };
  cancelled(); progress('checking');
  if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('This pinned browser component requires Windows x64.');
  source = local(source); target = local(target);
  const current = await inspectFingerprintRuntime(target, { full: true, release: pinnedRelease });
  if (current.state === 'ready') {
    await ensureReadPermissions(target, signal);
    cancelled(); progress('already-ready');
    return { installed: false, source: 'bundle', ...current };
  }
  // A directory with missing files is different from an absent directory. Even
  // a partial/corrupt installation is retained for explicit inspection/recovery.
  try {
    await lstat(target);
    throw Object.assign(new Error('指纹浏览器组件已有文件但未通过校验，请保留配置并检查组件目录后重试。'), { code: current.errorCode || 'BROWSER_FINGERPRINT_FILES_CHANGED', status: 409 });
  } catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
  source = await canonicalBundleDirectory(source);
  const bundled = await inspectFingerprintRuntime(source, { full: true, release: pinnedRelease });
  cancelled();
  if (bundled.state !== 'ready') throw Object.assign(new Error('安装包中的指纹浏览器组件未通过校验，请重新安装完整的交付版。'), { code: bundled.errorCode, status: 409 });
  const receipt = JSON.parse(await readFile(path.join(source, FINGERPRINT_RECEIPT), 'utf8'));
  const parent = path.dirname(target);
  // Verify the nearest existing ancestor before creating any child directory.
  // This also rejects junctions on Windows without following them for copying.
  let ancestor = parent;
  while (true) {
    try { await lstat(ancestor); break; }
    catch (cause) { if (cause.code !== 'ENOENT' || path.dirname(ancestor) === ancestor) throw cause; ancestor = path.dirname(ancestor); }
  }
  if (path.resolve(await realpath(ancestor)).toLowerCase() !== ancestor.toLowerCase()) throw Object.assign(new Error('Linked component directories are forbidden.'), { code: 'BROWSER_FINGERPRINT_PATH_UNSAFE', status: 409 });
  await mkdir(parent, { recursive: true });
  if (path.resolve(await realpath(parent)).toLowerCase() !== parent.toLowerCase()) throw Object.assign(new Error('Linked component directories are forbidden.'), { code: 'BROWSER_FINGERPRINT_PATH_UNSAFE', status: 409 });
  const scratch = await mkdtemp(path.join(parent, '.fingerprint-stage-'));
  const engine = path.join(scratch, 'engine');
  const totalBytes = receipt.files.reduce((sum, file) => sum + file.bytes, 0);
  try {
    await mkdir(engine);
    let receivedBytes = 0, reportedBytes = 0;
    progress('copying-bundle', 0, totalBytes);
    for (const file of receipt.files) {
      cancelled();
      if (typeof file.path !== 'string' || !file.path || file.path.includes('\\') || /[:\x00-\x1f\x7f]/.test(file.path)
        || file.path.startsWith('/') || file.path.split('/').some(part => !part || part === '.' || part === '..')) throw new Error('Unsafe bundled component path.');
      const destination = path.resolve(engine, file.path);
      if (!destination.toLowerCase().startsWith(engine.toLowerCase() + path.sep)) throw new Error('Unsafe bundled component path.');
      await mkdir(path.dirname(destination), { recursive: true });
      let fileBytes = 0;
      await pipeline(createReadStream(path.join(source, file.path)), new Transform({ transform(chunk, _encoding, next) {
        fileBytes += chunk.length; receivedBytes += chunk.length;
        if (receivedBytes - reportedBytes >= 1048576 || receivedBytes === totalBytes) { reportedBytes = receivedBytes; progress('copying-bundle', receivedBytes, totalBytes); }
        next(fileBytes > file.bytes ? new Error('Bundled component file exceeded its verified size.') : null, chunk);
      } }), createWriteStream(destination, { flags: 'wx' }), { signal });
      if (fileBytes !== file.bytes) throw new Error('Bundled component file size changed while copying.');
    }
    cancelled(); progress('verifying-engine', receivedBytes, totalBytes);
    if (fingerprintInventoryHash(receipt.files) !== pinnedRelease.inventorySha256) throw new Error('Bundled component inventory changed after inspection.');
    await writeFile(path.join(engine, FINGERPRINT_RECEIPT), JSON.stringify({ version: 1, engineVersion: pinnedRelease.version,
      architecture: pinnedRelease.architecture, archiveSha256: pinnedRelease.archiveSha256,
      ...(pinnedRelease.revision ? { componentRevision: pinnedRelease.revision } : {}), files: receipt.files }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    const copied = await inspectFingerprintRuntime(engine, { full: true, release: pinnedRelease });
    if (copied.state !== 'ready') throw Object.assign(new Error('Bundled component changed while copying.'), { code: copied.errorCode });
    await ensureReadPermissions(engine, signal);
    cancelled(); await rename(engine, target); progress('installed', receivedBytes, totalBytes);
    return { installed: true, source: 'bundle', ...copied, executable: path.join(target, pinnedRelease.executable) };
  } catch (cause) {
    const aborted = signal?.aborted || cause.name === 'AbortError';
    throw Object.assign(new Error(aborted ? '指纹浏览器组件准备已取消，原组件保持不变。' : '随包指纹浏览器组件准备失败，原组件保持不变。', { cause }), {
      code: aborted ? 'BROWSER_FINGERPRINT_INSTALL_CANCELLED' : 'BROWSER_FINGERPRINT_INSTALL_FAILED', status: 409,
    });
  } finally {
    const resolved = path.resolve(await realpath(scratch));
    if (path.dirname(resolved).toLowerCase() !== parent.toLowerCase() || !path.basename(resolved).startsWith('.fingerprint-stage-')) throw new Error('Temporary cleanup boundary changed; files were retained for inspection.');
    await rm(resolved, { recursive: true, force: true });
  }
}

export async function prepareFingerprintBrowser(target, { onProgress = () => {}, signal } = {}) {
  const progress = (status, receivedBytes = 0) => { try { onProgress({ status, receivedBytes, totalBytes: release.archiveBytes, version: release.version }); } catch {} };
  const cancelled = () => { if (signal?.aborted) throw Object.assign(new Error('指纹浏览器组件准备已取消。'), { code: 'BROWSER_FINGERPRINT_INSTALL_CANCELLED', status: 409 }); };
  cancelled(); progress('checking');
  if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('This pinned browser component requires Windows x64.');
  if (!path.isAbsolute(target) || /^[\\/]{2}/.test(target) || /[\x00-\x1f\x7f]/.test(target)) throw new Error('Use an absolute local component directory.');
  target = path.resolve(target);
  try {
    await lstat(target);
    const current = await inspectFingerprintRuntime(target, { full: true });
    if (current.state !== 'ready') throw Object.assign(new Error('指纹浏览器组件已有文件但未通过校验，原组件已保留，请检查后重试。'), { code: current.errorCode || 'BROWSER_FINGERPRINT_FILES_CHANGED', status: 409 });
    await ensureReadPermissions(target, signal);
    cancelled(); progress('already-ready');
    return { installed: false, ...current };
  } catch (cause) { if (cause.code !== 'ENOENT') throw cause; }
  cancelled();
  // The native source-built release is shipped as a fully verified component.
  // An older public binary or a network download cannot substitute for it.
  throw Object.assign(new Error('未找到已验证的指纹浏览器组件，请使用随附新内核的完整安装包或指定本地组件目录。Chrome 浏览器仍可正常使用。'), { code: 'BROWSER_FINGERPRINT_BUNDLE_REQUIRED', status: 409 });
}
