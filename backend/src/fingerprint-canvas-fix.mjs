import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, open, realpath, rename, rm } from 'node:fs/promises';

// Local, controlled correction for the pinned Windows x64 Chromium 150 DLL;
// this is not an upstream release or a general-purpose binary patch interface.
// The next-row pixel pointer must use the row-stride address already calculated
// in RDX, rather than add the row index to the image base address again.
// The published Chromium 150 crash analysis identifies this exact Windows
// offset/instruction and the missing y * rowBytes scaling:
// https://github.com/adryfish/fingerprint-chromium/issues/94#issuecomment-6106290683
// Public source references for the older pixel path and Brave's bounded output
// readback implementation (immutable source revision):
// https://github.com/adryfish/fingerprint-chromium/blob/144.0.7559.132/patches/extra/fingerprint/012-canvas-get-image-data.patch
// https://github.com/brave/brave-core/blob/a41bf5350b94a69e457f82f9fa33f50a89aefa89/chromium_src/third_party/blink/renderer/core/html/canvas/html_canvas_element.cc
// Chromium 150's machine-code correction is independently pinned below; the
// older public source is context, not a claim that its bytes match version 150.
export const FINGERPRINT_CANVAS_FIX = Object.freeze({
  revision: 'canvas-win-x64-150-r1',
  file: 'chrome.dll',
  bytes: 315028992,
  originalSha256: '6464a50a8f8eae824f85733b52bc42912405390ac7dcb2a7fda7228ea51cbbac',
  fixedSha256: '2a2ca874e7944c9496888b07d56c8dd1ed76bf0a2b87c005874fe0a2729bbeed',
  offset: 0xc392046,
  originalInstruction: '4901c0',
  fixedInstruction: '4989d0',
  contextBytes: 32,
  originalWindow: '488b4d104889ca490fafd0488b45084801c2488995800100004c8985c80000004901c0498d0408488985c00000004c0345184c8985b8000000488b4550488985780100',
});
const fix = FINGERPRINT_CANVAS_FIX;
const originalWindow = Buffer.from(fix.originalWindow, 'hex');
const fixedWindow = Buffer.from(originalWindow);
Buffer.from(fix.fixedInstruction, 'hex').copy(fixedWindow, fix.contextBytes);
const fail = cause => Object.assign(new Error('指纹浏览器 Canvas 修复未通过固定组件校验，原组件保持不变。', { cause }), { code: 'BROWSER_FINGERPRINT_CANVAS_FIX_INVALID', status: 409 });
const cancelled = signal => {
  if (signal?.aborted) throw Object.assign(new Error('指纹浏览器组件准备已取消，原组件保持不变。'), { code: 'BROWSER_FINGERPRINT_INSTALL_CANCELLED', status: 409 });
};
const normalized = value => path.resolve(value).replace(/[\\/]+$/, '').toLowerCase();

// Fixed 67-byte instruction window only, so unit checks do not need to clone a
// 315 MB DLL. This cannot authorize a file: the installer API checks full hashes.
export function correctFingerprintCanvasWindow(window) {
  if (!Buffer.isBuffer(window) || window.length !== originalWindow.length
    || !window.equals(originalWindow) && !window.equals(fixedWindow)) throw fail();
  return Buffer.from(fixedWindow);
}

async function ordinary(file, directory = false) {
  let cursor = path.parse(file).root;
  for (const segment of file.slice(cursor.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, segment);
    const stat = await lstat(cursor);
    if (stat.isSymbolicLink() || normalized(await realpath(cursor)) !== normalized(cursor)) throw fail();
  }
  const stat = await lstat(file);
  if (directory ? !stat.isDirectory() : !stat.isFile() || stat.nlink !== 1) throw fail();
  return stat;
}
const sameFile = (left, right) => left.dev === right.dev && left.ino === right.ino && left.size === right.size
  && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs && right.nlink === 1;
async function hashFile(handle, signal) {
  const hash = createHash('sha256'), buffer = Buffer.allocUnsafe(1024 * 1024);
  for (let offset = 0; ; ) {
    cancelled(signal);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, offset);
    if (!bytesRead) break;
    hash.update(buffer.subarray(0, bytesRead)); offset += bytesRead;
  }
  cancelled(signal);
  return hash.digest('hex');
}

// Only the installer's unpublished .fingerprint-stage-* descendants are legal.
// Installed runtimes, customer profiles and arbitrary user-selected DLLs are
// deliberately outside this API's write boundary.
export async function applyFingerprintCanvasFix(engine, { signal } = {}) {
  cancelled(signal);
  let source, temporaryHandle, temporary;
  try {
    if (typeof engine !== 'string' || !path.isAbsolute(engine) || /^[\\/]{2}/.test(engine)
      || /[\x00-\x1f\x7f]/.test(engine) || engine.slice(2).includes(':')) throw fail();
    engine = path.resolve(engine);
    let ancestor = path.dirname(engine), staging = false;
    while (path.dirname(ancestor) !== ancestor) {
      if (/^\.fingerprint-stage-[A-Za-z0-9_-]{6,64}$/.test(path.basename(ancestor))) { staging = true; break; }
      ancestor = path.dirname(ancestor);
    }
    if (!staging) throw fail();
    await ordinary(engine, true);
    const file = path.join(engine, fix.file), before = await ordinary(file);
    if (before.size !== fix.bytes) throw fail();
    source = await open(file, 'r');
    if (!sameFile(before, await source.stat())) throw fail();
    const digest = await hashFile(source, signal);
    if (digest !== fix.originalSha256 && digest !== fix.fixedSha256) throw fail();
    const window = Buffer.alloc(originalWindow.length);
    if ((await source.read(window, 0, window.length, fix.offset - fix.contextBytes)).bytesRead !== window.length) throw fail();
    correctFingerprintCanvasWindow(window);
    if (!window.equals(digest === fix.originalSha256 ? originalWindow : fixedWindow)) throw fail();
    if (!sameFile(before, await ordinary(file)) || !sameFile(before, await source.stat())) throw fail();
    cancelled(signal);
    if (digest === fix.fixedSha256) return { applied: false, revision: fix.revision, sha256: fix.fixedSha256 };

    temporary = path.join(engine, `.chrome-canvas-fix-${randomUUID()}.tmp`);
    temporaryHandle = await open(temporary, 'wx+', 0o600);
    const buffer = Buffer.allocUnsafe(1024 * 1024), instruction = Buffer.from(fix.fixedInstruction, 'hex');
    for (let offset = 0; offset < fix.bytes; ) {
      cancelled(signal);
      const { bytesRead } = await source.read(buffer, 0, Math.min(buffer.length, fix.bytes - offset), offset);
      if (!bytesRead) throw fail();
      for (let i = 0; i < instruction.length; i++) {
        const index = fix.offset + i - offset;
        if (index >= 0 && index < bytesRead) buffer[index] = instruction[i];
      }
      for (let written = 0; written < bytesRead; ) {
        cancelled(signal);
        const result = await temporaryHandle.write(buffer, written, bytesRead - written, offset + written);
        if (!result.bytesWritten) throw fail();
        written += result.bytesWritten;
      }
      offset += bytesRead;
    }
    await temporaryHandle.sync();
    const temporaryStat = await temporaryHandle.stat();
    if (temporaryStat.size !== fix.bytes || await hashFile(temporaryHandle, signal) !== fix.fixedSha256
      || await hashFile(source, signal) !== fix.originalSha256 || !sameFile(before, await source.stat())
      || !sameFile(before, await ordinary(file))) throw fail();
    if (!sameFile(temporaryStat, await ordinary(temporary))) throw fail();
    await temporaryHandle.close(); temporaryHandle = null;
    await source.close(); source = null;
    cancelled(signal);
    await ordinary(engine, true);
    if (!sameFile(before, await ordinary(file)) || !sameFile(temporaryStat, await ordinary(temporary))) throw fail();
    cancelled(signal);
    await rename(temporary, file); temporary = null;
    return { applied: true, revision: fix.revision, sha256: fix.fixedSha256 };
  } catch (cause) {
    if (cause.code === 'BROWSER_FINGERPRINT_INSTALL_CANCELLED' || cause.code === 'BROWSER_FINGERPRINT_CANVAS_FIX_INVALID') throw cause;
    throw fail(cause);
  } finally {
    await temporaryHandle?.close().catch(() => {});
    await source?.close().catch(() => {});
    if (temporary) await rm(temporary, { force: true }).catch(() => {});
  }
}
