import { constants, openSync, fstatSync, writeFileSync, fsyncSync, closeSync, lstatSync, unlinkSync } from 'node:fs';
import { lstat, open } from 'node:fs/promises';
import { dirname, resolve, parse, join, sep } from 'node:path';
import { LicenseError } from '../../backend/src/license-format.mjs';

const unsafe = () => { throw new LicenseError('UNSAFE_FILE', 'Licensing files must be ordinary private files without links'); };
export async function safeDirectory(path) {
  const absolute = resolve(path);
  try {
    let current = parse(absolute).root;
    for (const segment of absolute.slice(current.length).split(sep).filter(Boolean)) {
      current = join(current, segment);
      const stat = await lstat(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) unsafe();
    }
    return absolute;
  } catch { unsafe(); }
}
export async function checkSafeFile(path, maxBytes) {
  const absolute = resolve(path);
  await safeDirectory(dirname(absolute));
  try {
    const stat = await lstat(absolute);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > maxBytes) unsafe();
    return { absolute, stat };
  } catch { unsafe(); }
}
export async function readSafeText(path, maxBytes) {
  const { absolute, stat } = await checkSafeFile(path, maxBytes);
  let file;
  try {
    file = await open(absolute, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const opened = await file.stat();
    if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== stat.dev || opened.ino !== stat.ino || opened.size > maxBytes) unsafe();
    const bytes = Buffer.alloc(maxBytes + 1); let length = 0;
    while (length < bytes.length) {
      const { bytesRead } = await file.read(bytes, length, bytes.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length > maxBytes) unsafe();
    return bytes.subarray(0, length).toString('utf8');
  } catch { unsafe(); }
  finally { await file?.close(); }
}
export async function checkNewOutput(path) {
  await safeDirectory(dirname(resolve(path)));
  try { await lstat(resolve(path)); } catch (error) { if (error.code === 'ENOENT') return; unsafe(); }
  throw new LicenseError('OUTPUT_EXISTS', 'Output already exists; choose a new output file');
}
export async function reserveSafeOutput(path) {
  const absolute = resolve(path);
  await checkNewOutput(absolute);
  const fd = openSync(absolute, 'wx', 0o600), original = fstatSync(fd);
  let closed = false;
  return {
    write(content) { writeFileSync(fd, content, 'utf8'); fsyncSync(fd); },
    close() { if (!closed) { closeSync(fd); closed = true; } },
    cancel() {
      this.close();
      try { const current = lstatSync(absolute); if (current.isFile() && !current.isSymbolicLink() && current.dev === original.dev && current.ino === original.ino) unlinkSync(absolute); } catch {}
    }
  };
}
