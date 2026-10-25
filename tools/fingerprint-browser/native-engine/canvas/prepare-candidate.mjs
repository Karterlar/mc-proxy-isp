// Generate/apply-check the current native Canvas patch against four pinned
// public 150 files. This operation is not a native build or runtime acceptance.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
const roots = process.argv.slice(2).map(value => path.resolve(value));
assert(roots.length, 'Pass a public Chromium 150 source root or downloaded source-fixture directories');
const inputs = [
  { path: 'third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc', sha256: '7694bc7cb254d21629818f792fe77d38de324fffd1a334380e632e9295e7d2c9' },
  { path: 'third_party/blink/renderer/core/html/canvas/html_canvas_element.cc', sha256: '4de69265e479e56cd8f1ce8794371484272a908ea55b55f76426460463fa54d6' },
  { path: 'third_party/blink/renderer/core/html/canvas/canvas_async_blob_creator.cc', sha256: 'e2a511dc9a206c6afe3d030762cc3b05084f709825e40cfd0da3c61486b6f5af' },
  { path: 'third_party/blink/renderer/platform/BUILD.gn', sha256: '0ad367d52bd9e66a6f4ef2958526be0133721e728ec26f449da483f9c7042638' },
];
const additions = [
  ['canvas_noise.h', 'third_party/blink/renderer/platform/graphics/mc_canvas_noise.h'],
  ['mc_canvas_fingerprint.h', 'third_party/blink/renderer/platform/graphics/mc_canvas_fingerprint.h'],
  ['mc_canvas_fingerprint.cc', 'third_party/blink/renderer/platform/graphics/mc_canvas_fingerprint.cc'],
  ['mc_canvas_fingerprint_test.cc', 'third_party/blink/renderer/platform/graphics/mc_canvas_fingerprint_test.cc'],
];
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fixture = await mkdtemp(path.join(os.tmpdir(), 'mc-proxy-public-canvas-150-'));
const clean = await mkdtemp(path.join(os.tmpdir(), 'mc-proxy-public-canvas-apply-'));
const git = (...args) => execFileSync('git', ['-c', 'core.autocrlf=false', '-C', fixture, ...args], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
const write = async (root, relative, bytes) => { const file = path.join(root, relative); await mkdir(path.dirname(file), { recursive: true }); await writeFile(file, bytes); };
for (const input of inputs) {
  const candidates = roots.flatMap(root => [path.join(root, input.path), path.join(root, path.basename(input.path))]);
  let source;
  for (const candidate of candidates) { try { await access(candidate); source = candidate; break; } catch (error) { if (error.code !== 'ENOENT') throw error; } }
  assert(source, 'Missing public source fixture ' + input.path);
  const bytes = await readFile(source); assert.equal(hash(bytes), input.sha256, 'Pinned public source: ' + input.path);
  input.url = 'https://raw.githubusercontent.com/chromium/chromium/150.0.7871.186/' + input.path;
  await write(fixture, input.path, bytes); await write(clean, input.path, bytes);
}
git('init', '--quiet'); git('add', '.');
async function replace(relative, before, after) {
  const file = path.join(fixture, relative), original = await readFile(file, 'utf8');
  assert.equal(original.split(before).length, 2, 'Unique pinned hook: ' + relative);
  await writeFile(file, original.replace(before, after));
}
const include = '#include "third_party/blink/renderer/platform/graphics/mc_canvas_fingerprint.h"\n';
for (const input of inputs.slice(0, 3)) {
  const file = path.join(fixture, input.path), source = await readFile(file, 'utf8'), first = source.indexOf('\n', source.indexOf('#include '));
  assert(first > 0); await writeFile(file, source.slice(0, first + 1) + '\n' + include + source.slice(first + 1));
}
await replace(inputs[0].path,
  '  }\n\n  return image_data;\n}\n\nvoid BaseRenderingContext2D::putImageData(',
  '  }\n\n  // Only the fresh returned buffer is modified; source resources remain exact.\n' +
  '  const uint32_t fingerprint_seed = CanvasFingerprintSeed();\n' +
  '  if (fingerprint_seed &&\n' +
  '      !ProtectCanvasOwnedPixmap(image_data->GetSkPixmap(), sx, sy,\n' +
  '                                fingerprint_seed)) {\n' +
  '    exception_state.ThrowRangeError("Unable to allocate protected Canvas readback");\n' +
  '    return nullptr;\n' +
  '  }\n\n  return image_data;\n}\n\nvoid BaseRenderingContext2D::putImageData(');
await replace(inputs[1].path,
  '  scoped_refptr<StaticBitmapImage> image_bitmap = Snapshot(source_buffer);\n',
  '  scoped_refptr<StaticBitmapImage> image_bitmap = Snapshot(source_buffer);\n' +
  '  image_bitmap = MakeCanvasFingerprintCopy(std::move(image_bitmap),\n' +
  '                                          CanvasFingerprintSeed());\n');
await replace(inputs[2].path,
  '  image_ = image->MakeUnaccelerated();\n',
  '  image_ = image->MakeUnaccelerated();\n' +
  '  // This constructor serves both Window idle and Worker encoders. Keep a\n' +
  '  // private snapshot alive across async work; never alter borrowed src_data_.\n' +
  '  image_ = MakeCanvasFingerprintCopy(std::move(image_),\n' +
  '                                    CanvasFingerprintSeed());\n');
await replace(inputs[3].path,
  '    "graphics/image_data_buffer.h",\n',
  '    "graphics/image_data_buffer.h",\n' +
  '    "graphics/mc_canvas_fingerprint.cc",\n' +
  '    "graphics/mc_canvas_fingerprint.h",\n' +
  '    "graphics/mc_canvas_noise.h",\n');
await replace(inputs[3].path,
  '    "graphics/static_bitmap_image_transform_test.cc",\n',
  '    "graphics/mc_canvas_fingerprint_test.cc",\n' +
  '    "graphics/static_bitmap_image_transform_test.cc",\n');
for (const [name, relative] of additions) await write(fixture, relative, await readFile(path.join(here, name)));
git('add', '-N', ...additions.map(([, relative]) => relative));
const patch = git('diff', '--no-ext-diff', '--binary');
assert(patch.includes('MakeCanvasFingerprintCopy') && !patch.includes('ShuffleSubchannel'), 'Self-contained candidate');
const patchFile = path.join(here, '0002-canvas-owned-native-150.patch');
await writeFile(patchFile, patch);
// Isolate apply from an unrelated ancestor repository (e.g. a user-home repo).
// Otherwise Git may report success while skipping every patch outside cwd.
execFileSync('git', ['-c', 'core.autocrlf=false', '-C', clean, 'init', '--quiet'], { stdio: 'pipe' });
execFileSync('git', ['-c', 'core.autocrlf=false', '-C', clean, 'apply', '--check', patchFile], { stdio: 'pipe' });
execFileSync('git', ['-c', 'core.autocrlf=false', '-C', clean, 'apply', patchFile], { stdio: 'pipe' });
for (const relative of [...inputs.map(item => item.path), ...additions.map(([, name]) => name)])
  assert.equal(hash(await readFile(path.join(clean, relative))),
               hash(await readFile(path.join(fixture, relative))), 'Applied bytes: ' + relative);
const status = {
  status: 'source-fix-pending-native-build', chromium: '150.0.7871.186',
  patch: path.basename(patchFile), patchSha256: hash(patch), inputs,
  applyCheck: true, appliedFixture: clean, preparedFixture: fixture,
  standaloneCppCompiled: false, blinkCompiled: false, nativeBrowserVerified: false,
  protection: { sdr: 'owned canonical RGBA8888 unpremul; content-dependent idempotent full low-bit projection, independent of position for readback/crop/encoding parity and translation-majority resistance',
    float: 'normalized F16/F32 share observable 8-bit projection and retain residual precision; finite out-of-range HDR uses mantissa projection; alpha/special values/color metadata preserved',
    floatEncodedExport: 'requires new native quantization and browser matrix acceptance; lossy encoding and arbitrary color conversion are not guaranteed' },
};
await writeFile(path.join(here, 'candidate-status.json'), JSON.stringify(status, null, 2) + '\n');
console.log(JSON.stringify(status, null, 2));
