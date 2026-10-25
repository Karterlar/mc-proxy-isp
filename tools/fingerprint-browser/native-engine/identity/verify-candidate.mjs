// Verify only a pinned, post-UG150 target-file fixture. No downloads, source
// mutation, browser launch, compilation, or runtime component activation.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { access, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
assert.equal(process.argv.length, 3, 'Pass the pinned, post-UG150 source-fixture root');
const source = path.resolve(process.argv[2]);
const manifest = JSON.parse(await readFile(path.join(here, 'candidate-inputs.json'), 'utf8'));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fixture = await mkdtemp(path.join(os.tmpdir(), 'mc-proxy-identity-apply-'));
const patch = path.join(here, '001-public-identity-150.patch');
const patchHash = hash(await readFile(patch));
const git = (...args) => execFileSync('git', ['-c', 'core.autocrlf=false', '-C', fixture, ...args], { encoding: 'utf8', stdio: 'pipe' });
const checks = [];
function check(name, passed) { assert(passed, name); checks.push({ name, passed: true }); }
for (const input of manifest.inputs) {
  const bytes = await readFile(path.join(source, input.path));
  check('Pinned baseline: ' + input.path, hash(bytes) === input.sha256);
  const target = path.join(fixture, input.path);
  await mkdir(path.dirname(target), { recursive: true }); await writeFile(target, bytes);
}
try { await access(path.join(source, 'components/ungoogled/fingerprint_data.h')); assert.fail('Input is already patched: fingerprint_data.h exists'); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
git('apply', '--check', patch); check('Forward patch application', true);
git('apply', patch);
const text = relative => readFile(path.join(fixture, relative), 'utf8');
const target = (data, type, name) => {
  const value = data.match(new RegExp(type + '\\("' + name + '"\\) \\{([\\s\\S]*?)\\n\\}'));
  assert(value, 'Exact GN target ' + name); return value[1];
};
const deps = value => { const match = value.match(/\n  deps = \[([\s\S]*?)\n  \]/); assert(match, 'Direct target dependency list'); return match[1]; };
const ug = '"//components/ungoogled:ungoogled_switches"';
check('UA producer links ungoogled switches directly', deps(target(await text('components/embedder_support/BUILD.gn'), 'static_library', 'user_agent')).includes(ug));
check('UA producer links the exported metadata implementation', deps(target(await text('components/embedder_support/BUILD.gn'), 'static_library', 'user_agent')).includes('"//third_party/blink/public/common"'));
check('Metadata implementation links ungoogled switches directly', deps(target(await text('third_party/blink/common/BUILD.gn'), 'source_set', 'common')).includes(ug));
const core = await text('third_party/blink/renderer/core/BUILD.gn');
check('Core navigator and Worker mixins link switches directly', deps(target(core, 'component', 'core')).includes(ug));
check('Hot DOM sources link switches directly', deps(target(core, 'blink_core_sources', 'core_hot')).includes(ug));
check('Platform normalization has its own declaring include', (await text('third_party/blink/renderer/core/execution_context/navigator_base.cc')).includes('#include "base/strings/string_util.h"'));
const header = await text('third_party/blink/public/common/user_agent/user_agent_metadata.h');
check('Metadata update is exported for Windows component builds', header.includes('void BLINK_COMMON_EXPORT UpdateUserAgentMetadataFingerprint('));
check('UA brand update is exported for Windows component builds', header.includes('std::string BLINK_COMMON_EXPORT GetUserAgentFingerprintBrandInfo();'));
const propagation = await text('content/browser/renderer_host/render_process_host_impl.cc');
for (const name of ['kFingerprint', 'kFingerprintBrand', 'kFingerprintBrandVersion', 'kDisableSpoofing', 'kFingerprintHardwareConcurrency', 'kFingerprintPlatform', 'kFingerprintPlatformVersion', 'kFingerprintTimezone'])
  check('Renderer and Worker process propagation: ' + name, propagation.includes('switches::' + name + ','));
const producer = await text('components/embedder_support/user_agent_utils.cc');
check('Initial browser metadata is fingerprinted before Worker inheritance', producer.includes('blink::UpdateUserAgentMetadataFingerprint(&metadata);'));
check('NavigatorUA uses the same update for window and Worker', (await text('third_party/blink/renderer/core/frame/navigator_ua.cc')).includes('UpdateUserAgentMetadataFingerprint(&metadata);'));
check('Hardware mixin preserves the explicit saved core count', (await text('third_party/blink/renderer/core/frame/navigator_concurrent_hardware.cc')).includes('return custom_concurrency;'));
const outputs = [];
for (const input of manifest.inputs) outputs.push({ path: input.path, sha256: hash(await readFile(path.join(fixture, input.path))) });
outputs.push({ path: 'components/ungoogled/fingerprint_data.h', sha256: hash(await readFile(path.join(fixture, 'components/ungoogled/fingerprint_data.h'))) });
git('apply', '--reverse', '--check', patch); check('Reverse patch application', true);
git('apply', '--reverse', patch);
for (const input of manifest.inputs) check('Exact baseline restored: ' + input.path, hash(await readFile(path.join(fixture, input.path))) === input.sha256);
const report = { schemaVersion: 1, at: new Date().toISOString(), status: 'source-candidate-not-built', chromium: manifest.chromium,
  patch: 'identity/001-public-identity-150.patch', patchSha256: patchHash, baselineManifestSha256: hash(await readFile(path.join(here, 'candidate-inputs.json'))),
  fixture, applyCheck: true, reverseCheck: true, checks, outputFiles: outputs, nativeCompiled: false, nativeRuntimeValidated: false };
await writeFile(path.join(here, 'candidate-status.json'), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ fixture, checks: checks.length, patchSha256: patchHash, nativeCompiled: false, nativeRuntimeValidated: false }));
