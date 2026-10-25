// Explicit local promotion of the accepted build. No build, download, packaging,
// profile migration or change to the candidate/build evidence occurs here.
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { readCandidateRuntime } from './candidate-runtime.mjs';
import { prepareFingerprintBrowserFromBundle } from '../../../backend/src/fingerprint-browser-install.mjs';
import { FINGERPRINT_BROWSER_RELEASE, FINGERPRINT_BROWSER_CACHE_DIRECTORY,
  fingerprintFileHash, requireFingerprintRuntime } from '../../../backend/src/fingerprint-browser-runtime.mjs';

const project = fileURLToPath(new URL('../../../', import.meta.url));
const acceptanceRoot = path.join(project, 'deliverables/verification/2026-10-18-fingerprint-full-fix');
const acceptanceSha256 = '1198bc3cbbfea58b2744038c76d884b160e91c2d81e18d74b1ff8f1810c14461';
const evidenceSha256 = 'b9d362348c6a3031e14ba71cbd9f68a82f5f9d155c47e8837aef9aa4c9a0e85d';

export async function promoteAcceptedRuntime() {
  const acceptanceFile = path.join(acceptanceRoot, 'native150-acceptance-summary.json');
  assert.equal(await fingerprintFileHash(acceptanceFile), acceptanceSha256, 'Reviewed acceptance record changed');
  const accepted = JSON.parse(await readFile(acceptanceFile, 'utf8'));
  assert.equal(accepted.status, 'accepted-as-independent-test-candidate');
  assert.equal(accepted.independentEvidenceAudit.sha256, evidenceSha256);
  assert.equal(await fingerprintFileHash(path.join(acceptanceRoot, 'final-native-evidence-audit.json')), evidenceSha256);
  const candidate = await readCandidateRuntime(path.join(project, '.cache/native-engine-build'));
  for (const key of ['version', 'architecture', 'platform', 'revision', 'archiveSha256', 'executable', 'executableSha256', 'inventorySha256']) {
    assert.equal(candidate.release[key], FINGERPRINT_BROWSER_RELEASE[key], `Accepted release pin mismatch: ${key}`);
  }
  for (const key of ['sourceManifestSha256', 'buildReceiptSha256']) {
    assert.equal(candidate[key], FINGERPRINT_BROWSER_RELEASE[key], `Build provenance mismatch: ${key}`);
    assert.equal(accepted[key], candidate[key], `Acceptance provenance mismatch: ${key}`);
  }
  // Only this explicit tool accepts the test-only input, after its complete
  // source/build/acceptance proof and compiled-in production pin agree. The
  // existing installer copies public resources and writes a new normal receipt.
  // Ordinary product startup cannot launch a candidate receipt or select a pin.
  const target = path.join(project, '.cache', FINGERPRINT_BROWSER_CACHE_DIRECTORY);
  const prepared = await prepareFingerprintBrowserFromBundle(candidate.root, target, { release: candidate.release });
  const runtime = await requireFingerprintRuntime(target);
  return { installed: prepared.installed, ...runtime, directory: target,
    sourceManifestSha256: candidate.sourceManifestSha256, buildReceiptSha256: candidate.buildReceiptSha256,
    acceptanceSha256, customerProfilesUsed: false, packaged: false };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    assert.deepEqual(process.argv.slice(2), ['--promote'], 'Use --promote to install the accepted local component');
    console.log(JSON.stringify(await promoteAcceptedRuntime(), null, 2));
  } catch (cause) { console.error(cause.code || cause.message); process.exitCode = 1; }
}
