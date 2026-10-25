// An advisory channel only: remote release data can never select or install code.
export const FINGERPRINT_SECURITY_BASELINE = Object.freeze({
  version: '155.0.8059.85', reviewedAt: '2026-10-18T00:00:00.000Z',
  source: 'https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1',
});
const versionParts = value => typeof value === 'string' && /^\d{1,5}(?:\.\d{1,5}){3}$/.test(value) ? value.split('.').map(Number) : null;
const compare = (left, right) => { const a=versionParts(left),b=versionParts(right); if(!a||!b) return null; for(let i=0;i<4;i++)if(a[i]!==b[i])return Math.sign(a[i]-b[i]); return 0; };

export function createFingerprintSecurityCheck({ version, now = Date.now, fetchRelease = globalThis.fetch, mock = false } = {}) {
  let baseline = { ...FINGERPRINT_SECURITY_BASELINE }, checkedAt = null, checkError = null, pending = null, attemptedAt = null;
  const snapshot = () => {
    const order = compare(version, baseline.version), stale = now() - Date.parse(baseline.reviewedAt) > 14 * 86400000;
    return { status: mock ? 'mocked' : order === null ? 'unverified' : order < 0 ? 'outdated' : stale ? 'unverified' : 'meets-baseline',
      engineVersion: version, baselineVersion: baseline.version, baselineReviewedAt: baseline.reviewedAt,
      source: baseline.source, checkedAt, checking: Boolean(pending), stale, checkError,
      automaticDownload: false, affectsConnection: false };
  };
  async function check() {
    if (mock) return snapshot();
    if (pending) return pending;
    // Prevent repeated clicks from turning an optional check into a poll loop.
    if (attemptedAt !== null && now() - attemptedAt < 15 * 60000) return snapshot();
    attemptedAt = now();
    pending = (async () => {
      // Publish the in-flight promise before an injected/platform fetch can throw.
      await Promise.resolve();
      try {
        const response = await fetchRelease(FINGERPRINT_SECURITY_BASELINE.source, { signal: AbortSignal.timeout(5000), redirect: 'error', credentials: 'omit' });
        if (!response.ok || !response.body) throw new Error('RELEASE_CHECK_FAILED');
        const reader = response.body.getReader(); let size=0; const chunks=[];
        try { for (;;) { const {done,value}=await reader.read(); if(done)break; size+=value.byteLength; if(size>65536)throw new Error('RELEASE_RESPONSE_INVALID'); chunks.push(value); } }
        finally { await reader.cancel().catch(()=>{}); }
        const rows=JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if(!Array.isArray(rows)||rows.length!==1||rows[0].channel!=='Stable'||rows[0].platform!=='Windows'||!versionParts(rows[0].version)
          || !Number.isSafeInteger(rows[0].time) || rows[0].time < Date.UTC(2020,0,1) || rows[0].time > now()+86400000
          || compare(rows[0].version,baseline.version)<0) throw new Error('RELEASE_RESPONSE_INVALID');
        baseline={version:rows[0].version,reviewedAt:new Date(now()).toISOString(),source:FINGERPRINT_SECURITY_BASELINE.source};
        checkedAt=new Date(now()).toISOString();checkError=null;
      } catch { checkError='FINGERPRINT_SECURITY_CHECK_FAILED'; }
      finally { pending=null; }
      return snapshot();
    })();
    return pending;
  }
  return { snapshot, check };
}
