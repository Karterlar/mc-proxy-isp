import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { matchesAdminFileUrl } from '../admin-file-policy.mjs';

test('the exact packaged resource accepts both Chromium and Node spelling of a temporary 8.3 path', () => {
  const file = path.resolve('owned-tests/ADMINI~1/临时 app/resources/app.asar/frontend/admin-required.html');
  const encoded = pathToFileURL(file).href;
  assert.equal(matchesAdminFileUrl(encoded, file), true);
  assert.equal(matchesAdminFileUrl(encoded.replace(/%7E/gi, '~'), file), true);
});

test('normalization does not permit navigation, remote files or other resources', () => {
  const file = path.resolve('owned-tests/app.asar/frontend/admin-required.html');
  const url = pathToFileURL(file).href;
  for (const bad of [`${url}?config=1`, `${url}#bypass`, url.replace('admin-required.html', 'app.js'), url.replace('admin-required.html', '../private.json'),
    'https://localhost/admin-required.html', 'file://remote-host/share/admin-required.html', 'data:text/html,unsafe', 'chrome-error://chromewebdata/']) {
    assert.equal(matchesAdminFileUrl(bad, file), false, bad);
  }
  assert.equal(matchesAdminFileUrl(url, 'relative-file.html'), false);
});
