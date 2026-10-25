import test from 'node:test';
import assert from 'node:assert/strict';
import { DISTRIBUTION } from '../distribution.mjs';

test('source checkout has a fixed immutable developer distribution without licensing resources', () => {
  assert.deepEqual(DISTRIBUTION, { edition: 'developer', licenseConfig: { version: 1, mode: 'development' } });
  assert(Object.isFrozen(DISTRIBUTION)); assert(Object.isFrozen(DISTRIBUTION.licenseConfig));
  assert.throws(() => { DISTRIBUTION.edition = 'licensed'; }, TypeError);
  assert.throws(() => { DISTRIBUTION.licenseConfig.mode = 'required'; }, TypeError);
});
