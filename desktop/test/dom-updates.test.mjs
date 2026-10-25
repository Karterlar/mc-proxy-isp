import test from 'node:test';
import assert from 'node:assert/strict';
import { setText, setHtml } from '../../frontend/dom-updates.js';

test('identical text preserves the current node; changed or cleared text is applied', () => {
  let writes = 0, content = 'Ready';
  const node = { get textContent() { return content; }, set textContent(value) { content = value; writes++; } };
  assert.equal(setText(node, 'Ready'), false);
  assert.equal(writes, 0);
  assert.equal(setText(node, 3), true);
  assert.equal(content, '3');
  assert.equal(setText(node, '3'), false);
  assert.equal(setText(node, null), true);
  assert.equal(content, '');
  assert.equal(writes, 2);
});

test('unchanged HTML templates preserve hydrated icons, focus and child identities', () => {
  const node = {};
  const template = '<button><i data-lucide="arrow-left"></i>Back</button>';
  assert.equal(setHtml(node, template), true);
  node.innerHTML = '<button><svg aria-hidden="true"></svg>Back</button>';
  assert.equal(setHtml(node, template), false);
  assert.match(node.innerHTML, /<svg/);
  assert.equal(setHtml(node, '<button>Next</button>'), true);
  assert.equal(node.innerHTML, '<button>Next</button>');
  assert.equal(setHtml(node, ''), true);
  assert.equal(setHtml(node, ''), false);
});
