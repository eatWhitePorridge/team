// Pure request data tests: no DOM, React rendering, browser or UI tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createSplitTarget, splitPayload } from '../src/batchSplit.ts';

test('freezes the complete cross-page selection and deduplicates IDs', () => {
  const selected = [1, 50, 51, 150, 1];
  const target = createSplitTarget(selected);
  selected.splice(0, selected.length, 999);
  assert.deepEqual(target.ids, [1, 50, 51, 150]);
  assert.match(target.requestId, /^[a-f0-9]{12}4[a-f0-9]{3}[89ab][a-f0-9]{15}$/);
});

test('manual retry reuses the frozen request instead of creating another batch', () => {
  const target = createSplitTarget([7, 8]);
  const first = splitPayload(target);
  assert.deepEqual(splitPayload(target), first);
  first.account_ids.push(999);
  assert.deepEqual(splitPayload(target).account_ids, [7, 8]);
  assert.notEqual(createSplitTarget([7, 8]).requestId, target.requestId);
});

test('uses getRandomValues without depending on HTTPS-only randomUUID', () => {
  let calls = 0;
  const target = createSplitTarget([1], { getRandomValues(bytes) { calls++; return bytes.fill(0); } });
  assert.equal(calls, 1);
  assert.equal(target.requestId, '00000000000040008000000000000000');
  assert.deepEqual(splitPayload(target), { account_ids: [1], request_id: target.requestId, confirm: true });
});

test('rejects empty, oversized and invalid selections before generating a request', () => {
  for (const ids of [[], [0], [-1], [NaN], [1.5], [true], [Infinity], Array(5001).fill(1)]) {
    assert.throws(() => createSplitTarget(ids));
  }
  assert.equal(createSplitTarget(Array.from({ length: 5000 }, (_, i) => i + 1)).ids.length, 5000);
});
