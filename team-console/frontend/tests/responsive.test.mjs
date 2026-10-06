import assert from 'node:assert/strict';
import test from 'node:test';
import { MOBILE_QUERY, pageNumber, pageRows, pageSelection, selectPage, toggleSelection } from '../src/responsive.ts';

test('mobile threshold matches the stylesheet without changing tablet/desktop scope', () => {
  assert.equal(MOBILE_QUERY, '(max-width: 767px)');
});
test('selecting or deselecting one record retains cross-page picks and does not mutate input', () => {
  const keys = [1, 55];
  assert.deepEqual(toggleSelection(keys, 2, true), [1, 55, 2]);
  assert.deepEqual(toggleSelection(keys, 1, false), [55]);
  assert.deepEqual(toggleSelection(keys, 55, true), keys);
  assert.deepEqual(keys, [1, 55]);
});
test('page selection preserves other pages and typed identifiers without duplicates', () => {
  assert.deepEqual(selectPage([101, '1'], [1, 2, 2], true), [101, '1', 1, 2]);
  assert.deepEqual(selectPage([1, 2, 101], [1, 2], false), [101]);
  assert.deepEqual(selectPage(['batch-a'], ['batch-b'], true), ['batch-a', 'batch-b']);
  assert.deepEqual(selectPage([101], [], false), [101]);
});
test('empty, partial and complete page selection states only consider current page', () => {
  assert.deepEqual(pageSelection([101], []), { checked: false, indeterminate: false });
  assert.deepEqual(pageSelection([1, 101], [1, 2]), { checked: false, indeterminate: true });
  assert.deepEqual(pageSelection([1, 2, 101], [1, 2]), { checked: true, indeterminate: false });
});
test('filtered or shrinking task lists clamp paging without discarding or altering rows', () => {
  const rows = Array.from({ length: 41 }, (_, i) => i + 1);
  assert.deepEqual(pageRows(rows, 2, 20), { page: 2, items: rows.slice(20, 40) });
  assert.deepEqual(pageRows(rows, 9, 20), { page: 3, items: [41] });
  assert.deepEqual(pageRows([], 9, 20), { page: 1, items: [] });
  assert.equal(pageNumber(-1, 41, 20), 1);
  assert.equal(rows.length, 41);
});
