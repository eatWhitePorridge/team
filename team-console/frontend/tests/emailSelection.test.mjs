// Pure selection/text tests: no DOM, clipboard, React rendering or UI tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { selectAccountEmails, selectedEmailText } from '../src/emailSelection.ts';

test('single copy contains the full email only, never credentials or a display ellipsis', () => {
  const email = 'long.account+test@example.com';
  const selected = selectAccountEmails('all', [1], [{ id: 1, email, password: 'private', totp_secret: 'private', access_token: 'private' }]);
  assert.deepEqual(selected, { scope: 'all', keys: [1], emails: { 1: email } });
  assert.deepEqual(selectedEmailText(selected), { text: email, count: 1 });
});

test('retains cross-page picks and formats one address per line in selection order', () => {
  const first = selectAccountEmails('all', [50, 1], [{ id: 1, email: 'first@example.com' }, { id: 50, email: 'last@example.com' }]);
  const next = selectAccountEmails('all', [50, 1, 51], [{ id: 51, email: 'next@example.com' }], first);
  assert.deepEqual(selectedEmailText(next), { text: 'last@example.com\nfirst@example.com\nnext@example.com', count: 3 });
  assert.deepEqual(first.keys, [50, 1]);
});

test('unselecting prunes cached emails without losing other pages', () => {
  const first = selectAccountEmails('all', [1, 2], [{ id: 1, email: 'a@example.com' }, { id: 2, email: 'b@example.com' }]);
  const next = selectAccountEmails('all', [2, 3], [{ id: 3, email: 'c@example.com' }], first);
  assert.deepEqual(next.emails, { 2: 'b@example.com', 3: 'c@example.com' });
  assert.deepEqual(selectAccountEmails('all', [], [], next), { scope: 'all', keys: [], emails: {} });
});

test('changing filters cannot reuse the previous scope or silently copy a partial list', () => {
  const first = selectAccountEmails('batch-a', [1], [{ id: 1, email: 'a@example.com' }]);
  const next = selectAccountEmails('batch-b', [1, 2], [{ id: 2, email: 'b@example.com' }], first);
  assert.deepEqual(next.emails, { 2: 'b@example.com' });
  assert.throws(() => selectedEmailText(next), /邮箱不完整/);
});

test('current-page data refreshes cached emails and input mutations do not change selection', () => {
  const ids = [1];
  const rows = [{ id: 1, email: 'old@example.com' }];
  const first = selectAccountEmails('all', ids, rows);
  ids.push(2); rows[0].email = 'changed@example.com';
  assert.equal(selectedEmailText(first).text, 'old@example.com');
  const next = selectAccountEmails('all', [1], rows, first);
  assert.equal(selectedEmailText(next).text, 'changed@example.com');
});

test('deduplicates IDs and email addresses without normalizing Gmail aliases', () => {
  const selected = selectAccountEmails('all', [1, 1, 2, 3], [
    { id: 1, email: ' Mail.Name@gmail.com ' }, { id: 2, email: 'mail.name@gmail.com' }, { id: 3, email: 'mailname@gmail.com' },
  ]);
  assert.deepEqual(selected.keys, [1, 2, 3]);
  assert.deepEqual(selectedEmailText(selected), { text: 'Mail.Name@gmail.com\nmailname@gmail.com', count: 2 });
});

test('rejects empty/invalid/missing rows and embedded line breaks instead of copying partial data', () => {
  assert.throws(() => selectedEmailText(selectAccountEmails('all', [], [])));
  for (const ids of [[0], [-1], [NaN], [1.5], [true]]) assert.throws(() => selectAccountEmails('all', ids, []));
  for (const email of [undefined, '', 'not-an-email', 'a@example.com\nb@example.com', 'a@example.com\r\npassword']) {
    assert.throws(() => selectedEmailText(selectAccountEmails('all', [1], [{ id: 1, email }])));
  }
});

test('large cross-page selections are not restricted to the visible page or 200 rows', () => {
  const rows = Array.from({ length: 1200 }, (_, index) => ({ id: index + 1, email: `account${index + 1}@example.com` }));
  let selected = selectAccountEmails('all', [], []);
  for (let end = 100; end <= rows.length; end += 100) {
    selected = selectAccountEmails('all', rows.slice(0, end).map(row => row.id), rows.slice(end - 100, end), selected);
  }
  const result = selectedEmailText(selected);
  assert.equal(result.count, 1200);
  assert.equal(result.text.split('\n').length, 1200);
});
