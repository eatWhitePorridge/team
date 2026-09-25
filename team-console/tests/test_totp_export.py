import copy
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from backend.totp_export import export_accounts
from core import db
from core.password_totp_import import parse_accounts

SECRET = 'JBSWY3DPEHPK3PXP'


class TotpExportTests(unittest.TestCase):
    def export(self, rows, ids=None):
        source = SimpleNamespace(get_account_totp_export_candidates=Mock(return_value=rows))
        result = export_accounts(source, ids or list(rows))
        source.get_account_totp_export_candidates.assert_called_once()
        return result

    def row(self, **changes):
        return {'id': 1, 'email': 'one@example.invalid', 'registration_password': 'Fixture-Password!',
                'totp_secret': SECRET, 'totp_status': 'active', **changes}

    def test_password_spaces_and_delimiters_round_trip_without_modification(self):
        for password in (' -leading----middle-tail- ', '----', '密碼%#-value'):
            with self.subTest(password_length=len(password)):
                result = self.export({1: self.row(registration_password=password, totp_secret=SECRET.lower())})
                imported = parse_accounts(result['data'])
                self.assertEqual(imported[0]['registration_password'], password)
                self.assertEqual(imported[0]['totp_secret'], SECRET)
                self.assertEqual(result['warnings'], [])

    def test_unverified_imports_export_with_warning_not_false_verification(self):
        row = self.row(totp_status='activation_uncertain'); before = copy.deepcopy(row)
        result = self.export({1: row})
        self.assertEqual(result['exported_count'], 1)
        self.assertEqual(len(result['warnings']), 1)
        self.assertIn('尚未验证', result['warnings'][0]['error'])
        self.assertEqual(row, before)

    def test_missing_invalid_busy_or_archived_rows_are_reported_without_secrets(self):
        rows = {1: self.row(registration_password=''),
                2: self.row(totp_secret='not-valid-private-secret'),
                3: self.row(totp_status='running'),
                4: self.row(archived=True),
                5: self.row(email='invalid-email-with-private-content'),
                6: self.row(totp_status='active_external', totp_secret='')}
        result = self.export(rows, [*rows, 999])
        self.assertFalse(result['ok']); self.assertEqual(result['data'], '')
        self.assertEqual(result['failed_count'], 7)
        self.assertEqual(result['exported_count'], 0)
        for private in (SECRET, 'Fixture-Password!', 'not-valid-private-secret', 'invalid-email-with-private-content'):
            self.assertNotIn(private, json.dumps(result))

    def test_control_characters_cannot_inject_export_lines(self):
        for separator in ('\r', '\n', '\v', '\f', '\x1c', '\x85', '\u2028', '\u2029', '\x00'):
            with self.subTest(separator=repr(separator)):
                result = self.export({1: self.row(registration_password='private' + separator + 'injected')})
                self.assertFalse(result['ok']); self.assertNotIn('private', json.dumps(result))

    def test_partial_export_preserves_selection_order_and_excludes_tokens(self):
        rows = {1: self.row(access_token='PRIVATE_AT', codex_refresh_token='PRIVATE_RT'),
                2: self.row(email='two@example.invalid'), 3: self.row(registration_password='')}
        result = self.export(rows, [2, 3, 1])
        self.assertEqual((result['exported_count'], result['failed_count']), (2, 1))
        self.assertTrue(result['data'].startswith('two@example.invalid----'))
        self.assertNotIn('PRIVATE_AT', json.dumps(result)); self.assertNotIn('PRIVATE_RT', json.dumps(result))

    def test_db_snapshot_scans_once_and_never_uses_mailbox_password_or_tokens(self):
        rows = [self.row(extra_json=json.dumps({'registration_password': '  -exact----password- ', 'token': 'PRIVATE_EXTRA'}),
                         password='MAILBOX_PASSWORD', access_token='PRIVATE_AT'),
                self.row(id=2, registration_password='fallback-password', extra_json='invalid-json'),
                self.row(id=3, registration_password='', password='MAILBOX_PASSWORD'),
                self.row(id=4, extra_json={'registration_password': 'dict-password'}),
                self.row(id=99)]
        before = copy.deepcopy(rows)
        with patch.object(db, '_load_accounts', return_value=rows) as load, \
             patch.object(db, '_save_accounts', side_effect=AssertionError('export wrote accounts')), \
             patch.object(db, 'get_account', side_effect=AssertionError('N per-account reads')):
            result = db.get_account_totp_export_candidates([1, 2, 3, 4])
            load.assert_called_once()
            self.assertEqual(db.get_account_totp_export_candidates([]), {})
            load.assert_called_once()
        self.assertEqual(result[1]['registration_password'], '  -exact----password- ')
        self.assertEqual(result[2]['registration_password'], 'fallback-password')
        self.assertEqual(result[3]['registration_password'], '')
        self.assertEqual(result[4]['registration_password'], 'dict-password')
        self.assertEqual(rows, before)
        for private in ('PRIVATE_EXTRA', 'MAILBOX_PASSWORD', 'PRIVATE_AT', 'extra_json'):
            self.assertNotIn(private, json.dumps(result))
        self.assertNotIn(99, result)
