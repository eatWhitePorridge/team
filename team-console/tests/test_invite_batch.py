"""Invitation request batch boundaries; fake transport and no remote writes."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class InvitationBatchTests(unittest.TestCase):
    def test_hundred_recipients_per_post_without_readback_or_duplicates(self):
        root = Path(__file__).resolve().parents[2]
        script = r'''
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch
sys.path.insert(0, sys.argv[1])
from core import team_admin_service as s
assert s._INVITE_BATCH_SIZE == 100
assert s._INVITE_PAGE_SIZE == 100  # GET page size and POST batch size remain separate controls.
with patch('requests.sessions.Session.request', side_effect=AssertionError('network forbidden')), \
     patch('curl_cffi.requests.Session.request', side_effect=AssertionError('network forbidden')), \
     patch.object(s, '_sync_invites', return_value=[]) as before, \
     patch.object(s, '_check_cancel'), patch.object(s.store, 'mark_invites_stale'), \
     patch.object(s.store, 'upsert_invites'), patch.object(s.store, 'update_job'):
    for count, lengths in ((1,[1]), (25,[25]), (99,[99]), (100,[100]), (101,[100,1]), (200,[100,100])):
        calls=[]
        def request(method, path, *, timeout, body):
            assert method == 'POST' and path.endswith('/invites')
            assert 1 <= len(body['email_addresses']) <= 100 and timeout == 60
            assert body['flow_id'] == 'fixture-flow' and body['submission_id'] == 'fixture-submission'
            calls.append(list(body['email_addresses']))
            return {'account_invites': [{'id':'invite-'+email.split('@')[0], 'email_address':email,
                    'role':'standard-user', 'seat_type':'prolite', 'status':2} for email in body['email_addresses']],
                    'errored_emails':[]}
        client=SimpleNamespace(parent={'id':1}, workspace_id='fixture-workspace', request=request,
                               token='FIXTURE', material={})
        emails=[f'new-{i}@example.invalid' for i in range(count)]
        job={'id':'fixture-job','email_addresses':emails,'total':count,'seat_type':'prolite',
             'resend_emails':False,'flow_id':'fixture-flow','submission_id':'fixture-submission'}
        results=[]
        before.reset_mock()
        s._run_invitations(client,job,results,[])
        assert [len(call) for call in calls] == lengths
        assert [email for call in calls for email in call] == emails
        assert len(results)==count and all(row['status']=='success' for row in results)
        before.assert_called_once_with(client)  # No post-submit verification GET.
print('100-recipient invitation boundaries passed; no remote writes')
'''
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, 'PYTHON_DOTENV_DISABLED': '1', 'PYTHONDONTWRITEBYTECODE': '1',
                   'TEAM_CONSOLE_DATA_DIR': directory}
            result = subprocess.run([sys.executable, '-c', script, str(root)], env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn('boundaries passed', result.stdout)
