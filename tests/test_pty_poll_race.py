"""Synthetic regression: a child may close its PTY before process exit."""
import subprocess
import sys
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts' / 'authelia_onboarding'))
import onboarding_service as service

CHILD = r'''
import os,time
os.write(1,b'__JARVIS_HASH_TTY_READY__\n')
os.read(0,1024)
os.write(1,b'$argon2id$v=19$m=65536,t=3,p=1$YWJj$ZGVm\n')
for fd in (0,1,2): os.close(fd)
time.sleep(0.5)
'''

def controlled_popen(_command, **kwargs):
    return subprocess.Popen([sys.executable, '-c', CHILD], **kwargs)

def stalled_popen(_command, **kwargs):
    stalled = CHILD.replace('time.sleep(0.5)', 'time.sleep(5)')
    return subprocess.Popen([sys.executable, '-c', stalled], **kwargs)

class PTYRace(unittest.TestCase):
    def test_control_child_normally_exits_zero_after_closing_output(self):
        result = subprocess.run([sys.executable, '-c', CHILD], input=b'synthetic-input\n',
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b'$argon2id$', result.stdout)

    def test_closed_pty_is_not_a_timeout_if_child_exits_successfully(self):
        with patch.object(service, 'subprocess', SimpleNamespace(Popen=controlled_popen)), \
             patch.object(service, 'HASH_TIMEOUT_SECONDS', 3):
            result = service.hash_password('synthetic-input')
        self.assertTrue(result.startswith('$argon2id$'))

    def test_closed_pty_child_that_exceeds_deadline_times_out(self):
        with patch.object(service, 'subprocess', SimpleNamespace(Popen=stalled_popen)), \
             patch.object(service, 'HASH_TIMEOUT_SECONDS', 0.5):
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                service.hash_password('synthetic-input')

if __name__ == '__main__':
    unittest.main()
