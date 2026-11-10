from __future__ import annotations

import hashlib
import multiprocessing
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts.authelia_onboarding import legacy_helper_lock_patch, onboarding_service


HELPER_FIXTURE = b'''import ipaddress
import os
import tempfile
import time
from pathlib import Path
import yaml

USERS_DB = Path(os.environ["TEST_USERS_DB"])

def replace_user_password(username: str, digest: str) -> None:
    data = yaml.safe_load(USERS_DB.read_text(encoding="utf-8"))
    data["users"][username]["password"] = digest
    fd, name = tempfile.mkstemp(dir=USERS_DB.parent)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        yaml.safe_dump(data, stream)
    os.replace(name, USERS_DB)

def restart_authelia() -> None:
    pass
'''


def run_helper_writer(source: bytes, users_path: str, entered) -> None:
    os.environ["TEST_USERS_DB"] = users_path
    namespace = {"__name__": "test_helper"}
    exec(compile(source, "test_helper.py", "exec"), namespace)
    entered.set()
    namespace["replace_user_password"]("LabUser", "helper-new")


def run_onboarding_writer(users_path: str, entered) -> None:
    user_file = onboarding_service.UserFile(Path(users_path))
    entered.set()
    user_file.add("new-user", {"displayname": "New User", "password": "new-hash", "groups": []})


class SharedUserFileLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "users_database.yml"
        self.path.write_text(yaml.safe_dump({"users": {"LabUser": {"password": "old"}}}), encoding="utf-8")
        os.chmod(self.path, 0o600)
        self.user_file = onboarding_service.UserFile(self.path)
        with patch.object(legacy_helper_lock_patch, "EXPECTED_ORIGINAL_SHA256",
                          hashlib.sha256(HELPER_FIXTURE).hexdigest()):
            self.helper_source = legacy_helper_lock_patch.patch_known_source(HELPER_FIXTURE)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _start(self, target, *args):
        context = multiprocessing.get_context("fork")
        entered = context.Event()
        process = context.Process(target=target, args=(*args, entered))
        process.start()
        self.assertTrue(entered.wait(3), "writer did not reach the lock")
        time.sleep(0.2)
        self.assertTrue(process.is_alive(), "writer bypassed the shared lock")
        return process

    def _finish(self, process) -> None:
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join(3)
            self.fail("writer did not finish after lock release")
        self.assertEqual(process.exitcode, 0)

    def test_helper_waits_for_onboarding_and_preserves_both_changes(self) -> None:
        with self.user_file.write_lock():
            data = self.user_file.load()
            data["users"]["onboarded"] = {"password": "onboarding-hash"}
            process = self._start(run_helper_writer, self.helper_source, str(self.path))
            self.user_file._write_locked(data)
        self._finish(process)

        users = self.user_file.load()["users"]
        self.assertEqual(users["LabUser"]["password"], "helper-new")
        self.assertEqual(users["onboarded"]["password"], "onboarding-hash")
        self.assertEqual(self.user_file.lock_path.stat().st_mode & 0o777, 0o600)

    def test_onboarding_add_waits_for_helper_lock(self) -> None:
        with patch.dict(os.environ, {"TEST_USERS_DB": str(self.path)}):
            namespace = {"__name__": "test_helper"}
            exec(compile(self.helper_source, "test_helper.py", "exec"), namespace)
            with namespace["user_db_write_lock"]():
                process = self._start(run_onboarding_writer, str(self.path))
                namespace["_replace_user_password_unlocked"]("LabUser", "helper-new")
        self._finish(process)

        users = self.user_file.load()["users"]
        self.assertEqual(users["LabUser"]["password"], "helper-new")
        self.assertEqual(users["new-user"]["password"], "new-hash")


if __name__ == "__main__":
    unittest.main()
