from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

import yaml

from scripts.authelia_onboarding import account_context as context

RULES = {"access_control": {"default_policy": "two_factor", "rules": [
    {"domain": ["auth.example.invalid"], "resources": ["^/onboarding/admin$"], "subject": ["user:labowner"], "policy": "two_factor"},
    {"domain": ["jellyfin.example.invalid"], "policy": "two_factor"},
    {"domain": ["jellyfin-app.example.invalid"], "subject": ["group:jellyfin-users"], "policy": "one_factor"},
    {"domain": ["jellyfin-app.example.invalid"], "policy": "deny"},
    {"domain": ["*.example.invalid"], "policy": "two_factor"},
]}, "storage": {"local": {"path": "/config/db.sqlite3"}}}


class AccountContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.db = self.directory / "db.sqlite3"
        self.config = self.directory / "configuration.yml"
        with sqlite3.connect(self.db) as connection:
            for table in context.METHOD_TABLES.values():
                connection.execute(f"CREATE TABLE {table} (username TEXT, secret TEXT)")
            connection.execute("INSERT INTO totp_configurations VALUES (?, ?)", ("labowner", "DO_NOT_EXPOSE_TOTP"))
            connection.execute("INSERT INTO webauthn_credentials VALUES (?, ?)", ("labowner", "DO_NOT_EXPOSE_PASSKEY"))
        os.chmod(self.db, 0o600)
        self.config.write_text(yaml.safe_dump(RULES))
        os.chmod(self.config, 0o600)
        self.users = [{"username": "labowner", "groups": ["jellyfin-users"], "disabled": False},
                      {"username": "LabUser", "groups": ["jellyfin-users"], "disabled": False}]

    def test_distinguishes_enrollment_from_group_and_preserves_accounts(self):
        before = self.db.read_bytes()
        result = context.AccountContext(self.config, self.db).summary(self.users, "labowner", ("labowner", "jarvis"))
        self.assertEqual(result["admin_username"], "labowner")
        self.assertEqual(result["admin_usernames"], ["labowner", "jarvis"])
        self.assertEqual(result["mfa_policy"]["status"], "verified")
        self.assertEqual(result["users"][0]["mfa"], {"status": "known", "totp": True, "webauthn": True, "duo": False})
        self.assertEqual(result["users"][1]["mfa"], {"status": "known", "totp": False, "webauthn": False, "duo": False})
        self.assertNotIn("mfa", self.users[0])
        self.assertNotIn("DO_NOT_EXPOSE", str(result))
        self.assertEqual(self.db.read_bytes(), before)

    def test_administrators_are_explicit_caller_metadata_not_groups(self):
        users = self.users + [{"username": "jarvis", "groups": [], "disabled": False},
                              {"username": "other", "groups": ["admins", "jarvis"], "disabled": False}]
        administrators = ("labowner", "jarvis")
        result = context.AccountContext(self.config, self.db).summary(users, "labowner", administrators)
        self.assertEqual(result["admin_username"], "labowner")
        self.assertEqual(result["admin_usernames"], ["labowner", "jarvis"])
        self.assertEqual(result["users"][2]["groups"], [])
        self.assertEqual(result["users"][3]["groups"], ["admins", "jarvis"])
        self.assertFalse(result["users"][2]["mfa"]["totp"])
        self.assertNotIn("other", result["admin_usernames"])
        result["admin_usernames"].append("other")
        self.assertEqual(administrators, ("labowner", "jarvis"))

    def test_username_matching_is_exact_and_sql_is_parameterized(self):
        self.db.chmod(0o644)  # Actual existing root-owned Authelia storage mode.
        result = context.mfa_context(self.db, ["labowner", "LABOWNER", "' OR 1=1 --"])
        self.assertTrue(result["labowner"]["totp"])
        self.assertFalse(result["LABOWNER"]["totp"])
        self.assertFalse(result["' OR 1=1 --"]["totp"])

    def test_database_with_untrusted_writers_is_unknown(self):
        self.db.chmod(0o666)
        self.assertEqual(context.mfa_context(self.db, ["labowner"])["labowner"]["status"], "unknown")

    def test_missing_table_or_storage_is_unknown_not_unregistered(self):
        with sqlite3.connect(self.db) as connection:
            connection.execute("DROP TABLE duo_devices")
        self.assertEqual(context.mfa_context(self.db, ["labowner"])["labowner"]["status"], "unknown")
        self.db.unlink()
        self.assertEqual(context.mfa_context(self.db, ["labowner"])["labowner"]["status"], "unknown")

    def test_unsafe_database_and_config_are_not_followed(self):
        actual = self.directory / "actual.sqlite3"
        self.db.rename(actual)
        self.db.symlink_to(actual)
        self.assertEqual(context.mfa_context(self.db, ["labowner"])["labowner"]["status"], "unknown")
        self.config.chmod(0o666)
        result = context.AccountContext(self.config, actual).summary(self.users, "labowner", ("labowner", "jarvis"))
        self.assertEqual(result["mfa_policy"]["status"], "unknown")
        self.assertEqual(result["users"][0]["mfa"]["status"], "unknown")

    def test_unknown_storage_mapping_and_duplicate_config_fail_closed(self):
        config = dict(RULES, storage={"local": {"path": "/another/db.sqlite3"}})
        self.config.write_text(yaml.safe_dump(config))
        result = context.AccountContext(self.config, self.db).summary(self.users, "labowner", ("labowner", "jarvis"))
        self.assertEqual(result["users"][0]["mfa"]["status"], "unknown")
        self.config.write_text("access_control: {}\naccess_control: {}\n")
        self.assertEqual(context.AccountContext(self.config, self.db).summary(self.users, "labowner", ("labowner", "jarvis"))["mfa_policy"]["status"], "unknown")

    def test_earlier_wildcard_or_conditional_policy_is_unknown(self):
        for extra in [{"domain": ["*.example.invalid"], "policy": "one_factor"},
                      {"domain": ["jellyfin.example.invalid"], "policy": "two_factor", "networks": ["127.0.0.0/8"]},
                      {"domain_regex": [".*"], "policy": "bypass"}]:
            config = yaml.safe_load(yaml.safe_dump(RULES))
            config["access_control"]["rules"].insert(0, extra)
            self.assertEqual(context.policy_context(config)["status"], "unknown")

    def test_live_wal_registration_is_visible(self):
        connection = sqlite3.connect(self.db)
        self.addCleanup(connection.close)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("INSERT INTO duo_devices VALUES (?, ?)", ("LabUser", "DO_NOT_EXPOSE_DUO"))
        connection.commit()
        for suffix in ("-wal", "-shm"):
            self.db.with_name(self.db.name + suffix).chmod(0o600)
        self.assertTrue(context.mfa_context(self.db, ["LabUser"])["LabUser"]["duo"])


if __name__ == "__main__":
    unittest.main()
