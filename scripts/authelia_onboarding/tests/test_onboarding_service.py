from __future__ import annotations

import io
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from scripts.authelia_onboarding import onboarding_service as onboarding


ARGON_HASH = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
ONBOARDING_DIR = Path(__file__).resolve().parents[1]


class OnboardingStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name, value in {"ADMIN": "labowner", "ADMINS": ("labowner", "jarvis"),
                            "ALLOWED_GROUPS": {"jellyfin-users"},
                            "EXPECTED_ORIGIN": "https://auth.example.invalid"}.items():
            active = patch.object(onboarding, name, value)
            active.start()
            self.addCleanup(active.stop)
        # Never allow HTTP-handler tests to inspect system Authelia paths.
        context_type = onboarding.AccountContext
        context_patch = patch.object(onboarding, "AccountContext", side_effect=lambda: context_type(
            config_path=self.root / "fixture-authelia.yml", storage_path=self.root / "fixture-mfa.sqlite3"))
        context_patch.start()
        self.addCleanup(context_patch.stop)
        self.db_path = self.root / "state.sqlite3"
        self.users_path = self.root / "users_database.yml"
        self.users_path.write_text(
            yaml.safe_dump({"users": {"LabUser": {
                "displayname": "LabUser", "email": "labuser@example.invalid",
                "groups": ["jellyfin-users"], "password": ARGON_HASH,
            }, "labowner": {
                "displayname": "Administrator", "email": "admin@example.invalid",
                "groups": ["jellyfin-users"], "password": ARGON_HASH,
            }, "jarvis": {
                "displayname": "Jarvis", "email": "jarvis@example.invalid",
                "groups": [], "password": ARGON_HASH,
            }}}),
            encoding="utf-8",
        )
        os.chmod(self.users_path, 0o600)
        self.store = onboarding.Store(self.db_path, self.users_path, hasher=lambda _: ARGON_HASH)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_invitation_persists_only_token_digest(self) -> None:
        created, token = self.store.create_invite(7, 1, [])

        self.assertTrue(self.store.check_invite(token)["valid"])
        with closing(sqlite3.connect(self.db_path)) as db:
            stored_digest = db.execute("SELECT token_hash FROM invites WHERE id=?", (created["id"],)).fetchone()[0]
        self.assertEqual(stored_digest, onboarding.token_digest(token))
        self.assertNotIn(token.encode(), self.db_path.read_bytes())

    def test_redeem_creates_account_and_consumes_single_use_invite(self) -> None:
        created, token = self.store.create_invite(7, 1, ["jellyfin-users"])
        password = "correct horse battery staple"

        self.store.redeem(token, "new-user", "New User", "new@example.invalid", password)

        record = self.store.users.load()["users"]["new-user"]
        self.assertEqual(record["password"], ARGON_HASH)
        self.assertEqual(record["groups"], ["jellyfin-users"])
        self.assertNotEqual(record["password"], password)
        self.assertFalse(self.store.check_invite(token)["valid"])
        self.assertEqual(self.store.list_invites()[0]["used_count"], 1)
        self.assertEqual(self.store.audit_tail()[0]["action"], "account_created")
        self.assertEqual(self.store.audit_tail()[0]["actor"], f"invite:{created['id']}")
        self.assertEqual(self.users_path.stat().st_mode & 0o777, 0o600)

    def test_invitation_with_removed_group_becomes_invalid(self) -> None:
        _, token = self.store.create_invite(7, 1, ["jellyfin-users"])
        before = self.users_path.read_bytes()
        onboarding.ALLOWED_GROUPS.clear()
        self.assertFalse(self.store.check_invite(token)["valid"])
        with self.assertRaisesRegex(ValueError, "invitation"):
            self.store.redeem(token, "stale-user", "Test User", "test@example.invalid", "correct horse battery staple")
        self.assertEqual(self.users_path.read_bytes(), before)

    def test_invitation_rechecks_allowed_groups_at_reservation(self) -> None:
        created, token = self.store.create_invite(7, 1, ["jellyfin-users"])
        before = self.users_path.read_bytes()
        def revoke_during_hash(_):
            onboarding.ALLOWED_GROUPS.clear()
            return ARGON_HASH
        self.store.hasher = revoke_during_hash
        with self.assertRaisesRegex(ValueError, "invitation"):
            self.store.redeem(token, "stale-user", "Test User", "test@example.invalid", "correct horse battery staple")
        self.assertEqual(self.users_path.read_bytes(), before)
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending WHERE invite_id=?", (created["id"],)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT used_count FROM invites WHERE id=?", (created["id"],)).fetchone()[0], 0)

    def test_recovery_stops_for_previously_reserved_disallowed_groups(self) -> None:
        created, _ = self.store.create_invite(7, 1, ["jellyfin-users"])
        record = {"displayname": "Test User", "email": "test@example.invalid", "groups": ["jellyfin-users"],
                  "password": ARGON_HASH, "disabled": False}
        with self.store._connect() as db:
            db.execute("INSERT INTO pending(id,invite_id,username,record_json,created_at) VALUES(?,?,?,?,?)",
                       ("pending-test", created["id"], "stale-user", json.dumps(record), onboarding.iso(onboarding.utc_now())))
            db.commit()
        before = self.users_path.read_bytes()
        onboarding.ALLOWED_GROUPS.clear()
        with self.assertRaisesRegex(RuntimeError, "group"):
            self.store.recover_pending()
        self.assertEqual(self.users_path.read_bytes(), before)
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending WHERE id='pending-test'").fetchone()[0], 1)

    def test_multi_use_invitation_consumes_exact_limit_across_stores(self) -> None:
        created, token = self.store.create_invite(7, 3, ["jellyfin-users"])
        for index in range(3):
            with self.subTest(index=index):
                store = onboarding.Store(self.db_path, self.users_path, hasher=lambda _: ARGON_HASH)
                self.assertEqual(store.check_invite(token)["remaining_uses"], 3 - index)
                store.redeem(token, f"multi-user-{index}", "Multi User",
                             f"multi-{index}@example.invalid", "correct horse battery staple")
                self.assertEqual(store.list_invites()[0]["used_count"], index + 1)
                self.assertEqual(store.users.load()["users"][f"multi-user-{index}"]["groups"],
                                 ["jellyfin-users"])

        reopened = onboarding.Store(self.db_path, self.users_path, hasher=lambda _: self.fail("exhausted invite was hashed"))
        self.assertFalse(reopened.check_invite(token)["valid"])
        with self.assertRaisesRegex(ValueError, "invitation is invalid"):
            reopened.redeem(token, "over-limit-user", "Over Limit", "over@example.invalid",
                            "correct horse battery staple")
        self.assertNotIn("over-limit-user", reopened.users.load()["users"])
        with reopened._connect() as db:
            self.assertEqual(db.execute("SELECT used_count FROM invites WHERE id=?", (created["id"],)).fetchone()[0], 3)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending WHERE invite_id=?", (created["id"],)).fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='account_created'").fetchone()[0], 3)

    def test_concurrent_stores_enforce_single_and_multi_use_invitation_limits(self) -> None:
        contenders = 5
        for max_uses in (1, 3):
            with self.subTest(max_uses=max_uses):
                created, token = self.store.create_invite(7, max_uses, ["jellyfin-users"])
                # Every contender must pass the initial invite check before any
                # reservation is made. Separate Store locks cannot serialize them.
                hash_barrier = threading.Barrier(contenders)

                def simultaneous_hasher(_: str) -> str:
                    hash_barrier.wait(timeout=5)
                    return ARGON_HASH

                stores = [onboarding.Store(self.db_path, self.users_path, hasher=simultaneous_hasher)
                          for _ in range(contenders)]

                def redeem(index: int) -> tuple[str, str]:
                    username = f"race-{max_uses}-{index}"
                    try:
                        stores[index].redeem(token, username, "Race User",
                                             f"race-{max_uses}-{index}@example.invalid",
                                             "correct horse battery staple")
                    except ValueError as exc:
                        return "rejected", str(exc)
                    return "created", username

                with ThreadPoolExecutor(max_workers=contenders) as executor:
                    futures = [executor.submit(redeem, index) for index in range(contenders)]
                    results = [future.result(timeout=10) for future in futures]
                successful = [value for outcome, value in results if outcome == "created"]
                rejected = [value for outcome, value in results if outcome == "rejected"]
                self.assertEqual(len(successful), max_uses)
                self.assertEqual(len(rejected), contenders - max_uses)
                self.assertTrue(all("invitation use limit reached" in error for error in rejected))
                users = self.store.users.load()["users"]
                actual = {name for name in users if name.startswith(f"race-{max_uses}-")}
                self.assertEqual(actual, set(successful))
                self.assertTrue(all(users[name]["groups"] == ["jellyfin-users"] for name in successful))
                self.assertFalse(self.store.check_invite(token)["valid"])
                with self.store._connect() as db:
                    self.assertEqual(db.execute("SELECT used_count FROM invites WHERE id=?", (created["id"],)).fetchone()[0], max_uses)
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM pending WHERE invite_id=?", (created["id"],)).fetchone()[0], 0)
                    audit = db.execute("SELECT details_json FROM audit WHERE action='account_created'").fetchall()
                    self.assertEqual(sum(json.loads(row[0])["invite_id"] == created["id"] for row in audit), max_uses)

    def test_invalid_or_expired_invitation_never_calls_password_hasher(self) -> None:
        called = False

        def hasher(_: str) -> str:
            nonlocal called
            called = True
            return ARGON_HASH

        self.store.hasher = hasher
        with self.assertRaisesRegex(ValueError, "invitation is invalid"):
            self.store.redeem("not-a-valid-token", "new-user", "New User", "new@example.invalid", "long enough password")
        self.assertFalse(called)

    def test_hash_failure_does_not_consume_invite_or_create_user(self) -> None:
        _, token = self.store.create_invite(7, 1, [])
        self.store.hasher = lambda _: (_ for _ in ()).throw(RuntimeError("hash unavailable"))

        with self.assertRaisesRegex(RuntimeError, "hash unavailable"):
            self.store.redeem(token, "new-user", "New User", "new@example.invalid", "long enough password")

        self.assertTrue(self.store.check_invite(token)["valid"])
        self.assertNotIn("new-user", self.store.users.load()["users"])

    def test_redeem_retries_one_failed_file_write_and_consumes_once(self) -> None:
        created, token = self.store.create_invite(7, 1, [])
        original_write = self.store.users._write_locked
        attempts = 0

        def fail_once(data: dict) -> None:
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise OSError("temporary file write failure")
            original_write(data)

        with patch.object(self.store.users, "_write_locked", side_effect=fail_once):
            self.store.redeem(token, "new-user", "New User", "new@example.invalid",
                              "correct horse battery staple")
        self.assertEqual(attempts, 2)
        self.assertIn("new-user", self.store.users.load()["users"])
        self.assertFalse(self.store.check_invite(token)["valid"])
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT used_count FROM invites WHERE id=?", (created["id"],)).fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending").fetchone()[0], 0)

    def test_hash_password_waits_for_marker_and_rejects_echo(self) -> None:
        dummy = "generated dummy value"
        marker = onboarding.HASH_READY_MARKER + b"\r\n"

        def exercise(output_after_marker: bytes) -> tuple[list[str], list[bytes], list[str]]:
            chunks = [marker, output_after_marker]
            events: list[str] = []
            sent: list[bytes] = []
            commands: list[str] = []

            class OSProxy:
                def __getattr__(self, name: str):
                    return getattr(os, name)

                def read(self, _fd: int, _size: int) -> bytes:
                    events.append("read")
                    return chunks.pop(0)

                def write(self, _fd: int, value) -> int:
                    events.append("write")
                    sent.append(bytes(value))
                    return len(value)

            class FinishedProcess:
                def poll(self) -> int:
                    return 0

                def wait(self, timeout: int) -> int:
                    return 0

                def kill(self) -> None:
                    raise AssertionError("finished fake process must not be killed")

            def fake_popen(command, *, stdin, stdout, stderr, close_fds):
                self.assertEqual(stdout, stdin)
                self.assertEqual(stderr, stdin)
                self.assertTrue(close_fds)
                commands.append(repr(command))
                return FinishedProcess()

            def fake_select(readers, _writers, _errors, _timeout):
                return (readers, [], []) if chunks else ([], [], [])

            with patch.object(onboarding, "os", OSProxy()), \
                    patch.object(onboarding, "subprocess", SimpleNamespace(Popen=fake_popen)), \
                    patch.object(onboarding, "select", SimpleNamespace(select=fake_select)):
                if dummy.encode() in output_after_marker:
                    with self.assertRaisesRegex(RuntimeError, "failed safely"):
                        onboarding.hash_password(dummy)
                else:
                    self.assertEqual(onboarding.hash_password(dummy), ARGON_HASH)
            return events, sent, commands

        for output in (ARGON_HASH.encode() + b"\r\n",
                       dummy.encode() + b"\r\n" + ARGON_HASH.encode() + b"\r\n"):
            events, sent, commands = exercise(output)
            self.assertEqual(events, ["read", "write", "read"])
            self.assertEqual(sent, [dummy.encode() + b"\n"])
            self.assertEqual(len(commands), 1)
            self.assertNotIn(dummy, commands[0])

    def test_pending_account_write_recovers_and_consumes_exactly_once(self) -> None:
        created, token = self.store.create_invite(7, 1, [])
        record = {"displayname": "Recovered User", "email": "recovered@example.invalid",
                  "groups": [], "password": ARGON_HASH, "disabled": False}
        pending_id = "c" * 32
        with self.store._connect() as db:
            db.execute(
                "INSERT INTO pending(id,invite_id,username,record_json,created_at) VALUES(?,?,?,?,?)",
                (pending_id, created["id"], "recovered-user", json.dumps(record), onboarding.iso(onboarding.utc_now())),
            )

        recovered = onboarding.Store(self.db_path, self.users_path, hasher=lambda _: ARGON_HASH)

        self.assertEqual(recovered.users.load()["users"]["recovered-user"], record)
        self.assertEqual(recovered.list_invites()[0]["used_count"], 1)
        self.assertFalse(recovered.check_invite(token)["valid"])
        with recovered._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT used_count FROM invites WHERE id=?", (created["id"],)).fetchone()[0], 1)

    def test_user_rights_change_keeps_durable_audit_intent_across_failure(self) -> None:
        _, token = self.store.create_invite(7, 1, [])
        self.store.redeem(token, "rights-user", "Rights User", "rights@example.invalid",
                          "correct horse battery staple")
        with patch.object(self.store, "_finish_user_update", side_effect=RuntimeError("audit offline")):
            with self.assertRaisesRegex(RuntimeError, "audit offline"):
                self.store.update_user("rights-user", groups=["jellyfin-users"])
        self.assertEqual(self.store.users.load()["users"]["rights-user"]["groups"], ["jellyfin-users"])
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending_user_updates").fetchone()[0], 1)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM audit WHERE action='user_update_requested' AND subject='rights-user'"
            ).fetchone()[0], 1)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM audit WHERE action='user_updated' AND subject='rights-user'"
            ).fetchone()[0], 0)

        recovered = onboarding.Store(self.db_path, self.users_path, hasher=lambda _: ARGON_HASH)
        self.assertEqual(recovered.users.load()["users"]["rights-user"]["groups"], ["jellyfin-users"])
        self.assertEqual(recovered.audit_tail()[0]["action"], "user_updated_recovered")
        self.assertEqual(recovered.audit_tail()[0]["actor"], "system")
        with recovered._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending_user_updates").fetchone()[0], 0)

    def test_failed_rights_write_never_applies_later(self) -> None:
        _, token = self.store.create_invite(7, 1, [])
        self.store.redeem(token, "rights-user", "Rights User", "rights@example.invalid",
                          "correct horse battery staple")
        with patch.object(self.store.users, "_write_locked", side_effect=OSError("disk unavailable")):
            with self.assertRaisesRegex(RuntimeError, "did not complete"):
                self.store.update_user("rights-user", groups=["jellyfin-users"])
        self.assertEqual(self.store.users.load()["users"]["rights-user"]["groups"], [])
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending_user_updates").fetchone()[0], 0)
        restarted = onboarding.Store(self.db_path, self.users_path, hasher=lambda _: ARGON_HASH)
        self.assertEqual(restarted.users.load()["users"]["rights-user"]["groups"], [])
        self.assertEqual(restarted.audit_tail()[0]["action"], "user_update_not_applied")

    def test_directory_sync_failure_keeps_intent_until_durability_is_confirmed(self) -> None:
        _, token = self.store.create_invite(7, 1, [])
        self.store.redeem(token, "rights-user", "Rights User", "rights@example.invalid",
                          "correct horse battery staple")
        with patch.object(self.store.users, "fsync_directory", side_effect=OSError("sync unavailable")):
            with self.assertRaisesRegex(OSError, "sync unavailable"):
                self.store.update_user("rights-user", groups=["jellyfin-users"])
        with self.store._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending_user_updates").fetchone()[0], 1)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM audit WHERE action='user_updated' AND subject='rights-user'"
            ).fetchone()[0], 0)
        restarted = onboarding.Store(self.db_path, self.users_path, hasher=lambda _: ARGON_HASH)
        self.assertEqual(restarted.audit_tail()[0]["action"], "user_updated_recovered")
        with restarted._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending_user_updates").fetchone()[0], 0)

    def test_rights_recovery_does_not_replay_over_external_change(self) -> None:
        _, token = self.store.create_invite(7, 1, [])
        self.store.redeem(token, "rights-user", "Rights User", "rights@example.invalid",
                          "correct horse battery staple")
        with self.store._connect() as db:
            db.execute("INSERT INTO pending_user_updates(id,username,changes_json,created_at) VALUES(?,?,?,?)",
                       ("d" * 32, "rights-user", json.dumps({"before": {"groups": []},
                                                              "after": {"groups": ["jellyfin-users"]}}),
                        onboarding.iso(onboarding.utc_now())))
        self.store.users.update("rights-user", disabled=None, groups=["other-integration"])
        restarted = onboarding.Store(self.db_path, self.users_path, hasher=lambda _: ARGON_HASH)
        self.assertEqual(restarted.users.load()["users"]["rights-user"]["groups"], ["other-integration"])
        self.assertEqual(restarted.audit_tail()[0]["action"], "user_update_conflict")
        with restarted._connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM pending_user_updates").fetchone()[0], 0)

    def test_managed_group_toggle_preserves_existing_other_groups(self) -> None:
        _, token = self.store.create_invite(7, 1, [])
        self.store.redeem(token, "rights-user", "Rights User", "rights@example.invalid",
                          "correct horse battery staple")
        self.store.users.update("rights-user", disabled=None, groups=["other-integration"])
        self.store.update_user("rights-user", groups=["jellyfin-users"])
        self.assertEqual(self.store.users.load()["users"]["rights-user"]["groups"],
                         ["jellyfin-users", "other-integration"])
        self.store.update_user("rights-user", groups=[])
        self.assertEqual(self.store.users.load()["users"]["rights-user"]["groups"],
                         ["other-integration"])

    def test_invite_input_types_and_group_allowlist_are_strict(self) -> None:
        for args in ((True, 1, []), (7, False, []), (7, 1, "jellyfin-users"), (7, 1, [1])):
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.store.create_invite(*args)
        with self.assertRaisesRegex(ValueError, "unsupported group"):
            self.store.create_invite(7, 1, ["admin"])

    def test_expiry_revocation_and_administrator_protection(self) -> None:
        _, token = self.store.create_invite(7, 1, [])
        with patch.object(onboarding, "utc_now", return_value=onboarding.utc_now() + timedelta(days=8)):
            self.assertFalse(self.store.check_invite(token)["valid"])

        created, revocable = self.store.create_invite(7, 1, [])
        self.assertTrue(self.store.revoke_invite(created["id"]))
        self.assertFalse(self.store.check_invite(revocable)["valid"])
        for username in ("labowner", "labowner", "jarvis", "Jarvis", "JARVIS"):
            with self.subTest(username=username):
                with self.assertRaisesRegex(ValueError, "administrator account is protected"):
                    self.store.update_user(username, disabled=True)
                with self.assertRaisesRegex(ValueError, "administrator account is protected"):
                    self.store.update_user(username, groups=[])
        self.store.update_user("LabUser", disabled=True, groups=[])
        self.assertTrue(self.store.users.load()["users"]["LabUser"]["disabled"])
        self.assertEqual(self.store.users.load()["users"]["LabUser"]["groups"], [])
        self.store.update_user("LabUser", disabled=False, groups=["jellyfin-users"])
        self.assertFalse(self.store.users.load()["users"]["LabUser"]["disabled"])
        self.assertEqual(self.store.audit_tail()[0]["actor"], "system")

    def test_admin_http_requires_identity_and_rejects_string_numbers(self) -> None:
        class RecordingHandler(onboarding.Handler):
            def _json(self, code: int, value: object) -> None:
                self.response = (code, value)

        def post(headers: dict[str, str], peer: str = "127.0.0.1") -> tuple[int, object]:
            handler = RecordingHandler.__new__(RecordingHandler)
            handler.client_address = (peer, 12345)
            handler.headers = Message()
            for key, value in {
                "Content-Type": "application/json", "Origin": onboarding.EXPECTED_ORIGIN,
                "X-Requested-With": "JarvisOnboarding", **headers,
            }.items():
                handler.headers[key] = value
            body = json.dumps({"days": "7", "max_uses": 1, "groups": []}).encode()
            handler.headers["Content-Length"] = str(len(body))
            handler.rfile = io.BytesIO(body)
            handler.path = "/onboarding/admin/api/invites"
            handler.server = SimpleNamespace(store=self.store, rate_limiter=onboarding.RateLimiter())
            handler.do_POST()
            return handler.response

        with patch.object(onboarding, "TRUSTED_PROXY", "127.0.0.1"):
            self.assertEqual(post({})[0], 403)
            for identity in ("LabUser", "labuser", "Labowner", "LABOWNER", "Jarvis", "JARVIS", "jörvis"):
                with self.subTest(identity=identity):
                    self.assertEqual(post({"Remote-User": identity})[0], 403)
            self.assertEqual(post({"Remote-User": "LabUser", "Remote-Groups": "admins,jarvis"})[0], 403)
            for identity in onboarding.ADMINS:
                with self.subTest(identity=identity):
                    self.assertEqual(post({"Remote-User": identity}, peer="127.0.0.2")[0], 403)
                    self.assertEqual(post({"Remote-User": identity, "Origin": "https://evil.invalid"})[0], 403)
                    self.assertEqual(post({"Remote-User": identity, "X-Requested-With": "wrong"})[0], 403)
                    self.assertEqual(post({"Remote-User": identity}),
                                     (400, {"error": "days and max_uses must be integers"}))

    def test_invitation_redemption_reserves_both_administrators(self) -> None:
        _, token = self.store.create_invite(7, 1, [])
        for username in ("labowner", "LABOWNER", "jarvis", "Jarvis", " JARVIS "):
            with self.subTest(username=username), self.assertRaisesRegex(ValueError, "username is not allowed"):
                self.store.redeem(token, username, "Admin", "admin@example.invalid",
                                  "correct horse battery staple")
        self.assertTrue(self.store.check_invite(token)["valid"])

    def test_jarvis_http_administration_keeps_actual_audit_actor(self) -> None:
        class RecordingHandler(onboarding.Handler):
            def _json(self, code: int, value: object) -> None:
                self.response = (code, value)

        def request(method: str, path: str, body: dict | None = None) -> tuple[int, object]:
            handler = RecordingHandler.__new__(RecordingHandler)
            handler.client_address = ("127.0.0.1", 12345)
            handler.headers = Message()
            for key, value in {
                "Content-Type": "application/json", "Origin": onboarding.EXPECTED_ORIGIN,
                "X-Requested-With": "JarvisOnboarding", "Remote-User": "jarvis",
            }.items():
                handler.headers[key] = value
            encoded = json.dumps(body or {}).encode()
            handler.headers["Content-Length"] = str(len(encoded))
            handler.rfile = io.BytesIO(encoded)
            handler.path = path
            handler.server = SimpleNamespace(store=self.store, rate_limiter=onboarding.RateLimiter())
            with patch.object(onboarding, "TRUSTED_PROXY", "127.0.0.1"):
                getattr(handler, "do_" + method)()
            return handler.response

        code, result = request("GET", "/onboarding/admin/api/summary")
        self.assertEqual(code, 200)
        self.assertEqual(result["admin_username"], "labowner")
        self.assertEqual(result["admin_usernames"], ["labowner", "jarvis"])
        self.assertEqual([entry["id"] for entry in result["group_catalog"]], ["jellyfin-users"])
        self.assertTrue(result["group_catalog"][0]["editable"])
        code, invite = request("POST", "/onboarding/admin/api/invites",
                               {"days": 7, "max_uses": 1, "groups": [], "actor": "labowner"})
        self.assertEqual(code, 201)
        self.assertEqual(request("POST", f"/onboarding/admin/api/invites/{invite['id']}/revoke")[0], 200)
        self.assertEqual(request("POST", "/onboarding/admin/api/users/LabUser/groups",
                                 {"groups": [], "actor": "labowner"})[0], 200)
        self.assertEqual(request("POST", "/onboarding/admin/api/users/LabUser/disabled", {"disabled": True})[0], 200)
        self.assertEqual({event["actor"] for event in self.store.audit_tail()}, {"jarvis"})
        self.assertEqual({event["action"] for event in self.store.audit_tail()},
                         {"invite_created", "invite_revoked", "user_update_requested", "user_updated"})
        before = self.users_path.read_bytes()
        for username in ("labowner", "LABOWNER", "jarvis", "Jarvis"):
            with self.subTest(username=username):
                self.assertEqual(request("POST", f"/onboarding/admin/api/users/{username}/disabled",
                                         {"disabled": True})[0], 400)
                self.assertEqual(request("POST", f"/onboarding/admin/api/users/{username}/groups",
                                         {"groups": []})[0], 400)
        self.assertEqual(self.users_path.read_bytes(), before)

    def test_rate_limiter_expires_at_window_boundary_and_isolates_buckets(self) -> None:
        limiter = onboarding.RateLimiter()
        with patch.object(onboarding.time, "monotonic") as clock:
            clock.return_value = 100.0
            self.assertTrue(limiter.allow("first", 2))
            self.assertTrue(limiter.allow("first", 2))
            self.assertFalse(limiter.allow("first", 2))
            self.assertTrue(limiter.allow("other", 2))
            clock.return_value = 159.999
            self.assertFalse(limiter.allow("first", 2))
            clock.return_value = 160.0
            self.assertTrue(limiter.allow("first", 2))
            self.assertTrue(limiter.allow("first", 2))
            self.assertFalse(limiter.allow("first", 2))

    def test_http_rate_limits_return_429_and_reset_at_window_boundary(self) -> None:
        class RecordingHandler(onboarding.Handler):
            def _json(self, code: int, value: object) -> None:
                self.response = (code, value)

        cases = (
            ("POST", "/onboarding/api/invite/check", False, 30, 200),
            ("POST", "/onboarding/admin/api/unknown", True, 120, 404),
            ("GET", "/onboarding/admin/api/summary", True, 180, 200),
        )
        for method, path, admin, limit, expected in cases:
            with self.subTest(method=method, path=path):
                server = SimpleNamespace(store=self.store, rate_limiter=onboarding.RateLimiter())

                def request() -> tuple[int, object]:
                    handler = RecordingHandler.__new__(RecordingHandler)
                    handler.client_address = ("127.0.0.1", 12345)
                    handler.server = server
                    handler.path = path
                    handler.headers = Message()
                    if admin:
                        handler.headers["Remote-User"] = "labowner"
                        handler.headers["X-Requested-With"] = "JarvisOnboarding"
                    if method == "POST":
                        body = json.dumps({"token": "not-a-valid-token"}).encode()
                        handler.headers["Origin"] = onboarding.EXPECTED_ORIGIN
                        handler.headers["Content-Type"] = "application/json"
                        handler.headers["Content-Length"] = str(len(body))
                        handler.rfile = io.BytesIO(body)
                    getattr(handler, "do_" + method)()
                    return handler.response

                with patch.object(onboarding, "TRUSTED_PROXY", "127.0.0.1"), \
                        patch.object(onboarding.time, "monotonic") as clock:
                    clock.return_value = 100.0
                    for _ in range(limit):
                        self.assertEqual(request()[0], expected)
                    self.assertEqual(request(), (429, {"error": "rate limit exceeded"}))
                    clock.return_value = 159.999
                    self.assertEqual(request()[0], 429)
                    clock.return_value = 160.0
                    self.assertEqual(request()[0], expected)


class TraefikRouteTests(unittest.TestCase):
    def test_routes_are_tls_scoped_and_auth_headers_are_scrubbed(self) -> None:
        config = yaml.safe_load((ONBOARDING_DIR / "traefik-onboarding.yaml").read_text(encoding="utf-8"))
        http = config["http"]
        public = http["routers"]["authelia-onboarding-public"]
        admin = http["routers"]["authelia-onboarding-admin"]

        self.assertTrue(all("Host(`auth.example.invalid`)" in router["rule"] for router in (public, admin)))
        self.assertTrue(all(router["entryPoints"] == ["websecure"] and router["tls"] == {} for router in (public, admin)))
        self.assertIn("/onboarding/api/invite/redeem", public["rule"])
        self.assertIn("PathPrefix(`/onboarding/admin/`)", admin["rule"])
        self.assertNotIn("forward-auth", public["middlewares"])
        self.assertEqual(admin["middlewares"], ["onboarding-client-scrub", "onboarding-forward-auth"])
        self.assertEqual(http["services"]["authelia-onboarding"]["loadBalancer"]["servers"],
                         [{"url": "http://10.77.0.11:9945"}])

        scrub = http["middlewares"]["onboarding-client-scrub"]["headers"]["customRequestHeaders"]
        self.assertTrue({"Remote-User", "Remote-Groups", "Remote-Email", "Remote-Name",
                         "X-Auth-Request-User", "X-Forwarded-User", "Authorization"}.issubset(scrub))
        self.assertTrue(all(value == "" for value in scrub.values()))
        auth = http["middlewares"]["onboarding-forward-auth"]["forwardAuth"]
        self.assertEqual(auth["address"], "http://10.77.0.11:9091/api/authz/forward-auth-noauth")
        self.assertEqual(auth["authResponseHeaders"], ["Remote-User"])
        self.assertFalse(auth["trustForwardHeader"])
        self.assertEqual(set(http["routers"]), {"authelia-onboarding-public", "authelia-onboarding-admin"})

    def test_systemd_unit_limits_writable_paths_and_process_flags(self) -> None:
        service = (ONBOARDING_DIR / "authelia-onboarding.service").read_text(encoding="utf-8")

        self.assertIn("User=root", service)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ReadWritePaths=/opt/authelia/config", service)
        self.assertIn("StateDirectoryMode=0700", service)
        self.assertIn("UMask=0077", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", service)
        self.assertNotIn("/etc/traefik", service)

    def test_invite_link_and_irreversible_admin_actions_have_safe_ui_affordances(self) -> None:
        accept = onboarding.ACCEPT_JS.decode("utf-8")
        admin = onboarding.ADMIN_JS.decode("utf-8")

        self.assertIn("let token=", accept)
        self.assertIn("history.replaceState(null,'',location.pathname)", accept)
        self.assertIn("password:values.get('password')", accept)
        self.assertNotIn("location.search", accept)
        self.assertIn("await ask(disabled?'Konto deaktivieren?'", admin)
        self.assertIn("kann sich danach nicht mehr anmelden. Bereits aktive Anwendungssitzungen können bestehen bleiben. Das Konto und seine Daten bleiben erhalten.", admin)
        self.assertIn("change.removed.length?", admin)
        self.assertIn("Bereits aktive Anwendungssitzungen können bestehen bleiben.", admin)
        self.assertIn("await ask('Gruppenänderungen speichern?',description", admin)
        self.assertIn("Mitgliedschaft hinzufügen: ", admin)
        self.assertIn("Mitgliedschaft entfernen: ", admin)
        self.assertIn("data.admin_usernames.includes(u.username)", admin)
        self.assertNotIn("#legacy-view", admin)
        self.assertNotIn("#legacy-purge", admin)
        self.assertIn("if(await ask('Einladung widerrufen?'", admin)
        self.assertIn("wird sofort ungültig. Bereits erstellte Konten bleiben bestehen.", admin)


if __name__ == "__main__":
    unittest.main()
