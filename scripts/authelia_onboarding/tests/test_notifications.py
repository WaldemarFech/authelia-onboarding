from __future__ import annotations

import datetime as dt
from email.message import Message
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.authelia_onboarding import onboarding_service
from scripts.authelia_onboarding.notifications import LegacyNotificationArchive, MAX_VIEW_BYTES
from scripts.authelia_onboarding import notifications


class LegacyNotificationArchiveTests(unittest.TestCase):
    def setUp(self) -> None:
        allowed = patch.object(notifications, "ADMIN_USERNAMES", ("labowner", "jarvis"))
        allowed.start()
        self.addCleanup(allowed.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "configuration.yml"
        self.config.write_text("notifier:\n  smtp:\n    host: relay.example.invalid\n", encoding="utf-8")
        os.chmod(self.config, 0o644)
        self.log = self.root / "notification.txt"
        self.log.write_text("Date: old\nRecipient: example\nSubject: reset\nsecret-token\n", encoding="utf-8")
        os.chmod(self.log, 0o600)
        self.archive = LegacyNotificationArchive(self.log, self.config)

    def test_exact_admin_and_bounded_tail(self) -> None:
        for actor in ("LabUser", "labuser", "Labowner", "LABOWNER", "Jarvis", "JARVIS", "jörvis", None):
            with self.subTest(actor=actor), self.assertRaises(PermissionError):
                self.archive.read_for_admin(actor)
        self.log.write_bytes(b"x" * MAX_VIEW_BYTES + b"visible-tail")
        for actor in ("labowner", "jarvis"):
            with self.subTest(actor=actor):
                result = self.archive.read_for_admin(actor)
                self.assertEqual(result["state"], "available")
                self.assertTrue(result["truncated"])
                self.assertLessEqual(len(result["content"].encode()), MAX_VIEW_BYTES)
                self.assertTrue(result["content"].endswith("visible-tail"))

    def test_overdue_archive_requires_explicit_confirmed_purge(self) -> None:
        now = dt.datetime(2026, 9, 30, tzinfo=dt.timezone.utc)
        old = (now - dt.timedelta(days=31)).timestamp()
        os.utime(self.log, (old, old))
        before = self.log.read_bytes()
        result = self.archive.read_for_admin("labowner", now=now)
        self.assertTrue(result["retention_due"])
        self.assertEqual(self.log.read_bytes(), before)
        with self.assertRaises(ValueError):
            self.archive.purge_expired_for_admin("labowner", "purge", now=now)
        self.assertEqual(self.log.read_bytes(), before)
        purged = self.archive.purge_expired_for_admin(
            "labowner", "PURGE EXPIRED NOTIFICATIONS", now=now)
        self.assertEqual(purged, {"purged": True, "reason": "retention_due"})
        self.assertEqual(self.log.read_bytes(), b"")
        self.assertNotIn("secret-token", str(purged))
        self.assertFalse(self.archive.purge_expired_for_admin(
            "labowner", "PURGE EXPIRED NOTIFICATIONS", now=now)["purged"])

    def test_active_filesystem_notifier_and_unsafe_files_are_rejected(self) -> None:
        self.config.write_text("notifier:\n  filesystem:\n    filename: notification.txt\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "requires active SMTP"):
            self.archive.read_for_admin("labowner")
        self.config.write_text("notifier:\n  smtp:\n    host: relay.example.invalid\n", encoding="utf-8")
        os.chmod(self.log, 0o644)
        with self.assertRaisesRegex(RuntimeError, "unsafe notification file metadata"):
            self.archive.read_for_admin("labowner")
        os.chmod(self.log, 0o600)
        self.log.unlink()
        self.log.symlink_to(self.config)
        with self.assertRaises(OSError):
            self.archive.read_for_admin("labowner")


class NotificationAdminHTTPTests(unittest.TestCase):
    def setUp(self) -> None:
        for name, value in {"ADMIN": "labowner", "ADMINS": ("labowner", "jarvis"),
                            "EXPECTED_ORIGIN": "https://auth.example.invalid"}.items():
            active = patch.object(onboarding_service, name, value)
            active.start()
            self.addCleanup(active.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = root / "configuration.yml"
        self.config.write_text("notifier:\n  smtp:\n    host: relay.example.invalid\n", encoding="utf-8")
        os.chmod(self.config, 0o644)
        self.log = root / "notification.txt"
        self.log.write_text("<script>secret-token</script>", encoding="utf-8")
        os.chmod(self.log, 0o600)
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=31)).timestamp()
        os.utime(self.log, (old, old))
        users = root / "users_database.yml"
        users.write_text("users:\n  labowner:\n    password: placeholder\n", encoding="utf-8")
        os.chmod(users, 0o600)
        self.store = onboarding_service.Store(root / "state.sqlite3", users, hasher=lambda _: "")
        self.server = SimpleNamespace(
            store=self.store,
            legacy_notifications=LegacyNotificationArchive(self.log, self.config),
            rate_limiter=onboarding_service.RateLimiter(),
        )

    def _request(self, method: str, *, identity: str = "labowner", xhr: bool = True,
                 origin: str | None = None,
                 confirmation: str = "PURGE EXPIRED NOTIFICATIONS", peer: str = "127.0.0.1") -> tuple[int, object]:
        if origin is None:
            origin = onboarding_service.EXPECTED_ORIGIN
        class RecordingHandler(onboarding_service.Handler):
            def _json(self, code: int, value: object) -> None:
                self.response = (code, value)

        handler = RecordingHandler.__new__(RecordingHandler)
        handler.server = self.server
        handler.client_address = (peer, 12345)
        handler.headers = Message()
        handler.headers["Remote-User"] = identity
        if xhr:
            handler.headers["X-Requested-With"] = "JarvisOnboarding"
        handler.path = "/onboarding/admin/api/notifications"
        if method == "POST":
            handler.path += "/purge"
            body = json.dumps({"confirmation": confirmation}).encode()
            handler.headers["Content-Type"] = "application/json"
            handler.headers["Content-Length"] = str(len(body))
            handler.headers["Origin"] = origin
            handler.rfile = io.BytesIO(body)
        with patch.object(onboarding_service, "TRUSTED_PROXY", "127.0.0.1"):
            getattr(handler, "do_" + method)()
        return handler.response




    def test_archive_endpoints_unavailable_and_unchanged(self) -> None:
        before = self.log.read_bytes()
        for method in ("GET", "POST"):
            for identity in ("labowner", "jarvis"):
                with self.subTest(method=method, identity=identity):
                    self.assertEqual(self._request(method, identity=identity)[0], 404)
            self.assertEqual(self._request(method, identity="unknown")[0], 403)
            self.assertEqual(self._request(method, peer="127.0.0.2")[0], 403)
        self.assertEqual(self.log.read_bytes(), before)
        self.assertEqual(self.store.audit_tail(), [])


if __name__ == "__main__":
    unittest.main()
