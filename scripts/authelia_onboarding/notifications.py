"""Bounded access to the inactive Authelia filesystem notification archive.

Authelia's active notifier must be SMTP. The legacy file is one append-only
plaintext object, so retention age is based on the last write to the whole file,
not on a guessed message boundary inside user-influenced text. Purging is a
separate explicit operation because the existing archive predates this policy.
The caller must
also enforce the exact labowner/jarvis HTTP allowlist, same-origin policy, rate limit,
no-store response headers, and a metadata-only audit event.
"""
from __future__ import annotations

import datetime as dt
import hmac
import os
from pathlib import Path
import stat

import yaml


ADMIN_USERNAMES = ()
DEFAULT_LEGACY_FILE = Path("/opt/authelia/config/notification.txt")
DEFAULT_CONFIG_FILE = Path("/opt/authelia/config/configuration.yml")
RETENTION_DAYS = 30
MAX_VIEW_BYTES = 16 * 1024


class LegacyNotificationArchive:
    """Read and expire one explicitly configured, inactive notification file."""

    def __init__(self, path: Path = DEFAULT_LEGACY_FILE,
                 config_path: Path = DEFAULT_CONFIG_FILE):
        if not path.is_absolute() or not config_path.is_absolute():
            raise ValueError("notification paths must be absolute")
        self.path = path
        self.config_path = config_path

    @staticmethod
    def _checked_open(path: Path, flags: int, *, private: bool = True) -> int:
        """Open an owner-controlled regular file without following symlinks."""
        fd = os.open(path, flags | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1
                    or metadata.st_mode & (0o077 if private else 0o022)):
                raise RuntimeError("unsafe notification file metadata")
            current = path.lstat()
            if (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise RuntimeError("notification file changed while opening")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _require_inactive(self) -> None:
        fd = self._checked_open(self.config_path, os.O_RDONLY, private=False)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            config = yaml.safe_load(stream)
        if not isinstance(config, dict) or not isinstance(config.get("notifier"), dict):
            raise RuntimeError("Authelia notifier configuration is unavailable")
        notifier = config["notifier"]
        if not isinstance(notifier.get("smtp"), dict) or notifier.get("filesystem") is not None:
            raise RuntimeError("legacy notification access requires active SMTP")

    @staticmethod
    def _require_admin(actor: str) -> None:
        if not isinstance(actor, str) or not any(
                hmac.compare_digest(actor.encode("utf-8"), admin.encode("utf-8"))
                for admin in ADMIN_USERNAMES):
            raise PermissionError("administrator authentication required")

    def read_for_admin(self, actor: str, *, now: dt.datetime | None = None) -> dict:
        """Return a bounded tail and state whether the archive is overdue.

        No request-supplied path, offset, age or byte limit is accepted. File
        contents are returned only here and must never be included in an audit
        record, exception message, server log, or HTML markup.
        """
        self._require_admin(actor)
        now = now or dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None:
            raise ValueError("aware time required")
        self._require_inactive()
        try:
            fd = self._checked_open(self.path, os.O_RDONLY)
        except FileNotFoundError:
            return {"state": "missing", "content": "", "truncated": False,
                    "retention_days": RETENTION_DAYS, "retention_due": False}
        try:
            metadata = os.fstat(fd)
            cutoff = now.timestamp() - RETENTION_DAYS * 86400
            if metadata.st_size == 0:
                return {"state": "empty", "content": "", "truncated": False,
                        "retention_days": RETENTION_DAYS, "retention_due": False}
            start = max(0, metadata.st_size - MAX_VIEW_BYTES)
            os.lseek(fd, start, os.SEEK_SET)
            data = os.read(fd, MAX_VIEW_BYTES)
            return {"state": "available", "content": data.decode("utf-8", errors="replace"),
                    "truncated": start > 0, "retention_days": RETENTION_DAYS,
                    "retention_due": metadata.st_mtime <= cutoff}
        finally:
            os.close(fd)

    def purge_expired_for_admin(self, actor: str, confirmation: str,
                                *, now: dt.datetime | None = None) -> dict:
        """Clear an overdue inactive archive after an explicit admin action.

        The endpoint must require same-origin POST and audit only the returned
        metadata. It must never echo file contents into the confirmation form.
        """
        self._require_admin(actor)
        if confirmation != "PURGE EXPIRED NOTIFICATIONS":
            raise ValueError("explicit purge confirmation required")
        now = now or dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None:
            raise ValueError("aware time required")
        self._require_inactive()
        try:
            fd = self._checked_open(self.path, os.O_RDWR)
        except FileNotFoundError:
            return {"purged": False, "reason": "missing"}
        try:
            metadata = os.fstat(fd)
            if not metadata.st_size or metadata.st_mtime > now.timestamp() - RETENTION_DAYS * 86400:
                return {"purged": False, "reason": "not_due"}
            # The file is known inactive, but confirm both the notifier and
            # file metadata once more before the irreversible operation.
            self._require_inactive()
            current = os.fstat(fd)
            if ((current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                    != (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)):
                raise RuntimeError("notification file changed during retention")
            os.ftruncate(fd, 0)
            os.fsync(fd)
            return {"purged": True, "reason": "retention_due"}
        finally:
            os.close(fd)
