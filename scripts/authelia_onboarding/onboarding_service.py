#!/usr/bin/env python3
"""Private Authelia file-backend onboarding service.

The service is reachable only through the pinned Traefik peer. The proxy strips
client-supplied identity headers; admin routes then use Authelia forward-auth
and the service independently requires an exact allowlisted administrator identity.
"""
from __future__ import annotations

import collections
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import html
import hmac
import importlib.util
import ipaddress
import json
import os
import pty
import re
import select
import secrets
import signal
import sqlite3
import stat
import subprocess
import tempfile
import termios
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml


# The systemd unit runs Python with -I, so the script directory is absent from
# sys.path. Load this fixed sibling module without opening a general import path.
_notifications_spec = importlib.util.spec_from_file_location(
    "authelia_onboarding_notifications", Path(__file__).with_name("notifications.py"))
if _notifications_spec is None or _notifications_spec.loader is None:
    raise RuntimeError("notification archive module is unavailable")
_notifications_module = importlib.util.module_from_spec(_notifications_spec)
_notifications_spec.loader.exec_module(_notifications_module)
LegacyNotificationArchive = _notifications_module.LegacyNotificationArchive

_context_spec = importlib.util.spec_from_file_location(
    "authelia_onboarding_account_context", Path(__file__).with_name("account_context.py"))
if _context_spec is None or _context_spec.loader is None:
    raise RuntimeError("account metadata module is unavailable")
_context_module = importlib.util.module_from_spec(_context_spec)
_context_spec.loader.exec_module(_context_module)
AccountContext = _context_module.AccountContext


PREFIX = "/onboarding"
ADMIN = ""
ADMINS = ()
TRUSTED_PROXY = ""
EXPECTED_ORIGIN = ""
DB_PATH = Path(os.getenv("ONBOARDING_DB", "/var/lib/authelia-onboarding/state.sqlite3"))
USERS_PATH = Path(os.getenv("AUTHELIA_USERS_DB", "/opt/authelia/config/users_database.yml"))
ALLOWED_GROUPS = set()
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
MAX_INVITE_USES = 50
MAX_INVITE_DAYS = 30
HASH_TIMEOUT_SECONDS = 35
USER_FILE_LOCK_TIMEOUT_SECONDS = 10
HASH_READY_MARKER = b"__JARVIS_HASH_TTY_READY__"
HASH_COMMAND = "stty -echo && printf '__JARVIS_HASH_TTY_READY__\\n' && exec authelia crypto hash generate argon2 --no-confirm"
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{40,48}$")
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
ARGON_RE = re.compile(rb"\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+")


class StaleGroupsError(ValueError):
    """Managed groups changed after the administrator opened the dialog."""


class DuplicateKeyLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader: DuplicateKeyLoader, node: yaml.MappingNode, deep: bool = False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("duplicate YAML mapping key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


DuplicateKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def groups_allowed(groups: object) -> bool:
    """Only explicitly permitted string groups may be granted or recovered."""
    return isinstance(groups, list) and all(isinstance(group, str) and group in ALLOWED_GROUPS for group in groups)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", errors="strict")).hexdigest()


class UserFile:
    def __init__(self, path: Path):
        self.path = path
        # Lock a stable sidecar: flock on the YAML inode would stop protecting
        # writers after either service atomically replaces that inode.
        self.lock_path = path.with_name(path.name + ".lock")

    @contextmanager
    def write_lock(self):
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open(self.lock_path, flags, 0o600)
        locked = False
        try:
            metadata = os.fstat(fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                    or metadata.st_nlink != 1 or metadata.st_mode & 0o077):
                raise RuntimeError("unsafe Authelia user database lock metadata")
            deadline = time.monotonic() + USER_FILE_LOCK_TIMEOUT_SECONDS
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Authelia user database is busy")
                    time.sleep(0.05)
            yield
        finally:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def load(self) -> dict:
        st = self.path.lstat()
        if not self.path.is_file() or self.path.is_symlink() or st.st_mode & 0o077:
            raise RuntimeError("unsafe Authelia user database metadata")
        data = yaml.load(self.path.read_text(encoding="utf-8"), Loader=DuplicateKeyLoader)
        if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
            raise RuntimeError("unsupported Authelia user database structure")
        if any(not isinstance(k, str) or not isinstance(v, dict) for k, v in data["users"].items()):
            raise RuntimeError("unsupported Authelia user record")
        return data

    def fsync_directory(self) -> None:
        fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _write_locked(self, data: dict) -> None:
        parent = self.path.parent
        if self.path.is_symlink() or not self.path.is_file():
            raise RuntimeError("unsafe Authelia user database target")
        fd, temp_name = tempfile.mkstemp(prefix=".users_database.onboarding.", dir=parent)
        temp = Path(temp_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False, default_flow_style=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, self.path)
            self.fsync_directory()
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass

    def add(self, username: str, record: dict) -> None:
        with self.write_lock():
            data = self.load()
            folded = username.casefold()
            if any(name.casefold() == folded for name in data["users"]):
                raise ValueError("username already exists")
            data["users"][username] = record
            self._write_locked(data)

    def apply_pending_record(self, username: str, record: dict) -> str:
        with self.write_lock():
            data = self.load()
            existing = data["users"].get(username)
            if existing is not None:
                if hmac.compare_digest(str(existing.get("password", "")), str(record.get("password", ""))):
                    self.fsync_directory()
                    return "already-applied"
                return "conflict"
            if any(name.casefold() == username.casefold() for name in data["users"]):
                return "conflict"
            data["users"][username] = record
            self._write_locked(data)
            return "applied"

    def update(self, username: str, *, disabled: bool | None, groups: list[str] | None) -> tuple[str, dict]:
        with self.write_lock():
            data = self.load()
            exact = next((name for name in data["users"] if name.casefold() == username.casefold()), None)
            if exact is None:
                raise KeyError("user not found")
            record = data["users"][exact]
            changes = {}
            if disabled is not None:
                record["disabled"] = bool(disabled)
                changes["disabled"] = bool(disabled)
            if groups is not None:
                record["groups"] = sorted(set(groups))
                changes["groups"] = record["groups"]
            self._write_locked(data)
            return exact, changes

    def summary(self) -> list[dict]:
        users = self.load()["users"]
        return [
            {"username": name, "displayname": str(record.get("displayname") or ""),
             "groups": sorted(str(group) for group in (record.get("groups") or [])),
             "disabled": bool(record.get("disabled", False))}
            for name, record in sorted(users.items(), key=lambda item: item[0].casefold())
        ]


class ClosingSQLiteConnection(sqlite3.Connection):
    """Make ``with connection`` release the handle as well as its transaction."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class Store:
    def __init__(self, db_path: Path, users_path: Path, hasher=None):
        self.db_path = db_path
        self.db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.db_path.parent, 0o700)
        self.users = UserFile(users_path)
        self.hasher = hasher or hash_password
        self.lock = threading.RLock()
        self._init_db()
        self.recover_pending()
        self.recover_pending_user_updates()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5, isolation_level=None,
                               factory=ClosingSQLiteConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA secure_delete=ON")
        os.chmod(self.db_path, 0o600)
        return conn

    def _init_db(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS invites (
                    id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    max_uses INTEGER NOT NULL CHECK(max_uses BETWEEN 1 AND 50),
                    used_count INTEGER NOT NULL DEFAULT 0,
                    groups_json TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS pending (
                    id TEXT PRIMARY KEY,
                    invite_id TEXT NOT NULL REFERENCES invites(id),
                    username TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pending_user_updates (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    changes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    subject TEXT NOT NULL DEFAULT '',
                    details_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS audit_at_idx ON audit(at);
            """)
        os.chmod(self.db_path, 0o600)

    def _audit(self, db: sqlite3.Connection, action: str, subject: str = "",
               details: dict | None = None, *, actor: str = "system") -> None:
        db.execute("INSERT INTO audit(at,actor,action,subject,details_json) VALUES(?,?,?,?,?)",
                   (iso(utc_now()), actor, action, subject, json.dumps(details or {}, sort_keys=True)))

    def create_invite(self, days: int, max_uses: int, groups: list[str], *, actor: str = "system") -> tuple[dict, str]:
        if (type(days) is not int or type(max_uses) is not int
                or not (1 <= days <= MAX_INVITE_DAYS and 1 <= max_uses <= MAX_INVITE_USES)):
            raise ValueError("invalid invitation expiry or use limit")
        if not isinstance(groups, list) or any(not isinstance(group, str) for group in groups):
            raise ValueError("groups must be a list of strings")
        checked_groups = sorted(set(groups))
        if any(group not in ALLOWED_GROUPS for group in checked_groups):
            raise ValueError("unsupported group")
        raw = secrets.token_urlsafe(32)
        invite_id = secrets.token_hex(12)
        now = utc_now()
        expires = now + dt.timedelta(days=days)
        with self.lock:
            self.recover_pending()
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO invites(id,token_hash,created_at,expires_at,max_uses,groups_json) VALUES(?,?,?,?,?,?)",
                           (invite_id, token_digest(raw), iso(now), iso(expires), max_uses, json.dumps(checked_groups)))
                self._audit(db, "invite_created", invite_id, {"expires_at": iso(expires), "max_uses": max_uses, "groups": checked_groups}, actor=actor)
                db.commit()
        return ({"id": invite_id, "created_at": iso(now), "expires_at": iso(expires),
                 "max_uses": max_uses, "used_count": 0, "groups": checked_groups,
                 "revoked": False}, raw)

    def _find_invite(self, db: sqlite3.Connection, raw_token: str):
        if not TOKEN_RE.fullmatch(raw_token):
            return None
        return db.execute("SELECT * FROM invites WHERE token_hash=?", (token_digest(raw_token),)).fetchone()

    def check_invite(self, raw_token: str) -> dict:
        with self._connect() as db:
            row = self._find_invite(db, raw_token)
            if not row or row["revoked"] or row["used_count"] >= row["max_uses"] or utc_now() >= dt.datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00")):
                return {"valid": False}
            try:
                valid_groups = groups_allowed(json.loads(row["groups_json"]))
            except (ValueError, TypeError):
                valid_groups = False
            if not valid_groups:
                return {"valid": False}
            pending = db.execute("SELECT COUNT(*) FROM pending WHERE invite_id=?", (row["id"],)).fetchone()[0]
            return {"valid": pending + row["used_count"] < row["max_uses"], "expires_at": row["expires_at"],
                    "remaining_uses": max(0, row["max_uses"] - row["used_count"] - pending)}

    def redeem(self, raw_token: str, username: str, displayname: str, email: str, password: str) -> None:
        username = username.strip().casefold()
        displayname = displayname.strip()
        email = email.strip().casefold()
        if not USERNAME_RE.fullmatch(username) or username in {admin.casefold() for admin in ADMINS}:
            raise ValueError("username is not allowed")
        if not 1 <= len(displayname) <= 80 or not EMAIL_RE.fullmatch(email) or len(email) > 254:
            raise ValueError("display name or email is invalid")
        if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH or any(c in password for c in "\r\n\x00"):
            raise ValueError("password must be 12–256 characters and contain no line breaks")
        with self.lock:
            self.recover_pending()
            data = self.users.load()
            if any(name.casefold() == username for name in data["users"]):
                raise ValueError("username already exists")
            if not self.check_invite(raw_token).get("valid"):
                raise ValueError("invitation is invalid, expired, revoked, or fully used")
            password_hash = self.hasher(password)
            if not isinstance(password_hash, str) or not ARGON_RE.fullmatch(password_hash.encode("ascii", errors="ignore")):
                raise RuntimeError("password hasher returned an unsupported format")
            row_id = secrets.token_hex(16)
            record = {"displayname": displayname, "email": email, "groups": [], "password": password_hash, "disabled": False}
            record_json = json.dumps(record, sort_keys=True)
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                invite = self._find_invite(db, raw_token)
                if not invite or invite["revoked"] or utc_now() >= dt.datetime.fromisoformat(invite["expires_at"].replace("Z", "+00:00")):
                    db.rollback()
                    raise ValueError("invitation is invalid or expired")
                pending_count = db.execute("SELECT COUNT(*) FROM pending WHERE invite_id=?", (invite["id"],)).fetchone()[0]
                if invite["used_count"] + pending_count >= invite["max_uses"]:
                    db.rollback()
                    raise ValueError("invitation use limit reached")
                try:
                    groups = json.loads(invite["groups_json"])
                except (ValueError, TypeError):
                    groups = None
                if not groups_allowed(groups):
                    db.rollback()
                    raise ValueError("invitation has unsupported groups")
                record["groups"] = groups
                record_json = json.dumps(record, sort_keys=True)
                db.execute("INSERT INTO pending(id,invite_id,username,record_json,created_at) VALUES(?,?,?,?,?)",
                           (row_id, invite["id"], username, record_json, iso(utc_now())))
                db.commit()
            try:
                self.users.add(username, record)
            except Exception as write_error:
                try:
                    outcome = self.users.apply_pending_record(username, record)
                    if outcome in ("applied", "already-applied"):
                        self._finish_pending(row_id, invite["id"], username)
                        return
                    else:
                        with self._connect() as db:
                            db.execute("BEGIN IMMEDIATE")
                            db.execute("DELETE FROM pending WHERE id=?", (row_id,))
                            self._audit(db, "registration_conflict_recovered", username, actor="system")
                            db.commit()
                except Exception:
                    # Keep the durable pending row for a later safe recovery.
                    pass
                raise RuntimeError("account write did not complete; recovery is pending") from write_error
            self._finish_pending(row_id, invite["id"], username, record["groups"])

    def _finish_pending(self, row_id: str, invite_id: str, username: str, groups: list[str] | None = None) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            removed = db.execute("DELETE FROM pending WHERE id=? AND invite_id=? AND username=?",
                                 (row_id, invite_id, username))
            if not removed.rowcount:
                db.rollback()
                return
            db.execute("UPDATE invites SET used_count=used_count+1 WHERE id=?", (invite_id,))
            action = "account_created" if groups is not None else "account_created_recovered"
            details = {"invite_id": invite_id}
            if groups is not None:
                details["groups"] = groups
            self._audit(db, action, username, details,
                        actor=f"invite:{invite_id}" if groups is not None else "system")
            db.commit()

    def recover_pending(self) -> None:
        with self.lock:
            with self._connect() as db:
                rows = db.execute("SELECT * FROM pending ORDER BY created_at").fetchall()
            for row in rows:
                record = json.loads(row["record_json"])
                if not isinstance(record, dict) or not groups_allowed(record.get("groups")):
                    raise RuntimeError("pending registration has unsupported groups; manual reconciliation required")
                outcome = self.users.apply_pending_record(row["username"], record)
                if outcome in ("applied", "already-applied"):
                    self._finish_pending(row["id"], row["invite_id"], row["username"])
                else:
                    with self._connect() as db:
                        db.execute("BEGIN IMMEDIATE")
                        self._audit(db, "registration_conflict_recovered", row["username"], actor="system")
                        db.execute("DELETE FROM pending WHERE id=?", (row["id"],))
                        db.commit()

    def list_invites(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT id,created_at,expires_at,max_uses,used_count,groups_json,revoked FROM invites ORDER BY created_at DESC LIMIT 100").fetchall()
        now = utc_now()
        return [{"id": row["id"], "created_at": row["created_at"], "expires_at": row["expires_at"],
                 "max_uses": row["max_uses"], "used_count": row["used_count"],
                 "groups": json.loads(row["groups_json"]), "revoked": bool(row["revoked"]),
                 "expired": now >= dt.datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))}
                for row in rows]

    def revoke_invite(self, invite_id: str, *, actor: str = "system") -> bool:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute("UPDATE invites SET revoked=1 WHERE id=? AND revoked=0", (invite_id,))
            if cur.rowcount:
                self._audit(db, "invite_revoked", invite_id, actor=actor)
            db.commit()
            return bool(cur.rowcount)

    def update_user(self, username: str, *, disabled: bool | None = None, groups: list[str] | None = None,
                    expected_groups: list[str] | None = None, actor: str = "system") -> None:
        if username.casefold() in {admin.casefold() for admin in ADMINS}:
            raise ValueError("the administrator account is protected")
        if disabled is None and groups is None:
            raise ValueError("no account change requested")
        if groups is not None:
            if not groups_allowed(groups) or not groups_allowed(expected_groups):
                raise ValueError("groups and expected groups must be explicitly allowed lists")
        elif expected_groups is not None:
            raise ValueError("unexpected group precondition")
        with self.lock:
            self.recover_pending_user_updates()
            # Hold the same cross-process lock as the password helper from the
            # baseline read through the durable intent, YAML swap, and audit.
            with self.users.write_lock():
                data = self.users.load()
                users = data["users"]
                exact = next((name for name in users if name.casefold() == username.casefold()), None)
                if exact is None:
                    raise KeyError("user not found")
                record = users[exact]
                before = {}
                after = {}
                if disabled is not None:
                    before["disabled"] = bool(record.get("disabled", False))
                    after["disabled"] = bool(disabled)
                if groups is not None:
                    existing = sorted(set(record.get("groups") or []))
                    managed_existing = set(existing) & ALLOWED_GROUPS
                    if managed_existing != set(expected_groups):
                        raise StaleGroupsError("groups changed; refresh before retrying")
                    before["groups"] = existing
                    # Admin UI manages only its allowlisted rights. Keep any
                    # other groups owned by existing integrations.
                    after["groups"] = sorted((set(existing) - ALLOWED_GROUPS) | set(groups))
                intent = {"before": before, "after": after}
                update_id = secrets.token_hex(16)
                with self._connect() as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute(
                        "INSERT INTO pending_user_updates(id,username,changes_json,created_at) VALUES(?,?,?,?)",
                        (update_id, exact, json.dumps(intent, sort_keys=True), iso(utc_now())),
                    )
                    self._audit(db, "user_update_requested", exact, after, actor=actor)
                    db.commit()
                for key, value in after.items():
                    record[key] = value
                try:
                    self.users._write_locked(data)
                except Exception as write_error:
                    # A failed fsync can follow a successful atomic swap.
                    # Inspect the file; never replay the request later.
                    outcome = self._reconcile_user_update_locked(update_id, exact, intent)
                    if outcome == "applied":
                        return
                    raise RuntimeError("account update did not complete") from write_error
                try:
                    self._finish_user_update(update_id, exact, after, actor=actor)
                except Exception:
                    # The YAML may already be durable. Reconcile once while
                    # retaining the file lock; leave a pending intent if the
                    # audit database itself is still unavailable.
                    self._reconcile_user_update_locked(update_id, exact, intent)

    def _finish_user_update(self, update_id: str, username: str, changes: dict, *,
                            recovered: bool = False, outcome: str = "applied", actor: str = "system") -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            removed = db.execute("DELETE FROM pending_user_updates WHERE id=?", (update_id,))
            if removed.rowcount:
                action = ("user_updated_recovered" if recovered else "user_updated") if outcome == "applied" else "user_update_" + outcome
                self._audit(db, action, username, changes,
                            actor="system" if recovered or outcome != "applied" else actor)
            db.commit()

    def _reconcile_user_update_locked(self, update_id: str, username: str, intent: dict) -> str:
        before, after = intent.get("before"), intent.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict) or set(before) != set(after):
            raise RuntimeError("unsupported pending user update journal")
        users = self.users.load()["users"]
        record = users.get(username)
        if not isinstance(record, dict):
            outcome = "conflict"
        else:
            observed = {}
            for key in after:
                observed[key] = (bool(record.get("disabled", False)) if key == "disabled"
                                 else sorted(set(record.get("groups") or [])))
            if observed == after:
                # A prior error may have followed os.replace but preceded the
                # directory durability barrier. Only finalize after that
                # barrier succeeds now.
                self.users.fsync_directory()
                outcome = "applied"
            elif observed == before:
                outcome = "not_applied"
            else:
                outcome = "conflict"
        self._finish_user_update(update_id, username, after, recovered=True, outcome=outcome)
        return outcome

    def recover_pending_user_updates(self) -> None:
        with self.lock:
            with self.users.write_lock():
                with self._connect() as db:
                    rows = db.execute(
                        "SELECT id,username,changes_json FROM pending_user_updates ORDER BY created_at,id"
                    ).fetchall()
                for row in rows:
                    self._reconcile_user_update_locked(row["id"], row["username"],
                                                       json.loads(row["changes_json"]))

    def audit_legacy_notifications(self, action: str, outcome: str, *, actor: str = "system") -> None:
        allowed = {
            "legacy_notifications_viewed": {"available", "empty", "missing"},
            "legacy_notifications_purge_requested": {"retention_due", "not_due", "missing"},
        }
        if action not in allowed or outcome not in allowed[action]:
            raise ValueError("unsupported notification audit event")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._audit(db, action, "legacy_notification_archive", {"outcome": outcome}, actor=actor)
            db.commit()

    def audit_tail(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT at,actor,action,subject,details_json FROM audit ORDER BY id DESC LIMIT 50").fetchall()
        return [{"at": r["at"], "actor": r["actor"], "action": r["action"],
                 "subject": r["subject"], "details": json.loads(r["details_json"])} for r in rows]

    def prune(self, days: int = 180) -> None:
        cutoff = iso(utc_now() - dt.timedelta(days=days))
        with self._connect() as db:
            db.execute("DELETE FROM audit WHERE at < ?", (cutoff,))


def hash_password(password: str) -> str:
    """Hash through Authelia's CLI without argv, environment, or log exposure."""
    password_bytes = bytearray(password.encode("utf-8"))
    master, slave = pty.openpty()
    os.set_blocking(master, False)
    output = bytearray()
    proc = None
    sent = False
    try:
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        command = ["docker", "exec", "-it", "authelia", "/bin/sh", "-c", HASH_COMMAND]
        # Match the verified docker exec TTY probe: keep the PTY's inherited
        # session semantics while still isolating the password from argv/env.
        proc = subprocess.Popen(command, stdin=slave, stdout=slave, stderr=slave,
                                close_fds=True)
        os.close(slave)
        slave = -1
        deadline = time.monotonic() + HASH_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(master, 4096)
                    if not chunk:
                        break
                    output.extend(chunk)
                except BlockingIOError:
                    continue
                except OSError:
                    break
                if len(output) > 16384:
                    raise RuntimeError("password hash output exceeded the safe limit")
                if not sent and HASH_READY_MARKER in output:
                    input_buffer = bytearray(password_bytes)
                    input_buffer.append(10)
                    view = memoryview(input_buffer)
                    try:
                        while view:
                            written = os.write(master, view)
                            if written <= 0:
                                raise OSError("password input write made no progress")
                            previous_view = view
                            view = view[written:]
                            previous_view.release()
                    finally:
                        view.release()
                        input_buffer[:] = b"\x00" * len(input_buffer)
                    sent = True
            if proc.poll() is not None and not ready:
                break
        if proc is not None and proc.poll() is None:
            proc.kill()
            raise RuntimeError("password hash operation timed out")
        if proc is None or proc.wait(timeout=2) != 0 or not sent or bytes(password_bytes) in output:
            raise RuntimeError("password hashing failed safely")
        match = ARGON_RE.search(output)
        if not match:
            raise RuntimeError("Authelia returned an unsupported password hash")
        return match.group(0).decode("ascii")
    finally:
        if slave >= 0:
            os.close(slave)
        os.close(master)
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        password_bytes[:] = b"\x00" * len(password_bytes)
        output[:] = b"\x00" * len(output)


class RateLimiter:
    def __init__(self):
        self.lock = threading.Lock()
        self.events: dict[str, collections.deque[float]] = {}

    def allow(self, bucket: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self.lock:
            q = self.events.setdefault(bucket, collections.deque())
            while q and now - q[0] >= window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


# Fixed sibling UI assets; Python -I intentionally excludes the script directory.
_ui_spec = importlib.util.spec_from_file_location(
    "authelia_onboarding_ui", Path(__file__).with_name("ui.py"))
if _ui_spec is None or _ui_spec.loader is None:
    raise RuntimeError("account interface assets are unavailable")
_ui_module = importlib.util.module_from_spec(_ui_spec)
_ui_spec.loader.exec_module(_ui_module)
CSS = _ui_module.CSS
PUBLIC_PAGE = _ui_module.PUBLIC_PAGE
ACCEPT_JS = _ui_module.ACCEPT_JS
ADMIN_PAGE = _ui_module.ADMIN_PAGE
ADMIN_JS = _ui_module.ADMIN_JS






class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "JarvisOnboarding"
    sys_version = ""

    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined]

    @property
    def legacy_notifications(self):
        return self.server.legacy_notifications  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        # Do not log headers, bodies, query strings, invite tokens, or passwords.
        path = urllib.parse.urlsplit(self.path).path
        print(f"onboarding_http {self.command} {path} {args[1] if len(args) > 1 else ''}", flush=True)

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _json(self, code: int, value: object) -> None:
        self._send(code, _json_bytes(value), "application/json; charset=utf-8")

    def _trusted_peer(self) -> bool:
        try:
            return ipaddress.ip_address(self.client_address[0]) == ipaddress.ip_address(TRUSTED_PROXY)
        except ValueError:
            return False

    def _is_admin(self) -> bool:
        return self._trusted_peer() and any(
            hmac.compare_digest(self.headers.get("Remote-User", "").encode("utf-8"), admin.encode("utf-8"))
            for admin in ADMINS)

    def _same_origin(self) -> bool:
        return self.headers.get("Origin", "") == EXPECTED_ORIGIN

    def _read_json(self) -> dict:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ValueError("application/json required")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if not 1 <= length <= 8192:
            raise ValueError("request body size is invalid")
        data = json.loads(self.rfile.read(length))
        if not isinstance(data, dict):
            raise ValueError("JSON object required")
        return data

    def _limited(self, bucket: str, maximum: int) -> bool:
        return self.server.rate_limiter.allow(bucket, maximum)  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        if not self._trusted_peer():
            self._json(403, {"error": "forbidden"})
            return
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith(PREFIX + "/admin") and not self._is_admin():
            self._json(403, {"error": "administrator authentication required"})
            return
        if path.startswith(PREFIX + "/admin") and not self._limited("admin-get", 180):
            self._json(429, {"error": "rate limit exceeded"})
            return
        if path in (PREFIX + "/accept", PREFIX + "/accept.js", PREFIX + "/site.css"):
            body, kind = {PREFIX + "/accept": (PUBLIC_PAGE, "text/html; charset=utf-8"),
                          PREFIX + "/accept.js": (ACCEPT_JS, "application/javascript; charset=utf-8"),
                          PREFIX + "/site.css": (CSS, "text/css; charset=utf-8")}[path]
            self._send(200, body, kind)
            return
        if path == PREFIX + "/admin":
            self._send(200, ADMIN_PAGE, "text/html; charset=utf-8")
            return
        if path == PREFIX + "/admin.js":
            self._send(200, ADMIN_JS, "application/javascript; charset=utf-8")
            return
        if path == PREFIX + "/admin/api/summary":
            # Do not inspect site-specific Authelia configuration or databases.
            users = self.store.users.summary()
            unknown = {"status": "unknown", "totp": None, "webauthn": None, "duo": None}
            context = {"users": [{**user, "mfa": dict(unknown)} for user in users],
                       "admin_username": ADMIN, "admin_usernames": list(ADMINS),
                       "directory_source": "Authelia-Dateibackend",
                       "group_catalog": [{"id": group, "label": group, "editable": True,
                                          "description": "Explizit freigegebene Gruppe"}
                                         for group in sorted(ALLOWED_GROUPS)],
                       "mfa_policy": {"status": "unknown"}}
            self._json(200, {**context, "invites": self.store.list_invites(),
                             "audit": self.store.audit_tail(), "filesystem_notifications_active": False})
            return
        # Notification archive endpoints are not available in this candidate.
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._trusted_peer():
            self._json(403, {"error": "forbidden"})
            return
        path = urllib.parse.urlsplit(self.path).path
        admin = path.startswith(PREFIX + "/admin/")
        if admin and not self._is_admin():
            self._json(403, {"error": "administrator authentication required"})
            return
        if admin and (self.headers.get("X-Requested-With") != "JarvisOnboarding" or not self._same_origin()):
            self._json(403, {"error": "same-origin request required"})
            return
        if not self._limited("admin-post" if admin else "public-post", 120 if admin else 30):
            self._json(429, {"error": "rate limit exceeded"})
            return
        try:
            data = self._read_json()
            if path == PREFIX + "/api/invite/check":
                token = data.get("token", "")
                if not isinstance(token, str):
                    raise ValueError("invitation is invalid")
                self._json(200, self.store.check_invite(token))
                return
            if path == PREFIX + "/api/invite/redeem":
                if not self._same_origin():
                    raise PermissionError("same-origin request required")
                values = [data.get(k) for k in ("token", "username", "displayname", "email", "password")]
                if not all(isinstance(value, str) for value in values):
                    raise ValueError("required account fields are missing")
                self.store.redeem(*values)
                self._json(201, {"ok": True})
                return
            if path == PREFIX + "/admin/api/invites":
                days, max_uses = data.get("days"), data.get("max_uses")
                if type(days) is not int or type(max_uses) is not int:
                    raise ValueError("days and max_uses must be integers")
                result, raw = self.store.create_invite(days, max_uses, data.get("groups", []), actor=self.headers["Remote-User"])
                self._json(201, {**result, "token": raw})
                return
            match = re.fullmatch(re.escape(PREFIX) + r"/admin/api/invites/([a-f0-9]{24})/revoke", path)
            if match:
                self._json(200 if self.store.revoke_invite(match.group(1), actor=self.headers["Remote-User"]) else 404, {"ok": True})
                return
            match = re.fullmatch(re.escape(PREFIX) + r"/admin/api/users/([^/]+)/disabled", path)
            if match:
                disabled = data.get("disabled")
                if not isinstance(disabled, bool):
                    raise ValueError("disabled must be boolean")
                self.store.update_user(urllib.parse.unquote(match.group(1)), disabled=disabled, actor=self.headers["Remote-User"])
                self._json(200, {"ok": True})
                return
            match = re.fullmatch(re.escape(PREFIX) + r"/admin/api/users/([^/]+)/groups", path)
            if match:
                groups = data.get("groups")
                expected = data.get("expected_groups")
                if not groups_allowed(groups) or not groups_allowed(expected):
                    raise ValueError("groups and expected groups must be explicitly allowed lists")
                self.store.update_user(urllib.parse.unquote(match.group(1)), groups=groups,
                                       expected_groups=expected, actor=self.headers["Remote-User"])
                self._json(200, {"ok": True})
                return
            self._json(404, {"error": "not found"})
        except StaleGroupsError as exc:
            self._json(409, {"error": str(exc)})
        except PermissionError as exc:
            self._json(403, {"error": str(exc)})
        except KeyError as exc:
            self._json(404, {"error": str(exc).strip("'")})
        except ValueError as exc:
            self._json(400, {"error": str(exc)})
        except Exception:
            # Details may contain personal data or hashes; keep responses generic.
            message = ("request outcome could not be confirmed; reload the administrator view before retrying"
                       if admin else "account creation outcome could not be confirmed; contact the administrator before retrying")
            self._json(503, {"error": message})


def configure_from_environment() -> tuple[str, int]:
    """Require explicit site-specific authorization before opening a socket."""
    global ADMIN, ADMINS, TRUSTED_PROXY, EXPECTED_ORIGIN, ALLOWED_GROUPS
    values = {key: os.environ.get(key, "").strip() for key in (
        "ONBOARDING_ADMINS", "ONBOARDING_TRUSTED_PROXY", "ONBOARDING_ORIGIN",
        "ONBOARDING_BIND_IP", "ONBOARDING_BIND_PORT")}
    if not all(values.values()):
        raise RuntimeError("all ONBOARDING security and bind settings are required")
    admins = tuple(values["ONBOARDING_ADMINS"].split(","))
    if not admins or any(not USERNAME_RE.fullmatch(name) for name in admins):
        raise RuntimeError("invalid administrator allowlist")
    if len({name.casefold() for name in admins}) != len(admins):
        raise RuntimeError("duplicate administrator names")
    try:
        proxy_ip = ipaddress.ip_address(values["ONBOARDING_TRUSTED_PROXY"])
        bind_ip = ipaddress.ip_address(values["ONBOARDING_BIND_IP"])
        port = int(values["ONBOARDING_BIND_PORT"])
    except ValueError as exc:
        raise RuntimeError("invalid proxy or bind address") from exc
    # ThreadingHTTPServer uses AF_INET: do not accept an unusable IPv6 setup.
    if proxy_ip.version != 4 or bind_ip.version != 4:
        raise RuntimeError("only IPv4 proxy and bind addresses are supported")
    if (proxy_ip.is_unspecified or proxy_ip.is_multicast or bind_ip.is_unspecified
            or bind_ip.is_multicast or not (1 <= port <= 65535)):
        raise RuntimeError("unspecified or multicast addresses and invalid ports are forbidden")
    origin = urllib.parse.urlsplit(values["ONBOARDING_ORIGIN"])
    if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
            or origin.path or origin.query or origin.fragment):
        raise RuntimeError("origin must be an HTTPS origin without path or credentials")
    groups = set(filter(None, os.environ.get("ONBOARDING_ALLOWED_GROUPS", "").split(",")))
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", group) for group in groups):
        raise RuntimeError("invalid group identifier")
    ADMIN, ADMINS = admins[0], admins
    TRUSTED_PROXY, EXPECTED_ORIGIN = values["ONBOARDING_TRUSTED_PROXY"], values["ONBOARDING_ORIGIN"]
    ALLOWED_GROUPS = groups
    _notifications_module.ADMIN_USERNAMES = admins
    return str(bind_ip), port


def main() -> None:
    bind_ip, bind_port = configure_from_environment()
    store = Store(DB_PATH, USERS_PATH)
    store.prune()
    server = ThreadingHTTPServer((bind_ip, bind_port), Handler)
    server.daemon_threads = True
    server.store = store  # type: ignore[attr-defined]
    server.rate_limiter = RateLimiter()  # type: ignore[attr-defined]
    print("authelia_onboarding_ready", flush=True)
    server.serve_forever(poll_interval=0.5)


if __name__ == "__main__":
    main()
