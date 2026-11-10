"""Read-only account context; never reads MFA credential or secret columns.

This is descriptive metadata. The proxy, Authelia ACL and service identity
guard remain the authorization boundary. Unsupported rules/storage fail to
explicit unknown rather than inferring an effective access permission.
"""
from __future__ import annotations

import fnmatch
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import stat

import yaml


CONFIG_PATH = Path("/opt/authelia/config/configuration.yml")
STORAGE_PATH = Path("/opt/authelia/config/db.sqlite3")
METHOD_TABLES = {"totp": "totp_configurations", "webauthn": "webauthn_credentials", "duo": "duo_devices"}


class UniqueLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("account metadata unavailable")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def _regular(path: Path, *, private: bool) -> os.stat_result:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_nlink != 1 or info.st_mode & (0o077 if private else 0o022)):
        raise RuntimeError("account metadata unavailable")
    return info


def _read_configuration(path: Path) -> dict:
    before = _regular(path, private=False)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        current = os.fstat(stream.fileno())
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino) or current.st_size > 1024 * 1024:
            raise RuntimeError("account metadata unavailable")
        data = stream.read(1024 * 1024 + 1)
    result = yaml.load(data, Loader=UniqueLoader)
    if not isinstance(result, dict):
        raise RuntimeError("account metadata unavailable")
    return result


def _subjects(value: object) -> list[str] | None:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _domain_rules(rules: list, domain: str) -> list[dict] | None:
    selected = []
    for rule in rules:
        if not isinstance(rule, dict) or "domain_regex" in rule:
            return None
        domains = rule.get("domain", [])
        if isinstance(domains, str):
            domains = [domains]
        if not isinstance(domains, list) or not all(isinstance(item, str) for item in domains):
            return None
        if any(fnmatch.fnmatchcase(domain, item) for item in domains):
            # This reader describes only simple domain rules. Do not pretend
            # to evaluate conditional ACLs, resource regexes or network scope.
            if set(rule) - {"domain", "policy", "subject"}:
                return None
            selected.append(rule)
    return selected


def policy_context(config: dict) -> dict:
    unknown = {"status": "unknown", "default": None, "jellyfin_browser": None,
               "jellyfin_app": None, "jellyfin_app_group": None}
    access = config.get("access_control")
    if not isinstance(access, dict) or not isinstance(access.get("rules"), list):
        return unknown
    browser = _domain_rules(access["rules"], "jellyfin.example.invalid")
    app = _domain_rules(access["rules"], "jellyfin-app.example.invalid")
    if (access.get("default_policy") != "two_factor" or not browser or not app or len(app) < 2
            or browser[0].get("policy") != "two_factor" or _subjects(browser[0].get("subject")) != []
            or app[0].get("policy") != "one_factor" or _subjects(app[0].get("subject")) != ["group:jellyfin-users"]
            or app[1].get("policy") != "deny" or _subjects(app[1].get("subject")) != []):
        return unknown
    return {"status": "verified", "default": "two_factor", "jellyfin_browser": "two_factor",
            "jellyfin_app": "one_factor", "jellyfin_app_group": "jellyfin-users"}


def mfa_context(path: Path, usernames: list[str]) -> dict[str, dict]:
    result = {name: {"status": "unknown", "totp": None, "webauthn": None, "duo": None} for name in usernames}
    try:
        if not path.is_absolute() or len(usernames) > 10000:
            return result
        directory = path.parent.lstat()
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
                or directory.st_mode & 0o022):
            return result
        # The existing Authelia SQLite file is root-owned 0644. Require owner
        # controlled writes without altering its established storage mode.
        before = _regular(path, private=False)
        # SQLite must see its actual WAL. immutable=1 would silently ignore
        # live registrations, so use the real path and read-only mode instead.
        for suffix in ("-wal", "-shm"):
            sidecar = path.with_name(path.name + suffix)
            if sidecar.exists() or sidecar.is_symlink():
                _regular(sidecar, private=False)
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.25)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            for table in METHOD_TABLES.values():
                columns = connection.execute(f"PRAGMA table_info({table})").fetchall()
                if not any(column[1] == "username" for column in columns):
                    raise RuntimeError("account metadata unavailable")
            known = {}
            for name in usernames:
                methods = {method: bool(connection.execute(
                    f"SELECT EXISTS(SELECT 1 FROM {table} WHERE username = ? LIMIT 1)", (name,)).fetchone()[0])
                    for method, table in METHOD_TABLES.items()}
                known[name] = {"status": "known", **methods}
            after = _regular(path, private=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise RuntimeError("account metadata unavailable")
            result = known
    except (OSError, ValueError, sqlite3.Error, RuntimeError):
        # No paths, usernames, SQL errors or credential values in responses.
        pass
    return result


class AccountContext:
    def __init__(self, config_path: Path = CONFIG_PATH, storage_path: Path = STORAGE_PATH):
        self.config_path = config_path
        self.storage_path = storage_path

    def summary(self, users: list[dict], admin_username: str, admin_usernames: tuple[str, ...]) -> dict:
        policy = policy_context({})
        try:
            config = _read_configuration(self.config_path)
            policy = policy_context(config)
            storage = config.get("storage", {}).get("local", {})
            # Fixed known Docker bind mapping, not a request-controlled path.
            configured = storage.get("path") if isinstance(storage, dict) else None
            methods = (mfa_context(self.storage_path, [user["username"] for user in users])
                       if configured == "/config/db.sqlite3" else {})
        except (OSError, ValueError, RuntimeError, yaml.YAMLError, AttributeError):
            methods = {}
        unknown = {"status": "unknown", "totp": None, "webauthn": None, "duo": None}
        return {"users": [{**user, "mfa": methods.get(user["username"], dict(unknown))} for user in users],
                "admin_username": admin_username, "admin_usernames": list(admin_usernames),
                "directory_source": "Authelia-Dateibackend",
                "group_catalog": [],
                "mfa_policy": policy}
