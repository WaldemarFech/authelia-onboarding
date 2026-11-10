"""Narrow, comment-preserving Authelia configuration edit for onboarding."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
import shutil
import sys
import tempfile
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

import yaml


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


PORTAL_DOMAIN = ""
ADMIN_SUBJECTS = []
RESOURCE_PATTERNS = [
    r"^/onboarding/admin$",
    r"^/onboarding/admin\.js$",
    r"^/onboarding/admin/.*$",
]


class ConfigurationPatchError(ValueError):
    pass


@dataclass(frozen=True)
class PatchResult:
    text: str
    changed: bool


def _mapping_value(node: yaml.Node, key: str) -> yaml.Node | None:
    if not isinstance(node, yaml.MappingNode):
        return None
    for key_node, value_node in node.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value == key:
            return value_node
    return None


def _domain_matches(rule: dict, domain: str) -> bool:
    domains = rule.get("domain", [])
    if isinstance(domains, str):
        domains = [domains]
    return domain in domains


def _expected_rules() -> list[dict]:
    shared = {"domain": [PORTAL_DOMAIN], "resources": list(RESOURCE_PATTERNS)}
    return [
        {**shared, "subject": list(ADMIN_SUBJECTS), "policy": "two_factor"},
        {**shared, "policy": "deny"},
    ]


def _snippet(indent: int) -> str:
    lead = " " * indent
    child = " " * (indent + 2)
    grandchild = " " * (indent + 4)
    rules = _expected_rules()
    lines: list[str] = []
    for rule in rules:
        lines.extend((f"{lead}- domain:", f"{grandchild}- {PORTAL_DOMAIN}", f"{child}resources:"))
        lines.extend(f"{grandchild}- '{pattern}'" for pattern in RESOURCE_PATTERNS)
        if "subject" in rule:
            lines.append(f"{child}subject:")
            lines.extend(f"{grandchild}- '{subject}'" for subject in ADMIN_SUBJECTS)
        lines.append(f"{child}policy: {rule['policy']}")
    return "\n".join(lines) + "\n"


def patch_configuration(text: str) -> PatchResult:
    """Enable file-watch and enforce labowner/jarvis MFA admin access before bypass.

    The transformer edits source spans instead of re-dumping the complete YAML,
    preserving comments, unrelated rule text, and formatting. The exact legacy
    LabUser or labowner-only rule pair can migrate by editing only its subject list.
    """

    if not PORTAL_DOMAIN or not ADMIN_SUBJECTS:
        raise ConfigurationPatchError("explicit portal and administrator policy is required")
    try:
        before = yaml.load(text, Loader=DuplicateKeyLoader)
        root_node = yaml.compose(text, Loader=yaml.SafeLoader)
    except Exception as exc:
        raise ConfigurationPatchError("Authelia YAML could not be parsed safely") from exc
    if not isinstance(before, dict) or not isinstance(root_node, yaml.MappingNode):
        raise ConfigurationPatchError("Authelia YAML root must be a mapping")

    auth_backend = before.get("authentication_backend")
    file_backend = auth_backend.get("file") if isinstance(auth_backend, dict) else None
    access_control = before.get("access_control")
    rules = access_control.get("rules") if isinstance(access_control, dict) else None
    if not isinstance(file_backend, dict) or not isinstance(access_control, dict) or not isinstance(rules, list):
        raise ConfigurationPatchError("expected file backend and access-control rules were not found")

    auth_node = _mapping_value(root_node, "authentication_backend")
    file_node = _mapping_value(auth_node, "file") if auth_node else None
    access_node = _mapping_value(root_node, "access_control")
    rules_node = _mapping_value(access_node, "rules") if access_node else None
    if not isinstance(file_node, yaml.MappingNode) or not isinstance(rules_node, yaml.SequenceNode):
        raise ConfigurationPatchError("configuration source structure is unsupported")

    watch_value = file_backend.get("watch")
    if watch_value not in (None, False, True):
        raise ConfigurationPatchError("file-backend watch must be boolean or unset")
    watch_node = _mapping_value(file_node, "watch")
    edits: list[tuple[int, int, str]] = []
    if watch_value is not True:
        if watch_node is not None:
            if not isinstance(watch_node, yaml.ScalarNode):
                raise ConfigurationPatchError("file-backend watch source node is not scalar")
            edits.append((watch_node.start_mark.index, watch_node.end_mark.index, "true"))
        else:
            end_line = file_node.end_mark.line
            watch_indent = " " * file_node.start_mark.column
            lines = text.splitlines(keepends=True)
            insertion = sum(len(line) for line in lines[:end_line])
            if end_line >= len(lines) and text and not text.endswith("\n"):
                insertion = len(text)
                edits.append((insertion, insertion, f"\n{watch_indent}watch: true\n"))
            else:
                edits.append((insertion, insertion, f"{watch_indent}watch: true\n"))

    expected = _expected_rules()
    existing_onboarding = []
    onboarding_indexes = []
    bypass_indexes = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ConfigurationPatchError("access-control rules must be mappings")
        if _domain_matches(rule, PORTAL_DOMAIN):
            resources = rule.get("resources", [])
            if isinstance(resources, str):
                resources = [resources]
            if any("/onboarding/admin" in str(resource) for resource in resources):
                existing_onboarding.append(rule)
                onboarding_indexes.append(index)
            if rule.get("policy") == "bypass":
                bypass_indexes.append(index)
    migrating_singleton = False
    if existing_onboarding:
        if len(existing_onboarding) != 2:
            raise ConfigurationPatchError("partial onboarding policy found; refusing to guess")
        if existing_onboarding != expected:
            raise ConfigurationPatchError("existing onboarding policy does not match; manual review required")
    if len(bypass_indexes) != 1:
        raise ConfigurationPatchError("exactly one existing auth portal bypass rule is required")
    if existing_onboarding:
        admin_index, deny_index = onboarding_indexes
        if deny_index != admin_index + 1 or deny_index >= bypass_indexes[0]:
            raise ConfigurationPatchError("onboarding rule pair must be adjacent and precede the auth portal bypass")

    # Authelia uses first-match rule evaluation. Rules before our protected
    # pair must be provably disjoint from the portal hostname. We deliberately
    # reject wildcards, regexes and malformed selectors rather than guessing
    # whether their resources, networks or subjects might intersect.
    protected_index = onboarding_indexes[0] if existing_onboarding else bypass_indexes[0]
    portal = PORTAL_DOMAIN.rstrip(".").casefold()
    dns_name = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$", re.I)
    for rule in rules[:protected_index]:
        domains = rule.get("domain")
        if "domain_regex" in rule or not isinstance(domains, (str, list)):
            raise ConfigurationPatchError("earlier rule domain is not provably disjoint from portal")
        domains = [domains] if isinstance(domains, str) else domains
        if not domains:
            raise ConfigurationPatchError("earlier rule domain is not provably disjoint from portal")
        for domain in domains:
            if (not isinstance(domain, str) or not dns_name.fullmatch(domain.rstrip("."))
                    or domain.rstrip(".").casefold() == portal):
                raise ConfigurationPatchError("earlier rule domain is not provably disjoint from portal")

    if existing_onboarding:
        if migrating_singleton:
            admin_node = rules_node.value[admin_index]
            subject_node = _mapping_value(admin_node, "subject")
            if (not isinstance(admin_node, yaml.MappingNode)
                    or not isinstance(subject_node, yaml.SequenceNode)
                    or len(subject_node.value) != 1
                    or not isinstance(subject_node.value[0], yaml.ScalarNode)):
                raise ConfigurationPatchError("singleton administrator subject source is unsupported")
            subject = subject_node.value[0]
            old_value = existing_onboarding[0]["subject"][0]
            old_scalar = text[subject.start_mark.index:subject.end_mark.index]
            if (subject.value != old_value
                    or old_scalar not in (old_value, "'" + old_value + "'", '"' + old_value + '"')
                    or not admin_node.start_mark.index <= subject_node.start_mark.index
                    <= subject.start_mark.index < subject.end_mark.index
                    <= subject_node.end_mark.index <= admin_node.end_mark.index):
                raise ConfigurationPatchError("singleton administrator subject source is unsupported")
            quote = old_scalar[0] if old_scalar[0] in ("'", '"') else ""
            new_scalar = quote + ADMIN_SUBJECTS[0] + quote
            if new_scalar != old_scalar:
                edits.append((subject.start_mark.index, subject.end_mark.index, new_scalar))
            extra_scalar = quote + ADMIN_SUBJECTS[1] + quote
            if subject_node.flow_style:
                edits.append((subject.end_mark.index, subject.end_mark.index, ", " + extra_scalar))
            else:
                line_start = text.rfind("\n", 0, subject.start_mark.index) + 1
                prefix = text[line_start:subject.start_mark.index]
                if prefix != " " * (subject.start_mark.column - 2) + "- ":
                    raise ConfigurationPatchError("singleton administrator list indentation is unsupported")
                line_end = text.find("\n", subject.end_mark.index)
                if line_end < 0:
                    raise ConfigurationPatchError("singleton administrator list line is unterminated")
                newline = "\r\n" if text[line_end - 1:line_end] == "\r" else "\n"
                insertion = line_end + 1
                edits.append((insertion, insertion, prefix + extra_scalar + newline))
    if not existing_onboarding:
        bypass_index = bypass_indexes[0]
        if bypass_index >= len(rules_node.value):
            raise ConfigurationPatchError("auth bypass source node does not match parsed rules")
        bypass_node = rules_node.value[bypass_index]
        if not isinstance(bypass_node, yaml.MappingNode):
            raise ConfigurationPatchError("auth bypass source node is unsupported")
        insertion_line = bypass_node.start_mark.line
        lines = text.splitlines(keepends=True)
        insertion = sum(len(line) for line in lines[:insertion_line])
        source_line = lines[insertion_line]
        indent = len(source_line) - len(source_line.lstrip(" "))
        edits.append((insertion, insertion, _snippet(indent)))

    updated = text
    for start, end, replacement in sorted(edits, reverse=True):
        updated = updated[:start] + replacement + updated[end:]
    try:
        after = yaml.load(updated, Loader=DuplicateKeyLoader)
    except Exception as exc:
        raise ConfigurationPatchError("patched Authelia YAML failed duplicate-safe validation") from exc

    expected_after = copy.deepcopy(before)
    expected_after["authentication_backend"]["file"]["watch"] = True
    if not existing_onboarding:
        expected_after["access_control"]["rules"][bypass_indexes[0]:bypass_indexes[0]] = expected
    elif migrating_singleton:
        expected_after["access_control"]["rules"][onboarding_indexes[0]]["subject"] = list(ADMIN_SUBJECTS)
    if after != expected_after:
        raise ConfigurationPatchError("patch changed configuration outside the two intended settings")
    return PatchResult(updated, updated != text)


def _atomic_write(path: Path, content: bytes, mode: int, uid: int, gid: int) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.onboarding.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        if os.geteuid() == 0:
            os.fchown(fd, uid, gid)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def apply_file(path: Path) -> dict[str, object]:
    """Back up, validate, and atomically install the narrow source-preserving edit."""

    stat_result = path.lstat()
    if path.is_symlink() or not path.is_file():
        raise ConfigurationPatchError("configuration target must be a regular file")
    original = path.read_bytes()
    original_hash = hashlib.sha256(original).hexdigest()
    result = patch_configuration(original.decode("utf-8"))
    if not result.changed:
        return {"changed": False, "sha256_before": original_hash, "sha256_after": original_hash}

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    backup = path.with_name(f"{path.name}.bak.onboarding.{stamp}")
    shutil.copy2(path, backup)
    if hashlib.sha256(backup.read_bytes()).hexdigest() != original_hash:
        raise ConfigurationPatchError("configuration backup verification failed")
    updated = result.text.encode("utf-8")
    try:
        _atomic_write(path, updated, stat_result.st_mode & 0o7777, stat_result.st_uid, stat_result.st_gid)
        installed = path.read_bytes()
        if installed != updated or hashlib.sha256(installed).hexdigest() != hashlib.sha256(updated).hexdigest():
            raise ConfigurationPatchError("installed configuration verification failed")
        if patch_configuration(installed.decode("utf-8")).changed:
            raise ConfigurationPatchError("installed configuration is not idempotent")
    except Exception:
        _atomic_write(path, original, stat_result.st_mode & 0o7777, stat_result.st_uid, stat_result.st_gid)
        raise
    return {"changed": True, "backup": str(backup), "sha256_before": original_hash,
            "sha256_after": hashlib.sha256(updated).hexdigest()}


def restore_file(path: Path, backup: Path) -> dict[str, object]:
    """Restore only a verified same-directory backup created by this tool."""

    if (backup.parent != path.parent or not backup.name.startswith(f"{path.name}.bak.onboarding.")
            or backup.is_symlink() or not backup.is_file()):
        raise ConfigurationPatchError("restore source is not a trusted onboarding backup")
    path.lstat()
    if path.is_symlink() or not path.is_file():
        raise ConfigurationPatchError("configuration target must be a regular file")
    backup_stat = backup.stat()
    original = backup.read_bytes()
    original_hash = hashlib.sha256(original).hexdigest()
    _atomic_write(path, original, backup_stat.st_mode & 0o7777, backup_stat.st_uid, backup_stat.st_gid)
    if path.read_bytes() != original or hashlib.sha256(path.read_bytes()).hexdigest() != original_hash:
        raise ConfigurationPatchError("restored configuration verification failed")
    return {"restored": True, "sha256": original_hash, "mode": oct(backup_stat.st_mode & 0o7777)}


def main() -> int:
    global PORTAL_DOMAIN, ADMIN_SUBJECTS
    try:
        origin = urllib.parse.urlsplit(os.environ.get("ONBOARDING_ORIGIN", ""))
        names = os.environ.get("ONBOARDING_ADMINS", "").split(",")
        if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
                or origin.path or origin.query or origin.fragment
                or not names or any(not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,63}", n) for n in names)
                or len(set(names)) != len(names)):
            raise ConfigurationPatchError("explicit valid origin and admins required")
        PORTAL_DOMAIN = origin.hostname
        ADMIN_SUBJECTS = ["user:" + n for n in names]
        if len(sys.argv) == 4 and sys.argv[1] == "--restore":
            result = restore_file(Path(sys.argv[2]), Path(sys.argv[3]))
        elif len(sys.argv) == 2:
            result = apply_file(Path(sys.argv[1]))
        else:
            print(json.dumps({"ok": False, "error": "usage"}))
            return 2
    except Exception as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__}))
        return 1
    print(json.dumps({"ok": True, **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
