#!/usr/bin/env python3
"""Build a guarded lock patch for the deployed CT1004 password helper.

This prepares a new source file locally. Deployment must separately verify the
live source hash, back it up, validate the candidate, and restart the helper.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import os
from pathlib import Path


EXPECTED_ORIGINAL_SHA256 = "7e0d87cc166cfaf5ccbafc586ffb90d0cfd2a130ff9962f652903974176cab4a"
MARKER = "# JARVIS_SHARED_USER_DB_LOCK_V1"
IMPORT_ANCHOR = "import ipaddress\n"
FUNCTION_ANCHOR = "def replace_user_password(username: str, digest: str) -> None:\n"
NEXT_FUNCTION_ANCHOR = "\ndef restart_authelia() -> None:\n"

LOCK_FUNCTION = '''# JARVIS_SHARED_USER_DB_LOCK_V1
@contextmanager
def user_db_write_lock():
    # The YAML inode is replaced on every write; lock a permanent sidecar.
    lock_path = USERS_DB.with_name(USERS_DB.name + ".lock")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    locked = False
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1 or metadata.st_mode & 0o077):
            raise RuntimeError("unsafe Authelia user database lock metadata")
        deadline = time.monotonic() + 10
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


'''

WRAPPER = '''
def replace_user_password(username: str, digest: str) -> None:
    # Re-read and replace under the same cross-process lock as onboarding.
    with user_db_write_lock():
        _replace_user_password_unlocked(username, digest)

'''


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("password helper source no longer has the expected structure")
    return source.replace(old, new, 1)


def patch_known_source(raw: bytes) -> bytes:
    if hashlib.sha256(raw).hexdigest() != EXPECTED_ORIGINAL_SHA256:
        raise ValueError("password helper source hash changed; inspect the live version")
    source = raw.decode("utf-8", errors="strict")
    if MARKER in source:
        raise ValueError("password helper source already contains a lock patch")
    source = replace_once(source, IMPORT_ANCHOR,
                          "from contextlib import contextmanager\nimport fcntl\nimport ipaddress\nimport stat\n")
    source = replace_once(source, FUNCTION_ANCHOR,
                          LOCK_FUNCTION + "def _replace_user_password_unlocked(username: str, digest: str) -> None:\n")
    source = replace_once(source, NEXT_FUNCTION_ANCHOR,
                          WRAPPER + NEXT_FUNCTION_ANCHOR)
    ast.parse(source)
    return source.encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("candidate", type=Path)
    args = parser.parse_args()
    if args.source.resolve() == args.candidate.resolve():
        parser.error("candidate must be a separate path")
    patched = patch_known_source(args.source.read_bytes())
    fd = os.open(args.candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(patched)
        handle.flush()
        os.fsync(handle.fileno())
    print(f"candidate_sha256={hashlib.sha256(patched).hexdigest()}")


if __name__ == "__main__":
    main()
