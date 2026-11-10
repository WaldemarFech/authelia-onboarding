#!/usr/bin/env python3
"""Origin: Codex mac-mini-wf; Context: owner-requested native Authelia settings.

Target: official Authelia v4.39.16 public_html archive; local candidate only.
Purpose: replace only native SettingsView, version its complete inbound JS
dependency graph, and prove every other code byte survives URL normalization.
No extraction, network, credential access, service change, or remote mutation.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile

ARCHIVE_SHA256 = "058dd768787c4931d518c09e31bc0e58d869c81220894327b8dcaf8af71296ca"
SETTINGS = "public_html/static/js/settings.router.CJazlnaw.js"
SETTINGS_SHA256 = "5cafcc15d00943c3f997249b54e56542a65d619daeba023530dd6a69c615da3b"
INDEX = "public_html/static/js/index.D1XP2tyz.js"
INDEX_SHA256 = "73b74b9ea78f90ea3e93251d6d5cf71a3d0e920c018362b755da7e56a92b3069"
HTML = "public_html/index.html"
HTML_SHA256 = "e7268477f9d28655a8e2fee94b417911ee4ca5adf3b42b1e809b714cd4525d86"
START = b"qr=function(){let{t:e}=h(`settings`);"
END = b"};async function Jr()"
PLACEHOLDER = b"This is the user settings area at the present time it's very minimal but will include new features in the near future"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def build(archive: Path, component: Path, output: Path) -> dict:
    raw = archive.read_bytes()
    require(digest(raw) == ARCHIVE_SHA256, "official archive SHA-256 mismatch")
    files: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as source:
        for member in source.getmembers():
            name = member.name
            path = PurePosixPath(name)
            require(not path.is_absolute() and ".." not in path.parts and path.parts[0] == "public_html", "unsafe archive path")
            require(member.isdir() or member.isfile(), "archive contains a nonregular asset")
            if not member.isfile():
                continue
            require(name not in files and member.size <= 8 * 1024**2, "duplicate or oversized archive asset")
            handle = source.extractfile(member)
            require(handle is not None, "asset cannot be read")
            files[name] = handle.read()
            modes[name] = member.mode & 0o777
    for name, expected in [(SETTINGS, SETTINGS_SHA256), (INDEX, INDEX_SHA256), (HTML, HTML_SHA256)]:
        require(name in files and digest(files[name]) == expected, f"pinned asset mismatch: {name}")

    original = files[SETTINGS]
    require(original.count(START) == 1 and original.count(END) == 1 and original.count(PLACEHOLDER) == 1, "SettingsView marker must be unique")
    start = original.index(START)
    end = original.index(END, start) + 2
    previous_component = original[start:end]
    replacement = component.read_bytes().strip()
    # Documentation stays in the source sidecar; the replacement itself occupies
    # the original `var ...,qr=function(){...};` expression span.
    replacement = replacement[replacement.index(b"qr=function(){"):]
    require(replacement.startswith(b"qr=function(){") and replacement.endswith(b"};"), "replacement component shape mismatch")
    require(PLACEHOLDER not in replacement and b"/api/state" in replacement and b"/api/user/info" in replacement, "replacement does not implement native account overview")
    require(b"/settings/security" in replacement and b"/settings/two-factor-authentication" in replacement, "native security links missing")
    patched_settings = original[:start] + replacement + original[end:]
    require(patched_settings[:start] == original[:start] and patched_settings[start + len(replacement):] == original[end:], "unrelated settings-router bytes changed")
    require(original[-len(b"export{pa as default};\n"):] == patched_settings[-len(b"export{pa as default};\n"):], "settings-router export changed")

    # Filename changes propagate through inbound import and preload references.
    # The entry exports shared code, so leaving any original entry reference
    # would evaluate two distinct entry modules and may mount the app twice.
    affected = {SETTINGS}
    javascript = {name for name in files if name.startswith("public_html/static/js/") and name.endswith(".js")}
    while True:
        names = [PurePosixPath(name).name.encode() for name in affected]
        expanded = affected | {name for name in javascript if any(token in files[name] for token in names)}
        if expanded == affected:
            break
        affected = expanded
    require(INDEX in affected, "entry dependency closure missing")
    revision = digest(bytes.fromhex(ARCHIVE_SHA256) + replacement)[:16]
    rename = {name: str(PurePosixPath(name).with_name(PurePosixPath(name).stem + f".jarvis-settings-{revision}.js")) for name in sorted(affected)}
    substitutions = {PurePosixPath(old).name.encode(): PurePosixPath(new).name.encode() for old, new in rename.items()}
    pattern = re.compile(b"|".join(re.escape(name) for name in sorted(substitutions, key=len, reverse=True)))
    reverse = {new: old for old, new in substitutions.items()}
    reverse_pattern = re.compile(b"|".join(re.escape(name) for name in sorted(reverse, key=len, reverse=True)))
    result: dict[str, bytes] = {}
    manifest = []
    for name, before in sorted(files.items()):
        intermediate = patched_settings if name == SETTINGS else before
        after = pattern.sub(lambda match: substitutions[match.group()], intermediate) if name in affected or name == HTML else intermediate
        normalized = reverse_pattern.sub(lambda match: reverse[match.group()], after)
        require(normalized == intermediate, f"reverse URL normalization failed: {name}")
        if name != SETTINGS:
            require(normalized == before, f"unrelated code bytes changed: {name}")
        new_name = rename.get(name, name)
        require(new_name not in result, "renamed asset collision")
        result[new_name] = after
        manifest.append({"original_path": name, "candidate_path": new_name,
                         "sha256_original": digest(before), "sha256_candidate": digest(after),
                         "component_changed": name == SETTINGS, "reference_urls_changed": after != intermediate,
                         "normalized_code_unchanged": name != SETTINGS})
    all_old_references = [old for old in substitutions if any(old in body for body in result.values())]
    require(not all_old_references, "stale reference remains in candidate asset graph")
    require(result[HTML].count(PurePosixPath(rename[INDEX]).name.encode()) == 1, "candidate entry HTML reference mismatch")
    require(set(files) - set(rename) == set(result) - set(rename.values()), "unexpected asset additions/removals")
    output.mkdir(parents=True, exist_ok=True)
    candidate = output / f"authelia-v4.39.16-jarvis-settings-{revision}-public_html.tar.gz"
    with candidate.open("wb") as stream, gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as zipped, tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as destination:
        for name, data in sorted(result.items()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = modes.get(next((old for old, new in rename.items() if new == name), name), 0o644)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            destination.addfile(info, io.BytesIO(data))
    bundle = output / PurePosixPath(rename[SETTINGS]).name
    bundle.write_bytes(result[rename[SETTINGS]])
    report = {"ok": True, "version": "v4.39.16", "source_archive_sha256": ARCHIVE_SHA256,
              "replacement_source_sha256": digest(component.read_bytes()), "replacement_component_sha256": digest(replacement),
              "original_component_sha256": digest(previous_component), "revision": revision,
              "candidate_archive": str(candidate.resolve()), "candidate_archive_sha256": digest(candidate.read_bytes()),
              "settings_router_original": SETTINGS, "settings_router_candidate": rename[SETTINGS],
              "entry_candidate": rename[INDEX], "file_count": len(files), "renamed_js_count": len(rename),
              "component_code_changed_count": 1, "other_code_reverse_normalization": "PASS", "assets": manifest}
    (output / "native-settings-assets-manifest.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {key: value for key, value in report.items() if key != "assets"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--component", type=Path, default=Path(__file__).with_name("native_settings_view.js"))
    parser.add_argument("--output", type=Path, required=True, help="Generated artifact output directory; use generated_files or SESSIONS")
    args = parser.parse_args()
    print(json.dumps(build(args.archive, args.component, args.output), indent=2))


if __name__ == "__main__":
    main()
