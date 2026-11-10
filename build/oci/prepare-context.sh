#!/usr/bin/env bash
set -euo pipefail

# Build a new, minimal context; never send a user's checkout or secrets.
if [ "$#" -ne 1 ]; then
  echo "usage: prepare-context.sh /absolute/new/context-directory" >&2
  exit 2
fi
out=$1
case "$out" in /*) ;; *) echo "context path must be absolute" >&2; exit 2 ;; esac
if [ -e "$out" ] || [ -L "$out" ]; then
  echo "context path already exists; refusing to overwrite" >&2
  exit 2
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo=$(CDPATH= cd -- "$script_dir/../.." && pwd -P)
base="$repo/scripts/authelia_onboarding/patches/v4.39.28"
patch="$base/patches/authelia-v4.39.28-guarded-experimental.patch"
watcher="$base/tests/file_watcher_port_test.go"
for source in "$patch" "$watcher" "$script_dir/Containerfile"; do
  if [ ! -f "$source" ] || [ -L "$source" ]; then
    echo "expected a regular non-symlink source file" >&2
    exit 2
  fi
done
mkdir -m 700 -- "$out"
# Normalize CRLF checkouts to canonical LF; SHA-256 catches other edits.
sed 's/\r$//' "$patch" > "$out/port.patch"
sed 's/\r$//' "$watcher" > "$out/watch.go"
sed 's/\r$//' "$script_dir/Containerfile" > "$out/Containerfile"
printf '%s  %s\n' 3afe312272884ac5155fdafcb8c2ae56d895c4f4f26a0fee7dbbaeca19c78b73 "$out/port.patch" | sha256sum -c --status
printf '%s  %s\n' 2e9dfdaac582bf2daead81aa687f38f41b7aa73aa0337b24137c1c553a728be2 "$out/watch.go" | sha256sum -c --status
cat > "$out/.dockerignore" <<'IGNORE'
*
!Containerfile
!port.patch
!watch.go
IGNORE
printf 'Prepared minimal verified context: %s\n' "$out"
