# Experimental Authelia v4.39.28 file-user lock port

**For isolated testing and independent review only. Not a supported release, OCI image, or production installation.** This is a version-specific derivative of the original v4.39.16 file-user-lock patch developed for the separate Authelia Onboarding service. It is not an upstream Authelia release or a complete fork. The historical patch remains unchanged outside this package.

- Upstream: tag `v4.39.28`, commit `8da42b2348b0351c6284a2940a9c5eec3d4cd3fd`; license: Apache-2.0, included under `licenses/`.
- Port: `patches/authelia-v4.39.28-file-user-lock.patch`, SHA-256 `4ff3800ee4e5c8ab6537adca3547a296446d9f82c1cf1a872ce29d39759f8cac`.
- Separate real-watcher test: `tests/file_watcher_port_test.go`, SHA-256 `2e9dfdaac582bf2daead81aa687f38f41b7aa73aa0337b24137c1c553a728be2`.
- Base file hashes, compiler and candidate binary provenance: `provenance.json`.

The upstream file backend uses a 500 ms reload cooldown and does not share the Python service's stable file lock. This port reloads under a stable sidecar `users.yml.lock` before native password writes, serializes those writes with the external writer, replaces YAML atomically and reloads after save failure. It removes the provider reload cooldown. The `Disabled` field is already preserved upstream in this version; the older patch's duplicate assignment was not carried over.

## Reproduction in a disposable Linux lab

Prerequisites: Git, tar, SHA-256 utilities, Linux/amd64, Go **1.27.1** with `GOTOOLCHAIN=local`, working C compiler/headers for `CGO_ENABLED=1`, and a sandbox with no production state. The tested Go archive SHA-256 is in `provenance.json`. An Internet connection is required to obtain pinned sources and Go dependencies; make subsequent tests and build offline after prefetch. The exact dependency fetch mechanism should be reviewed for your network and trust model.

1. Download the official `authelia-v4.39.28-public_html.tar.gz` from [the upstream release](https://github.com/authelia/authelia/releases/tag/v4.39.28). Verify SHA-256 against `provenance.json`. Set `PACKAGE` to the absolute path of this directory and `FRONTEND` to the absolute path of that archive. Use a new disposable working directory.
2. Clone `https://github.com/authelia/authelia.git` at `v4.39.28`, verify `git rev-parse HEAD` equals the commit above, and verify the patch and test file hashes. Run `git apply --check "$PACKAGE/patches/authelia-v4.39.28-file-user-lock.patch"`, then `git apply` the same file. Copy `"$PACKAGE/tests/file_watcher_port_test.go"` to `internal/service/file_watcher_port_test.go`.
3. Prefetch exact Go module dependencies with `go list -deps -test ./internal/authentication ./internal/service` and `go list -deps ./cmd/authelia`. Then disconnect the lab from external networks while preserving isolated loopback for the package's LDAP tests. Do not connect to or use a production database. Run:

```sh
export GOTOOLCHAIN=local CGO_ENABLED=0 GOPROXY=off GOSUMDB=off
export GOMAXPROCS=2
go test -p 2 -count=1 ./internal/authentication
go test -p 2 -count=1 ./internal/service -run '^TestPortWatcherAtomicReplaceThenImmediateDisable$'
```

The service test observes a real fsnotify watcher and confirms that an atomic replacement followed immediately by account disable causes authentication rejection. It is not a browser or full system test.

4. Before extraction, verify the archive contains only regular files/directories below `public_html/`, no path traversal and no links. In the disposable checkout, move the existing `internal/server/public_html` placeholder to a new unique backup path, then extract the verified archive with `tar --no-same-owner -xzf "$FRONTEND" -C internal/server`. Ensure the expected index and JavaScript assets are present. The stock source checkout placeholder alone is not a usable web UI.
5. With dependencies cached and external networking disabled, build a **test binary**, not an image:

```sh
export CGO_ENABLED=1 GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off
flags='-X github.com/authelia/authelia/v4/internal/utils.BuildTag=v4.39.28 -X github.com/authelia/authelia/v4/internal/utils.BuildState=tagged -X github.com/authelia/authelia/v4/internal/utils.BuildCommit=8da42b2348b0351c6284a2940a9c5eec3d4cd3fd -X github.com/authelia/authelia/v4/internal/utils.BuildBranch=patch-lab'
go build -p 2 -trimpath -ldflags "$flags" -o ./authelia-4.39.28-port ./cmd/authelia
sha256sum ./authelia-4.39.28-port
./authelia-4.39.28-port --version
```

The observed lab binary reports `v4.39.28-dirty`; its SHA is provenance for that specific build, not a promise that all builds are bit-for-bit reproducible. Its maximum observed GLIBC symbol is `GLIBC_2.34` and its ELF interpreter is `/lib64/ld-linux-x86-64.so.2`. Verify architecture, loader, libc, dependencies and the hash against the actual target before use; this does not establish portability to every Debian 13 environment or container.

## Evidence and changes to tests

- RED: against the unmodified pinned upstream source, the imported password-write/lock/reload regression run failed, including the cooldown case; the real fsnotify test also failed to observe auth revocation after an immediate disabled-user atomic replacement.
- GREEN: the four targeted tests, an explicit hash-fixture roundtrip, the complete `internal/authentication` package (including LDAP test over namespace-only loopback), and the real fsnotify watcher test passed with CGO disabled in an isolated Linux namespace/chroot. Test data was synthetic; no deployed service was changed.
- Original upstream concurrent-write test used a plaintext hasher whose output the file-user decoder did not accept on the next reload. The fixture was changed to a low-cost **test-only** Argon2 configuration; a separate test asserts that the old fixture fails decoding and the replacement roundtrips. These weak parameters must not be used for actual accounts. A save-failure mock was also updated to expect the extra initial and recovery reloads.
- The first full run exposed test fixture/mocking differences and namespace limitations; after fixes and enabling loopback only inside the lab network namespace, the full relevant package passed. An initial full binary build with CGO disabled failed due to SQLite; the CGO-enabled rebuild with the verified official frontend succeeded.
- A separate agent reported an isolated E2E of the pinned candidate binary with TOTP, admin access, invite creation/redemption and new-user login. This is not an OCI image acceptance, production rollout, concurrent-writer acceptance or independent security approval.

## Important limits and failure behavior

- Uses Linux-specific `syscall.Flock`, `Stat_t`, `O_NOFOLLOW` and same-filesystem rename. The external Python writer and Authelia container must access the **same sidecar lock inode** with compatible effective UID and user-namespace mappings; otherwise operation fails or coordination cannot be assumed.
- The data and lock parent directory must be trusted and not writable by untrusted users. The patch checks owner, regular-file type, mode and hard-link count but does not turn an attacker-controlled directory into a safe one.
- Atomic replacement creates a new inode with restrictive mode. Existing POSIX ACLs, SELinux labels, other extended attributes and original group ownership are **not explicitly preserved**. Environments depending on them need additional design, implementation and tests before use.
- **Confirmed lab defect:** fault injection before rename followed by a failed recovery reload left memory and disk accepting different passwords. After rename, an injected directory-fsync failure returned an error while the new password was visible, but crash durability remained uncertain. Do not deploy this port; the fail-closed correction and further tests are in progress.
- Concurrent group updates, policy refresh, direct-backend bypass, fake headers, 2FA, backup/restore and image startup require end-to-end validation of the **whole** stack. Direct provider/watcher tests cannot prove all of them.
- A static upstream pin needs ongoing security maintenance. The upstream advisories [GHSA-j748-h363-wqj8](https://github.com/authelia/authelia/security/advisories/GHSA-j748-h363-wqj8) and [GHSA-hjj4-hfjm-fmrj](https://github.com/authelia/authelia/security/advisories/GHSA-hjj4-hfjm-fmrj) list versions through 4.39.19 as affected; 4.39.28 is outside those stated ranges. Review all current advisories before any deployment.

## Neuer experimenteller Guard-Kandidat

`patches/authelia-v4.39.28-guarded-experimental.patch` (SHA-256 `3afe312272884ac5155fdafcb8c2ae56d895c4f4f26a0fee7dbbaeca19c78b73`) ist ein **vollständiger alternativer Patch gegen den oben angegebenen sauberen Upstream-Commit**, nicht ein Zusatzpatch. Er darf nicht zusätzlich auf den ursprünglichen Port angewendet werden.

Der Kandidat serialisiert Provider-Lese- und Schreibzugriffe und sperrt den Provider nach einem unsicheren Speicherfehler. Der zentrale Authz-Handler prüft für das Datei-Backend vor und während der Entscheidung einen Guard; fehlt er, antwortet er mit 503. Im isolierten Labor bestanden die Authentication- und Handler-Suite, der echte Watcher-Test und gezielte Race-Detector-Tests. In synthetischen Cookie-Tests führten Speicherfehler bei `refresh=never` und gültiger Refresh-TTL von vorher HTTP 200 auf HTTP 503. Ein LDAP-konfigurierter Testpfad mit Provider-Mock ohne diesen Guard blieb erreichbar; ein reales LDAP-Backend wurde nicht getestet. Der Code wurde unabhängig geprüft.

**Weiterhin nicht installations- oder produktionsreif:** Der Guard deckt nicht alle OIDC-/Tokenpfade ab und widerruft keine extern validierten App-Tokens. Ein `fsnotify.Remove` sperrt nicht automatisch; Mehrfachreplikate, Neustart-/Recovery-Verfahren, reale Netzwerkgrenzen und vollständige Stacktests dieses neuen Kandidaten sind offen. Die Barriere hält ein Leseschloss über die Authz-Entscheidung und kann Reloads oder Schreibvorgänge bei langsamen Abhängigkeiten verzögern. ACL-/SELinux-/xattr- und I/O-Dauerhaftigkeitsgrenzen oben gelten weiter. Keines der Bilder oder Tests belegt eine produktive Freigabe.

For the exact patch SHA above, the complete Authentication and Handler suites, the actual watcher test and targeted race-detector checks passed in an isolated Linux lab after applying the frozen patch. Two clean source trees and separate caches on the same host produced binary SHA-256 `dfee58f5355afcd6a9819804e12298194444c627d0f3c11b163ac11b8a05be64`. A separate isolated HTTPS normal-path test of that binary passed TOTP, invitation redemption and stale-group rejection using an explicitly disclosed Docker CLI test shim. These checks do not validate a real Docker image, external network boundaries, OIDC/app tokens, multiple replicas or every failure path.
