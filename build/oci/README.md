# Experimental pinned OCI build recipe

**Status: recipe only. The OCI image has not been built, started or independently reviewed. Do not deploy it or treat it as an installation release.** A separate Linux/amd64 binary was tested in an isolated lab, but no such test establishes this OCI image; the image's build, runtime ABI and networking are unverified.

The goal is to make a reviewable Linux/amd64 image from the [v4.39.28 patch package](../../scripts/authelia_onboarding/patches/v4.39.28/README.md). It intentionally uses a pinned Debian 13 runtime: the separate test binary is dynamically linked against glibc, so replacing the binary inside the official upstream image without first proving its runtime ABI is unsafe.

## Exact inputs

| Input | Pin |
| --- | --- |
| Authelia source | tag `v4.39.28`, verified commit `8da42b2348b0351c6284a2940a9c5eec3d4cd3fd` |
| Full guarded experimental patch (alternative, not additive) | SHA-256 `3afe312272884ac5155fdafcb8c2ae56d895c4f4f26a0fee7dbbaeca19c78b73` |
| Watcher regression test | SHA-256 `2e9dfdaac582bf2daead81aa687f38f41b7aa73aa0337b24137c1c553a728be2` |
| Official frontend release archive | SHA-256 `2009c5f499f92179c0b4c8a3185a8bc4f3e1666d169818d382242103c09a380f` |
| Dockerfile frontend, linux/amd64 child manifest | `sha256:7b32114e84ca21aeb2d6f871a0b62b3a0762193f75d9afd048ee4cbe889f3148` |
| Go 1.27.1 bookworm, linux/amd64 child manifest | `sha256:e114385c58e7280d2f56d6cf374219dda33fef8eb77f72e9f290ccae6160bd90` |
| Debian 13 slim, linux/amd64 child manifest | `sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392` |

Go modules are obtained from the pinned source's `go.mod` and `go.sum`. Fetches require Internet access; tests and compilation specify `--network=none` and use the populated cache. A source commit timestamp is supplied to supported BuildKit versions. These pins constrain inputs; **bit-for-bit reproducibility of the OCI artifact has not been demonstrated** and must be tested with two clean independent builds. Registries, upstream dependencies, build frontend and security advisories need ongoing review.

## Prepare a safe minimal context

Use a disposable Linux/amd64 host with BuildKit and Docker access authorized for this lab. Do not point the build at a production Docker daemon or mount production data. `prepare-context.sh` creates a **new** directory; it refuses an existing path or symlink, copies only the Containerfile and two pinned inputs, normalizes CRLF checkouts and verifies their canonical hashes. It creates a restrictive `.dockerignore`. If it fails, stop and inspect the specific lab directory before removing your own temporary files.

```sh
# Run from the repository root; substitute a new absolute lab path.
bash build/oci/prepare-context.sh /tmp/authelia-lock-build-context
find /tmp/authelia-lock-build-context -maxdepth 1 -type f -printf '%f\n' | sort
```

The resulting context should contain exactly `.dockerignore`, `Containerfile`, `port.patch` and `watch.go`. Inspect it before sending it to any builder. **Never use your checkout, a credentials directory, or a context containing secrets as the Docker build context.**

The following is the planned lab invocation; it has not yet been run against a real OCI daemon:

```sh
DOCKER_BUILDKIT=1 docker build --platform linux/amd64 \
  -f /tmp/authelia-lock-build-context/Containerfile \
  -t authelia-file-lock-lab:local /tmp/authelia-lock-build-context
```

The build verifies the upstream commit and frontend archive, verifies and applies the patch, runs the complete `internal/authentication` and `internal/handlers` test packages and the real fsnotify regression as an unprivileged temporary UID with CGO enabled (the service package depends on SQLite CGO symbols and upstream permission tests fail as root), then compiles a CGO-enabled executable. Treat any test, download, checksum, architecture or permission failure as a stop. Do not silently fall back to different versions, skip tests or disable hash checks.

## Runtime checks before any broader trial

In an isolated lab, with no production paths or credentials, record the resulting local image ID/digest and check the binary starts with no network:

```sh
docker image inspect authelia-file-lock-lab:local --format '{{.Id}} {{.Os}}/{{.Architecture}}'
docker run --rm --network none --read-only --tmpfs /tmp \
  --security-opt no-new-privileges authelia-file-lock-lab:local --version
```

Record the version it actually reports as a startup check only. **Neither that output nor an image label proves that the patch is present.** The OCI labels state the intended upstream commit, patch SHA-256 and frontend archive SHA-256; inspect and record them as claims, and compare them separately with the verified input hashes and an independently retained build record.

Before building, record the SHA-256 of each of the four context files, the exact source repository revision, the pinned base/frontend manifest digests and the BuildKit version. Retain the successful checksum, patch-application and test results with the build log; do not include credentials or other secrets. After building, record the local image ID and inspect `docker image inspect authelia-file-lock-lab:local --format '{{json .Config.Labels}}'`. An image ID is a local configuration digest; it is not necessarily a registry manifest digest. If the image is later distributed, record its actual registry manifest digest separately.

Extract the built executable from a **new, never-started laboratory container** into a new private temporary directory and compute its SHA-256:

```sh
artifact_dir=$(mktemp -d)
container_id=$(docker create --network none authelia-file-lock-lab:local)
trap 'docker rm -f "$container_id" >/dev/null 2>&1 || true' EXIT
docker cp "$container_id:/usr/local/bin/authelia" "$artifact_dir/authelia"
docker rm "$container_id" >/dev/null
trap - EXIT
sha256sum "$artifact_dir/authelia"
```

The executable hash, local image ID and any registry digest are different identifiers; record each with its scope. Compare the executable hash against a trusted record **for the same build**, or verify independently produced evidence. The earlier uncontainerized binary hash is not expected to prove this image's contents. For stronger source-to-artifact assurance, retain and independently verify build attestations or independently reproduce the build; labels and logs alone are not cryptographic proof.

Next examine the image's dynamic loader/glibc compatibility and verify the embedded official frontend. Then conduct a separate disposable integration test of Traefik, real Authelia, 2FA, invitations, file-lock contention, auth revocation, spoofed identity headers, backend bypass, backups and recovery. Do not expose ports publicly until an independently reviewed security decision is made.

The runtime presently uses UID 0 because the separate current onboarding writer and lock verification require matching effective UIDs across the shared file and lock. Docker user-namespace remapping, bind mounts, permissions, ownership and the **same sidecar lock inode** must be verified for the actual stack. Root plus Docker access is a significant trust boundary; this is not an endorsement of a production privilege model. This Debian image has a different entrypoint and filesystem from upstream's official image; integrations expecting the upstream entrypoint, healthcheck or container features need separate design and tests.

Do not assume atomic replacement preserves existing POSIX ACLs, SELinux labels, extended attributes or original group ownership. Separate fault-injection tests on the port reproduced post-rename directory-fsync failure and recovery failure. The earlier unguarded port exhibited authentication divergence after a pre-rename save failure followed by failed recovery reload. This recipe selects the newer guarded alternative, but it has not been tested as an OCI image. Its guard does not cover all OIDC/token paths or revoke externally validated tokens; `fsnotify.Remove` does not automatically lock the provider. Multi-replica behavior, restart and recovery procedures, real network boundaries, and complete stack tests remain open. Durability can be uncertain after post-rename failures. These gaps block deployment. A trusted data directory, explicit backup/restore plan and independent review remain required.

## Current evidence

- On the Windows authoring host both the default and desktop-linux Docker contexts could not connect to a daemon. The documented VPS host had no `docker`, `podman`, `buildah` or `nerdctl` executable. No runtime was installed and no production daemon, service or host network was changed.
- For the earlier patch, the context preparation path was exercised in an isolated Linux user/mount/network namespace and chroot using a synthetic repository: the exact minimal file set was produced, an existing destination was rejected and a modified patch was rejected. The shell script passed `bash -n`. These checks do not execute the Containerfile.
- For the guarded patch update, Git Bash on Windows checked shell syntax, the exact four-file context, the canonical guard SHA-256, existing-directory refusal and tampered-patch refusal in a synthetic checkout. Because Windows rejected `mkdir -m 700`, this test removed that option **only in the disposable test copy**; it did not validate Linux permissions or run the unmodified script end to end. WSL was unavailable.
- For the guard update, the unchanged context-preparation script passed in a disposable Linux user/mount/network namespace: exact files, mode 0700, hashes, existing path refusal and tamper refusal. In a separate chroot, CGO-enabled authentication, handler and watcher tests passed after dropping DAC override capabilities; this approximates permission behavior but does not validate the Containerfile unprivileged-user setup.
- Registry manifest metadata and input file hashes were inspected; a separate uncontainerized Linux binary build and its isolated tests are documented in the patch package. No OCI build, image digest, image smoke test, full lab stack or production acceptance has been established for this recipe.

The recipe includes the pinned upstream `LICENSE` and `LICENSES` directory and the frontend archive files named as licenses/notices. A complete third-party notices and license review is still required; no claim is made that this list is exhaustive.
