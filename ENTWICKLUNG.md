# Authelia Onboarding — development candidate

**DEVELOPMENT SOURCE ONLY — NOT READY TO INSTALL OR EXPOSE.** This isolated educational candidate derives from a Jarvis source package (`scripts/authelia_onboarding`, source revision `636a90ed986a16012a5633344ef36d27eea4fd26`). It consists of a separate account/onboarding service, a version-pinned Authelia file-writer patch and an experimental native settings modification. It is not a complete fork of Authelia.

The candidate contains **unreviewed security changes**. The portability unit tests check only a narrow configuration subset and do not prove live authorization or deployment safety. The historical tests were adapted to explicit fixtures and disabled archive endpoints; the native UI builder's old component hash still does not match the changed component. The configuration patcher still needs integration tests. Do not expose or install this on any real system.

## Configuration under development

The service requires explicit `ONBOARDING_ADMINS` (comma-separated exact lower-case account IDs), `ONBOARDING_TRUSTED_PROXY` (a single exact IP), `ONBOARDING_ORIGIN` (HTTPS origin), `ONBOARDING_BIND_IP` (a non-wildcard IP) and `ONBOARDING_BIND_PORT`. Group writes default to disabled. `ONBOARDING_ALLOWED_GROUPS` can be set to a comma-separated list, and these groups are exposed as editable in the administrative UI. Group behavior has synthetic tests, not real-stack acceptance. `AUTHELIA_USERS_DB` and `ONBOARDING_DB` configure local state paths. Never put credentials in these values.

The ACL patcher requires the same origin and administrators and refuses mismatched preexisting onboarding ACLs. The checked-in Traefik YAML is only an example with reserved example domains and example IPs. It is not safe to activate without a security review: access to the service must be restricted at the network layer to the designated proxy, identity headers must be stripped, and the Authelia two-factor rule and deny rule must precede portal bypass. Check the actual Authelia/Traefik version and validate with positive and spoofed-header negative tests. An authenticated header alone is not proof of a second factor.

## Open release gates

- Configure and validate all services in an isolated Debian 13 environment; test anonymous, forged-header, unauthorized-admin, wrong-2FA and direct-backend paths.
- Verify file-writer locking and concurrent user/password changes against the actual chosen Authelia image; keep the exact upstream patch provenance.
- Review the remaining legacy Jellyfin-specific policy helper and remove it if unused. The legacy notification HTTP endpoints are disabled and are not a bootstrap viewer.
- Rebuild and review the version-pinned native UI, or omit it. Its shortcut is deliberately disabled in this candidate.
- Re-scan the final exact snapshot and history for secrets and private information; manually review findings and license/provenance.
- Review Linux service permissions, backup, recovery and deployment instructions.

The file-writer patch targets Authelia v4.39.16. The upstream project is Apache-2.0; retain its license and notices when distributing derived material. The separate original component's licensing has not been resolved here.

Run the limited local checks from this directory using `python -m pytest tests/test_portability.py -q`. The startup-validation tests extract the function AST so they can run without Linux-specific modules; this does not execute the service or replace Linux tests.

The legacy notification archive HTTP endpoints are disabled; account summaries no longer read the fixed Authelia configuration and MFA database paths and report MFA/policy as unknown. The native UI builder is not release-ready. A service environment file at `/etc/authelia-onboarding/config.env` is required by the candidate systemd unit.

Earlier access-control rules must have plain, provably different literal domains; wildcard, regex, same-host and unrecognized selectors are rejected to avoid bypassing the protected pair through first-match ordering. This is conservative and can reject safe configurations.

A Linux isolated test run passed 60 tests on 2026-11-10; it used no production configuration, network access, running service or real Authelia/Traefik process. This is not deployment or end-to-end acceptance. The upstream Authelia v4.39.16 Apache-2.0 text is retained under `licenses/`; the license and notices for all included material still need release review.

`LAB-INSTALL.md` is an unverified laboratory draft and cannot be used as a production installation recipe. The optional `native_ui` directory is experimental and excluded from the supported installation path.

Known limitation: group edits currently submit the whole allowed-group selection without a version precondition. Simultaneous administrators can overwrite changes made after one opened the dialog; use a single administrator at a time until optimistic concurrency and conflict handling are implemented and tested. The UI text about service rules and 2FA registration is also pending clarification: the candidate intentionally reports these as unknown.

Run only a single onboarding process; overlapping processes with different allowed-group settings do not share one policy. Recovery fails closed on a pending invitation with a now-disallowed group and requires manual review.
