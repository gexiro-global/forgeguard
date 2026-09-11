# Upstream evidence

Configuration is independently checked against the stated release tags; release-note branch content is frozen by its captured SHA-256. No upstream code is copied into the Python implementation. Config sources were retrieved 2026-09-10; advisory records were re-frozen 2026-09-11 (see below).

| Source | SHA-256 of retrieved bytes |
|---|---|
| [gitea-config](https://github.com/go-gitea/gitea/blob/v1.27.3/custom/conf/app.example.ini) | e84218d594230f62eb15d4e5615f25dc16ca21303339585a80a79f103c1fa785 |
| [forgejo-config](https://codeberg.org/forgejo/forgejo/src/tag/v16.0.4/custom/conf/app.example.ini) | c78f4ed6a3457261ae1725f4f77b6bb6a49c4234faa58a1c134a44657c041757 |
| [forgejo-lts-config](https://codeberg.org/forgejo/forgejo/src/tag/v15.0.8/custom/conf/app.example.ini) | 6759febe183afefcb4139e073746b89a09c40fdeae79084f1848ad253be2e035 |
| [gitea-GHSA-8qw8-rq86-9pc2 (single record)](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-8qw8-rq86-9pc2) | 09a541436af61a369d038203d01c9bd1bb4c903b1bc6ab19f7694da62f4f52f5 |
| [gitea-GHSA-frpv-2xgv-wxpq (single record)](https://api.github.com/repos/go-gitea/gitea/security-advisories/GHSA-frpv-2xgv-wxpq) | c8e6cec99c7f6fc41a4b18b6cb0cff9e2c86561dec7952d63176a52aee7a5110 |
| [forgejo-16.0.4-notes](https://codeberg.org/forgejo/forgejo/src/branch/forgejo/release-notes-published/16.0.4.md) | 5769d9d511c035f29e0c345718f4a2cc1f9567f9f93895005e038cafd2c4b99a |
| [forgejo-15.0.8-notes](https://codeberg.org/forgejo/forgejo/src/branch/forgejo/release-notes-published/15.0.8.md) | d0ca357d547734c72b2956ba5fd36784ce3a37f1c2fb3c1c28cf870ff25dd7d4 |

Each advisory catalog record binds to the exact single-record retrieval, not a collection listing. The prior candidate hashed record `FG-CVE-78433` against the `security-advisories?per_page=5` collection listing, whose bytes and hash drift as new advisories are published; it now binds to the single `GHSA-frpv-2xgv-wxpq` record endpoint. The exact retrieved bytes for every advisory record are frozen under `tests/fixtures/sources/` with a structured manifest (`manifest.json`: source_id, canonical_advisory_url, retrieval_url, resolved_url, retrieved_at_utc, media_type, upstream_revision_or_tag, raw_bytes_sha256, selected_record_id, selected_record_location, supported_conclusion, limitations). `tests/test_sources.py` re-verifies the hashes offline; `forgeguard scan` never fetches them.

Gitea config includes [security] TWO_FACTOR_AUTH and [repository] FORCE_PRIVATE/DEFAULT_PRIVATE. Forgejo v15/v16 independently includes [security] GLOBAL_TWO_FACTOR_REQUIREMENT. service registration/sign-in keys are mapped separately from repository keys.

Gitea advisory records retain upstream GHSA severity and affected/fixed metadata (GHSA-8qw8-rq86-9pc2 high; GHSA-frpv-2xgv-wxpq medium). The GHSA-frpv record has explicit affected range 1.26.0–1.27.2 and fixed 1.27.3. Fixed extrapolation stops at 1.27.3. Forgejo release notes establish exact fixes at 15.0.8 and 16.0.4, not an affected introduction boundary; other versions are undetermined.

The unchanged OASIS schema and complete copyright notice are included under forgeguard/schemas. Its SHA-256 is checked by tests. The project remains Apache-2.0; the OASIS schema retains its own notice.

Forgejo v16.0.4 Makefile appends GITEA_COMPATIBILITY=gitea-1.22.0 to its API version. Source: https://codeberg.org/forgejo/forgejo/src/tag/v16.0.4/Makefile (SHA-256 acf93a41758c7b70eb899a69f34ed76788dc863c5f0020aa97f4015766a49b77). Both v15/v16 version handlers return setting.AppVer; source handlers SHA-256 478bd137f67e29a045e6b8ff55073d4d473028f1d6e6889cec1cff81af8046b0. Real integration observed the compatibility suffix in both exact target releases. It is a compatibility marker, not independent product confirmation.

## Runner review upstream evidence

Retrieved 2026-09-11. These citations are documentation-only (not wired into the
`tests/test_sources.py` frozen-manifest re-verification that binds the HTTP advisory catalog);
each was independently confirmed by downloading the exact, checksum-verified official release
binary and running its own `--version` and `generate-config` (no registration, no network job
execution) rather than trusting a blog post.

| Fact | Source | Retrieved |
|---|---|---|
| Gitea Runner >=3.0.0 strips host-escape `container.options` (`PidMode`, `CapAdd`, `SecurityOpt`, `Devices`, `DeviceCgroupRules`, `DeviceRequests`, `VolumesFrom`, `Runtime`, `CgroupParent`, `Sysctls`, ...) from non-privileged job containers | [blog.gitea.com/release-of-runner-3.0.0](https://blog.gitea.com/release-of-runner-3.0.0/), [gitea/runner#1058](https://gitea.com/gitea/runner/issues/1058) | 2026-09-11 |
| `gitea-runner` v3.4.2 self-reported version and `generate-config` output confirm the exact `privileged`/`valid_volumes`/`network`/`docker_host`/`options` field names and defaults, and the non-privileged option-stripping note verbatim in the generated config comments | `https://gitea.com/gitea/runner/releases/download/v3.4.2/gitea-runner-3.4.2-linux-amd64`, sha256 `3d823df5b6084d6d8d8cfb86713a5525285eb99d0ca66692b87e050e3eec2466` (verified against the release's own `checksums.txt`) | 2026-09-11 |
| Forgejo Runner v13.0.0 removes implicit `DOCKER_USERNAME`/`DOCKER_PASSWORD` registry auth (replaced by explicit `jobs.<job_id>.container.credentials`) and removes the `add-path`/`set-output`/`set-env` workflow commands (workflow-command-injection class) | [forgejo.org/2026-08-runner-release-v13](https://forgejo.org/2026-08-runner-release-v13/) | 2026-09-11 |
| Forgejo Runner v13.1.0 adds an experimental, alpha-stability gRPC plugin execution-engine protocol; no stability guarantee | [forgejo.org/2026-09-runner-release-v131](https://forgejo.org/2026-09-runner-release-v131/) | 2026-09-11 |
| `forgejo-runner` v13.1.0 self-reported version and `generate-config` output confirm the same `container.privileged`/`valid_volumes`/`network`/`docker_host`/`options` field names as Gitea, and that `docker_host="-"` (default) means no daemon socket is mounted into the job container while a non-empty value mounts it at `/var/run/docker.sock` | `https://code.forgejo.org/forgejo/runner/releases/download/v13.1.0/forgejo-runner-13.1.0-linux-amd64`, sha256 `29dae21e93f0eab5cdf3564008d44603c74770b41a4f4f1aceed172c774bc376` (verified against the release's own `.sha256` file) | 2026-09-11 |
| Forgejo Actions security guidance: `container.privileged` default `false`; `container.valid_volumes` default `[]`, wildcard `**` allows any volume; `docker`/`lxc`/`host` label isolation levels (`lxc` has no CPU/memory/disk/network limit enforcement; `host` runs as the runner's own user with zero isolation) | [forgejo.org/docs/latest/admin/actions/security](https://forgejo.org/docs/latest/admin/actions/security/) | 2026-09-11 |
| Ephemeral registration (`--ephemeral`) is server-enforced: at most one job, credential revoked on assignment; stricter than `--once` (stops after one job but the credential remains valid) — confirmed identically documented for both Gitea and Forgejo runners | [forgejo.org/docs/v15.0/admin/actions/registration](https://forgejo.org/docs/v15.0/admin/actions/registration/), [docs.gitea.com/runner/registration](https://docs.gitea.com/runner/registration/) | 2026-09-11 |

Gitea Runner's Docker Hub image `gitea/act_runner:latest` was checked and found to self-report
`version=v0.6.1` — a stale/mismatched tag scheme relative to the real `gitea.com/gitea/runner`
source releases (`v3.4.2` at the time of this qualification). ForgeGuard's citations and
qualified-version list use the verified source-repo binary, not that Docker Hub image.

## Gitea previous-line qualification

Read 2026-09-10: [release management](https://github.com/go-gitea/gitea/blob/579de92b8adceb4d0feea7d6a142809440e68b9c/docs/release-management.md)
describes general support for the latest and previous major release;
[security policy](https://github.com/go-gitea/gitea/blob/579de92b8adceb4d0feea7d6a142809440e68b9c/SECURITY.md)
limits security fixes to the newest release and main. General maintenance does
not imply security maintenance. Gitea 1.26.4 is tested with its known advisory
reported, never recommended as a secure downgrade.

The seven snapshot setting names, types and defaults were also checked against
[v1.26.4 app.example.ini](https://github.com/go-gitea/gitea/blob/v1.26.4/custom/conf/app.example.ini);
these mapped settings match the v1.27.3 definitions referenced by the provider.
Config SHA-256: `6b5ee7290cbee1f99e45d216bb0575ce7d0c78d4a2377b98a35baaf2d0be82e8`.
Maintenance policy SHA-256: `eb193767e674373905e0dffe450b7dee754c29d80065194ba5abc681a10776c5`.
Security policy SHA-256: `a598fbfd6f9aa289705754e959f39afee03dca95c4f03db1264f535b13a5c818`.
