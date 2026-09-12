# Candidate release checklist

- Preserve the Python 3.11 and 3.12 regression gates, lint/format/compile and pip check.
- Run provider error matrices and real pinned-image integration variants.
- Validate golden, integration and installed-wheel JSON/SARIF offline.
- Build wheel and sdist, twine check, inspect package resources/license/type markers.
- Install exact distributions in fresh environments outside the source tree.
- Capture runtime/build/dev dependency inventories, audits and license metadata.
- Generate the runtime SBOM, artifact hashes and commit/toolchain manifest.
- Compare two clean builds; document byte/content differences.
- Review the final diff and secret checks. Push one branch and maintain one PR.
- Candidate provenance must be generated and verified for exact CI artifacts.
  An implemented workflow alone is not verified attestation.
- Read CI results for the final head/merge revision. Skipped/pending is not PASS.
- Keep PR draft when any mandatory evidence gate is incomplete.
- Do not merge, publish tags/releases/PyPI, change environments, trust publishers,
  branch protection or production as part of this milestone.

## Manual publish contract (no automatic publication)

Qualification (test, build, attest) happens on the trusted push in `ci.yml`.
`release.yml` only PROMOTES an already-qualified candidate and never rebuilds.
A GitHub Release (`release: published`) cannot reach the upload job. To publish
in the future, a maintainer must:

1. Dispatch the `publish` workflow (`workflow_dispatch`) providing `version`
   (== project version == manifest version), the full `source_sha`, the trusted
   push `run_id`/`run_attempt` that qualified the candidate, and the qualification
   `manifest_json` (+ its `manifest_sha256`).
2. The `promote` job downloads the exact frozen artifacts of that run (no rebuild),
   independently reads the run metadata from the API, runs `gh attestation verify`
   on the exact wheel and sdist, and validates every binding via
   `tools/release_preflight.py`. This yields `prepared` and `publish_allowed`.
3. `publish=false` is a successful prepare-only (exit 0, `publish_allowed=false`,
   no upload). Any validation failure refuses with a non-zero code.
4. `publish=true` reaches `pypi-publish` only when `publish_allowed==true`. That
   job re-downloads the same frozen set, re-verifies digests against the manifest,
   and hands exactly those bytes to the publisher. `id-token: write` is scoped to
   that single job; the promotion path never rebuilds.

Inputs are validated as data (never interpolated into a shell). `attestation_verified`
is not a sufficient input: a real verifier result is required. Covered by
`tests/test_release_workflow.py`.

## Public surfaces to refresh after a version bump

The repository social preview carries the version number and is the card every
social platform renders when the repo is shared. GitHub exposes it only through
Settings -> Social preview; there is no REST or GraphQL field for it, and web
routes do not accept a token, so it cannot be scripted. Regenerate
`assets/versionsec_social_1280x640.png` with the new version and re-upload it by
hand, or the card silently advertises the previous release.

The same generated mark is served from versionsec.com and from the Gexiro product
page. Those two rebuild from source, so they only need a deploy.
