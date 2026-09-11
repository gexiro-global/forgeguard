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

`release.yml` prepares and qualifies candidates on every trigger but never uploads
automatically. A GitHub Release (`release: published`) can no longer reach the
upload job. To publish in the future, a maintainer must:

1. Dispatch the `publish` workflow (`workflow_dispatch`) against the exact commit
   to release; the preflight refuses unless `source_sha` equals the built HEAD.
2. Provide `version` (must equal the project version), the qualifying `run_id`
   (must be a completed successful run), and `attestation_verified=true`.
3. Set `publish=true`. The upload job runs only when the data-validated preflight
   approves, and `id-token: write` is scoped to that single job.
4. The upload job downloads the exact prepared distributions and re-verifies their
   SHA-256 before publishing; it never rebuilds.

Inputs are validated as data (`tools/release_preflight.py`), never interpolated
into a shell. The contract is covered by `tests/test_release_workflow.py`.
