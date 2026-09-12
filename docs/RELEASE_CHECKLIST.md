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

## Things that have actually gone wrong

Each of these cost a failed run or a silently wrong artefact. They are conditions
of the current process, not future ideas.

### The candidate branch must be allowed before it is qualified

`candidate-provenance` and `qualification-evidence` in `ci.yml` are gated on an
explicit list of branch refs, and `tools/release_preflight.py` checks the same ref
against `ALLOWED_SOURCE_REFS`. A release branch missing from either produces a
candidate with **no attestation and no evidence bundle**, and the preflight then
refuses to promote it. Add the branch to both before pushing the candidate.

Do not widen or remove the gate to make a run pass. It is what keeps an arbitrary
branch from minting a publishable candidate.

### Hash the manifest bytes the workflow actually writes

`release.yml` materialises the manifest with `printf '%s' "$FG_MANIFEST_JSON"`,
which appends **no trailing newline**. `manifest_sha256` must be computed over
exactly those bytes. A digest taken over a pretty-printed file that ends in `\n`
fails `manifest_hash_verified`, and because later checks depend on it every gate
reports `ok:false` at once, which reads like a much larger failure than it is.

Do not reformat or re-serialise the JSON after computing its digest.

### Checking publishers means checking for extra ones too

Confirming that the correct Trusted Publisher exists is only half of it. PyPI
allows several grants per project, and a stale one from a renamed repository, or
the canonical `release.yml` left pointing at the bridge project, keeps working
silently. Review the whole list for each project and remove anything that is not
needed, matching on the full tuple: owner, repository, workflow filename and
environment.

PEP 740 provenance proves which identity published a given file. It does not tell
you what else is currently allowed to publish.

### After a rename, a release or a tool upgrade, re-check the trust surface

Documentation-only step; it must not trigger a release.

1. Repository identity: the numeric repo id is unchanged and the former name still
   redirects.
2. The Scorecard workflow ran on the new head and succeeded.
3. The **official service** reflects it: `api.scorecard.dev` returns the new commit
   and date, and the badge renders that score. A green workflow alone is not proof of
   publication, and the old repository name keeps its own stale entry.
4. If a Best Practices Badge project exists, its name and repository URL still point
   at this project.
5. `docs/SECURITY-TRUST.md` carries the current score with its commit and date, and
   still separates historical measurements from current ones.
6. Public marketing wording matches what the evidence supports.

## Dependency locks

Every index install in CI runs under `--require-hashes`. Before tagging:

- [ ] `requirements/*.txt` are current for `requirements/*.in`, and the `dev`
      extra in `pyproject.toml` matches `requirements/dev.in`
      (`tests/test_dependency_pinning.py` proves both).
- [ ] If a lock was regenerated, it was resolved on **Python 3.11** and then
      installed on 3.11 **and** 3.12. A lock resolved on 3.12 omits
      `backports.tarfile` and fails `--require-hashes` on 3.11.
- [ ] No workflow gained a `pip install` without `--require-hashes` or
      `--no-deps`.

Procedure: `docs/DEPENDENCY_PINNING.md`.

## Fuzzing

- [ ] `cflite-batch` has run since the last release and reported no crash.
- [ ] If a harness or a parsed model changed, the harnesses were rebuilt and run
      locally (`docs/FUZZING.md`) before tagging.
