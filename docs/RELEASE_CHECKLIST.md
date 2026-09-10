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
