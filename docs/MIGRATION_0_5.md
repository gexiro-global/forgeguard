# Migrating to the 0.5 preview

The candidate is 0.5.0rc1. Nothing in this change publishes a release.

The CLI now produces `forgeguard.assessment.v1`. Its packaged JSON Schema is
`forgeguard/schemas/assessment-v1.json`. Historical v0.3 examples remain clearly
identified as 0.2.2 examples; they are not current 0.5 score examples.

Existing `scan`, `checks`, `--authorized`, `--product`, `--known-version`,
`--token`, `--out`, `--format` and `--scan-id` names remain.
Use `providers` for the closed provider registry. `--product forgejo` is now accepted.
Omitting the product leaves identity unknown and the assessment incomplete.
The private Python module layout is not a supported API; historical check helpers
and the old renderer are retained for regression comparison. The CLI uses the new
provider-aware core.

## Changed meaning

Scoring algorithm 2 is not comparable with 0.2.2. Default policy is `unspecified`.
Anonymous HTTP 200 is informational for public or unspecified intent. Private
intent produces a review warning, never a claim of access to private data.
The API and browsing observations share a penalty group (maximum penalty only).
Version advisories likewise share a maximum penalty group.
Version disclosure and header presence are informational.

A warning and incomplete evidence can coexist. Incomplete evidence takes
precedence in the overall grade: null/N/A/unassessed. A profile excludes controls
explicitly; skipped controls do not become PASS. Supported configuration mappings
are limited to the exact qualification targets shown by `providers`.

## Identity and versions

Both raw inventory and observed version are retained. Different normalized values or unrecognized metadata produce a conflict; raw
values are always retained. The exact Forgejo v15/v16 compatibility suffix
+gitea-1.22.0 is normalized by the Forgejo provider, as documented by its tagged
Makefile, and does not mean the product is Gitea. Explicit opposing product markers in either value
stop product-dependent inference. Final upstream x.y.z and explicit product build
markers are accepted. Prerelease, vendor metadata, vendor suffixes, leading zeros,
unrecognized syntax and versions outside catalog bounds remain undetermined.
No arbitrary backport is inferred.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Complete selected assessment with no warning or failure; or successful dry-run/list |
| 2 | Invalid input, authorization refusal or unsafe output |
| 3 | Execution/output failure |
| 4 | Incomplete assessment, even if another finding warns |
| 5 | Complete assessment containing policy warning or advisory failure |

JSON/SARIF stdout contains only the document. Diagnostics go to stderr.
Multiple formats require `--out`. Markdown uses that path; JSON/SARIF replace
the suffix. Existing output files, symlinks and collisions are refused before
requests. Writes are atomic and never clobber an existing file. Choose a new base
name for each assessment.

## SARIF

SARIF 2.1.0 is validated against the packaged, unchanged official OASIS errata01
schema. Findings have stable rules and matching indices. Only WARN/FAIL produce
results; no source filenames/line numbers are invented for HTTP observations.
Run properties preserve incompleteness, skipped checks, catalog and scope.
Fingerprints bind the instance identifier, rule and policy, not execution time.
Schema validation is the tested integration boundary. No DevGuard or GitHub Code
Scanning importer compatibility is claimed and no report is uploaded to them.

`Assessment.normalized()` removes run metadata and scan_id. Arrays have stable
ordering. The instance identifier and evidence remain part of the comparison.
