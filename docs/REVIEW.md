# Review and acceptance

## How a change is accepted

1. Work happens on a branch and is proposed as a pull request. Every change in
   the project's history has gone through one.
2. Automated gates must pass. Five are configured as required status checks on
   `main` (`test (3.11)`, `test (3.12)`, `build`, `Analyze (python)`,
   `Analyze (actions)`) in strict mode, so a branch must also be up to date
   with `main`. The protection applies to administrators, and force-push and
   branch deletion are blocked.
3. The maintainer reviews against the criteria below.
4. The change merges. The branch is deleted.

Two details worth stating precisely rather than implying:

- **A pull request is the convention, not a branch-protection rule.** GitHub is
  not configured to require one, so the rule that keeps `main` honest is the
  required status checks, which apply either way.
- **Approving reviews are not required**, because with one maintainer requiring
  them would either block every change or be satisfied by the author.

## What must pass before a change can merge

| Gate | What it catches |
| --- | --- |
| `ruff check` / `ruff format --check` | style and a class of correctness defects |
| `pytest` with the coverage floor | behaviour regressions, untested new code |
| `pip check` | a locked version that no longer satisfies `pyproject.toml` |
| wheel smoke, outside the checkout | packaging defects invisible in a source tree |
| CodeQL (Python and Actions) | common vulnerability classes, workflow weaknesses |
| Dependency Review | a newly introduced vulnerable dependency |
| ClusterFuzzLite | crashes in changed parsing and serialisation code |
| `tests/test_dependency_pinning.py` | an unpinned or unhashed install sneaking back in |

## What the maintainer looks for beyond the gates

Green CI is necessary, not sufficient. A change is also judged on:

- **Evidence honesty.** Does every conclusion follow from evidence the tool
  actually collected? A finding must not claim more certainty than its source
  supports. `INDETERMINATE` is a correct answer; a confident wrong answer is not.
- **Read-only discipline.** No write path, no state change, no probe of anything
  the operator did not explicitly authorize.
- **Scope.** One authorized instance. No discovery, no third-party targets.
- **Blast radius.** Does this touch the release pipeline, the schemas or the
  published contract? Those need a stronger justification than internal code.
- **Tests that would have failed before.** A test that passes against both the
  old and the new behaviour proves nothing.
- **Documentation that matches reality.** A claim in the README or in
  `docs/SECURITY-TRUST.md` that the code no longer supports is a defect.

## Release changes

Anything touching versioning, packaging, the workflows or published artifacts
additionally follows [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md), which records
the failure modes this project has actually hit rather than a generic list.

## The limit of this process, stated plainly

**There is no independent human review.** The project has one maintainer. Pull
requests are opened and merged by the same person, so no second human inspects a
change before it lands. OpenSSF Scorecard reports this accurately as
`Code-Review: 0`, and [MAINTAINERS.md](../MAINTAINERS.md) discloses the
structure.

The automated gates above are a real and deliberate compensating control: they
catch regressions, common vulnerability classes, packaging defects, supply-chain
drift and parser crashes without human attention. They do **not** substitute for
a second person, and this project does not claim they do. Specifically, no
automated gate reliably catches:

- a design that is coherent and well-tested but wrong for the problem;
- a finding whose wording overstates what the evidence supports;
- a scope decision that should have been refused.

This is the single largest gap in the project's development process. It is a
structural property of a one-person project, not an oversight, and it will only
close when a second maintainer joins. Until then it is disclosed rather than
papered over.

Outside review is welcome. Anyone may open an issue or a pull request, and
review comments on a merged change are still useful.
