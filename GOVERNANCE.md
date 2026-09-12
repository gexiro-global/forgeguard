# Governance

VersionSec is maintained by Gexiro Global Enterprises Ltd.

## Decisions

The maintainer decides scope, accepts or rejects changes, and cuts releases.
Changes are proposed through GitHub pull requests and must pass the required
automated checks on `main`. Branch protection applies to administrators, and
force-push and branch deletion are blocked. Approving reviews are not required;
[docs/REVIEW.md](docs/REVIEW.md) explains why, and what that costs.

A change is rejected, regardless of code quality, if it adds unauthorized
discovery, exploit behaviour, a write path or state-changing probe, or a PASS
conclusion the collected evidence does not support. The criteria a change is
judged against are written down in [docs/REVIEW.md](docs/REVIEW.md).

## Roles

| Role | Held by | Responsible for |
| --- | --- | --- |
| Project owner | `@dzeusking-dev` | scope, roadmap, final say on acceptance |
| Release maintainer | `@dzeusking-dev` | tagging, publishing, release provenance |
| Security contact | `@dzeusking-dev` | triage of private reports under [SECURITY.md](SECURITY.md) |
| Contributor | anyone | proposing changes, reporting defects, reviewing |

Contributor is an open role. Opening an issue or a pull request needs no prior
relationship with the project.

## What is not claimed

All four maintainer roles are currently held by one person. There is no
independent review of changes, no guaranteed response time, no service level
and no certification. [docs/REVIEW.md](docs/REVIEW.md) states exactly what the
automated gates do and do not compensate for, and
[MAINTAINERS.md](MAINTAINERS.md) discloses the structure.

If the project gains a second maintainer, two-person review of changes to the
release pipeline and the published contract is the first thing that changes.
