# Publication Checklist

## Local Package

- [x] Public package files prepared.
- [x] Source copied from the clean v0.2 package only.
- [x] Synthetic examples authored.
- [x] Examples validate against `ScanResult`.
- [x] `python -m compileall forgeguard` passed.
- [x] `python -m pytest -q` passed.
- [x] CLI checks/help commands passed.
- [x] `python -m build` passed.
- [x] sdist and wheel contents listed.
- [x] OPSEC and marketing scans completed.
- [x] Local git commit created.

## Human Review Before Private Staging

- [ ] Independent reviewer completes OPSEC grep and build inspection.
- [ ] Reviewer confirms no live-scan artifacts are present.
- [ ] Reviewer confirms examples are synthetic.
- [ ] Reviewer confirms docs match the intended public positioning.
- [ ] Reviewer approves private GitHub staging.

## Private GitHub Staging

- [ ] Create `gexiro-global/forgeguard` as private.
- [ ] Push local commit to the private repository.
- [ ] Enable GitHub security features.
- [ ] Verify README, license, security policy, issue templates, and PR template.
- [ ] Run GitHub Actions CI.
- [ ] Review package rendering and community profile.

## Public Release Gate

- [ ] Written final approval from the release owner.
- [ ] Confirm no remotes or publishing commands were run during package preparation.
- [ ] Confirm private staging has passed review.
- [ ] Flip repository visibility only after final approval.
- [ ] Publish package artifacts only after a separate package-release approval.
