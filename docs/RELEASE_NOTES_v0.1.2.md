# TRACE v0.1.2 Release Notes

Release date: 2026-04-21

## Release scope

TRACE v0.1.2 is a release-operations patch over v0.1.1.

This release does not change TRACE's forensic behavior. It fixes the GitHub release-build workflow so tagged releases build successfully from CI.

## What changed

- updated `.github/workflows/release-build.yml`
- release-build setup now installs:
  - `build`
  - `setuptools`
  - `wheel`

## Why this release exists

The `v0.1.1` tag and GitHub Release were published successfully, but the tag-triggered `Release Build` workflow failed during artifact generation because `wheel` was not available in the job environment while `./scripts/build_release.sh` used `python -m build --no-isolation`.

`v0.1.2` corrects that release-path defect so:

- sdist and wheel artifacts build in GitHub Actions
- `dist/SHA256SUMS.txt` is produced
- release artifact upload can complete

## Validation posture at release

At release time:

- unit and regression suite pass
- TRACE remains benchmark-stable on the bundled validation corpus
- the release-build workflow configuration is corrected for no-isolation builds

## Current maturity

TRACE v0.1.2 remains a serious pre-production evaluation release.

Appropriate uses:

- professor review
- partner review
- forensic lab pilot evaluation
- workflow validation and benchmark inspection

Not yet the right claim:

- production-final forensic platform
