# TRACE v0.1.3 Release Notes

Release date: 2026-04-21

## Release scope

TRACE v0.1.3 is a release-metadata correction over v0.1.2.

This release does not change TRACE's forensic behavior. It aligns package metadata with the published Git tag and release so built artifacts carry the correct version number.

## What changed

- updated `pyproject.toml` package version to `0.1.3`
- updated `src/trace_forensics/__init__.py` runtime version to `0.1.3`

## Why this release exists

The public `v0.1.2` release workflow succeeded, but the built wheel and sdist still carried package version `0.1.0` because the package metadata had not been updated.

`v0.1.3` corrects that mismatch so:

- release tag and package metadata agree
- wheel and sdist filenames reflect the public release version
- `trace version` reports the same version as the GitHub Release

## Validation posture at release

At release time:

- unit and regression suite pass
- live-hosted benchmark corpus remains stable
- release-build workflow is already fixed and succeeding

## Current maturity

TRACE v0.1.3 remains a serious pre-production evaluation release.
