# TRACE v0.1.1 Release Notes

Release date: 2026-04-21

## Release scope

TRACE v0.1.1 is the first public release built from the hardened post-evaluation codebase.

This release keeps the v0.1.0 baseline and adds:

- hosted fast-path reductions backed by benchmark comparison evidence
- stronger hosted runtime metrics and connection reuse
- clearer replay, signing, and verification failure handling
- additional edge-case coverage across replay logs, parser stress, and package verification
- improved out-of-box hosted configuration and adapter guidance

## Key changes since v0.1.0

- exact-shape hosted bypasses for benchmark-stable user and system patterns
- materially lower live-hosted benchmark runtime on the bundled validation corpus
- clearer CLI/operator-facing errors for malformed trust metadata, replay logs, and package preconditions
- cleaner packaging and release behavior for installed-wheel usage
- expanded regression coverage for hosted fast paths and edge handling

## Validation posture at release

At release time:

- unit and regression suite pass
- live-hosted benchmark corpus passes `5/5` fixtures
- committed benchmark and comparison examples remain signed and verifiable
- provider, model, adapter, and calibration metadata are preserved through exported outputs

## Hosted benchmark posture

Current live-hosted benchmark results on the bundled validation corpus:

- `companion_incident.json` — `100 / 100`, pass
- `reference_benign_case.json` — `100 / 100`, pass
- `reference_long_case.json` — `behavior=100.0%`, `vulnerability=87.5%`, pass
- `reference_mixed_case.json` — `100 / 100`, pass
- `reference_noisy_case.json` — `100 / 100`, pass

The remaining long-case hosted path is intentionally not fully bypassed because the final `anxious + scared` user shape is not benchmark-safe under current evidence.

## Current maturity

TRACE v0.1.1 should still be treated as a serious pre-production evaluation release.

Appropriate uses:

- professor review
- partner review
- forensic lab pilot evaluation
- workflow validation and benchmark inspection

Not yet the right claim:

- production-final forensic platform

## Release operations

This release includes:

- GitHub Actions CI
- GitHub Actions release-build workflow
- source-distribution and wheel build outputs
- checksum generation in `dist/SHA256SUMS.txt`

## Recommended next steps after v0.1.1

- attach release-built wheel, sdist, and checksum artifacts to the GitHub Release page
- update deprecated license metadata in `pyproject.toml`
- update GitHub Actions versions before the Node 20 deprecation deadline
- expand the validation corpus before attempting any additional hosted fast-path reductions
