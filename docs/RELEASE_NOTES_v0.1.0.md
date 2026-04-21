# TRACE v0.1.0 Release Notes

Release date: 2026-04-20

## Release scope

TRACE v0.1.0 is the first public release baseline for external evaluation.

This release establishes:

- repeatable transcript ingest and normalization
- deterministic and hosted-assisted classification paths
- replay capture and replay-only reanalysis
- evidence-package export with manifest and verification outputs
- benchmark, comparison, history, and trend workflows
- signed example artifact bundles
- adapter-aware hosted-provider configuration
- workspace bootstrap, demo, and release-build helpers

## Current maturity

TRACE v0.1.0 should be treated as a serious pre-production evaluation release.

Appropriate uses:

- professor review
- partner review
- forensic lab pilot evaluation
- workflow validation and benchmark inspection

Not yet the right claim:

- production-final forensic platform

## Validation posture at release

At release time:

- unit and regression suite pass
- local demo workflow passes
- committed benchmark and comparison examples are signed and verifiable
- provider, model, and adapter metadata are preserved through exported outputs

## Key operational capabilities

- `trace init` for workspace bootstrap
- `trace config-check` for provider and adapter readiness
- `trace validate` and benchmark workflows for validation discipline
- `trace report` for evidence-package export
- `./scripts/demo_trace.sh` for first-run evaluation
- `./scripts/build_release.sh` for sdist and wheel generation

## Hosted-provider posture

Hosted use is now adapter-aware.

Supported hosted adapters:

- `openai-compatible`
- `anthropic-messages`

Hosted results remain bounded by:

- replay capture support
- calibration rules
- provider-drift policy
- explicit metadata preservation in outputs

## Release operations

This release includes:

- GitHub Actions CI
- GitHub Actions release-build workflow
- source-distribution manifest
- packaged docs, examples, and validation fixtures

## Recommended next steps after v0.1.0

- publish a GitHub release using the generated tag
- attach release-built wheel and sdist artifacts
- attach checksum file
- keep benchmark and drift evidence synchronized with future tags
