# TRACE Release Checklist

This checklist defines the minimum release gate for a public TRACE revision intended for external review, demonstration, or partner evaluation.

## Validation gate

- Run the full unit and regression suite.
- Run `trace benchmark --validation-dir ./validation --profile heuristic`.
- Run `trace benchmark --validation-dir ./validation --profile hosted`.
- Run `trace benchmark-compare --validation-dir ./validation --baseline-profile heuristic --candidate-profile hosted`.
- Confirm:
  - `failed_fixtures == 0`
  - `pass_rate == 100.0`
  - `drift_count == 0` unless the change is intentional and documented

## Artifact gate

- Export benchmark artifacts in JSON and Markdown form.
- Sign emitted benchmark artifact bundles.
- Verify signed artifact manifests.
- Retain both latest and dated history snapshots.

## Documentation gate

- Update `README.md` if CLI or workflow behavior changed.
- Update `docs/VALIDATION.md` if benchmark coverage or fixture expectations changed.
- Update `docs/BENCHMARK_GOVERNANCE.md` if policy or interpretation changed.
- Update `examples/` artifacts if externally visible benchmark behavior changed.

## Review gate

- Confirm no benchmark fixture was added, removed, or modified without intent.
- Confirm any heuristic changes are reflected in expected benchmark behavior.
- Confirm any hosted-profile drift is understood and documented.
- Confirm any new parser or report capability has direct tests.

## Release note gate

- Record the release rationale.
- Record benchmark status at release time.
- Record whether benchmark comparison was drift-free.
- Record whether artifacts were signed and archived.

## Current hosted-profile note

The current hosted benchmark profile remains a mock-hosted workflow used for comparison plumbing and benchmark discipline. It is not yet a live-provider benchmark release gate.
