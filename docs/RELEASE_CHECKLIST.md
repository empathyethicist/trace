# TRACE Release Checklist

This checklist defines the minimum release gate for a public TRACE revision intended for external review, demonstration, or partner evaluation.

## Validation gate

- Run the full unit and regression suite.
- Run `trace benchmark --validation-dir ./validation --profile heuristic`.
- Run `trace benchmark --validation-dir ./validation --profile mock-hosted`.
- Run `trace benchmark --validation-dir ./validation --profile live-hosted` when release credentials are available and provider-drift evidence is desired.
- Run `trace benchmark-compare --validation-dir ./validation --baseline-profile heuristic --candidate-profile mock-hosted`.
- Run `trace benchmark-compare --validation-dir ./validation --baseline-profile heuristic --candidate-profile live-hosted` when a live-provider run is included in release evidence.
- Confirm:
  - `failed_fixtures == 0`
  - `pass_rate == 100.0`
  - `drift_count == 0` unless the change is intentional and documented

## Artifact gate

- Export benchmark artifacts in JSON and Markdown form.
- Sign emitted benchmark artifact bundles.
- Verify signed artifact manifests.
- Retain both latest and dated history snapshots.
- Generate and retain history trend summaries for any benchmark series included in the release.

## Documentation gate

- Update `README.md` if CLI or workflow behavior changed.
- Update `docs/VALIDATION.md` if benchmark coverage or fixture expectations changed.
- Update `docs/BENCHMARK_GOVERNANCE.md` if policy or interpretation changed.
- Update `docs/PROVIDER_DRIFT_POLICY.md` if hosted-provider thresholds or interpretation changed.
- Update `docs/RELEASE_TAGGING.md` if release-to-artifact linkage changed.
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
- Record exact live-provider model identifiers for any `live-hosted` benchmark run.

## Hosted-profile note

The current `mock-hosted` benchmark profile remains a simulated hosted workflow used for comparison plumbing and benchmark discipline. It is not a live-provider benchmark release gate.

## Live-hosted profile note

When credentials are available, `live-hosted` should be treated as the external-provider benchmark profile. It is appropriate for release evidence only when the emitted artifacts record the exact provider-backed model used and the signed benchmark bundle is archived with the release materials.

At present, a live-provider run is best treated as drift evidence rather than as a required pass/fail release gate. If `live-hosted` diverges from the deterministic baseline, the release notes should say so explicitly rather than hiding the result.
