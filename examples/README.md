# Example artifacts

This directory contains sample TRACE outputs intended to help reviewers understand the structure of exported evidence packages.

## Included example

- `companion_incident_package/`
- `benchmark_artifacts/`
- `benchmark_comparison/`
- `benchmark_artifacts/live_hosted/`
- `benchmark_artifacts/live_hosted_hardened/`
- `benchmark_comparison_live_hosted/`
- `benchmark_comparison_live_hosted_hardened/`
- `benchmark_history/`

This package was generated from the repository validation fixture using the current TRACE pipeline and demonstrates:

- normalized source transcript storage
- classified transcript outputs
- correlation analysis artifacts
- audit logging
- configuration and prompt-template preservation
- package manifest structure

The benchmark artifacts demonstrate:

- heuristic-profile benchmark summary output
- hosted-profile benchmark summary output
- live-hosted benchmark summary output
- JSON and Markdown benchmark artifacts suitable for review or archival
- detached benchmark artifact manifests, signatures, and trust metadata
- reproducible verification targets for reviewer spot-checks

The benchmark comparison demonstrates:

- profile-to-profile drift analysis
- zero-drift reporting across the bundled validation corpus
- JSON and Markdown comparison artifacts for reproducibility

The live-hosted comparison demonstrates:

- drift between the deterministic heuristic baseline and a real hosted-provider run
- signed artifact preservation for that drift evidence
- the current need to treat live-provider benchmarking as an observational quality signal rather than a release-pass gate

The current committed `live_hosted` example was produced against `openrouter/free` and shows non-zero drift relative to the heuristic baseline. That result is intentional to demonstrate how TRACE records live-provider divergence instead of hiding it.

That divergence should be interpreted together with `docs/PROVIDER_DRIFT_POLICY.md`.

The `live_hosted_hardened` and `benchmark_comparison_live_hosted_hardened` examples capture the replay-driven hardening state reached on April 19, 2026 after hosted vulnerability calibration and trajectory-tightening work. Those artifacts show:

- `0.0` behavioral delta across the crisis-sensitive replay set
- `0.0` vulnerability delta for `companion_incident.json`
- `0.0` vulnerability delta for `reference_noisy_case.json`
- residual `-12.5` vulnerability delta for `reference_long_case.json`
- provider drift policy status of `pass`

Those hardened replay artifacts should be interpreted together with:

- `docs/LIVE_PROVIDER_HARDENING.md`
- `docs/PROVIDER_DRIFT_POLICY.md`

The benchmark history demonstrates:

- latest-snapshot records for heuristic, hosted, and comparison runs
- immutable dated snapshot records for the same benchmark families
- history summary artifacts
- trend summary artifacts suitable for release-review comparison

These artifacts are illustrative sample outputs, not live case materials.

## Verification commands

Example verification flow for committed benchmark artifacts:

```bash
openssl dgst -sha256 -verify \
  examples/benchmark_artifacts/heuristic/bench_signer_public.pem \
  -signature examples/benchmark_artifacts/heuristic/artifact_manifest.sig \
  examples/benchmark_artifacts/heuristic/artifact_manifest.json

openssl dgst -sha256 -verify \
  examples/benchmark_comparison/bench_signer_public.pem \
  -signature examples/benchmark_comparison/artifact_manifest.sig \
  examples/benchmark_comparison/artifact_manifest.json

openssl dgst -sha256 -verify \
  examples/benchmark_artifacts/live_hosted/live_public.pem \
  -signature examples/benchmark_artifacts/live_hosted/artifact_manifest.sig \
  examples/benchmark_artifacts/live_hosted/artifact_manifest.json

openssl dgst -sha256 -verify \
  examples/benchmark_comparison_live_hosted/live_public.pem \
  -signature examples/benchmark_comparison_live_hosted/artifact_manifest.sig \
  examples/benchmark_comparison_live_hosted/artifact_manifest.json

trace benchmark-history \
  --history-dir ./examples/benchmark_history \
  --prefix benchmark_heuristic_latest

trace benchmark-trend \
  --history-dir ./examples/benchmark_history \
  --prefix benchmark_heuristic_latest

trace benchmark-trend \
  --history-dir ./examples/benchmark_history \
  --prefix benchmark_live-hosted_latest
```
