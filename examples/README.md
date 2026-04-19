# Example artifacts

This directory contains sample TRACE outputs intended to help reviewers understand the structure of exported evidence packages.

## Included example

- `companion_incident_package/`
- `benchmark_artifacts/`
- `benchmark_comparison/`
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
- JSON and Markdown benchmark artifacts suitable for review or archival
- detached benchmark artifact manifests, signatures, and trust metadata
- reproducible verification targets for reviewer spot-checks

The benchmark comparison demonstrates:

- profile-to-profile drift analysis
- zero-drift reporting across the bundled validation corpus
- JSON and Markdown comparison artifacts for reproducibility

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

trace benchmark-history \
  --history-dir ./examples/benchmark_history \
  --prefix benchmark_heuristic_latest

trace benchmark-trend \
  --history-dir ./examples/benchmark_history \
  --prefix benchmark_heuristic_latest
```
