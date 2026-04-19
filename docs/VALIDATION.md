# TRACE Validation

This document describes the current validation posture of TRACE and the standards required for broader production confidence.

## Purpose

TRACE is a forensic workflow tool. Validation is therefore not limited to software correctness; it must also address repeatability, schema stability, evidentiary integrity, and classification reliability.

## Current validation coverage

TRACE currently validates the following:

- ingest and normalization on supported input formats
- transcript structure and speaker constraints
- deterministic classification-path behavior
- correlation-analysis output generation
- evidence-package artifact creation
- evidence-package hash verification
- detached manifest signature verification
- signing-certificate verification with optional CRL checks
- dual-coder IRR computation
- reference-case agreement using the Companion Incident and benign baseline fixtures

## Current benchmark snapshot

The table below reflects the current repository validation posture on the included reference fixture.

| Validation target | Current state |
|---|---|
| Automated unit/regression suite | Passing |
| Reference behavioral agreement threshold | Implemented |
| Reference vulnerability agreement threshold | Implemented |
| Expected findings comparison | Implemented |
| Dual-coder IRR computation | Implemented |
| Multiple reference fixtures | Implemented |
| Parser validation for court / UFED / AXIOM ingest | Implemented |
| Hosted-provider benchmark corpus | Not yet implemented |
| PDF report generation validation | Implemented |
| Evidence-package hash verification | Implemented |
| Detached manifest signature verification | Implemented |
| Signing-certificate verification with CRL option | Implemented |

## Current automated checks

The repository test suite currently covers:

- parsing and ingest behavior
- classify → report pipeline execution
- inter-rater reliability metrics
- mock-provider classification path
- validation-threshold pass conditions
- full benchmark-suite execution across bundled reference fixtures

Run locally:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Reference validation fixture

TRACE ships with:

- `validation/companion_incident.json`
- `validation/reference_benign_case.json`
- `validation/reference_long_case.json`
- `validation/reference_mixed_case.json`
- `validation/reference_noisy_case.json`
- `validation/parsers/`

This fixture provides:

- a known transcript structure
- expected message-level labels
- expected inappropriate response rate
- expected crisis failure rate

The benign fixture provides:

- a baseline non-crisis interaction
- expected zero-harm findings
- a guard against over-escalation in vulnerability classification

The long-form fixture provides:

- a longer distress-oriented interaction
- repeated elevated-vulnerability states across multiple windows
- a regression check for report generation under denser transcripts

The mixed fixture provides:

- benign and harmful segments in the same conversation
- a regression check for mixed-pattern findings
- validation coverage for transitions between baseline and elevated states

The noisy fixture provides:

- informal language, shorthand, and emoji-like conversational noise
- mixed benign and harmful segments in a less curated style
- regression coverage for non-ideal but parseable transcript content

The parser fixtures provide:

- court-style transcript samples
- AXIOM-style JSON message samples
- UFED-style XML message samples
- malformed export samples for parser failure-path testing

Run:

```bash
trace validate --reference ./validation/companion_incident.json
trace validate --reference ./validation/reference_benign_case.json
trace validate --reference ./validation/reference_long_case.json
trace validate --reference ./validation/reference_mixed_case.json
trace validate --reference ./validation/reference_noisy_case.json
trace benchmark --validation-dir ./validation
trace benchmark --validation-dir ./validation --profile hosted --output-dir ./benchmark_artifacts
```

The benchmark command can emit:

- `benchmark_summary.json`
- `benchmark_summary.md`
- `artifact_manifest.json`
- `artifact_manifest.sig`
- `artifact_trust.json`

This allows TRACE benchmark runs to be preserved as inspectable artifacts rather than only terminal output.

The companion comparison workflow can emit:

- `benchmark_comparison.json`
- `benchmark_comparison.md`

This supports explicit drift review between heuristic and hosted benchmark profiles.

The benchmark workflow can also emit history snapshots such as:

- `benchmark_heuristic_latest.json`
- `benchmark_hosted_latest.json`
- `benchmark_compare_heuristic_vs_hosted_latest.json`
- `benchmark_heuristic_latest_<timestamp>.json`
- `benchmark_hosted_latest_<timestamp>.json`

This creates both a stable latest pointer and an immutable dated record for later regression review.

Governance expectations for benchmark acceptance and release review are defined in:

- `docs/BENCHMARK_GOVERNANCE.md`
- `docs/RELEASE_CHECKLIST.md`

## What is not yet fully validated

The following are still required for stronger production confidence:

- multiple gold-standard transcripts from varied conversational scenarios
- cross-platform parser validation for forensic-export formats
- provider-specific hosted-model reliability benchmarking
- long-transcript throughput and timeout testing
- adversarial validation of malformed or schema-drifting provider outputs
- examiner override workflow validation under realistic review conditions
- rendered report visual validation for final legal-facing output

## Evidence of current outputs

TRACE now includes a sample exported package at:

- `examples/companion_incident_package/`

This is intended to make package structure, manifest composition, and exported artifacts directly inspectable by reviewers.

## Validation standard for forensic credibility

TRACE should ultimately demonstrate:

- repeatable ingest behavior
- stable and versioned output schemas
- transparent provenance for model suggestions and examiner decisions
- deterministic fallback behavior when providers fail
- reproducible findings from the same classified input
- measurable agreement against reference classifications

## Interpretation note

Passing validation does not mean TRACE makes a forensic determination automatically. Validation demonstrates that TRACE behaves consistently as a forensic decision-support and evidence-packaging system under defined conditions.
