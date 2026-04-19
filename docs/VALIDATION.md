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
- dual-coder IRR computation
- reference-case agreement using the Companion Incident fixture

## Current benchmark snapshot

The table below reflects the current repository validation posture on the included reference fixture.

| Validation target | Current state |
|---|---|
| Automated unit/regression suite | Passing |
| Reference behavioral agreement threshold | Implemented |
| Reference vulnerability agreement threshold | Implemented |
| Expected findings comparison | Implemented |
| Dual-coder IRR computation | Implemented |
| Multiple gold-standard fixtures | Not yet implemented |
| Parser validation for UFED / AXIOM exports | Not yet implemented |
| Hosted-provider benchmark corpus | Not yet implemented |
| PDF report validation | Not yet implemented |

## Current automated checks

The repository test suite currently covers:

- parsing and ingest behavior
- classify → report pipeline execution
- inter-rater reliability metrics
- mock-provider classification path
- validation-threshold pass conditions

Run locally:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Reference validation fixture

TRACE ships with:

- `validation/companion_incident.json`

This fixture provides:

- a known transcript structure
- expected message-level labels
- expected inappropriate response rate
- expected crisis failure rate

Run:

```bash
trace validate --reference ./validation/companion_incident.json
```

## What is not yet fully validated

The following are still required for stronger production confidence:

- multiple gold-standard transcripts from varied conversational scenarios
- cross-platform parser validation for forensic-export formats
- provider-specific hosted-model reliability benchmarking
- long-transcript throughput and timeout testing
- adversarial validation of malformed or schema-drifting provider outputs
- examiner override workflow validation under realistic review conditions
- rendered report validation for final legal-facing output

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
