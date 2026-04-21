# TRACE Adoption Readiness

This document translates TRACE's current technical posture into adoption terms that matter to digital forensic companies, forensic labs, and expert-review teams.

## Purpose

TRACE is not being evaluated only as code that runs. It is being evaluated as software that may need to:

- survive adversarial review
- fit into existing forensic workflow
- reduce examiner time without increasing evidentiary risk
- present a credible validation and integrity posture to external reviewers

This document states clearly what TRACE is ready for today and what remains roadmap work.

## Current readiness summary

TRACE is currently credible as:

- an operational forensic decision-support workflow for conversational-harm analysis
- a structured evidence-packaging system for transcript-centered case review
- a benchmarked and documented comparison framework for deterministic and hosted classification paths
- a serious early-stage product candidate that a digital forensics company can inspect, evaluate, pilot, and pressure-test

TRACE is not yet positioned as:

- a fully mature production platform for high-volume lab deployment
- a replacement for examiner judgment
- a system with complete vendor-export coverage across all real-world forensic tooling

That distinction matters. The repo is strong because it is explicit about where it is ready and where it is not.

## What a forensic company can trust today

### Evidence handling

TRACE already provides:

- transcript ingest and normalization
- source hashing before transformation
- chain-of-custody artifacts
- auditable classification output
- evidence-package export
- manifest hashing and verification
- signed artifact-bundle support
- signing-certificate and trust-metadata handling

This means a reviewer can inspect not only what TRACE concluded, but also how the package was assembled and whether it remained intact.

### Validation discipline

TRACE already provides:

- automated regression tests
- benchmark fixtures across benign, mixed, noisy, crisis, and long-form distress cases
- heuristic, mock-hosted, and live-hosted benchmark profiles
- signed benchmark artifacts
- benchmark history and trend summaries
- explicit benchmark governance and provider-drift policy

This is materially stronger than a typical research-adjacent tool repo because the project preserves evidence of failure and drift rather than presenting only sanitized success cases.

### Hosted-model restraint

TRACE does not treat hosted-model output as authoritative. Instead, it now provides:

- deterministic baseline behavior
- hosted replay capture and replay-only benchmarking
- lexical crisis calibration
- state-aware risk calibration
- tightened acute-escalation rules for long-form distress
- explicit provider-drift policy evaluation

This is the correct posture for forensic adoption. It makes hosted inference usable without pretending it is stable enough to be the ground truth.

### Reviewer inspectability

External reviewers can already inspect:

- example evidence packages under `examples/companion_incident_package/`
- signed benchmark artifacts under `examples/benchmark_artifacts/`
- signed comparison artifacts under `examples/benchmark_comparison/`
- signed live-provider drift artifacts under `examples/benchmark_artifacts/live_hosted/`
- signed replay-hardened live-provider artifacts under `examples/benchmark_artifacts/live_hosted_hardened/`
- signed replay-hardened comparison artifacts under `examples/benchmark_comparison_live_hosted_hardened/`

That is a meaningful adoption signal because it lets a lab evaluate TRACE from artifacts, not from claims.

## Why TRACE is attractive to a forensic company now

TRACE is already stronger than ad hoc spreadsheet or informal LLM-assisted workflow on the dimensions that matter most:

- **Repeatability**: deterministic baseline, replay harness, versioned artifacts
- **Auditability**: manifests, trust metadata, signatures, override rationale support
- **Defensibility**: explicit non-goals, benchmark governance, provider-drift policy
- **Workflow fit**: CLI-first, artifact-driven, parser-aware, evidence-package oriented
- **Transparency**: committed examples include both failure evidence and hardened follow-up evidence

A serious forensic buyer does not need a claim of perfection. They need evidence that the tool is being engineered in the right direction and that its risks are visible and bounded. TRACE now does that.

## What still prevents full production adoption

TRACE still needs further work before it should be represented as production-final software for broad forensic deployment.

### Parser depth

Current parser support is meaningful, but the project still needs broader coverage and harder validation against:

- more varied court-export transcript structures
- messier AXIOM exports
- messier UFED exports
- additional vendor-native or downstream transcript formats encountered in practice

### Scale and throughput

TRACE still needs more evidence for:

- large-case batch handling
- high-volume transcript throughput
- hosted-path timeout and retry behavior under heavier load
- operational behavior in team or lab-scale review settings

### Validation corpus breadth

The bundled fixture set is useful and serious, but broader adoption would benefit from:

- more gold-standard transcripts
- more coder-validated ground truth
- more adversarial malformed inputs
- more cross-style conversational evidence

### Report polish

The report layer is functional and already useful. It is not yet the final form of a polished enterprise forensic reporting product.

## Current adoption posture

The most accurate current statement is:

> TRACE is ready for serious technical evaluation, method demonstration, pilot use on bounded conversational-evidence workflows, and external forensic review. It is not yet complete enough to be presented as universally production-final software.

That is a strong posture, not a weak one. It is credible because it is precise.

## Recommended use cases now

TRACE is ready now for:

- professor or peer review
- partner or lab evaluation
- methodology demonstration
- bounded pilot workflows
- expert-review preparation
- internal DFIR capability exploration
- evidence-package inspection and benchmark-governance review

## Recommended message to forensic companies

If TRACE is shown to a digital forensic company today, the strongest accurate message is:

> TRACE is a serious, working conversational-forensics system with explicit evidence integrity controls, benchmark governance, provider-drift handling, and inspectable artifact outputs. It is engineered for forensic defensibility first and product maturity second, with the remaining roadmap concentrated in parser breadth, corpus expansion, and broader deployment hardening.

## Related documents

- `docs/PRODUCT_GOALS.md`
- `docs/ROADMAP.md`
- `docs/VALIDATION.md`
- `docs/PROVIDER_DRIFT_POLICY.md`
- `docs/LIVE_PROVIDER_HARDENING.md`
- `docs/RELEASE_CHECKLIST.md`
