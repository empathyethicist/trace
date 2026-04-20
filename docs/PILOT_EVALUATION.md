# TRACE Pilot Evaluation Guide

This document defines a practical pilot process for a forensic lab, DFIR company, or expert-review team evaluating whether TRACE is worth adopting for bounded conversational-evidence workflows.

## Purpose

A pilot should answer one question:

> Does TRACE improve repeatability, auditability, and analyst efficiency without introducing unacceptable evidentiary risk?

The pilot should not try to prove universal production readiness in one pass. It should determine whether TRACE is strong enough to justify continued integration, deeper validation, or a formal partner trial.

## Recommended pilot length

Recommended duration:

- **1 week** for a quick technical evaluation
- **2 weeks** for a more realistic workflow pilot

Anything shorter risks collapsing important distinctions between:

- installation success
- workflow fit
- artifact quality
- benchmark posture
- actual examiner trust

## Pilot participants

The strongest pilot structure is:

- **1 technical evaluator**
  - responsible for setup, command execution, artifact verification, and parser review
- **1 forensic examiner**
  - responsible for evaluating workflow fit, classification usefulness, and report defensibility
- **1 reviewer or supervisor**
  - responsible for assessing whether outputs are credible enough for organizational interest

One person can perform all three roles in a small pilot, but separating them produces better signal.

## Pilot dataset

The pilot should use three classes of material:

### 1. TRACE bundled fixtures

Use the included fixtures first to verify that the environment reproduces the repo's expected posture:

- `validation/companion_incident.json`
- `validation/reference_benign_case.json`
- `validation/reference_long_case.json`
- `validation/reference_mixed_case.json`
- `validation/reference_noisy_case.json`

### 2. Internal non-case-sensitive samples

Next, use sanitized or non-sensitive transcripts that resemble the kinds of conversational evidence the lab expects to encounter.

The goal is to test:

- parser fit
- review workflow fit
- report usefulness
- edge cases not represented by the bundled corpus

### 3. Adversarial or messy samples

At least one pilot sample should be intentionally messy:

- inconsistent timestamps
- non-standard speaker labels
- shorthand or noisy language
- partial transcripts
- mixed benign and crisis content

This is where tool maturity becomes visible quickly.

## Pilot phases

## Phase 1: Environment and baseline verification

Objective:

- confirm that TRACE installs cleanly
- confirm that the repo reproduces its published validation posture

Recommended checks:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
trace benchmark --validation-dir ./validation
trace benchmark --validation-dir ./validation --profile hosted
```

If live-provider evaluation is desired:

```bash
trace benchmark --validation-dir ./validation --profile live-hosted --output-dir ./benchmark_artifacts_live
trace benchmark-compare --validation-dir ./validation --baseline-profile heuristic --candidate-profile live-hosted --output-dir ./benchmark_comparison_live
```

Success criteria:

- tests pass
- heuristic benchmark passes
- hosted workflow behaves as documented
- live-provider behavior, if run, is interpretable through the repo's drift policy

## Phase 2: Workflow trial on bounded samples

Objective:

- determine whether TRACE is useful in real examiner workflow

Recommended activities:

- ingest sample transcripts
- classify with deterministic baseline
- inspect review outputs
- export evidence packages
- verify package manifests
- inspect report output and artifact structure

Recommended questions:

- Is ingest straightforward?
- Does the normalized transcript structure make sense?
- Are classifications inspectable and challengeable?
- Are override pathways sufficient?
- Is the evidence package easier to review than a spreadsheet or ad hoc notes?

## Phase 3: Hosted-path evaluation

Objective:

- determine whether hosted augmentation is operationally useful without becoming a hidden source of risk

Recommended activities:

- run hosted or live-hosted classification on bounded samples
- capture replay artifacts
- rerun replay-only analysis
- compare against heuristic baseline

Recommended commands:

```bash
trace classify --case-id CASE-001 --provider openrouter --model openrouter/free --replay-dir ./replay_artifacts --replay-mode record
trace classify --case-id CASE-001 --provider openrouter --model openrouter/free --replay-dir ./replay_artifacts --replay-mode replay-only
trace benchmark-replay --validation-dir ./validation --profile live-hosted --replay-dir ./replay_artifacts --output-dir ./benchmark_artifacts_replay
```

Success criteria:

- hosted outputs remain inspectable
- replay works cleanly
- provider drift is visible rather than hidden
- the team remains willing to trust the workflow because the deterministic baseline and replay posture stay intact

## Phase 4: Adoption decision review

Objective:

- decide whether TRACE deserves deeper trial, limited internal use, or no further investment

The decision should be based on collected evidence, not general enthusiasm.

## Metrics to collect

The pilot should record both technical and operational metrics.

### Technical metrics

- install/setup time
- benchmark pass/fail posture
- parser success rate on pilot samples
- artifact verification success rate
- hosted replay success rate
- observed provider drift on any live-provider run

### Operational metrics

- analyst time per transcript
- time to produce a reviewable package
- number of manual overrides required
- reviewer confidence in the exported package
- reviewer confidence in classification traceability
- whether the workflow reduced or increased evidentiary ambiguity

## Questions the pilot must answer

At the end of the pilot, the lab should be able to answer:

- Does TRACE save analyst time relative to the current workflow?
- Does TRACE improve repeatability relative to current practice?
- Are the exported artifacts more inspectable than current working materials?
- Is hosted-model behavior sufficiently bounded for the organization’s risk tolerance?
- Are the current parser and report layers good enough for bounded use?
- Does the repo present enough maturity to justify continued engagement?

If the answer to most of those questions is yes, TRACE has passed the pilot even if it is not yet production-final.

## Recommended decision outcomes

### Outcome 1: Continue to bounded internal pilot

Choose this if:

- the workflow is useful
- artifacts are credible
- limitations are understood
- remaining gaps are acceptable for non-production-critical use

### Outcome 2: Engage as an early partner evaluation

Choose this if:

- the lab sees clear value
- the repo’s validation and integrity posture meets the organization’s seriousness threshold
- the remaining roadmap is concrete and aligned with actual workflow needs

### Outcome 3: Defer adoption but monitor

Choose this if:

- the tool is credible
- but parser breadth, throughput, or reporting maturity are still below operational needs

This is still a positive outcome. It means TRACE is interesting enough to track rather than dismiss.

## What should count as a failed pilot

The pilot should be considered unsuccessful if:

- benchmark behavior cannot be reproduced locally
- artifact verification is unreliable
- parser behavior is brittle on realistic samples
- hosted output cannot be bounded or replayed cleanly
- the workflow increases examiner ambiguity rather than reducing it
- reviewers would not trust the exported package under adversarial scrutiny

## Pilot deliverables

By the end of the pilot, the evaluating organization should retain:

- benchmark outputs used during evaluation
- at least one exported evidence package
- any replay artifacts generated for hosted evaluation
- a short internal memo answering the decision questions above

## Current recommended pilot message

The strongest accurate framing for a pilot is:

> TRACE should be piloted as a serious bounded-use forensic workflow candidate. The goal of the pilot is not to declare universal production readiness, but to determine whether its current evidence integrity, validation discipline, and workflow structure justify deeper operational investment.

## Related documents

- `docs/ADOPTION_READINESS.md`
- `docs/VALIDATION.md`
- `docs/BENCHMARK_GOVERNANCE.md`
- `docs/PROVIDER_DRIFT_POLICY.md`
- `docs/LIVE_PROVIDER_HARDENING.md`
- `docs/RELEASE_CHECKLIST.md`
