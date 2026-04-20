# TRACE Partner Brief

TRACE (Trajectory Analysis for Conversational Evidence) is a forensic software system for analyzing AI-human conversational transcripts in a way that is structured, repeatable, and reviewable.

This brief is intended for digital forensic companies, forensic labs, and expert-review organizations evaluating whether TRACE is worth piloting, reviewing, or partnering around.

## What TRACE does

TRACE helps examiners:

- ingest conversational transcripts
- normalize and preserve source evidence
- classify system behavior and user vulnerability
- compute repeatable forensic findings
- export auditable evidence packages
- benchmark deterministic and hosted classification paths

The current focus is conversational-harm casework involving AI systems, but the broader value is a defensible workflow for transcript-centered forensic analysis.

## Why this matters

Conversational AI evidence is growing faster than the forensic workflows used to analyze it. In many environments today, analysts still rely on:

- manual spreadsheet coding
- ad hoc narrative review
- unstructured expert judgment
- informal use of LLMs without preserved provenance

TRACE addresses that gap with a workflow that is:

- more repeatable
- more auditable
- easier to inspect
- easier to challenge and defend

## What makes TRACE different

TRACE is not positioned as an opaque AI classifier. It is built around forensic controls:

- deterministic baseline behavior
- source hashing and chain-of-custody artifacts
- explicit human review and override pathways
- evidence-package export
- manifest verification and signed artifact support
- benchmark governance and provider-drift policy
- replay capture for hosted-model analysis

The project also preserves failure evidence, not only passing examples. That is important. It shows how the system behaves when provider variance or drift becomes relevant.

## What a partner can inspect today

A partner evaluating TRACE can already inspect:

- working CLI implementation
- automated test suite
- bundled validation fixtures
- signed benchmark artifacts
- signed comparison artifacts
- live-provider drift artifacts
- replay-hardened live-provider comparison artifacts
- evidence-package examples
- governance, adoption, pilot, and deployment documentation

This means TRACE can be assessed from real artifacts and workflow behavior rather than from a conceptual pitch alone.

## Current maturity

TRACE is currently best suited for:

- technical evaluation
- bounded pilot use
- method demonstration
- forensic lab review
- partner exploration of conversational-evidence workflows

TRACE is not yet being represented as universally production-final software for all forensic environments. The current remaining gaps are primarily:

- parser breadth
- larger validation corpus
- broader throughput evidence
- further report-layer polish

Those are operational maturity tasks, not signs that the core direction is unsound.

## What a partner would gain from engaging now

A forensic company evaluating TRACE now would gain:

- a serious head start on conversational-forensics workflow
- a system already engineered around evidentiary integrity and reviewability
- a partnerable codebase with visible roadmap and validation posture
- the ability to influence parser coverage, workflow fit, and deployment priorities early

The practical opportunity is not merely “using a tool.” It is shaping an emerging forensic workflow category while the architecture is still flexible and the controls are already serious.

## Recommended engagement paths

The most practical next steps for a partner are:

### 1. Technical review

Review:

- `docs/EXECUTIVE_SUMMARY.md`
- `docs/ADOPTION_READINESS.md`
- `docs/LIVE_PROVIDER_HARDENING.md`
- `examples/`

### 2. Bounded pilot

Run a short pilot using:

- bundled fixtures
- internal sanitized transcripts
- replay capture for any hosted evaluation

See:

- `docs/PILOT_EVALUATION.md`

### 3. Lab-operational review

Assess deployment posture, retention, hosted access controls, and signing workflow.

See:

- `docs/LAB_DEPLOYMENT_NOTES.md`

## Current best description

The strongest accurate description of TRACE today is:

> TRACE is a serious bounded-use conversational-forensics system with evidence integrity controls, benchmark governance, hosted-model restraint, and inspectable artifacts. It is ready for pilot evaluation and partner review, with remaining work concentrated in parser breadth, corpus expansion, and broader deployment hardening.

## Contact posture

If TRACE is being reviewed for potential partnership or evaluation, the right question is not:

> Is this finished?

The right question is:

> Is this already serious enough, well-governed enough, and operationally clear enough to justify pilot evaluation or early collaboration?

On the current evidence, the answer is yes.
