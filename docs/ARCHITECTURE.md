# TRACE Architecture

TRACE is organized as a forensic pipeline rather than a generic chat-analysis application. The architecture is designed to preserve evidentiary provenance from ingest through export while allowing model-assisted classification under explicit human control.

## Architectural goals

TRACE is designed to:

- preserve transcript integrity from first ingest
- separate ingest, classification, and reporting concerns
- support deterministic fallback behavior when models fail
- make provider/model context explicit in exported artifacts
- allow examiner review, overrides, and dual-coder workflows

## Pipeline overview

TRACE currently follows a three-stage structure:

```text
Layer 1: Ingest
  parse -> hash -> normalize -> validate -> custody log

Layer 2: Classify
  message windows -> state summary -> provider suggestion -> review decision -> audit log

Layer 3: Report
  correlate -> compute findings -> export package -> manifest/hash
```

## Main modules

### `ingest.py`

Responsibilities:

- input parsing
- source hashing
- transcript normalization
- ingest validation
- initial chain-of-custody creation

### `classify.py`

Responsibilities:

- rolling-window construction
- state-summary generation
- review workflow orchestration
- classified transcript persistence
- classification audit logging

### `heuristics.py`

Responsibilities:

- deterministic local fallback rules
- baseline classification behavior when providers are unavailable or unsuitable

### `llm.py`

Responsibilities:

- provider-specific request execution
- retry and backoff behavior
- response caching
- schema normalization for provider outputs
- safe fallback to deterministic classification

### `irr.py`

Responsibilities:

- second-coder import
- Krippendorff’s alpha computation
- Cohen’s kappa computation
- IRR artifact generation

### `report.py`

Responsibilities:

- correlation analysis
- core forensic finding computation
- evidence-package assembly
- manifest generation

### `validation.py`

Responsibilities:

- fixture-driven validation runs
- agreement-threshold checks
- expected-findings comparison

## Provider model

TRACE supports multiple classification paths:

- deterministic heuristics
- mock provider path for local testing
- OpenRouter-backed hosted inference
- local Ollama path (wired, subject to local runtime availability)

All provider outputs are treated as suggestions until recorded in the classified transcript with explicit decision state.

## Evidence and provenance model

TRACE preserves provenance through:

- source hashing before transformation
- custody record creation at ingest
- per-message classification records
- provider/model metadata in outputs
- prompt-template version preservation
- audit-log event capture
- evidence-package manifest hashing

## Current limitations

The architecture is still evolving toward fuller production depth. Current known limitations include:

- limited parser coverage for real forensic exports
- no rendered PDF report output yet
- no signed package manifests yet
- limited multi-case workflow support
- no dedicated storage abstraction beyond the local filesystem

## Intended direction

The architecture is being developed to make TRACE attractive to digital forensic companies by combining:

- practical workflow fit
- evidentiary defensibility
- transparent AI assistance
- low-friction adoption in existing lab processes
