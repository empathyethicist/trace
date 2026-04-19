# TRACE Threat Model

TRACE handles conversational evidence and model-assisted classifications in contexts that may later face adversarial review. This threat model focuses on the practical risks most relevant to forensic adoption.

## Security objectives

TRACE should protect:

- transcript confidentiality
- evidence integrity
- audit-log completeness
- manifest correctness
- provider credential secrecy
- reproducibility of exported findings

## Trust boundaries

The major trust boundaries in TRACE are:

1. source transcript input
2. normalized local case data
3. provider-backed classification requests
4. examiner review decisions
5. exported evidence package

## Key threats

### 1. Silent transcript mutation

Risk:
- input content changes without explicit record

Mitigation direction:
- source hashing before transformation
- normalized transcript persistence
- custody log entries for ingest events

### 2. Audit-log incompleteness

Risk:
- classification or export activity occurs without durable audit trace

Mitigation direction:
- append-only JSONL audit logging
- event capture for ingest, classify, IRR, and export

### 3. Provider output schema drift

Risk:
- hosted models return malformed or semantically off-schema output

Mitigation direction:
- output normalization
- deterministic fallback behavior
- version-pinned prompt templates
- human review modes

### 4. Provider outage or rate-limit instability

Risk:
- classification pipeline becomes unreliable under network or provider failures

Mitigation direction:
- retry/backoff handling
- local heuristics fallback
- response caching

### 5. Credential exposure

Risk:
- API credentials leak through logs or package outputs

Mitigation direction:
- do not write provider secrets into exported artifacts
- keep model config separate from credential storage

### 6. Misinterpretation of model suggestions as final findings

Risk:
- TRACE is treated as an automated decision engine rather than an examiner-support tool

Mitigation direction:
- explicit non-goal statements
- preserved human review/override pathways
- provenance retention in classified outputs

### 7. Evidence-package tampering after export

Risk:
- exported package contents are modified without detection

Mitigation direction:
- manifest hashing
- package hash generation
- future signed-manifest roadmap

## Highest-priority next mitigations

The most important future security and integrity upgrades are:

- signed manifests
- stronger override-rationale preservation
- better package replay and verification tooling
- parser hardening against malformed forensic exports
- explicit credential-handling documentation for hosted providers

## Operating assumption

TRACE should be treated as operating in a partially adversarial environment. Every major output may eventually be reviewed by opposing experts, counsel, regulators, or courts. The system should therefore prefer explicit provenance and controlled failure over convenience-oriented hidden behavior.
