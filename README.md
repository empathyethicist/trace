# TRACE

TRACE (Trajectory Analysis for Conversational Evidence) is a forensic software implementation of the AI Behavioral Trajectory Forensics methodology. It ingests AI-human conversational transcripts, supports behavioral and vulnerability classification, computes correlation-based forensic findings, and exports auditable evidence packages for legal and investigative review.

The goal is not merely to produce a research prototype. TRACE is being built to the standard of a tool that digital forensic companies would actively want to adopt for real conversational-harm casework. See `docs/PRODUCT_GOALS.md`.

## Status

TRACE is currently a working pre-production implementation with:

- transcript ingest, normalization, hashing, and chain-of-custody logging
- classification workflows with deterministic local heuristics, mock LLM mode, and hosted-provider integration paths
- rolling-window state summaries and human review modes
- correlation analysis for inappropriate response rate, pattern distribution, and crisis failure rate
- dual-coder import and inter-rater reliability computation
- structured evidence-package export with manifest, verification output, audit log, schema versions, prompt templates, classified transcript outputs, Markdown report output, and PDF report output
- package verification and manifest signing commands
- detached manifest signature verification
- trust metadata for signed packages
- signing-certificate verification against a supplied CA file
- optional CRL-backed revocation checks during signing-certificate verification
- validation fixtures and automated tests

Current gaps to full production deployment include deeper parser coverage against vendor-native exports, broader adversarial validation fixtures, and additional hardening for high-volume hosted-model execution. See `docs/ROADMAP.md`.

## Forensic position

TRACE is a decision-support and evidence-packaging tool for trained examiners.

- TRACE does **not** make final forensic determinations.
- TRACE does **not** replace expert review.
- TRACE is designed to preserve provenance, human overrides, and repeatable outputs.

## Core capabilities

### Ingest

TRACE accepts conversational transcripts, computes source hashes before transformation, normalizes messages to an internal schema, and creates custody records suitable for later evidentiary review.

Supported inputs currently include:

- JSON transcripts
- CSV transcripts
- plain-text formatted transcripts
- court-style plain-text transcripts
- AXIOM-style JSON message exports
- UFED-style XML message exports

### Classification

TRACE classifies:

- **system messages** against the Zhang et al. (2025) behavioral taxonomy
- **user messages** against the TRACE C-SSRS-derived vulnerability scale

Classification can run through:

- deterministic local heuristics
- mock hosted-model mode for testability
- OpenRouter-backed hosted inference
- manual review pathways with accept / flag / override behavior
- examiner override rationale capture in classified output

### Correlation and reporting

From the classified transcript, TRACE computes:

- inappropriate response rate
- pattern distribution
- crisis failure rate

It then exports an evidence package containing machine-readable artifacts, a Markdown report summary, a PDF report, verification metadata, and signing-ready manifests.

## Repository layout

```text
src/trace/
  cli.py          Command-line interface
  ingest.py       Input parsing, normalization, hashing, custody logging
  classify.py     Classification pipeline, windows, review loop
  heuristics.py   Deterministic fallback rules
  llm.py          Provider-backed model integration and normalization
  irr.py          Inter-rater reliability import and computation
  report.py       Correlation analysis and evidence package export
  schemas.py      Classification schema definitions
  prompts.py      Version-pinned prompt templates
  validation.py   Validation workflow
tests/
  test_trace.py   Automated verification
validation/
  companion_incident.json  Reference transcript fixture
  reference_benign_case.json  Baseline benign fixture
  reference_long_case.json    Long-form distress fixture
  reference_mixed_case.json   Mixed benign/harmful fixture
  reference_noisy_case.json   Noisy real-world style fixture
  parsers/                   Parser-format reference fixtures
```

## Installation

```bash
cd /home/dylan/trace
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quick start

### Check installation

```bash
trace version
```

### Run validation

```bash
trace validate --reference ./validation/companion_incident.json
trace validate --reference ./validation/reference_long_case.json
trace benchmark --validation-dir ./validation
trace benchmark --validation-dir ./validation --profile hosted --output-dir ./benchmark_artifacts
trace benchmark-compare --validation-dir ./validation --baseline-profile heuristic --candidate-profile hosted --output-dir ./benchmark_comparison
trace benchmark --validation-dir ./validation --output-dir ./benchmark_artifacts --history-dir ./benchmark_history --sign-private-key ./keys/benchmark_signer.pem --sign-public-key ./keys/benchmark_signer_public.pem --signing-certificate ./keys/benchmark_signer.crt
```

### End-to-end demo

```bash
trace ingest \
  --input ./validation/companion_incident.json \
  --format json \
  --case-id DEMO-001 \
  --examiner "D. Mobley"

trace classify \
  --case-id DEMO-001 \
  --provider heuristic \
  --review-mode auto

trace report \
  --case-id DEMO-001 \
  --examiner "D. Mobley" \
  --output ./evidence
```

## CLI commands

### Ingest

```bash
trace ingest --input transcript.json --format json --case-id CASE-001 --examiner "D. Mobley"
trace ingest --input court_transcript.txt --format court --case-id CASE-002 --examiner "D. Mobley"
trace ingest --input axiom_messages.json --format axiom --case-id CASE-003 --examiner "D. Mobley"
trace ingest --input ufed_messages.xml --format ufed --case-id CASE-004 --examiner "D. Mobley"
```

### Classify

```bash
trace classify --case-id CASE-001 --provider heuristic
trace classify --case-id CASE-001 --provider mock --model mock-model --window-size 4
trace classify --case-id CASE-001 --provider openrouter --model openrouter/free
trace classify --case-id CASE-001 --manual
```

### Inter-rater reliability

```bash
trace irr-import --case-id CASE-001 --coder-2-file ./coder2_classified_transcript.json
trace irr-compute --case-id CASE-001
```

### Report export

```bash
trace report --case-id CASE-001 --examiner "D. Mobley" --output ./evidence
```

### Package verification and signing

```bash
trace verify-package --package ./evidence/CASE-001
trace sign-package --package ./evidence/CASE-001 --private-key ./keys/trace_manifest_signing.pem --public-key ./keys/trace_manifest_signing.pub.pem --signing-certificate ./keys/trace_manifest_signing.crt
trace verify-signature --package ./evidence/CASE-001 --public-key ./keys/trace_manifest_signing.pub.pem --ca-file ./keys/trace_ca.pem --crl-file ./keys/trace_ca.crl
```

### Validation

```bash
trace validate --reference ./validation/companion_incident.json
trace benchmark --validation-dir ./validation
trace benchmark --validation-dir ./validation --profile hosted --output-dir ./benchmark_artifacts
trace benchmark-compare --validation-dir ./validation --baseline-profile heuristic --candidate-profile hosted --output-dir ./benchmark_comparison
```

## Quality and forensic controls

TRACE is designed around the following controls:

- hashing before transformation
- explicit chain-of-custody artifacts
- version-pinned schema and prompt metadata
- audit logging for ingest, classification, IRR, and export events
- deterministic fallback behavior when provider output is unavailable or malformed
- dual-coder support and IRR computation
- package verification against exported manifest hashes
- examiner override rationale preservation in classified output
- detached signature verification for signed manifests
- signer trust metadata preserved alongside manifest signatures
- malformed parser fixtures included for regression coverage
- optional examiner notes included in exported reports
- report appendices include artifact checklist and correlation snapshot
- benchmark artifacts can be signed and archived as history snapshots

## Project policies

- Contribution guidance: `CONTRIBUTING.md`
- Security policy: `SECURITY.md`
- Product intent: `docs/PRODUCT_GOALS.md`
- Roadmap: `docs/ROADMAP.md`
- Validation posture: `docs/VALIDATION.md`
- Evidence package specification: `docs/EVIDENCE_PACKAGE_SPEC.md`
- Architecture: `docs/ARCHITECTURE.md`
- Threat model: `docs/THREAT_MODEL.md`
- Example exported artifacts: `examples/README.md`

## Development notes

- Python 3.11+ is recommended.
- Hosted-model execution may require API credentials and network access.
- Free-model OpenRouter testing is supported, but hosted providers may return schema-drifting output; TRACE normalizes common deviations and falls back safely when needed.

## License

MIT. See `LICENSE`.
