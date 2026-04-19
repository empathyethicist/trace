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
- structured evidence-package export with manifest, audit log, schema versions, prompt templates, and classified transcript outputs
- validation fixtures and automated tests

Current gaps to full production deployment include richer source parsers, PDF report generation, broader adversarial validation fixtures, and additional hardening for high-volume hosted-model execution.

## Core capabilities

### Ingest

TRACE accepts conversational transcripts, computes source hashes before transformation, normalizes messages to an internal schema, and creates custody records suitable for later evidentiary review.

Supported inputs currently include:

- JSON transcripts
- CSV transcripts
- plain-text formatted transcripts

### Classification

TRACE classifies:

- **system messages** against the Zhang et al. (2025) behavioral taxonomy
- **user messages** against the TRACE C-SSRS-derived vulnerability scale

Classification can run through:

- deterministic local heuristics
- mock hosted-model mode for testability
- OpenRouter-backed hosted inference
- manual review pathways with accept / flag / override behavior

### Correlation and reporting

From the classified transcript, TRACE computes:

- inappropriate response rate
- pattern distribution
- crisis failure rate

It then exports an evidence package containing machine-readable artifacts and a human-readable report summary.

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

### Validation

```bash
trace validate --reference ./validation/companion_incident.json
```

## Quality and forensic controls

TRACE is designed around the following controls:

- hashing before transformation
- explicit chain-of-custody artifacts
- version-pinned schema and prompt metadata
- audit logging for ingest, classification, IRR, and export events
- deterministic fallback behavior when provider output is unavailable or malformed
- dual-coder support and IRR computation

## Development notes

- Python 3.11+ is recommended.
- Hosted-model execution may require API credentials and network access.
- Free-model OpenRouter testing is supported, but hosted providers may return schema-drifting output; TRACE normalizes common deviations and falls back safely when needed.

## License

Intended MIT-licensed project per the TRACE PRD. Add the formal `LICENSE` file before public release.
