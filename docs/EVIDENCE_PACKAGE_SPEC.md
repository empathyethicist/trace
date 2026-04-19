# TRACE Evidence Package Specification

TRACE exports an evidence package intended to preserve the full analytical path from transcript ingest through report generation.

## Purpose

The evidence package is designed to support:

- reproducibility
- adversarial review
- chain-of-custody inspection
- output verification
- examiner transparency

## Core package contents

TRACE currently exports the following artifacts:

```text
evidence_package/
  manifest.json
  manifest.sig
  verification.json
  override_summary.json
  forensic_report.pdf
  chain_of_custody.json
  source_transcript.json
  classified_transcript.json
  classified_transcript.csv
  correlation_analysis.json
  irr_statistics.json
  forensic_report.json
  forensic_report.md
  audit_log.jsonl
  configuration/
    model_config.json
    schema_versions.json
    prompt_templates/
```

## Artifact roles

### `manifest.json`

Contains package-level metadata including:

- case identifier
- export timestamp
- examiner identifier
- source hash
- classified transcript hash
- package hash
- schema versions
- prompt template versions
- classification mode
- IRR statistics summary

The package hash is computed over exported package contents while excluding `verification.json` and any detached signature file. The `package_hash_sha256` field is blanked during hash derivation so the manifest can verify itself without circular dependence.

### `manifest.sig`

Optional detached signature generated for `manifest.json`. TRACE can verify this signature against a supplied public key through the CLI.

### `verification.json`

Stores verification results for:

- source hash presence
- classified transcript hash match
- package hash match
- aggregate verification pass/fail

### `override_summary.json`

Stores a case-level summary of:

- accepted classifications
- flagged classifications
- overridden classifications
- per-message override rationales when present

### `chain_of_custody.json`

Records ingest and handling events from source acquisition into TRACE processing.

### `source_transcript.json`

Stores the normalized source transcript used for TRACE analysis.

### `classified_transcript.json`

Stores per-message classifications, reasoning, confidence, review state, override rationale, and state summaries.

### `classified_transcript.csv`

Provides a spreadsheet-friendly export for inspection and interoperability.

### `correlation_analysis.json`

Stores the raw findings computation, including:

- inappropriate response rate
- pattern distribution
- crisis failure rate
- supporting correlation pairs

### `irr_statistics.json`

Stores inter-rater reliability outputs when dual-coder workflows are used.

### `forensic_report.json`, `forensic_report.md`, and `forensic_report.pdf`

Provide machine-readable, Markdown, and PDF report outputs, including override summary counts.

### `audit_log.jsonl`

Records operational events, including ingest, classification, IRR, and export steps.

### `configuration/`

Preserves configuration context:

- model/provider metadata
- schema versions
- prompt template versions and contents

## Design principles

The evidence package is designed to be:

- inspectable without TRACE-specific hidden state
- reproducible from stored artifacts
- explicit about provider/model context
- explicit about schema and prompt versions
- suitable for review by opposing experts and counsel

## Current limitations

The current package format does not yet include:

- authenticated timestamping or external attestation
- embedded certificate-chain handling for signed manifests

Those are planned future enhancements rather than current guarantees.
