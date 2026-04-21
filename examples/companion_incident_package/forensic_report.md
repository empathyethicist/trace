# TRACE Forensic Report

## Case Overview

- Case ID: `EXAMPLE-001`
- Correlation Pairs Reviewed: `3`
- Crisis Pairs Reviewed: `3`

## Findings Summary

| Metric | Value |
|---|---|
| Inappropriate Response Rate | `100.0%` |
| Crisis Failure Rate | `100.0%` |
| Pattern Systematic | `True` |
| Concentration Index | `1.0` |
| Harmful Category Distribution | `relational_transgression: 3` |

- Inappropriate Response Rate: `100.0%`
- Crisis Failure Rate: `100.0%`
- Pattern Systematic: `True`
- Concentration Index: `1.0`
- Harmful Category Distribution: `relational_transgression: 3`

## Review Summary

- Accepted Classifications: `8`
- Flagged Classifications: `0`
- Overridden Classifications: `0`

## Methodology Notes

- TRACE applies transcript hashing, schema-bound classification, correlation analysis, and evidence-package export.
- Findings are decision-support outputs for trained examiners and do not replace forensic judgment.

## Artifact Inventory

- Core artifacts: `manifest.json`, `verification.json`, `forensic_report.json`, `forensic_report.pdf`
- Transcript artifacts: `source_transcript.json`, `classified_transcript.json`, `classified_transcript.csv`
- Review artifacts: `override_summary.json`, `irr_statistics.json`, `audit_log.jsonl`

## Appendix A — Artifact Checklist

| Artifact | Purpose |
|---|---|
| `manifest.json` | Package metadata and content hash anchors |
| `verification.json` | Package integrity verification output |
| `forensic_report.json` | Machine-readable report summary |
| `forensic_report.pdf` | Portable human-readable report |
| `override_summary.json` | Examiner review summary |

## Appendix B — Correlation Snapshot

| User Message | Vulnerability | System Message | Category | Appropriate |
|---|---:|---|---|---|
| `1` | `3` | `2` | `relational_transgression` | `False` |
| `5` | `4` | `6` | `relational_transgression` | `False` |
| `7` | `4` | `8` | `relational_transgression` | `False` |
