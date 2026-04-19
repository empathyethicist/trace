# Contributing to TRACE

TRACE is a forensic workflow project. Contributions should improve reproducibility, evidentiary defensibility, analyst usability, or parser/reporting coverage without weakening provenance or chain-of-custody guarantees.

## Contribution priorities

The highest-value contributions are:

- parser support for real forensic export formats
- stronger evidence-package integrity and provenance
- report generation improvements for legal review
- validation fixtures and benchmark coverage
- reliability improvements for provider-backed classification

## Ground rules

- Do not introduce features that imply TRACE makes final forensic determinations.
- Preserve human-in-the-loop review and override pathways.
- Keep outputs auditable and schema-stable.
- Prefer deterministic behavior and explicit failure modes over hidden automation.

## Development workflow

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Pull request expectations

Each pull request should include:

- a concise problem statement
- the forensic or product rationale for the change
- test coverage or a clear explanation of why tests are not applicable
- notes on any schema, output, or evidence-package changes

## Scope discipline

TRACE is intended to integrate into existing digital forensic workflows, not replace them. Contributions that improve interoperability, validation, and defensibility are favored over speculative feature expansion.
