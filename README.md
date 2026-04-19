# TRACE

Trajectory Analysis for Conversational Evidence.

This repository contains a working MVP of the TRACE PRD v2.0:

- Layer 1 ingest and normalization
- Layer 2 heuristic-assisted classification with audit logging
- Layer 3 correlation analysis and evidence package export
- Validation transcript and targeted tests

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
trace version
trace validate --reference ./validation/companion_incident.json
```
