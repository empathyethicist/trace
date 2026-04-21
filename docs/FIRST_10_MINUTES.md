# TRACE First 10 Minutes

This is the shortest path from clone to a usable local TRACE workspace.

## 1. Install

```bash
cd trace
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## 2. Create a workspace

```bash
trace init --root ./trace-workspace
```

This creates:

- `cases/`
- `replay_artifacts/`
- `benchmark_artifacts/`
- `benchmark_history/`
- `validation_runs/`
- `evidence_exports/`
- `keys/`

## 3. Check configuration

```bash
trace config-check --provider heuristic
trace config-check --provider hosted
```

If you plan to use hosted inference, set:

- `TRACE_HOSTED_API_KEY`
- `TRACE_HOSTED_BASE_URL`
- optional `TRACE_HOSTED_MODEL`
- optional `TRACE_HOSTED_ADAPTER`

## 4. Run a validation fixture

```bash
trace validate \
  --reference ./validation/companion_incident.json \
  --root ./trace-workspace/validation_runs
```

## 5. Run a local end-to-end case

```bash
trace ingest \
  --input ./validation/companion_incident.json \
  --format json \
  --case-id DEMO-001 \
  --examiner "Examiner-01" \
  --root ./trace-workspace

trace classify \
  --case-id DEMO-001 \
  --provider heuristic \
  --root ./trace-workspace

trace report \
  --case-id DEMO-001 \
  --examiner "Examiner-01" \
  --output ./trace-workspace/evidence_exports \
  --root ./trace-workspace
```

## 6. Move to hosted evaluation only if needed

Use hosted classification only after:

- the heuristic path is working
- `trace config-check --provider hosted` is clean
- replay capture is enabled for any meaningful hosted run

For hosted setup details, use `docs/HOSTED_PROVIDER_SETUP.md`.
