#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_ROOT="${1:-$ROOT_DIR/demo-workspace}"
TRACE_CMD="${TRACE_CMD:-python3 -m trace.cli}"

mkdir -p "$WORKSPACE_ROOT"

PYTHONPATH="$ROOT_DIR/src" $TRACE_CMD init --root "$WORKSPACE_ROOT"
PYTHONPATH="$ROOT_DIR/src" $TRACE_CMD validate \
  --reference "$ROOT_DIR/validation/companion_incident.json" \
  --root "$WORKSPACE_ROOT/validation_runs"
PYTHONPATH="$ROOT_DIR/src" $TRACE_CMD ingest \
  --input "$ROOT_DIR/validation/companion_incident.json" \
  --format json \
  --case-id DEMO-001 \
  --examiner "Examiner-01" \
  --root "$WORKSPACE_ROOT"
PYTHONPATH="$ROOT_DIR/src" $TRACE_CMD classify \
  --case-id DEMO-001 \
  --provider heuristic \
  --root "$WORKSPACE_ROOT"
PYTHONPATH="$ROOT_DIR/src" $TRACE_CMD report \
  --case-id DEMO-001 \
  --examiner "Examiner-01" \
  --output "$WORKSPACE_ROOT/evidence_exports" \
  --root "$WORKSPACE_ROOT"

echo "[DEMO] TRACE demo workspace ready at $WORKSPACE_ROOT"
echo "[DEMO] Evidence package: $WORKSPACE_ROOT/evidence_exports/DEMO-001"
