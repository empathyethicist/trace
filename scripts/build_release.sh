#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! python3 -m build --help >/dev/null 2>&1; then
  echo "[BUILD] python -m build is not available." >&2
  echo "[BUILD] Install it in your environment first, then rerun this script." >&2
  exit 1
fi

PYTHONPATH="$ROOT_DIR/src" python3 -m unittest discover -s "$ROOT_DIR/tests" -v

rm -rf "$ROOT_DIR/dist" "$ROOT_DIR/build" "$ROOT_DIR/src/trace_forensics.egg-info"
python3 -m build --sdist --wheel --no-isolation

(
  cd "$ROOT_DIR/dist"
  sha256sum * > SHA256SUMS.txt
)

echo "[BUILD] Release artifacts written to $ROOT_DIR/dist"
echo "[BUILD] Checksums written to $ROOT_DIR/dist/SHA256SUMS.txt"
