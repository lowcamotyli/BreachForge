#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

usage() {
  cat <<USAGE
Usage: $(basename "$0")

Runs CI smoke gates:
  1. Unit tests
  2. Quick scale benchmark
  3. Selected full benchmark lab
USAGE
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

if [[ -f "$PROJECT_DIR/.venv/bin/activate" ]]; then
  # shellcheck source=/dev/null
  source "$PROJECT_DIR/.venv/bin/activate"
fi

run_gate() {
  local label="$1"
  shift

  if "$@"; then
    echo "PASS - $label"
    return 0
  fi

  echo "FAIL - $label"
  return 1
}

failed=0

if ! run_gate "Gate 1: Unit tests" python -m pytest "$PROJECT_DIR/tests/unit/" -q --tb=short; then
  failed=1
fi

if ! run_gate "Gate 2: Quick scale" python "$SCRIPT_DIR/benchmark_lab.py" --scale 100 --output /tmp/smoke-scale.json; then
  failed=1
fi

if ! run_gate "Gate 3: Selected lab" python "$SCRIPT_DIR/benchmark_lab.py" --full --min-coverage 0.80 --max-fp 0; then
  failed=1
fi

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

exit 0
