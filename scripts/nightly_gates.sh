#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SCALE_OUTPUT="$PROJECT_DIR/.runtime/nightly-scale.json"

usage() {
  cat <<USAGE
Usage: $(basename "$0")

Runs nightly ship gates:
  1. All tests
  2. Full benchmark lab suite
  3. Scale benchmark
  4. Safety anomaly check
  5. Per-lab quick benchmark gates
  6. All-labs quick benchmark gate
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

cd "$PROJECT_DIR"
mkdir -p "$PROJECT_DIR/.runtime"
rm -f "$SCALE_OUTPUT"

run_stage() {
  local label="$1"
  shift

  if "$@"; then
    echo "PASS - $label"
    return 0
  fi

  echo "FAIL - $label"
  return 1
}

check_blocked_ratio() {
  python - "$SCALE_OUTPUT" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_file():
    print(f"missing scale output: {path}", file=sys.stderr)
    raise SystemExit(1)

with path.open("r", encoding="utf-8") as handle:
    payload = json.load(handle)

if not isinstance(payload, dict):
    print("scale output must be a JSON object", file=sys.stderr)
    raise SystemExit(1)

requests_total = payload.get("requests_total")
requests_blocked = payload.get("requests_blocked")
if not isinstance(requests_total, (int, float)) or isinstance(requests_total, bool):
    print("scale output missing numeric requests_total", file=sys.stderr)
    raise SystemExit(1)
if not isinstance(requests_blocked, (int, float)) or isinstance(requests_blocked, bool):
    print("scale output missing numeric requests_blocked", file=sys.stderr)
    raise SystemExit(1)
if requests_total <= 0:
    print("requests_total must be greater than zero", file=sys.stderr)
    raise SystemExit(1)

blocked_ratio = requests_blocked / requests_total
print(
    "Stage 4 details: "
    f"requests_blocked={requests_blocked:g} "
    f"requests_total={requests_total:g} "
    f"blocked_ratio={blocked_ratio:.3f}"
)
if blocked_ratio > 0.1:
    raise SystemExit(1)
PY
}

failed=0

if ! run_stage "Stage 1: All tests" python -m pytest tests/ -q --tb=short; then
  failed=1
fi

if ! run_stage "Stage 2: Full benchmark lab suite" python scripts/benchmark_lab.py --full --lab all --min-coverage 0.80 --max-fp 0; then
  failed=1
fi

if ! run_stage "Stage 3: Scale benchmark" python scripts/benchmark_lab.py --scale 500 --output .runtime/nightly-scale.json; then
  failed=1
fi

if ! run_stage "Stage 4: Safety anomaly check" check_blocked_ratio; then
  failed=1
fi

for lab_id in api_saas graphql spa_har business_race auth_oauth; do
  if ! run_stage "Stage 5: Quick benchmark gate ($lab_id)" \
    python scripts/benchmark_lab.py --quick --lab "$lab_id" --min-coverage 0.60 --max-fp 0; then
    failed=1
  fi
done

if ! run_stage "Stage 6: All-labs quick benchmark gate" \
  python scripts/benchmark_lab.py --quick --lab all --min-coverage 0.60 --max-fp 0; then
  failed=1
fi

if [[ "$failed" -eq 0 ]]; then
  echo "Final verdict: SHIP"
  exit 0
fi

echo "Final verdict: NO-SHIP"
exit 1
