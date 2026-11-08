#!/usr/bin/env bash
# S2 formal acceptance run: protocol core, recovery, persistence, service and the
# multi-process socket backend. Every run writes its own directory; nothing is overwritten.
set -uo pipefail
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$KIT/.." && pwd)"
cd "$KIT"

RUN_ID="${RUN_ID:-S2-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid RUN_ID" >&2; exit 2; }
OUT="$ROOT/results/formal/$RUN_ID"
[[ ! -e "$OUT" ]] || { echo "Run id exists; refusing to overwrite: $RUN_ID" >&2; exit 2; }
mkdir -p "$OUT"

{
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "run_id=$RUN_ID"
  echo "stage=S2"
  echo "host=$(uname -a)"
  echo "compiler=$(g++ --version | head -1)"
  echo "openssl=$(openssl version)"
  echo "sqlite3_cli=$(sqlite3 --version 2>/dev/null || echo n/a)"
  echo "workbuddy_kit=$KIT"
  echo "project_root=$ROOT"
} > "$OUT/environment.txt"

echo "== build =="
make formal > "$OUT/build.log" 2>&1 || { echo "BUILD FAILED"; tail -40 "$OUT/build.log"; exit 1; }

STATUS=0
run_case() {
  local name="$1"; shift
  echo "== $name =="
  local start end
  start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  "$@" > "$OUT/$name.log" 2>&1
  local rc=$?
  end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "{\"case\":\"$name\",\"exit_code\":$rc,\"start_utc\":\"$start\",\"end_utc\":\"$end\",\"command\":\"$*\"}" \
    >> "$OUT/commands.jsonl"
  if [[ $rc -ne 0 ]]; then STATUS=1; echo "  FAIL ($rc)"; tail -20 "$OUT/$name.log"; else echo "  PASS"; fi
}

run_case test_protocol_core ./build/test_protocol_core "$OUT"
run_case test_recovery       ./build/test_recovery "$OUT"
run_case test_persistence    ./build/test_persistence "$OUT"
run_case test_service        ./build/test_service "$OUT"
run_case nodes               ./build/uavma_formal nodes "$OUT/nodes" 47311

(cd "$OUT" && find . -type f \( -name "*.csv" -o -name "*.jsonl" -o -name "*.log" \) -print0 |
  xargs -0 sha256sum > SHA256SUMS.txt)

if [[ $STATUS -eq 0 ]]; then
  echo "S2 ACCEPTANCE PASSED" > "$OUT/STATUS.txt"
else
  echo "S2 ACCEPTANCE FAILED" > "$OUT/STATUS.txt"
fi
echo "Output: $OUT"
exit $STATUS
