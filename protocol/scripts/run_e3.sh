#!/usr/bin/env bash
# S4 / E3a + E3b: clock-independence grid and M2/M3 loss-recovery matrix.
set -uo pipefail
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$KIT/.." && pwd)"
cd "$KIT"

RUN_ID="${RUN_ID:-E3-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid RUN_ID" >&2; exit 2; }
OUT="$ROOT/results/formal/$RUN_ID"
[[ ! -e "$OUT" ]] || { echo "Run id exists; refusing to overwrite: $RUN_ID" >&2; exit 2; }
mkdir -p "$OUT"

{
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "run_id=$RUN_ID"
  echo "stage=S4_E3a+S4_E3b"
  echo "grid=Delta_clk/W in [-1.5,1.5] step 0.1 x Dnet/W in [0,0.5] step 0.05, W=500ms (controlled)"
  echo "schemes_E3a=P,A-Time"
  echo "schemes_E3b=P,A-Retry"
  echo "host=$(uname -a)"
} > "$OUT/environment.txt"

make formal > "$OUT/build.log" 2>&1 || { echo "BUILD FAILED"; tail -40 "$OUT/build.log"; exit 1; }

STATUS=0
for c in e3a e3b; do
  start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  ./build/uavma_e3 "$c" "$OUT" > "$OUT/$c.log" 2>&1
  rc=$?
  end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "{\"case\":\"$c\",\"exit_code\":$rc,\"start_utc\":\"$start\",\"end_utc\":\"$end\",\"command\":\"./build/uavma_e3 $c $OUT\"}" >> "$OUT/commands.jsonl"
  tail -2 "$OUT/$c.log"
  [[ $rc -ne 0 ]] && STATUS=1
done

(cd "$OUT" && find . -type f \( -name "*.csv" -o -name "*.log" \) -print0 | xargs -0 sha256sum > SHA256SUMS.txt)
if [[ $STATUS -eq 0 ]]; then echo "E3 PASSED" > "$OUT/STATUS.txt"; else echo "E3 FAILED" > "$OUT/STATUS.txt"; fi
echo "Output: $OUT"
exit $STATUS
