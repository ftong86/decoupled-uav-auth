#!/usr/bin/env bash
# E1: Linux-native full-procedure cost and handler calibration.
set -uo pipefail
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(cd "$KIT/.." && pwd)"
cd "$KIT"

RUN_ID="${RUN_ID:-E1-$(date -u +%Y%m%dT%H%M%SZ)}"
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "Invalid RUN_ID" >&2; exit 2; }
OUT="$ROOT/results/formal/$RUN_ID"
[[ ! -e "$OUT" ]] || { echo "Run id exists; refusing to overwrite: $RUN_ID" >&2; exit 2; }
mkdir -p "$OUT"
REPEATS="${E1_REPEATS:-100}"

{
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "run_id=$RUN_ID"
  echo "stage=S3_E1"
  echo "repeats=$REPEATS"
  echo "host=$(uname -a)"
  echo "compiler=$(g++ --version | head -1)"
  echo "openssl=$(openssl version)"
} > "$OUT/environment.txt"

echo "== build =="
make formal > "$OUT/build.log" 2>&1 || { echo "BUILD FAILED"; tail -40 "$OUT/build.log"; exit 1; }

start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
./build/uavma_e1 "$OUT" "$REPEATS" > "$OUT/e1.log" 2>&1
rc=$?
end=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "{\"case\":\"e1\",\"exit_code\":$rc,\"start_utc\":\"$start\",\"end_utc\":\"$end\",\"command\":\"./build/uavma_e1 $OUT $REPEATS\"}" > "$OUT/commands.jsonl"
tail -3 "$OUT/e1.log"

# ns-3 transport check (an IoD-Sim/ns-3 build tree is required for the network arm).
./build/test_ns3_transport > "$OUT/test_ns3_transport.log" 2>&1
ns3_rc=$?
echo "{\"case\":\"test_ns3_transport\",\"exit_code\":$ns3_rc}" >> "$OUT/commands.jsonl"

{
  echo "B-MES arm: not included in this implementation."
  echo "IoD-Sim/ns-3 arm: requires an external ns-3 build tree."
} > "$OUT/BLOCKED.txt"

(cd "$OUT" && find . -type f \( -name "*.csv" -o -name "*.json" -o -name "*.log" \) -print0 |
  xargs -0 sha256sum > SHA256SUMS.txt)

if [[ $rc -eq 0 ]]; then echo "E1 LINUX NATIVE PASSED" > "$OUT/STATUS.txt"; else echo "E1 FAILED" > "$OUT/STATUS.txt"; fi
echo "Output: $OUT"
exit $rc
