#!/usr/bin/env bash
# Repeat the primitive benchmark N times.
# Each repetition keeps its own raw output under results/.
set -euo pipefail

N="${1:-10}"
CORE="${CORE:-0}"
mkdir -p results

for i in $(seq 1 "${N}"); do
  echo "===== run ${i}/${N} ====="
  CORE="${CORE}" RUN_ID="${i}" ./run.sh
  sleep 2
done

echo "Finished. Raw per-run samples are in results/."
