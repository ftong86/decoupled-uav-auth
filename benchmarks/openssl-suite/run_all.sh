#!/usr/bin/env bash
# Build and execute the OpenSSL / PBC primitive micro-benchmarks.
#
# Adapted from the original experiment driver: the statistical summarisation and
# scheme-cost computation steps are intentionally NOT part of this source-only
# release. This script only produces raw per-run timing samples in $OUT/.
set -Eeuo pipefail

CPU="${CPU:-0}"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="${OUT:-results_${STAMP}}"
mkdir -p "$OUT"

trap 'echo "[ERROR] line ${LINENO}: command failed: ${BASH_COMMAND}" >&2' ERR

echo "[0/3] Building OpenSSL benchmark..."
make

echo "[0/3] Recording environment..."
if ! ./record_env.sh > "$OUT/environment.txt" 2>&1; then
    echo "[WARN] record_env.sh returned non-zero; continuing." >&2
fi

PIN=()
if command -v taskset >/dev/null 2>&1; then
    if taskset -c "$CPU" true >/dev/null 2>&1; then
        PIN=(taskset -c "$CPU")
        echo "[INFO] CPU affinity enabled: CPU $CPU"
    else
        echo "[WARN] CPU $CPU is not available/allowed; running without taskset." >&2
    fi
else
    echo "[WARN] taskset not found; running without CPU pinning." >&2
fi

if [ ! -x ./bench_openssl ]; then
    echo "[ERROR] ./bench_openssl not found or not executable after make." >&2
    exit 1
fi

echo "[1/3] OpenSSL/P-256 benchmark..."
"${PIN[@]}" ./bench_openssl "$OUT/runs_openssl.csv"

if [ -x ./bench_pairing ] && [ -f ./typea_256_1536.param ]; then
    echo "[2/3] PBC Type-A benchmark..."
    "${PIN[@]}" ./bench_pairing ./typea_256_1536.param "$OUT/runs_pairing.csv"
else
    echo "[2/3] Pairing benchmark skipped. Install PBC/GMP and run: make pairing && make param"
fi

echo "[3/3] Raw timing samples written to $OUT (local only, not committed)."
echo "Finished. Results: $OUT"
