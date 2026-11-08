#!/usr/bin/env bash
set -euo pipefail
CORE="${CORE:-0}"
RUN_ID="${RUN_ID:-1}"
MCL_ROOT="${MCL_ROOT:-}"

mkdir -p build results

CMAKE_ARGS=(-S . -B build -DCMAKE_BUILD_TYPE=Release)
if [[ -n "${MCL_ROOT}" ]]; then
  CMAKE_ARGS+=("-DMCL_ROOT=${MCL_ROOT}")
fi
cmake "${CMAKE_ARGS[@]}"
cmake --build build -j"$(nproc)"

{
  echo "=== date ==="; date -Is
  echo "=== OS ==="; cat /etc/os-release 2>/dev/null || true
  echo "=== CPU ==="; lscpu
  echo "=== kernel ==="; uname -a
  echo "=== compiler ==="; g++ --version | head -1
  echo "=== cmake ==="; cmake --version | head -1
  echo "=== openssl ==="; openssl version -a
  echo "=== PBC/GMP/mcl libraries ==="
  ldconfig -p 2>/dev/null | grep -E 'libpbc|libgmp|libmcl' || true
  echo "=== linked crypto_bench libraries ==="
  ldd build/crypto_bench 2>/dev/null | grep -E 'pbc|gmp|mcl|crypto' || true
  echo "=== MCL_ROOT ==="
  echo "${MCL_ROOT:-<not set; CMake searched system paths>}"
  if [[ -n "${MCL_ROOT}" && -d "${MCL_ROOT}/.git" ]]; then
    echo "=== mcl git commit ==="
    git -C "${MCL_ROOT}" rev-parse HEAD || true
    git -C "${MCL_ROOT}" status --short || true
  fi
  if [[ -n "${MCL_ROOT}" && -f "${MCL_ROOT}/lib/libmcl.a" ]]; then
    echo "=== libmcl.a SHA256 ==="
    sha256sum "${MCL_ROOT}/lib/libmcl.a" || true
  fi
} > "results/system_info_run${RUN_ID}.txt"

OUT="results/run${RUN_ID}.csv"
if command -v taskset >/dev/null 2>&1; then
  taskset -c "${CORE}" ./build/crypto_bench > "${OUT}"
else
  ./build/crypto_bench > "${OUT}"
fi

{
  echo "=== PBC parameter file (historical baseline only) ==="
  if [[ -f params/a_160_512.param ]]; then
    sha256sum params/a_160_512.param
  else
    echo "params/a_160_512.param not found"
  fi
} >> "results/system_info_run${RUN_ID}.txt"

echo "Saved ${OUT}"
echo "Saved results/system_info_run${RUN_ID}.txt"
