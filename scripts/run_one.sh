#!/usr/bin/env bash
# E2-DISTRIBUTED ABLATION - run ONE scene.
#
# Usage: run_one.sh <scene.json> <run_dir> <rng_run>
# The IoD-Sim/ns-3 build tree is supplied with IODSIM_ROOT (or IODSIM_NS3_DIR).
# All absolute paths from the development machine were removed for portability.
set -euo pipefail

IODSIM_ROOT="${IODSIM_ROOT:-$HOME/uav-iodsim-build/IoD_Sim}"
SRC="${IODSIM_NS3_DIR:-$IODSIM_ROOT/ns3}"
SCENE="$1"
RUN_DIR="$2"
RNG_RUN="${3:-3}"

# Resolve user-supplied paths before changing into the ns-3 build tree.
RUN_DIR="$(realpath -m "$RUN_DIR")"
SCENE="$(realpath -m "$SCENE")"
mkdir -p "$RUN_DIR/sim" "$RUN_DIR/state" "$RUN_DIR/logs"

echo "[run_one] scene   : $SCENE"
echo "[run_one] run_dir : $RUN_DIR"
echo "[run_one] RngRun  : $RNG_RUN"

cd "$SRC"
./ns3 run scenario --no-build -- \
  --config="$SCENE" --RngSeed=33 --RngRun="$RNG_RUN" \
  > "$RUN_DIR/logs/ns3.log" 2>&1

echo "[run_one] exit=0  log=$RUN_DIR/logs/ns3.log"
