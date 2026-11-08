#!/usr/bin/env bash
# E2-DISTRIBUTED ABLATION - run ONE formal job.
#
# usage: run_job.sh <wsl_run_dir> <rng_run> <event> <variant> <scene_sha256>
#
# Hard disk guard: refuses to start when free space drops below 40 GiB.
# Never deletes anything; every run writes
# into its own pre-generated unique directory.
set -u
R="$(realpath -m "$1")"; RN="$2"; EV="$3"; VA="$4"; SH="${5:-}"
# Portable build-tree location (absolute paths from the development host removed).
IODSIM_ROOT="${IODSIM_ROOT:-$HOME/uav-iodsim-build/IoD_Sim}"
NS3="${IODSIM_NS3_DIR:-$IODSIM_ROOT/ns3}"
ST="${BATCH_STATUS_FILE:-$PWD/batch_status.txt}"
FREE_GIB=$(df -B1 "$PWD" | tail -1 | awk '{printf "%d", $4/1073741824}')
if [ "$FREE_GIB" -lt 40 ]; then
  echo "$(date -u +%FT%TZ) rc=SKIP_LOW_DISK free_gib=$FREE_GIB event=$EV variant=$VA run=$RN dir=$R" >> "$ST"
  exit 91
fi
mkdir -p "$R/logs"
cd "$NS3" || exit 90
./ns3 run scenario --no-build -- --config="$R/scene.json" --RngSeed=33 --RngRun="$RN" \
    > "$R/logs/ns3.log" 2>&1
rc=$?
# The console log is pure progress output; gzip -9 measured 16.9x on real runs.
gzip -9 -f "$R/logs/ns3.log"
echo "$(date -u +%FT%TZ) rc=$rc event=$EV variant=$VA run=$RN sha=${SH:0:16} dir=$R" >> "$ST"
exit $rc
