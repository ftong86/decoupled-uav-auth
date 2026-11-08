#!/usr/bin/env bash
# E2-DISTRIBUTED ABLATION - parallel driver for the formal 120-run batch.
#
# usage: run_batch.sh <joblist.txt> [workers] [start_line] [end_line]
#
# joblist.txt lines: <wsl_run_dir>|<event>|<variant>|<rng_run>|<scene_sha256>
# Every job runs in its own pre-generated unique directory, so nothing is
# overwritten and nothing has to be deleted.
set -u
JL="$(realpath -m "$1")"; W="${2:-6}"; S="${3:-1}"; E="${4:-999999}"
# Scripts live alongside this file in the public repository; no absolute host paths.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOB="$SCRIPT_DIR/run_job.sh"
mkdir -p "$SCRIPT_DIR/logs"
sed -n "${S},${E}p" "$JL" \
  | xargs -P "$W" -d '\n' -I{} bash -c \
      'IFS="|" read -r a b c d e <<< "{}"; bash '"$JOB"' "$a" "$d" "$b" "$c" "$e"'
