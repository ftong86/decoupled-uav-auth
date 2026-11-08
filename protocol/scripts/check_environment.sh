#!/usr/bin/env bash
set -euo pipefail
printf 'Project location: %s\n' "$(pwd)"
for x in bash git g++ make cmake python3 openssl sha256sum; do
 if command -v "$x" >/dev/null; then printf 'OK %-12s %s\n' "$x" "$(command -v "$x")"; else printf 'MISSING %-12s\n' "$x"; fi
done
printf 'Kernel: '; uname -sr
printf 'Storage for current tree:\n'; df -h . | tail -n 1
printf 'Disk free in WSL home:\n'; df -h "$HOME" | tail -n 1
if grep -qi microsoft /proc/version; then echo 'Detected WSL.'; else echo 'No WSL marker (may be native Linux).'; fi
if [[ -n "${IODSIM_ROOT:-}" && -d "$IODSIM_ROOT" ]]; then
  echo "IoD-Sim build tree: $IODSIM_ROOT"
else
  echo 'IoD-Sim build tree not configured (set IODSIM_ROOT to enable ns-3 runs).'
fi
