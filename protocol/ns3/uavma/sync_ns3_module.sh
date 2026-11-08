#!/usr/bin/env bash
# Sync the uavma ns-3 module (protocol/) into an IoD-Sim/ns-3 build tree.
# Absolute paths from the working project were replaced with portable ones.
#
# It is idempotent and non-destructive:
#   * module sources   -> ns3/contrib/uavma/{CMakeLists.txt,model}
#   * S2 protocol core -> ns3/contrib/uavma/core/{src,include}
#     (byte-for-byte copies of protocol/src and protocol/include/uavma)
#   * scenario wiring  -> adds ${libuavma} to the 'scenario' target ONLY if absent
#
# A real directory is used under contrib/ (not a symlink) because CMake would not
# resolve relative source paths reliably through the contrib symlink.
#
# Frozen versions are never touched: ns-3 3.45, IoD-Sim 4.1.0, 5G LENA 5g-lena-v4.1.y.
set -euo pipefail

# Portable paths: the repository root is derived from this script's location;
# the IoD-Sim/ns-3 build tree is supplied by IODSIM_ROOT (or as argument 1).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
WSL_ROOT="${1:-${IODSIM_ROOT:-$HOME/uav-iodsim-build/IoD_Sim}}"
DEST="$WSL_ROOT/ns3/contrib/uavma"

echo "== sync uavma ns-3 module =="
echo "from: $REPO_ROOT/protocol"
echo "to  : $DEST"

[ -d "$REPO_ROOT/protocol/ns3/uavma" ] || { echo "FATAL: module source missing"; exit 1; }
[ -d "$WSL_ROOT/ns3" ] || { echo "FATAL: IoD-Sim/ns-3 build tree missing"; exit 1; }

# Preserve existing build-tree files; update only the known module sources.
# Do not erase the directory (source backups and unrelated files must survive).
mkdir -p "$DEST/model" "$DEST/core/src" "$DEST/core/include/uavma"

cp -f "$REPO_ROOT/protocol/ns3/uavma/CMakeLists.txt" "$DEST/CMakeLists.txt"
cp -f "$REPO_ROOT/protocol/ns3/uavma/model/uavma-ns3-transport.h" "$DEST/model/"
cp -f "$REPO_ROOT/protocol/ns3/uavma/model/uavma-ns3-transport.cc" "$DEST/model/"
cp -f "$REPO_ROOT/protocol/ns3/uavma/model/uavma-event-policy.h" "$DEST/model/"
cp -f "$REPO_ROOT/protocol/ns3/uavma/model/uavma-cell-partition.h" "$DEST/model/"
cp -f "$REPO_ROOT/protocol/ns3/uavma/model/uavma-measurement-ledger.h" "$DEST/model/"
cp -f "$REPO_ROOT/protocol/ns3/uavma/model/uavma-p4-cpu-model.h" "$DEST/model/"

# S2 protocol core (reused verbatim; never rewritten).
for f in protocol_core.cpp crypto.cpp state_store.cpp root_provider.cpp linux_transport.cpp \
         experiment_driver.cpp; do
  if [ -f "$REPO_ROOT/protocol/src/$f" ]; then
    cp -f "$REPO_ROOT/protocol/src/$f" "$DEST/core/src/$f"
  else
    echo "FATAL: missing S2 core source $f"
    exit 1
  fi
done
cp -f "$REPO_ROOT/protocol/include/uavma/"*.h "$DEST/core/include/uavma/"

echo "== SHA256 of reused S2 core (must match evaluation_manifest artifacts_sha256) =="
for f in protocol_core.cpp crypto.cpp state_store.cpp root_provider.cpp linux_transport.cpp; do
  printf '%-24s %s\n' "$f" "$(sha256sum "$DEST/core/src/$f" | awk '{print $1}')"
done

echo "== module tree =="
find "$DEST" -type f | sed "s|$DEST/||" | sort

# Wire ${libuavma} into the 'scenario' executable (idempotent, additive build wiring only).
CM="$WSL_ROOT/src/CMakeLists.txt"
if grep -q 'libuavma' "$CM"; then
  echo "scenario already links \${libuavma}"
else
  cp -n "$CM" "$CM.bak-uavma" 2>/dev/null || true
  sed -i 's|^\( *LIBRARIES_TO_LINK \${libiodsim}\)$|\1\n                    ${libuavma}|' "$CM"
  echo "added \${libuavma} to scenario target"
fi
grep -n "libuavma" "$CM" || true

echo "== sync done =="
