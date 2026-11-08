#!/usr/bin/env bash
# This script is informational only and must always exit successfully.
set +e

echo "=== DATE ==="
date -Is 2>/dev/null || date
echo

echo "=== UNAME ==="
uname -a 2>/dev/null || true
echo

echo "=== CPU ==="
lscpu 2>/dev/null || true
echo

echo "=== CPU AFFINITY OF THIS SHELL ==="
if command -v taskset >/dev/null 2>&1; then
    taskset -pc $$ 2>/dev/null || true
else
    echo "taskset unavailable"
fi
echo

echo "=== OPENSSL ==="
openssl version -a 2>/dev/null || true
echo

echo "=== COMPILER ==="
g++ --version 2>/dev/null || true
gcc --version 2>/dev/null || true
echo

echo "=== PYTHON ==="
python3 --version 2>/dev/null || true
echo

echo "=== CPU GOVERNOR ==="
found=0
for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [ -r "$f" ]; then
        echo "$f: $(cat "$f" 2>/dev/null)"
        found=1
    fi
done

if [ "$found" -eq 0 ]; then
    echo "Not exposed by this kernel/VM/WSL environment."
fi

echo
echo "=== WSL DETECTION ==="
if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "WSL detected"
else
    echo "No WSL marker detected"
fi

exit 0
