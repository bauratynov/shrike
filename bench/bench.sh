#!/usr/bin/env bash
# bench.sh — repeatable performance baseline.
#
# Runs shrike against a fixed corpus (system binaries that are
# present on any Linux workstation) and reports wall-clock time +
# gadgets emitted. Meant to be diff'ed against a baseline committed
# in bench/baseline.txt to catch regressions.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -x ./shrike ]]; then make; fi

targets=(/bin/ls /bin/bash /bin/cat /lib/x86_64-linux-gnu/libc.so.6)

printf '%-40s %12s %14s\n' 'binary' 'wall_ms' 'gadgets'
for bin in "${targets[@]}"; do
    [[ -x "$bin" ]] || { printf '%-40s %12s %14s\n' "$bin" skip -; continue; }
    out=$( { /usr/bin/time -f '%e' ./shrike --quiet "$bin" 2>&1 >/dev/null; } )
    wall_s=$(echo "$out" | tail -1 | awk '{print $1}')
    wall_ms=$(awk "BEGIN{printf \"%.0f\", $wall_s * 1000}")
    gad=$(./shrike --quiet "$bin" 2>&1 | awk '/emitted/ {for(i=1;i<=NF;i++)if($i=="emitted")print $(i-1); exit}' | head -1)
    printf '%-40s %12s %14s\n' "$bin" "$wall_ms" "$gad"
done
