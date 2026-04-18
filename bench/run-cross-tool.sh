#!/usr/bin/env bash
#
# run-cross-tool.sh — measure shrike against prior-art ROP
# scanners on a shared corpus. Writes CSV to stdout.
#
# Requirements on $PATH:
#   shrike        (this repo, built via `make`)
#   ropr          (cargo install ropr)
#   ROPgadget     (pip install ROPgadget)
#   rp++          (optional; skipped if missing — x86 only anyway)
#
# Usage:
#   bench/run-cross-tool.sh /bin/ls /bin/bash > results.csv
#
# Timing via `/usr/bin/time -f %e` for wall-clock + peak RSS;
# each measurement is median of 3 runs. File cache is warmed
# by a first (unmeasured) run.

set -euo pipefail

TIME=/usr/bin/time
if [[ ! -x "$TIME" ]]; then
    echo "run-cross-tool.sh: needs /usr/bin/time (GNU time)" >&2
    exit 2
fi

have()    { command -v "$1" >/dev/null 2>&1; }
median3() {
    local a=$1 b=$2 c=$3
    printf '%s\n%s\n%s\n' "$a" "$b" "$c" | sort -n | sed -n '2p'
}

measure() {
    local tool=$1 bin=$2 cmd=$3
    local t1 t2 t3 rss1 rss2 rss3

    # warm cache
    eval "$cmd" >/dev/null 2>&1 || true

    for i in 1 2 3; do
        local tmp
        tmp=$(mktemp)
        $TIME -f '%e %M' bash -c "$cmd" >/dev/null 2>"$tmp"
        local wall rss
        read -r wall rss < "$tmp"
        rm -f "$tmp"
        eval "t$i=$wall"
        eval "rss$i=$rss"
    done
    local mwall mrss
    # shellcheck disable=SC2154
    mwall=$(median3 "$t1" "$t2" "$t3")
    # shellcheck disable=SC2154
    mrss=$(median3 "$rss1" "$rss2" "$rss3")
    printf '%s,%s,%s,%s\n' "$tool" "$bin" "$mwall" "$mrss"
}

count_shrike() {
    local bin=$1
    shrike --quiet "$bin" 2>&1 | grep -oP 'emitted\s+\(|(?<=shrike: 1 inputs +)\d+' | head -1
}

count_ropgadget() {
    local bin=$1
    ROPgadget --binary "$bin" 2>/dev/null | grep -c '^0x'
}

count_ropr() {
    local bin=$1
    ropr "$bin" 2>/dev/null | tail -1 | grep -oP '\d+(?= gadgets)'
}

main() {
    if [[ $# -lt 1 ]]; then
        echo "usage: $0 binary [binary ...]" >&2
        exit 2
    fi

    printf 'tool,binary,wall_sec,rss_kb,gadgets\n'

    for bin in "$@"; do
        [[ -f "$bin" ]] || { echo "skip: $bin not found" >&2; continue; }

        if have shrike; then
            local g
            g=$(count_shrike "$bin" || echo 0)
            measure shrike "$bin" "shrike --quiet '$bin'" \
                | awk -v g="$g" '{print $0","g}'
        fi
        if have ropr; then
            local g
            g=$(count_ropr "$bin" || echo 0)
            measure ropr "$bin" "ropr '$bin'" \
                | awk -v g="$g" '{print $0","g}'
        fi
        if have ROPgadget; then
            local g
            g=$(count_ropgadget "$bin" || echo 0)
            measure ROPgadget "$bin" "ROPgadget --binary '$bin'" \
                | awk -v g="$g" '{print $0","g}'
        fi
    done
}

main "$@"
