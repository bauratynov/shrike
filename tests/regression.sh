#!/usr/bin/env bash
#
# regression.sh — build per-arch fixtures, run shrike on each,
# assert the gadget count lands in the expected range from
# tests/fixtures/expected-counts.txt.
#
# Exits 0 if every fixture built AND every count in range.
# Exits 1 if any count out of range.
# Missing fixtures (no cross-compiler available) are skipped
# with a [skip] line — not an error.
#
# Called from CI. Also runs locally for quick sanity:
#   make && tests/regression.sh

set -uo pipefail
# intentionally NOT -e: individual cross-compiler absence or a
# single out-of-range fixture shouldn't kill the whole regression.

cd "$(dirname "$0")/.."

if [[ ! -x ./shrike ]]; then
    echo "regression.sh: build shrike first" >&2
    exit 2
fi

bash tests/fixtures/gen.sh 2>&1 | sed 's/^/    gen.sh: /'

fails=0
checked=0

while IFS= read -r line; do
    line=${line%%#*}
    [[ -z "${line// }" ]] && continue
    read -r fixture lo hi <<< "$line"
    path="tests/fixtures/$fixture"
    if [[ ! -f "$path" ]]; then
        echo "  [skip] $fixture (no toolchain)"
        continue
    fi

    out=$(./shrike --quiet "$path" 2>&1 | grep 'emitted' | head -1)
    n=$(echo "$out" | awk '{for (i=1;i<=NF;i++) if ($i=="emitted") print $(i-1)}' | head -1)
    checked=$((checked+1))

    if [[ -z "$n" || ! "$n" =~ ^[0-9]+$ ]]; then
        echo "  [FAIL] $fixture: malformed summary '$out'"
        fails=$((fails+1))
        continue
    fi

    if (( n < lo || n > hi )); then
        echo "  [FAIL] $fixture: $n gadgets not in [$lo, $hi]"
        fails=$((fails+1))
    else
        echo "  [ok]   $fixture: $n gadgets (expected $lo..$hi)"
    fi
done < tests/fixtures/expected-counts.txt

if (( checked == 0 )); then
    echo "regression.sh: no fixtures built — missing all cross-compilers?"
    echo "            (not failing — presence of toolchains is a CI-env concern)"
    exit 0
fi
if (( fails > 0 )); then
    echo "regression.sh: $fails failure(s) of $checked checked"
    exit 1
fi
echo "regression.sh: $checked fixture(s) in range"
