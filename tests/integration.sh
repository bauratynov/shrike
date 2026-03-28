#!/usr/bin/env bash
#
# integration.sh — run shrike against real distro binaries and
# assert that it produces a plausible number of gadgets without
# crashing. These are not gadget-content assertions; the purpose is
# to catch regressions in the loader / decoder / scanner pipeline
# on real-world inputs.

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -x ./shrike ]]; then make; fi

fails=0
say_pass() { echo "  [ok]   $*"; }
say_fail() { echo "  [FAIL] $*"; fails=$((fails + 1)); }

audit() {
    local bin=$1
    local min=$2
    local label=$3

    if [[ ! -x "$bin" ]]; then
        echo "  [skip] $label ($bin not available)"
        return
    fi

    local out
    out=$(./shrike --quiet "$bin" 2>&1 | tail -1)

    # Summary line: "shrike: [arch] N emitted (SHSTK-blocked: X, ENDBR/BTI-start: Y)".
    # Column 3 is the emitted-count.
    local n
    n=$(echo "$out" | awk '{print $3}')
    if [[ -z "$n" ]] || ! [[ "$n" =~ ^[0-9]+$ ]]; then
        say_fail "$label: malformed summary: $out"
        return
    fi
    if (( n < min )); then
        say_fail "$label: only $n gadgets (expected >= $min)"
    else
        say_pass "$label: $n gadgets"
    fi
}

echo "integration tests"
audit /bin/ls     200 "ls"
audit /bin/bash   500 "bash"
audit /bin/cat    100 "cat"

# Exit code 0 when run without errors (even if nothing was found).
if ./shrike --quiet /bin/ls > /dev/null 2>&1; then
    say_pass "exit 0 on clean run"
else
    say_fail "exit $? on clean run"
fi

# Exit code 2 on bad invocation.
set +e
./shrike > /dev/null 2>&1
rc=$?
set -e
if [[ $rc -eq 2 ]]; then
    say_pass "exit 2 on missing argument"
else
    say_fail "expected exit 2, got $rc"
fi

# Exit code 1 on unreadable file.
set +e
./shrike /no/such/file > /dev/null 2>&1
rc=$?
set -e
if [[ $rc -eq 1 ]]; then
    say_pass "exit 1 on missing file"
else
    say_fail "expected exit 1 on missing file, got $rc"
fi

echo
if [[ $fails -eq 0 ]]; then
    echo "integration: all pass"
else
    echo "integration: $fails failure(s)"
    exit 1
fi
