#!/usr/bin/env bash
#
# gen.sh — build per-arch "hello world" fixtures for regression
# testing. Not checked into the repo (binaries drift across
# toolchains and inflate git history); CI runs this first.
#
# Output: tests/fixtures/hello_<arch>

set -uo pipefail
# intentionally NOT -e: a missing cross-compiler on one arch
# shouldn't abort the entire fixture-build phase.

SRC=$(dirname "$0")/hello.c
OUT=$(dirname "$0")

: > "$OUT/build.log"

cat > "$SRC" <<'EOF'
#include <stdio.h>
#include <stdlib.h>

/* Keep this file tiny and branch-rich so every terminator
 * category has a chance to surface in the scanner output. */

static int sum(int a, int b) { return a + b; }

int main(int argc, char **argv)
{
    if (argc < 2) {
        puts("no args");
        return 1;
    }
    int a = atoi(argv[1]);
    int b = argc > 2 ? atoi(argv[2]) : 0;
    printf("%d\n", sum(a, b));
    return 0;
}
EOF

have() { command -v "$1" >/dev/null 2>&1; }

# x86_64 — use system cc.
if have cc; then
    cc -O2 -o "$OUT/hello_x86_64" "$SRC" >>"$OUT/build.log" 2>&1 && \
        echo "built hello_x86_64"
fi

# aarch64 via debian's gcc-aarch64-linux-gnu.
if have aarch64-linux-gnu-gcc; then
    aarch64-linux-gnu-gcc -O2 -static -o "$OUT/hello_aarch64" "$SRC" \
        >>"$OUT/build.log" 2>&1 && echo "built hello_aarch64"
fi

# riscv64.
if have riscv64-linux-gnu-gcc; then
    riscv64-linux-gnu-gcc -O2 -static -o "$OUT/hello_riscv64" "$SRC" \
        >>"$OUT/build.log" 2>&1 && echo "built hello_riscv64"
fi

# PE x86_64 via mingw.
if have x86_64-w64-mingw32-gcc; then
    x86_64-w64-mingw32-gcc -O2 -o "$OUT/hello_pe.exe" "$SRC" \
        >>"$OUT/build.log" 2>&1 && echo "built hello_pe.exe"
fi

rm -f "$SRC"
