# tests/fixtures/

Per-arch hello-world binaries for regression testing. **Not
checked into git** — binaries drift across toolchain versions
and bloat commit history. `gen.sh` rebuilds them from source
on demand.

## Usage

```bash
tests/fixtures/gen.sh
ls tests/fixtures/
  hello_x86_64
  hello_aarch64      # if aarch64-linux-gnu-gcc is installed
  hello_riscv64      # if riscv64-linux-gnu-gcc is installed
  hello_pe.exe       # if mingw is installed
```

The CI workflow (`cross-arch` job) runs `gen.sh` for the
architectures that have cross-compilers available, then shells
out to `shrike` and checks the gadget counts land in a
reasonable range (see `expected-counts.txt`).

## Expected counts

Toolchain / optimisation / standard-library linkage all affect
gadget counts by tens of percent. We assert **ranges**, not
exact values, to avoid flakiness when CI runners bump gcc /
binutils / glibc minor versions.

See `expected-counts.txt` for the pinned ranges.

## Why not check in binaries

Three reasons:

1. **Non-determinism.** `gcc -O2 -o hello` produces slightly
   different bytes depending on ASLR jitter, linker version,
   debug-info flags. An in-repo binary forces us to freeze a
   toolchain.
2. **Size.** A static aarch64 binary pulls ~900 KB of libc; a
   dynamic one needs the loader + libc to match on every CI
   runner. Either way, git history bloats.
3. **Licensing.** A binary with glibc linked statically picks
   up LGPL restrictions we don't want on MIT code.

The cost is "CI has to build fixtures first". The payoff is
"shrike's regression test matches whatever the CI runner's
toolchain considers `hello world` today."
