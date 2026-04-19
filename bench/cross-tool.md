# Cross-tool benchmark

Apples-to-apples comparison of shrike against the prior-art
scanners I could get running. Honest numbers including where
shrike loses.

## Corpus

Three binaries, two architectures. Stripped, release-build,
no symbols.

| name               | size   | arch       | notes                |
|--------------------|--------|------------|----------------------|
| `/lib/libc.so.6`   | 2.3 MB | x86_64     | glibc 2.35, ubuntu 22.04 |
| `/bin/bash`        | 1.2 MB | x86_64     | bash 5.1.16            |
| `arm64-libc.so.6`  | 1.9 MB | aarch64    | cross-compiled glibc   |

I wanted to include a Mach-O dylib too, but I don't have a clean
macOS corpus and can't reliably cross-check against competitors
there.

## Tools

- **shrike** — this repo, v5.0.0, gcc 11.4, `-O2 -static`.
- **ROPgadget** — v7.4, python 3.10, same machine.
- **ropr** — v0.1.5, cargo build --release.
- **rp++** — v2.0.3, g++ 11.4 --release.

Runs on a Ryzen 5950X / 32GB, ubuntu 22.04 host, file cache
warm, `taskset -c 0` to pin to one core for fairness. Each
number is median of 5 runs.

## x86_64 — libc.so.6

| tool       | wall-clock | gadgets emitted | memory peak |
|------------|-----------:|----------------:|------------:|
| ropr       |    0.31 s  |          412318 |      48 MB  |
| shrike     |    0.84 s  |          411847 |      22 MB  |
| rp++       |    2.1 s   |          409204 |      89 MB  |
| ROPgadget  |   14.2 s   |          408103 |     287 MB  |

Observations:

- **ropr wins on speed** by ~2.7x. They SIMD-accelerate the
  0xC3 byte prefilter and parallelise across mapped segments.
  Worth studying; see TODO.md for the corresponding item.
- **shrike's memory footprint is the lowest** by a wide
  margin. Static binary, no Python interp, no C++ stdlib. For
  containerised CI pipelines this matters.
- Gadget-count delta is small (<1.5%) and accounted for by
  canonical dedup rules, which differ per tool. shrike's
  output is consistently slightly higher when `--canonical`
  is off; with it on we're basically at ropr's count.

## x86_64 — bash

| tool       | wall-clock | gadgets emitted |
|------------|-----------:|----------------:|
| ropr       |    0.18 s  |          87412  |
| shrike     |    0.42 s  |          86903  |
| rp++       |    1.1 s   |          85917  |
| ROPgadget  |    7.8 s   |          85224  |

Same pattern. ropr ~2.3x faster on smaller binaries — the
setup cost eats some of their SIMD advantage.

## aarch64 — libc

| tool       | wall-clock | gadgets emitted |
|------------|-----------:|----------------:|
| shrike     |    0.22 s  |          38241  |
| ROPgadget  |    4.1 s   |          37983  |
| ropr       |    N/A     |         (crash) |
| rp++       |    N/A     |      (x86 only) |

- **ropr crashed** on my aarch64 glibc — filed a bug upstream.
  Possibly specific to the cross-compiled binary I used. Not
  a fair comparison failure, but worth noting.
- **rp++ doesn't support aarch64** last I checked. Maybe a
  recent version does.
- shrike's aarch64 path is faster than x86 per-byte because
  the fixed-4-byte encoding means no backscan trial-decode
  loop.

## Semantic features

Beyond raw gadget counts, here's what each tool can tell you
about a gadget:

| feature                        | shrike | ropr | rp++ | ROPgadget |
|--------------------------------|:------:|:----:|:----:|:---------:|
| category classification        |   ✓    |  —   |  —   |     —     |
| register-control index         |   ✓    |  ✓   |  —   |     ✓     |
| multi-pop permutation search   |   ✓    |  —   |  —   |     —     |
| chain synthesis with padding   |   ✓    |  —   |  —   |  partial  |
| stack pivot atlas              |   ✓    |  —   |  —   |     —     |
| SARIF 2.1.0 output             |   ✓    |  —   |  —   |     —     |
| pwntools emitter               |   ✓    |  —   |  —   |     ✓     |
| CET / BTI awareness            |   ✓    |  —   |  —   |  partial  |
| canonical semantic dedup       |   ✓    |  —   |  —   |     —     |
| JOP dispatcher classifier      |   ✓    |  —   |  —   |     —     |
| DOP arbitrary-write detector   |   ✓    |  —   |  —   |     —     |
| SMT chain-correctness proof    |   ✓    |  —   |  —   |     —     |
| PE / Mach-O native loaders     |   ✓    |  —   |  ✓   |     ✓     |
| RV64 / PPC64 / MIPS scanners   |   ✓    |  —   |  —   |  partial  |

**The positioning:** ropr is faster; shrike is deeper. If you
run one tool, run the one whose tradeoffs match your need.
For CI regression-checking of hardening posture, shrike. For
sub-second interactive scanning of known-good binaries, ropr.

## Reproducing

```bash
cd bench/
./run-cross-tool.sh             # requires ropr, rp++, ROPgadget on $PATH
cat cross-tool.results
```

Results are CSV so plotting is easy. Please send better numbers
if you get them on other hardware.

## Missing from this bench

- **Determinism of output across runs.** shrike is fully
  deterministic; I haven't verified the others are.
- **Correctness vs. ground truth.** "Gadget count" proves
  nothing about whether each tool found the *same* gadgets.
  A full set-intersection analysis is TODO.
- **Big inputs (>100 MB).** My largest binary is 2.3 MB.
  Scaling behaviour at, say, 500 MB of kernel module could
  be completely different.
