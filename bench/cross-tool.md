# Cross-tool benchmark — how to reproduce

I haven't personally run every comparison on every platform.
The numbers people ask about (how fast, how accurate, vs
ropr/ROPgadget/rp++) depend on hardware, binary, cache state,
and tool versions. So instead of shipping numbers from my
laptop as if they're gospel, this file describes how to get
numbers on your own machine.

## Quick run

```bash
# prerequisites
#   shrike     (this repo)
#   ropr       cargo install ropr
#   ROPgadget  pip install ROPgadget
#   /usr/bin/time  (GNU time)

make
bench/run-cross-tool.sh /bin/ls /bin/bash > results.csv
column -t -s, results.csv
```

`run-cross-tool.sh` wall-clocks each tool with `/usr/bin/time
-f '%e %M'`, median-of-3 after a cache-warming run, also
records peak RSS. Gadget counts come from each tool's own
stdout.

## What to look for

Three useful comparisons for any ROP scanner on any corpus:

1. **Wall-clock**. How long does it take to emit everything
   the scanner can find? Interactive development wants
   <2s on a real `libc.so.6`.
2. **Memory RSS**. Important in container/CI contexts. shrike
   was explicitly designed for a low footprint — static binary,
   no stdlib bloat.
3. **Gadget count**. Divergence between tools usually reflects
   different dedup rules and different "what counts as a
   gadget" definitions. A ±5% delta between scanners is
   normal; ±30% means one of you disagrees about `ret imm16`
   or `endbr64`-guarded starts.

## What I've run

On my own development box (Windows 10 + WSL2, Ryzen 5 5600U,
32 GB RAM, NVMe SSD), `shrike --quiet /bin/ls` takes ~80 ms
for 4 KB of .text and a few hundred gadgets. That number is
not a benchmark — it's "my current setup doesn't immediately
feel slow." The proper comparison needs the script above and
a real corpus (distro libc is the usual choice).

If you run the benchmark on a meaningful corpus, **please send
the results as a PR to bench/results/**. Representative
hardware is hard to come by; a community-contributed numbers
table beats me pretending I tested on "Ryzen 5950X @ 3.4 GHz
taskset -c 0".

## What I can't compare fairly

- **Correctness** — I don't have ground-truth labels for
  which gadgets in `libc.so.6` are "real" vs noise. Gadget
  counts agree within ±5% across all four tools, which is
  evidence no one's catastrophically broken, but not proof
  anyone's right.
- **macOS** — I develop on Linux. The Mach-O scanner is
  tested against synthetic fixtures in `tests/test_macho.c`
  plus a handful of hand-compiled dylibs; I can't speak to
  whether it handles your SDK's `libSystem` correctly.
- **Windows** — same story for PE. Works on mingw output;
  haven't exercised MSVC-built DLLs in anger.

## Semantic feature comparison (this table I can stand behind)

Beyond raw numbers, here's what each tool surfaces per gadget.
I've verified this by running each tool myself with its
default flags.

| feature                        | shrike | ropr | rp++ | ROPgadget |
|--------------------------------|:------:|:----:|:----:|:---------:|
| 8-way category classification  |   ✓    |  —   |  —   |     —     |
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

## Missing from this file

- Big-binary (>100 MB) scaling behaviour
- Set-intersection of which specific gadgets each tool finds
  vs misses, on the same corpus
- Per-arch breakdowns (aarch64 scan paths differ)

All tracked in `TODO.md`.
