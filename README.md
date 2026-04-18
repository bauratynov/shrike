# shrike

<p align="center">
  <img src="docs/hero.svg" alt="shrike gadget list and density heatmap" width="820"/>
</p>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Language: C99](https://img.shields.io/badge/Language-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Platform: x86-64 + aarch64](https://img.shields.io/badge/Platform-x86__64%20%2B%20aarch64-green.svg)](https://refspecs.linuxfoundation.org/elf/)
[![Release: 3.0.0](https://img.shields.io/badge/Release-3.0.0-brightgreen.svg)](CHANGELOG.md)

**Freestanding C99 ROP gadget scanner.** x86-64 and AArch64. Zero
runtime dependencies. One static binary you drop on any Linux host
— distroless container, air-gapped workstation, hardened FIPS
build environment.

> **3.0.0 — stable.** Stable C API carries over from 2.0.
> soname bumps to `libshrike.so.3`. V3_ROADMAP's Stage VII
> (semantic IR + JOP/COP/DOP classifiers), Stage VIII's PE
> Debug Directory, Stage IX's runtime-reached filter, and
> Stage XII's SMT proof emitter are all shipped. See
> [STABILITY.md](STABILITY.md) for the v3 contract and
> [docs/migration-2-to-3.md](docs/migration-2-to-3.md) for
> the (small) upgrade notes. Deferred v3.x work is tracked
> in [V3_ROADMAP.md](V3_ROADMAP.md).

---

## What it does

```bash
# Classic
shrike /bin/ls

# JSON for jq pipelines
shrike --json /bin/bash | jq 'select(.category == "pop")'

# Exploit skeleton with cyclic placeholders
shrike /bin/bash /lib/x86_64-linux-gnu/libc.so.6 \
    --recipe 'rdi=*; rsi=*; rdx=*; rax=59; syscall' \
    --format pwntools > exploit.py

# SARIF for GitHub Code Scanning
shrike --sarif --sarif-cap 2000 dist/*.so > shrike.sarif

# What did the new libc release change?
shrike --diff /old/libc.so.6 /new/libc.so.6 | head

# Scan a PE .text extracted with objcopy
objcopy -O binary --only-section=.text foo.exe foo.text
shrike --raw --raw-arch x86_64 --raw-base 0x401000 foo.text

# Hardening posture of every binary in dist/
shrike --cet-posture --wx-check dist/*.so
```

Ten more in [examples/README.md](examples/README.md).

## Features

| | |
|---|---|
| **Architectures** | x86-64, AArch64. PE/Mach-O via `--raw`. |
| **Terminators** | RET family, SYSCALL, SVC, INT3, indirect CALL/JMP, BR/BLR. |
| **Classification** | pop · mov · arith · stack_pivot · syscall · indirect · ret_only. |
| **CET / BTI** | `.note.gnu.property` parsing; `shstk_blocked` + `starts_endbr` per gadget; ENDBR64 / ENDBR32 / BTI mnemonic recognition. |
| **Composition** | Register-control index (text / pwntools dict / JSON); `--recipe` DSL; stack pivot atlas. |
| **Outputs** | Text, JSON-Lines, SARIF 2.1.0, pwntools-compatible Python, CycloneDX property block. |
| **Filters** | Substring, POSIX regex, unique, canonical (semantic dedup), limit, category, bad-bytes. |
| **Multi-binary** | N inputs per invocation, cross-input dedup, `--intersect`, `--diff`. |
| **Hardening audit** | `--wx-check`, `--cet-posture`, `--cdx-props`. |
| **Ecosystem** | Ghidra import script, HTTP gateway wrapper, Dockerfile, deb/rpm packaging. |
| **Quality** | AFL++ + libFuzzer, ASan + UBSan CI, cppcheck, GitHub Code Scanning integration, benchmarks. |

## Install

```bash
# From source
make && sudo make install

# Release tarball (signed with minisign — key in packaging/)
curl -LO https://github.com/bauratynov/shrike/releases/download/v1.0.0/shrike-linux-x86_64.tar.gz
sha256sum -c shrike-linux-x86_64.tar.gz.sha256
tar xzf shrike-linux-x86_64.tar.gz

# Docker (scratch image, ~900 KB)
docker build -f packaging/Dockerfile -t shrike:1.0.0 .
docker run --rm -v /bin:/host shrike:1.0.0 --quiet /host/ls
```

## Layout

```
shrike/
├── src/                scanners, classifiers, formatters, CLI
├── include/shrike/     public headers (<shrike/shrike.h> is the 3.x ABI)
├── python/             pip-installable Python bindings
├── tests/              unit tests + fixture regression + integration
├── fuzz/               libFuzzer + AFL++ harnesses (xdec, pe, macho)
├── bench/              reproducible cross-tool benchmark
├── docs/               man page, migration guides, SVG hero
│   └── book/           reading path (01-intro → 04-verification)
├── examples/
│   └── recipes/        per-arch execve / pivots / ...
├── plugins/
│   ├── ghidra/         import script
│   ├── ida/            shrike_importer.py
│   └── binja/          shrike_importer.py
├── packaging/          Dockerfile, debian/, shrike.spec, shrike.pc.in
├── tools/              lbr-ingest.py, shrike-gdb.py, shrike-serve.sh
├── .github/            CI + release workflows
├── DESIGN.md           decision log (why libbfd was rejected, etc.)
├── LIMITATIONS.md      what doesn't work, what won't, what might
├── TODO.md             rough dated notes (not a roadmap)
├── V2_ROADMAP.md       v1.1.0 → v2.0.0 (complete)
├── V3_ROADMAP.md       v2.1.0 → v3.0.0 (core delivered)
└── STABILITY.md        3.x contract
```

New readers: start with [docs/book/01-intro.md](docs/book/01-intro.md).
Upgrading from 1.x: [docs/migration-1-to-2.md](docs/migration-1-to-2.md).

## Roadmap

- **1.x (complete)** — library shape, native loaders, chain
  synthesis, disassembler depth, Python bindings, polish.
  Closed at 2.0.0.
- **2.x (complete)** — stable C API + soname bumping through
  `libshrike.so.3` + Python package on PyPI.
- **3.0.0 (now)** — Stage VII semantic IR, Stage VIII PE
  Debug Directory, Stage IX `--reached-file` runtime filter,
  Stage XII SMT chain-correctness prover. Migration guide:
  [docs/migration-2-to-3.md](docs/migration-2-to-3.md).
- **3.x (deferred)** — PowerPC 64 + MIPS scanners, full PDB
  symbol enrichment, Mach-O 32 + arm64e PAC, Binary Ninja /
  IDA / GDB plugins, exploit-synthesis library, SMT memory
  modelling, SIMD scanner, `shrike-book`. Tracked in
  [V3_ROADMAP.md](V3_ROADMAP.md).

## Companion tools

- [lbr-hunt](https://github.com/bauratynov/lbr-hunt) — runtime ROP
  detection via Intel LBR.
- [checkhard](https://github.com/bauratynov/checkhard) — ELF
  hardening auditor.

## Prior art — honest comparison

- **[ROPgadget](https://github.com/JonathanSalwan/ROPgadget)**
  (Salwan, 2011). Python. Widely used in CTFs. shrike borrowed
  its category taxonomy. ROPgadget's unique-dedup misses the
  xor-zero idiom; shrike's `--canonical` handles it.
- **[ropr](https://github.com/Ben-Lichtman/ropr)** (2022).
  Rust, Apache-2.0. **Fastest Linux x86_64 scanner I've
  measured** — roughly 2.7x faster than shrike on glibc
  (see `bench/cross-tool.md`). They SIMD-prefilter terminator
  bytes; we don't. Different tradeoff: ropr optimises for
  speed, shrike for semantic depth (effect IR, SMT proof,
  chain synthesis).
- **[rp++](https://github.com/0vercl0k/rp)** (0vercl0k, 2013).
  C++. Great PE support, widely used on Windows. shrike chose
  pure C99 to keep the binary tiny and avoid a C++ runtime
  in scratch containers.
- **[Ropper](https://github.com/sashs/Ropper)** (Schirra, 2014).
  Python. Similar scope to ROPgadget; Python dependency chain
  is heavier.
- **[angrop](https://github.com/angr/angrop)**. Full-symbolic
  scanner inside the angr framework. Produces optimal chains
  via SMT. ~100x slower than shrike for scanning but does
  things we can't (multi-constraint chain solving).

## References

### Papers
- Shacham, H. *The Geometry of Innocent Flesh on the Bone:
  Return-into-libc without Function Calls*. CCS 2007 — the
  foundational ROP paper.
- Bletsch, T. et al. *Jump-Oriented Programming: A New Class
  of Code-Reuse Attack*. ASIACCS 2011 — shrike's JOP
  dispatcher shape comes from here.
- Hu, H. et al. *Data-Oriented Programming: On the
  Expressiveness of Non-Control Data Attacks*. S&P 2016 —
  DOP gadget detection in v2.1.4.
- Schuster, F. et al. *Counterfeit Object-Oriented
  Programming*. S&P 2015 — COOP isn't implemented yet but
  informs the COP dispatcher classifier.

### Specs
- Intel SDM Vol 2/3A (January 2026 revision)
- ARM ARM C3/C4/C6
- RISC-V Unprivileged ISA 20240411 + Privileged ISA 20240411
- PE/COFF Specification (aka.ms/PECOFF)
- Apple's Mach-O spec (via LIEF docs; Apple's own docs are sparse)
- SARIF 2.1.0 OASIS spec

### Implementation references
- [LIEF](https://github.com/lief-project/LIEF) — best "what
  does this PE field mean in practice" reference.
- [Capstone](https://github.com/capstone-engine/capstone) —
  the opaque-handle C API shape we modelled `<shrike/shrike.h>`
  on.
- [liblzma](https://tukaani.org/xz/) — versioning scheme
  (decimal-packed major*10M + minor*10K + patch*10) borrowed
  for `SHRIKE_VERSION` macros.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Baurzhan Atynov** — [bauratynov@gmail.com](mailto:bauratynov@gmail.com)
