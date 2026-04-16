# shrike

<p align="center">
  <img src="docs/hero.svg" alt="shrike gadget list and density heatmap" width="820"/>
</p>

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Language: C99](https://img.shields.io/badge/Language-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Platform: x86-64 + aarch64](https://img.shields.io/badge/Platform-x86__64%20%2B%20aarch64-green.svg)](https://refspecs.linuxfoundation.org/elf/)
[![Release: 2.0.0](https://img.shields.io/badge/Release-2.0.0-brightgreen.svg)](CHANGELOG.md)

**Freestanding C99 ROP gadget scanner.** x86-64 and AArch64. Zero
runtime dependencies. One static binary you drop on any Linux host
— distroless container, air-gapped workstation, hardened FIPS
build environment.

> **2.0.0 — stable.** C API frozen (`<shrike/shrike.h>`), CLI +
> JSON + SARIF + exit codes unchanged from 1.x, ships as
> `libshrike.so.2` + `libshrike.a`. See [STABILITY.md](STABILITY.md)
> for the contract. Upgrading from 1.x? Start at
> [docs/migration-1-to-2.md](docs/migration-1-to-2.md). See
> [CHANGELOG.md](CHANGELOG.md) for every minor since 0.1.0.

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
├── src/            scanners, classifiers, formatters, CLI
├── include/        public headers
├── tests/          35+ unit tests + integration harness
├── fuzz/           AFL++ / libFuzzer drivers + seed corpus
├── bench/          repeatable performance baseline
├── docs/           shrike(1) man page, launch kit, hero SVG
├── examples/       10 common recipes
├── plugins/ghidra/ companion import script
├── packaging/      Dockerfile, debian/, shrike.spec
├── tools/          shrike-serve.sh HTTP gateway
├── .github/        CI + release workflows
├── ROADMAP.md      29-sprint plan (v0.10 → v1.0) — complete
└── STABILITY.md    1.x API contract
```

## Roadmap

- **1.x (complete)** — Stage I library shape, Stage II native
  loaders (PE, Mach-O, RV64), Stage III chain synthesis,
  Stage IV disassembler depth, Stage V Python binding,
  Stage VI polish + test matrix.
- **2.0.0 (now)** — stable C API, `libshrike.so.2`, `shrike-py`
  wheel. Migration guide at
  [docs/migration-1-to-2.md](docs/migration-1-to-2.md).
- **2.x → 3.0** — 29-sprint plan in [V3_ROADMAP.md](V3_ROADMAP.md):
  symbolic gadget effects, JOP/COP/DOP enumeration, PE+PDB
  symbol enrichment, PowerPC + MIPS, dynamic discovery via
  LBR/perf, Binary Ninja/IDA plugins, SMT chain-correctness
  proofs.

## Companion tools

- [lbr-hunt](https://github.com/bauratynov/lbr-hunt) — runtime ROP
  detection via Intel LBR.
- [checkhard](https://github.com/bauratynov/checkhard) — ELF
  hardening auditor.

## References

- Shacham, *The Geometry of Innocent Flesh on the Bone*, CCS 2007
- Intel SDM Vol 2/3A · ARM ARM C3/C4/C6 · SARIF 2.1.0 OASIS spec
- Predecessors: [ROPgadget](https://github.com/JonathanSalwan/ROPgadget), [Ropper](https://github.com/sashs/Ropper), [rp++](https://github.com/0vercl0k/rp)

## License

MIT — see [LICENSE](LICENSE).

## Author

**Baurzhan Atynov** — [bauratynov@gmail.com](mailto:bauratynov@gmail.com)
