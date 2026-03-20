# shrike

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Language: C99](https://img.shields.io/badge/Language-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)
[![Platform: x86-64](https://img.shields.io/badge/Platform-x86__64-green.svg)](https://refspecs.linuxfoundation.org/elf/)

Minimal ROP gadget finder for x86-64 ELF64 binaries, written from
scratch in pure C99. Parses the ELF, walks executable PT_LOAD
segments, decodes instruction lengths with a small table-driven
length decoder, and enumerates return-terminated gadget sequences.

Named after the shrike — a songbird that impales its prey on thorns
for later retrieval. Appropriate.

> **Status:** Sprint 1 — ELF64 loader + CLI skeleton.
> Sprints 2–4 add the length decoder, the gadget scanner, and CI.

---

## Why

[ROPgadget](https://github.com/JonathanSalwan/ROPgadget) exists and is
excellent. It is also Python with a large dependency tree. `shrike`
is the thing you put in a static binary to drop into a locked-down
audit host — same output shape, zero runtime dependencies, auditable
in an afternoon. It also pairs naturally with
[lbr-hunt](https://github.com/bauratynov/lbr-hunt): static gadget
enumeration (shrike) plus runtime chain detection via Intel LBR.

## Design

- **C99, no libc dependencies** beyond `<string.h>` / `<stdio.h>` /
  `<sys/mman.h>`. One source tree, readable end-to-end.
- **Bounds-checked ELF loader.** Every offset validated against file
  size before dereferencing. Malformed binaries refused, not parsed
  into undefined behaviour.
- **Table-driven length decoder.** Two 256-byte tables drive the
  x86-64 instruction-length walk: primary opcode map and 0x0F escape
  map. Sufficient for gadget enumeration; not a full disassembler.
- **Walk backward from terminators.** For each `ret` / `syscall` /
  `int` / indirect jmp / indirect call byte, try decoding a window
  backwards; emit sequences that decode consistently to that point.

## Layout (end state)

```
shrike/
├── LICENSE
├── Makefile
├── README.md
├── SECURITY.md
├── CHANGELOG.md
├── include/
│   ├── elf64.h       # sprint 1
│   ├── xdec.h        # sprint 2
│   └── scan.h        # sprint 3
├── src/
│   ├── elf64.c       # sprint 1: parse + find executable PT_LOAD
│   ├── xdec.c        # sprint 2: x86-64 length decoder
│   ├── scan.c        # sprint 3: gadget scanner
│   ├── format.c      # sprint 3: mnemonic printer
│   └── main.c        # sprint 1: CLI
├── tests/
│   ├── Makefile
│   ├── test_xdec.c   # sprint 2: length decoder unit tests
│   ├── test_scan.c   # sprint 3: gadget scanner tests
│   └── integration.sh
└── docs/hero.svg
```

## Build

```bash
make
./shrike /bin/ls
```

Sprint 1 output:

```
file    : /bin/ls
type    : ET_DYN (PIE / shared)
entry   : 0x8000
segments: 2 executable
  [0] vaddr=0x0000000000000000  bytes=4032  flags=r-x
  [1] vaddr=0x0000000000002000  bytes=92416  flags=r-x
```

## Roadmap

- [x] Sprint 1: ELF64 loader + CLI skeleton
- [ ] Sprint 2: x86-64 length decoder + unit tests
- [ ] Sprint 3: gadget scanner + mnemonic printer
- [ ] Sprint 4: CI + integration tests against real distro binaries + v0.1.0

## Companion tools

- [lbr-hunt](https://github.com/bauratynov/lbr-hunt) — runtime ROP
  detection via Intel LBR. Static enumeration plus runtime detection
  gives full-coverage mitigation audit.
- [checkhard](https://github.com/bauratynov/checkhard) — ELF
  hardening auditor. What ASLR/PIE/NX is configured on the binary
  that shrike is scanning for gadgets.

## License

MIT — see [LICENSE](LICENSE).

## Author

**Baurzhan Atynov** — [bauratynov@gmail.com](mailto:bauratynov@gmail.com)
