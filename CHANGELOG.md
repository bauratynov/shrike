# Changelog

All notable changes to `shrike` are listed here. Project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-04-18

Quality-of-life improvements for real-world use.

### Added
- **`--filter PATTERN`** — only emit gadgets whose rendered
  mnemonic line contains the substring `PATTERN`. Enables
  one-liners like `shrike /bin/ls --filter 'pop rdi ; ret'`.
- **`--unique`** — de-duplicate gadgets by mnemonic text. Backed
  by an open-addressed FNV-1a hash set in `src/strset.c`. First
  occurrence wins; identical chains at different addresses
  collapse to one line.
- **`--limit N`** — stop after emitting N gadgets. Short-circuits
  the scanner, so auditing huge binaries for the first match of a
  filter returns quickly.
- **Mnemonic coverage** — the formatter now recognises `lea r, [r+d8]`,
  all sixteen `cmovcc reg, reg` forms, `shld`/`shrd` with imm8,
  and the `bt`/`bts`/`btr`/`btc` family via Group 8.

### Changed
- Internal `format.c` now renders via a small stack-allocated
  `strbuf_t` instead of emitting directly to `FILE*`. The public
  `format_gadget()` and `format_gadget_insns()` keep the same
  shape; a new `format_gadget_render(buf, len)` returns the
  mnemonic line as a string (used by `--filter` and `--unique`).

## [0.1.0] — 2026-04-18

Initial public release. First end-to-end usable slice.

### Added
- **ELF64 loader** (`src/elf64.c`). Bounds-checked parser. Resolves
  executable PT_LOAD segments; ignores everything else.
- **x86-64 length decoder** (`src/xdec.c`). Table-driven:
  256-entry primary opcode map + a classifier for the 0x0F two-byte
  map + generous defaults for the 3-byte 0x38 / 0x3A maps.
  Handles legacy prefixes, REX with `.W` immediate sizing, ModR/M +
  SIB + displacement, Group 3 `TEST` sub-opcode peeking, and ENTER's
  dual-immediate quirk. Rejects VEX/EVEX and illegal-in-64 opcodes.
- **Gadget scanner** (`src/scan.c`). For each terminator byte
  (RET, RETF, INT, SYSCALL, SYSRET, indirect CALL/JMP via FF),
  walks back up to `max_backscan` bytes, decodes candidate chains
  through the length decoder, and emits chains that land precisely
  on the terminator.
- **Mnemonic printer** (`src/format.c`). Recognises ~30 common gadget
  opcodes (push/pop/mov/xor/add reg-reg, ret family, syscall, int,
  leave, nop, hlt, jmp/call relative and indirect, MOV r,imm forms);
  falls back to `db 0x..` for everything else.
- **CLI** (`src/main.c`). Flags for max chain length, scan window,
  and inclusion of each terminator family. Summary on stderr.
- **Tests**. 40+ unit cases for the length decoder, 8 cases for the
  scanner. Integration script runs against real distro binaries
  (`/bin/ls`, `/bin/bash`, `/bin/cat`) and asserts non-zero gadget
  yield plus three exit-code contracts.
- **CI**. GitHub Actions: gcc + clang on ubuntu-22.04 / 24.04,
  cppcheck static analysis, AddressSanitizer + UBSan unit tests,
  integration run against distro binaries.
- **Docs**. README with architecture, build, usage; SECURITY.md
  with threat model; SVG hero showing gadget density heatmap.

### Known limitations
- **x86-64 only.** Length decoder is specific to the x86-64 ISA.
- **No VEX/EVEX decoding.** AVX-prefixed instructions appear as
  invalid and terminate candidate chains — gadgets that pass
  through a VEX-encoded op will not be enumerated.
- **Generous 3-byte map defaults.** 0x0F 0x38 / 0x3A opcodes are
  treated with uniform modrm + imm policies that are right for the
  common cases but may mis-size exotic forms.
- **No ARM64 / RISC-V.** Tracked for v0.3.
- **No output format switchers.** Plain text only; JSON/DB flavours
  are Sprint 5.

### Next
- 0.2.0: de-duplication by mnemonic hash so long scans don't flood;
  filter expressions (`--filter 'pop rdi ; ret'`).
- 0.2.0: more opcodes in the mnemonic recogniser (bts/btr/lea,
  SHLD/SHRD, CMOVcc).
- 0.3.0: ARM64 gadget support with a sibling length decoder.

## Companion releases

- [lbr-hunt v0.1.0](https://github.com/bauratynov/lbr-hunt) — runtime
  ROP detection via Intel LBR; the dynamic counterpart to shrike.
- [checkhard v0.1.0](https://github.com/bauratynov/checkhard) — ELF
  hardening auditor; answers the "is the target I'm scanning
  gadgets in actually hardened?" question.
