# Changelog

All notable changes to `shrike` are listed here. Project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] — 2026-04-18

Binary-to-binary gadget diff. Supply two ELFs with the `--diff`
flag; `shrike` emits gadgets present in the new binary but not in
the old (`+ mnemo`) and gadgets present in the old but not in the
new (`- mnemo`).

Matching is by rendered mnemonic text with the address prefix
stripped, so the comparison is ASLR-safe: identical gadget shapes
at different addresses count as "common".

### Added
- **`--diff`** flag; requires exactly two input paths.
- `strset_contains()` / `strset_foreach()` — new primitives that
  enable the set-difference algorithm.
- Diff emission: one `+` or `-` prefix per differing mnemonic.
- Summary line: `shrike --diff: +218  -74  common=3012`.

### Example
```bash
# What gadgets did the latest libc release add?
shrike --diff /old/libc.so.6 /new/libc.so.6 | head
```

## [0.8.0] — 2026-04-18

Multi-binary audit. Pass any number of ELF paths; the scanner
walks each in turn and --unique dedup applies across all of them,
so gadget chains shared between main binary and its dependencies
collapse to one line.

### Added
- **Multiple inputs**: `shrike bin libc.so.6 liblzma.so.5 …`. Up
  to 64 inputs per invocation.
- **`--src-tag`** — append `[<path>]` to each text line identifying
  which binary the gadget came from.
- **JSON output** always carries a `"src"` field.
- **Summary line** reports the number of inputs processed:
  `shrike: 3 inputs  5123 emitted  (SHSTK-blocked: 2910, ENDBR/BTI-start: 14)`
- On load failure for any input the tool continues with the rest
  and exits 1 at the end.

### Example
```bash
# Unique gadgets across the main binary and its shared libraries
shrike --unique --src-tag \
    dist/my-service \
    /lib/x86_64-linux-gnu/libc.so.6 \
    /lib/x86_64-linux-gnu/libpthread.so.0
```

## [0.7.0] — 2026-04-18

Exploit-development constraints: reject gadgets whose address
contains bytes that the payload can't carry.

### Added
- **`--bad-bytes CSV`** — comma-separated list of bad bytes
  (both `0x00` and `00` syntaxes accepted). A gadget is rejected
  if any byte of its 8-byte little-endian address is in the set.
  Classic exploit constraint: payloads copied through strcpy
  can't contain null bytes; web-body injections can't contain
  CR/LF/space.
- **Summary on stderr** gains a line when the filter is active:
  `shrike: 1823 gadgets rejected by --bad-bytes`

### Example
```bash
# Find every "pop rdi ; ret" whose address has no NUL or newline
shrike /bin/bash \
    --filter 'pop rdi ; ret' \
    --bad-bytes 0x00,0x0a
```

## [0.6.0] — 2026-04-18

Gadget categorisation. Each emitted gadget now carries a coarse
shape tag that you can filter on.

### Added
- **`gadget_categorize(g)`** (`src/category.c`). Eight categories:
  `other`, `ret_only`, `pop`, `mov`, `arith`, `stack_pivot`,
  `syscall`, `indirect`. Arch-aware across x86 and aarch64.
- **`--category CSV`** — keep only gadgets whose category is in
  the comma-separated list (e.g. `--category pop,mov`).
- **`--cat-tag`** — append `[<category>]` inline in text output.
- **JSON output** gains a `"category"` field.
- **Summary on stderr** prints a histogram:
  `shrike: categories: pop=128 mov=42 arith=71 stack_pivot=3 other=41`
- **`tests/test_category.c`** — 15+ cases across both arches plus
  the CSV mask parser.

## [0.5.0] — 2026-04-18

ARM AArch64 support. `shrike` now scans both x86‑64 and aarch64
ELF64 binaries through a single pipeline, with the ELF `e_machine`
driving the dispatch.

### Added
- **AArch64 scanner** (`scan_aarch64` in `src/scan.c`). Fixed
  4‑byte instructions make length decoding trivial. Walk 4‑byte
  aligned words, detect terminators (RET / RETAA / RETAB / BR /
  BLR / SVC), emit gadgets of length 1..max_insn ending at each.
- **AArch64 classifier + renderer** (`src/arm64.c`, `include/arm64.h`).
  Minimal but honest: ret variants, br/blr, svc, nop, MOV via
  ORR XZR, BTI (c/j/jc); unknown encodings → `.word 0xXXXXXXXX`.
- **CET classifier is now arch‑aware** (`src/cet.c`).
  `cet_shstk_blocked` matches aarch64 RET family too.
  `cet_starts_endbr` also returns true for aarch64 BTI. The JSON
  field name stays `starts_endbr` for continuity; the semantic
  meaning is "starts with an IBT / BTI landing pad".
- **ELF loader** accepts `EM_AARCH64` (183) alongside `EM_X86_64`.
- **JSON output** gains an `"arch":"x86_64" | "aarch64"` field.
- **Summary on stderr** shows the architecture tag:
  `shrike: [aarch64] 842 emitted (SHSTK-blocked: 798, ENDBR/BTI-start: 3)`
- **`tests/test_arm64.c`** — 20+ cases covering terminator
  detection, BTI variants, renderer output, and little‑endian
  instruction read.

### Changed
- `gadget_t` gained a `machine` field so format.c and cet.c
  dispatch locally without a vtable.

## [0.4.0] — 2026-04-18

CET‑aware classification. `shrike` now tells you which gadgets
would be neutralised by Intel Control‑flow Enforcement Technology.

### Added
- **ENDBR64 / ENDBR32 recognition** in the mnemonic printer.
  Instead of `db 0xf3, 0x0f, 0x1e, 0xfa` the output reads
  `endbr64` — the prologue every IBT‑enabled function starts with.
- **`cet_shstk_blocked(g)`** / **`cet_starts_endbr(g)`** helpers
  (new `src/cet.c`, `include/cet.h`). Pure byte inspection.
    * SHSTK‑blocked: terminator is RET / RETF family. The shadow
      stack neutralises such chains.
    * starts_endbr: first four bytes are `F3 0F 1E FA` (or `...FB`).
      Under IBT, only ENDBR‑starting gadgets are reachable by
      indirect CALL / JMP.
- **`--shstk-survivable`** — keep only non‑RET‑terminated gadgets.
- **`--endbr`** — keep only gadgets starting at an ENDBR.
- **`--cet-tag`** — text mode inline tags: `[SHSTK-BLOCKED]` / `[ENDBR]`.
- **JSON output** gains unconditional `shstk_blocked` and
  `starts_endbr` boolean fields.
- **Summary line on stderr** now prints classification counters:
  `shrike: 1284 emitted  (SHSTK-blocked: 1241, ENDBR-start: 18)`.
- **`tests/test_cet.c`** covers both helpers with truthy / falsy
  inputs and edge cases (empty gadget, truncated ENDBR prefix).

### Typical workflows
```bash
# Gadgets that could still be useful under full CET
shrike --shstk-survivable --endbr dist/my-service

# Text dump with CET annotations
shrike --cet-tag /bin/bash | less

# Count SHSTK‑survivable gadgets via jq
shrike --json /bin/ls | jq 'select(.shstk_blocked == false)' | wc -l
```

## [0.3.0] — 2026-04-18

Machine-readable output and proper regex filtering — makes shrike
a first-class participant in tool pipelines.

### Added
- **`--json`** — one JSON object per gadget (JSON-Lines), shape:
  ```
  {"addr":"0x...","insns":["mov rax, rdi","ret"],"bytes":"48 89 f8 c3","insn_count":2}
  ```
  Suitable for `jq`, ingestion into SIEM tools, or diffing across
  builds. When `--json` is set, the human-readable `#` comment
  header is suppressed so the output is pure JSON-Lines.

- **`--regex PATTERN`** — POSIX extended regex match against the
  mnemonic line, via `<regex.h>`. Composes with `--filter`
  (substring) — both must match if both are supplied. Invalid
  regex exits with code 2 and a `regerror` message.

### Changed
- `format.c` gained `format_gadget_json()` and
  `format_gadget_json_render()`. Internal JSON escaper handles the
  full set of characters required by RFC 8259.
- Canonical filter key remains the *text* rendering of the gadget,
  so `--filter`/`--regex`/`--unique` behave identically in text
  and JSON modes.

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
