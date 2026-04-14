# Changelog

All notable changes to `shrike` are listed here. Project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] — 2026-04-18

**x86-64 operand decoder — first pass.** Opens Stage IV
(disassembler depth). Gadgets with memory operands now render
with full addressing-mode detail instead of falling back to
byte-dump.

### Changes
- `reg64` / `reg32` / `reg16` / `reg8_nohi` tables grown to 16
  entries each so r8..r15 get proper names.
- `pick_reg` indexes into the full 16-wide tables.
- PUSH/POP for r8..r15 now render correctly (`push r12` instead
  of `push rsp` that the index-masking used to produce under
  REX.B).
- New `render_rm_mem()` helper decodes any mod ∈ {00,01,10}
  ModR/M + optional SIB into `[base + index*scale + disp]` form.
  Handles RIP-relative (mod=0, rm=5), SIB-disp32, REX.B for
  base high bit, REX.X for index high bit. 16-bit addressing
  is out of scope (not a ROP target).
- Opcodes upgraded from reg-only to full-operand:
  - `mov reg, r/m` / `mov r/m, reg` (0x8B / 0x89)
  - `lea reg, r/m` (0x8D)
- Rest of the opcode table still uses the legacy reg-only path
  for mod=3 and byte-dump for memory forms. Those patch bumps
  land in v1.6.1 (SSE/AVX) + V3 Stage VII's semantic-depth
  expansion.

### Example
Before: `lea rsp, [rbp-0x10]` rendered as `db 0x48, 0x8d, 0x65, 0xf0`.
After: it renders as `lea rsp, [rbp-0x10]`. Stack pivot atlases
read naturally now.

Version bump 1.5.4 → 1.6.0 (minor — new output capability,
additive).

## [1.5.4] — 2026-04-18

**Automatic padding insertion (Stage III complete).** Subset-match
enabled: when a recipe asks for e.g. `{rdi, rsi, rdx}` and the
best available gadget is `pop rdi ; pop rsi ; pop rdx ; pop r15
; ret`, the resolver uses it and emits a `0xdeadbeef` padding
slot for the extra `r15`.

### Changes
- `regidx_multi_t` grows `pop_order[REGIDX_MAX_POP_ORDER]` +
  `pop_count` — the textual (= stack) order of the popped
  registers. Populated by each per-arch observer from the
  `regs[]` list they already built.
- `regidx_credit_multi` takes the ordered array alongside the
  mask. Observer collects regs[] in stack order and hands both
  over in one call.
- `resolve_text` recipe emitter: exact-match is tried first;
  if nothing matches, it falls back to subset-match via
  `regidx_find_multi(strict_cover=0)`. When a subset gadget is
  used, the emitter walks `pop_order` and emits either the
  recipe's value for that register or a `0xdeadbeef` padding
  slot labelled with the covered register's name.
- Gadget header line now distinguishes "multi-pop" (exact) from
  "subset-pop" (has padding) so chain readers can see what's
  going on at a glance.

### Stage III — complete
Four sprints (v1.5.0 gadget effect IR → v1.5.1 stack-slot
accounting → v1.5.2 multi-pop permutation → v1.5.3 clobber graph
→ v1.5.4 subset-cover padding) shipped. The chain synthesizer
now picks the smallest-footprint gadget sequence that satisfies
a recipe without clobbering already-committed registers. Stage
IV (disassembler depth) starts at v1.6.0.

Version bump 1.5.3 → 1.5.4 (additive; recipes that resolved
before still resolve the same way unless a better subset gadget
exists).

## [1.5.3] — 2026-04-18

**Clobber-aware gadget picker.** The chain resolver now tracks
a `committed_mask` through the chain and refuses multi-pop
gadgets that would stomp on a register already set by an
earlier step. Prevents silent-breakage chains where e.g.
`rax = 59` gets overwritten by a later `pop rax; pop rdi; ret`.

### Changes
- `regidx_find_multi(ri, needed, committed, strict_cover)`
  generalises the v1.5.2 exact-match lookup. Returns the
  smallest-popcount gadget that covers `needed` and shares no
  bits with `committed`. `strict_cover=1` keeps exact-match
  semantics; `=0` allows subset-cover (padding will follow in
  v1.5.4).
- `resolve_text` threads a `committed_mask` through the
  statement loop. Every SET_REG (single or multi-pop) ORs its
  target registers into the mask; multi-pop lookup consults it
  via the new API.
- Picker prefers the gadget with the smallest popcount when
  several qualify — tighter chains, fewer padding slots once
  v1.5.4 starts emitting them.

### Not yet
Subset-match + auto-padding is still v1.5.4 — `strict_cover` is
hardcoded to 1 at the call site. Recipes that need three regs
and find only a four-reg gadget still miss; that changes next
sprint.

Version bump 1.5.2 → 1.5.3 (additive; chains from v1.5.2 that
were correct remain correct).

## [1.5.2] — 2026-04-18

**Multi-pop permutation search.** The chain resolver now prefers
a single multi-pop gadget over N single-pops when it can satisfy
several recipe registers at once. Output chains are shorter,
easier to ASLR-align, and eat less stack.

### Changes
- `regidx_t` grows `multi[REGIDX_MAX_MULTI]` — every gadget with
  popcount(writes_mask) ≥ 2 (and a RET terminator) lands here
  alongside its `writes_mask`, `addr`, `stack_consumed`.
- `regidx_find_multi_exact(ri, mask)` returns the first gadget
  whose mask exactly matches `mask`. Exact match (not cover)
  keeps v1.5.2 tight — subset-match with padding is v1.5.4.
- `resolve_text` in `recipe.c`: before falling back to per-reg
  gadgets, it scans forward across a contiguous run of SET_REG
  statements, builds the `needed` mask, and queries the multi
  index. On hit, emits one gadget line + N value lines;
  otherwise falls back to the existing single-pop per register
  path.
- Recipe example: `--recipe 'rdi=*; rsi=*; rdx=*; rax=59; syscall'`
  on a binary containing `pop rdi ; pop rsi ; pop rdx ; ret`
  now emits two gadget lines (the multi-pop + the syscall)
  instead of four.

### Not yet
- No clobber-aware filtering: picked multi-pop still wins even
  if it happens to clobber an already-committed register from
  an earlier step. That's v1.5.3.
- No subset-match / auto-padding: `pop rdi ; pop rsi ; pop rdx
  ; pop r15 ; ret` won't satisfy a three-reg recipe even though
  it could. That's v1.5.4.

Version bump 1.5.1 → 1.5.2 (additive; v1.x single-pop chains
remain valid output when no multi-pop is available).

## [1.5.1] — 2026-04-18

**Stack-slot accounting in the recipe emitter.** Every gadget
stored in the register-control index now carries the
`stack_consumed` it computed via `gadget_effect_compute`. The
chain emitter uses it to insert padding slots automatically
when a multi-pop gadget consumes more than the default 16
bytes — no more silently-misaligned payloads.

### Changes
- `regidx_t` grows `uint32_t stack_consumed[REGIDX_MAX_REGS]
  [REGIDX_MAX_PER]`, a parallel array to `addrs[][]`. New
  `regidx_credit(ri, r, addr, stack)` writes both in one step.
- `observe_x86`, `observe_a64`, `observe_rv` each call
  `gadget_effect_compute` once, then credit every register they
  detect using the same stack_consumed value. This is correct
  for pure `pop ... ; ret` chains where one gadget pops several
  registers — the stack footprint is shared.
- Text-format recipe emitter now annotates each line with the
  gadget's footprint (`# pop rdi ; ret  (stack: 16 bytes)`)
  and emits `0xdeadbeef`-filled padding lines when a gadget
  consumes more than 2 slots. Comment flags the extras as
  `padding (multi-pop spillover)` so exploit-dev users reading
  the chain can spot them.

### Not yet
Multi-pop gadget *selection* is still v1.5.2 — the emitter
currently still picks the first gadget from the per-register
index. When v1.5.2 lands, the picker will scan for gadgets that
set several needed regs in one shot and report the shared
stack footprint accordingly.

Version bump 1.5.0 → 1.5.1 (additive).

## [1.5.0] — 2026-04-18

**Gadget effect IR.** First sprint of Stage III (chain
synthesis). A new typed `gadget_effect_t` record describes what
each gadget does to the machine state — a minimum viable IR that
future sprints build on (stack-slot accounting, multi-pop
permutation, clobber graph, auto-padding).

### Changes
- `include/shrike/effect.h` + `src/effect.c`:
  - `gadget_effect_t` with fields
    `writes_mask`, `reads_mask`, `stack_consumed`,
    `terminator` (enum: NONE / RET / SYSCALL / JMP_REG /
    CALL_REG / INT), `is_pivot`, `has_syscall`.
  - `gadget_effect_compute(g, &e)` — linear walkers for x86-64,
    aarch64, and RV64. Unknown shape → fills terminator with
    GADGET_TERM_NONE so consumers treat the gadget as "skip."
- Register numbering matches `regidx` — x86 0..15
  (rax..r15), aarch64 0..31 (x0..x30+sp), RV64 0..31 (abi
  aliases at canonical indices).
- Supported patterns per arch:
  - x86: pop reg / pop r8-r15 (REX.B), ret / ret imm16,
    syscall, int3, FF /2–/5 call/jmp reg.
  - aarch64: `ldp Xa, Xb, [sp], #imm` post-index epilogues,
    ret / svc / brk / br / blr terminators.
  - RV64: `ld rd, imm(sp)` / `c.ldsp rd, imm(sp)` pops, `addi
    sp, sp, imm` adjustments, ecall / ebreak / ret /
    c.jr / c.jalr terminators.
- `tests/test_effect.c` exercises each arch's happy-path
  patterns against hand-encoded byte sequences.

### What this unlocks
v1.5.1 uses `stack_consumed` to insert dummy slots between
gadgets automatically. v1.5.2 uses `writes_mask` to find
multi-pop gadgets that satisfy several recipe registers at
once. v1.5.3 uses both masks to refuse gadgets that clobber
already-committed registers.

Version bump 1.4.1 → 1.5.0 (minor — first Stage III feature,
additive API).

## [1.4.1] — 2026-04-18

**RISC-V RV64GC scanner + recipe.** Closes Stage II. All three
new architectures (PE/COFF, Mach-O, RV64) are now fully
first-class: loaded, scanned, classified, and usable from the
chain-composer DSL.

### Changes
- `elf64.c` drops the `EM_RISCV -> -4 (ENOTSUP)` short-circuit.
  RV64 ELFs load through the normal PT_LOAD path and feed into
  the scanner.
- `scan.c` grows `scan_riscv()` — variable-length (2/4 byte)
  forward-from-terminator scan, mirroring the x86 backtrack
  logic but at 2-byte stride. Emits a 1-insn gadget for every
  standalone terminator plus every valid multi-insn tail that
  lands exactly on the terminator.
- Terminator filtering honours `cfg->include_syscall` for ECALL,
  `cfg->include_int` for EBREAK, `cfg->include_ff` for the
  linked C.JALR form. JALR, C.JR, MRET, SRET always on.
- `format.c` adds `emit_one_rv()` — minimal mnemonic render
  for the terminator family (ret / jalr / ecall / ebreak /
  mret / sret / c.jr / c.jalr). Everything else falls back to
  `.word 0x...` / `.hword 0x...` — the same "honest about what
  we don't decode" approach arm64 took in v0.5.
- `format.c` / `regidx.c` / `recipe.c`: arch name "riscv64"
  surfaces in text, JSON-Lines, pwntools, and SARIF outputs.
- `regidx.c`: RV64 ABI register map (a0..a7, s0..s11 as
  canonical; x0..x31 accepted as aliases at lookup). New
  `observe_rv()` credits canonical `ld regN, imm(sp) ; ... ;
  ret` epilogue patterns — both 4-byte `ld` and compressed
  `c.ldsp` flavours. System-call detection recognises the
  standalone 4-byte ecall encoding.
- `recipe.c`: DSL accepts `ecall` / `svc` / `syscall` as
  arch-agnostic aliases for the system-call terminator.
  `a0=*; a7=59; ecall` resolves on an RV64 input.
- `main.c` drops the outdated "use --raw --raw-arch riscv"
  message; arch string handling includes `riscv64`.

Version bump 1.4.0 → 1.4.1. Closes Stage II of V2_ROADMAP. Stage
III (chain synthesis) starts at v1.5.0.

## [1.4.0] — 2026-04-18

**RISC-V RV64GC length decoder + terminator classifier.**
Sprint 9, opens Stage II's last platform. Parser-level
infrastructure for RV64 gadget scanning lands now; scanner
wiring + recipe integration is v1.4.1.

### Changes
- `include/shrike/riscv.h` + `src/riscv.c`:
  - `riscv_insn_len(bytes, remaining)` — 2-byte (compressed
    RVC) vs 4-byte (base ISA) discriminated by the low two
    bits of the first halfword. 48-bit+ forms (reserved for
    future extensions, not emitted by any real compiler today)
    are rejected with length 0.
  - `riscv_classify_terminator()` — recognises JALR, ECALL,
    EBREAK, MRET, SRET on the 32-bit side; C.JR and C.JALR on
    the 16-bit side.
  - `riscv_is_ret()` — collapses the two ret spellings
    (`jalr x0, x1, 0` and `c.jr x1`) to one bool for the
    scanner.
- `tests/test_riscv.c` hand-encodes each terminator variant
  from the ISA spec + a couple of non-terminator opcodes and
  pins both forward (classify) and reverse (is_ret) paths.

### Scope deferred to v1.4.1
The scanner dispatch, register-control index, and recipe DSL
all still special-case x86-64 + aarch64. Wiring RV64 into
those layers lands in the next patch bump, along with the
`a0..a7 + s0..s11` register map for `a0=*; a7=59; ecall`
recipes.

Version bump 1.3.1 → 1.4.0 (minor — new architecture,
additive).

## [1.3.1] — 2026-04-18

**Mach-O universal binary dispatch.** Fat/universal binaries
(`FAT_MAGIC`, produced by `lipo`) are now resolved to a
single arch slice before the thin parser runs. Closes Stage II's
Mach-O work.

### Changes
- `--mach-o-arch x86_64|arm64` CLI flag picks the slice.
  Accepted aliases: `arm64` / `aarch64`.
- If the flag is not passed on a fat input, shrike scans the
  first slice and emits one stderr warning naming the choice
  (`lipo -thin <arch>` is the deterministic alternative).
- `macho_set_preferred_arch()` is the library-side API; it
  stays sticky across loads like the existing SARIF emitter
  context handle pattern.
- `parse_fat()` walks the 20-byte `fat_arch` records, validates
  slice offset/size against the outer mapping, then recurses
  into `parse()` with `e->map`/`e->size` re-pointed at the
  slice bytes.
- All fat-header fields are read big-endian regardless of host;
  only the inner thin Mach-O is native little-endian. The
  `FAT_CIGAM` variant is refused on purpose — Apple's tools
  never emit it.
- `test_macho.c` grows a fat-image synthesizer with arm64 in
  the only slot; exercises no-hint + matching-hint + wrong-hint
  behaviour and resets module state afterward.

Version bump 1.3.0 → 1.3.1 (additive; new flag + transparent
fat handling on existing `shrike foo.dylib` invocations).

## [1.3.0] — 2026-04-18

**Native Mach-O 64 loader.** Sprint 7 — opens Stage II's third
platform slot. Shrike can now scan Darwin `.bin` / `.dylib` /
`.bundle` thin binaries for x86-64 and arm64 without the
`otool -s __TEXT __text | xxd -r` workaround.

### Changes
- `include/shrike/macho.h` + `src/macho.c` — bounded loader.
  Walks `mach_header_64` then the `ncmds` load commands. Picks
  up every `LC_SEGMENT_64` whose `initprot` includes
  `VM_PROT_EXECUTE` and feeds its file-resident bytes to the
  scanner.
- Supported filetypes: `MH_EXECUTE` / `MH_DYLIB` / `MH_BUNDLE`.
  Everything else (object files, kext, core dumps) is refused.
- CPU types `CPU_TYPE_X86_64` and `CPU_TYPE_ARM64` both route
  into the existing x86-64 / AArch64 scanners. arm64e PAC bit
  handling is deferred — shrike scans bytes, so PAC'd pointer
  instructions are decoded as the underlying opcodes.
- `elf64_t.format` grows a third value: 2 = Mach-O. PE remains
  1, ELF remains 0.
- `main.c` falls through `elf64_load -> -3 (Mach-O detected)` to
  `macho_load` transparently; `shrike /usr/lib/dyld` just works.
- `tests/test_macho.c` synthesizes a minimal Mach-O 64 image
  in memory and exercises the happy path + fat/m32/bad-magic
  fail-closed paths.

### Scope deferred to v1.3.1
Fat / universal binaries (`FAT_MAGIC` / `FAT_CIGAM`) are detected
but refused. Fat dispatch — pick the right slice or emit a
warning if `--mach-o-arch` is unspecified — is the next sprint.

Version bump 1.2.1 → 1.3.0 (minor — new loader).

## [1.2.1] — 2026-04-18

**PE hardening audit.** `--cet-posture` now works on PE inputs
by reading `OptionalHeader.DllCharacteristics`. Closes the
loop on Stage II Sprint 2.

### Changes
- `elf64_t` grows `int format` (0 = ELF64, 1 = PE/COFF) and
  `uint16_t pe_dll_chars` — the raw DllCharacteristics bitfield
  from the OptionalHeader. Populated by `pe_load`; stays zero
  for ELF inputs.
- `<shrike/pe.h>` exports the DllCharacteristics constant names
  (`DYNAMIC_BASE`, `GUARD_CF`, `NX_COMPAT`, `HIGH_ENTROPY_VA`,
  `NO_SEH`) so downstream code doesn't hex-code-compare.
- `shrike --cet-posture foo.dll` now prints
  `# cet-posture foo.dll (pe): ASLR=on CFG=on DEP=on HIGH_ENTROPY=on`
  in one line. ELF inputs keep the existing GNU_PROPERTY-walker
  output unchanged.
- `test_pe.c` exercises the new fields.

Version bump 1.2.0 → 1.2.1 (additive, no breaking change).

## [1.2.0] — 2026-04-18

**Native PE/COFF loader.** Sprint 5 — first sprint of Stage II
(native platform loaders). Shrike can now scan Windows
`.exe` / `.dll` binaries directly. The v1.x `objcopy` workaround
still works but is no longer the recommended path.

### Changes
- `include/shrike/pe.h` + `src/pe.c` — bounded PE parser. Handles
  DOS stub → NT headers → FileHeader → OptionalHeader (PE32 and
  PE32+) → section table. Every pointer advance is size-checked
  before deref.
- Executable-section gate: `IMAGE_SCN_MEM_EXECUTE` alone (not
  `CNT_CODE`, which obfuscators and thunks routinely leave off).
- PE machine codes map to ELF `EM_*` values so the scanner,
  register-control index, recipe composer, CET classifier, and
  SARIF emitter all work unchanged on PE inputs.
- `ImageBase` + `VirtualAddress` is reported as the gadget VA —
  that's what IDA / WinDbg / Binja show. `VirtualSize` is clamped
  to `SizeOfRawData` so we don't scan zero-fill tails.
- ASLR surfaced as `is_dyn` (via
  `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` in `DllCharacteristics`),
  consistent with how we report `ET_DYN` for PIE ELFs.
- `main.c` falls through from `elf64_load -> -2 (PE detected)` to
  `pe_load` transparently. No flag flip required — `shrike foo.dll`
  just works.
- `tests/test_pe.c` synthesizes a minimal PE64 image in-memory
  and exercises the happy path + truncated-buffer + bad-DOS-magic
  fail-closed paths.

### Scope deliberately deferred
- Debug Directory → CET_COMPAT bit (v1.2.1 companion patch).
- PE32 (32-bit i386) — the decoder is x86-64 only, 32-bit
  x86 support is tracked in V3_ROADMAP.
- .NET / CLI images, delay-load imports, overlays, packed
  sections — all detected but unhandled, left to later sprints.
- PDB symbol enrichment is in V3_ROADMAP Stage VIII.

Version bump 1.1.3 → 1.2.0 (minor — first new loader since 1.0).

## [1.1.3] — 2026-04-18

**Shared library.** `libshrike.so.1.1.3` ships alongside
`libshrike.a`. Downstream consumers linking via pkg-config now
get the dynamic version by default — ld.so finds it through the
canonical three-level symlink chain (`libshrike.so` →
`libshrike.so.1` → `libshrike.so.1.1.3`).

### Changes
- Makefile builds a parallel PIC object tree (`src/*.pic.o`)
  alongside the non-PIC objects, then links them into
  `libshrike.so.$(SHRIKE_VERSION)` with
  `-Wl,-soname,libshrike.so.1`. Bumping the SOMAJOR tracks
  `SHRIKE_VERSION_MAJOR`, so 2.0.0 will bump the soname and
  downstream rebuilds will be required — exactly what a major
  version break means.
- Install drops all three files into `$(LIBDIR)`:
  - `libshrike.so.1.1.3` — the actual shared object.
  - `libshrike.so.1` — soname symlink used by ld.so at runtime.
  - `libshrike.so` — unversioned symlink used by `-lshrike` at
    link time.
- `make uninstall` removes the whole set.
- The CLI binary still links statically against `libshrike.a`,
  so the "drop this on any Linux host" story survives. Only the
  library consumer story is dynamic.
- Dockerfile pins `make shrike` (not `make`), because building
  the .so with `-static` CFLAGS in the same compile fails (you
  can't statically link a shared object).
- CI install-smoke grows: verifies the three-level symlink chain,
  reads `SONAME` via `readelf -d`, then compiles and runs a
  consumer against the .so with `-Wl,-rpath` and confirms `ldd`
  shows the dynamic dependency.

### Stage I of the V2 roadmap — complete
Library shape sprints (v1.1.0 → v1.1.3) are done. Static
library, versioned headers, pkg-config, shared library. Stage II
(native platform loaders for PE, Mach-O, RISC-V) starts at
v1.2.0.

## [1.1.2] — 2026-04-18

**pkg-config + proper `make install`.** Installing shrike now
produces a real Unix library layout: binary in `$(PREFIX)/bin`,
library in `$(PREFIX)/lib`, headers in
`$(PREFIX)/include/shrike/`, and a `shrike.pc` file in
`$(PREFIX)/lib/pkgconfig/` so downstream consumers can do
`pkg-config --cflags --libs shrike` instead of hardcoding paths.

### Changes
- `packaging/shrike.pc.in` — template with `@VERSION@`, `@PREFIX@`,
  `@LIBDIR@`, `@INCLUDEDIR@` placeholders. Built into `shrike.pc`
  by the top-level Makefile.
- Makefile install layout: `PREFIX` (default `/usr/local`),
  `BINDIR`, `LIBDIR`, `INCLUDEDIR`, `PCDIR` all overridable;
  `DESTDIR` respected for staged installs. A single source of
  truth for the version string — derived from
  `<shrike/version.h>` via awk so the Makefile can't drift from
  the header.
- `make uninstall` target for symmetry.
- CI `install-smoke` job: `make install DESTDIR=staging`, verifies
  files land in the expected places, then compiles a tiny
  consumer using `$(pkg-config --cflags --libs shrike)` and runs
  it. Catches regressions in the `.pc` file and the header
  layout simultaneously.

### Not yet
Only `libshrike.a` is shipped; users get static linking only.
`libshrike.so.1` with proper `soname` lands in v1.1.3.

## [1.1.1] — 2026-04-18

**Versioned public headers.** All public headers move from
`include/*.h` into `include/shrike/*.h`, and a new
`<shrike/version.h>` carries the compile-time macros and runtime
getters expected of a real C library.

### Changes
- `include/*.h` → `include/shrike/*.h`. External code now does
  `#include <shrike/scan.h>` instead of `#include <scan.h>` (or
  the `"..."`-form it never should have been using in the first
  place).
- New `<shrike/version.h>`:
  - `SHRIKE_VERSION_MAJOR / _MINOR / _PATCH` — component macros.
  - `SHRIKE_MK_VERSION(M, m, p)` — decimal packer (safe for
    components ≤ 999; matches `liblzma`'s scheme, so bigger
    version compares as bigger integer).
  - `SHRIKE_VERSION` — packed value for the *header* being
    consumed. Compile-time compares work: `#if SHRIKE_VERSION >=
    SHRIKE_MK_VERSION(1, 2, 0)`.
  - `SHRIKE_VERSION_STRING` — "1.1.1", stringified from the
    component macros, no template/codegen step.
  - `shrike_version_string(void)` / `shrike_version_number(void)`
    — runtime getters that report the *linked library*'s version
    (so `dlopen`/shared-lib mismatches can be detected).
- CLI grows `-V` / `--version` — prints
  `shrike <SHRIKE_VERSION_STRING>`.
- `tests/test_version.c` exercises macro visibility, runtime
  getter agreement, packing monotonicity, and string-shape
  invariants.

### Not yet
`make install` still drops headers into a flat path. The next
sprint (v1.1.2) adds pkg-config + `/usr/include/shrike/` layout.

## [1.1.0] — 2026-04-18

**Static-library split.** First step on the [V2 roadmap](V2_ROADMAP.md):
`make` now builds both `libshrike.a` and the `shrike` CLI. The binary
links against the archive; tests link against it too. No behavioural
changes — this is purely a build-system refactor that sets up the
shared-library and stable-C-API work in 1.1.x.

### Changes
- Top-level `Makefile` split into `LIB_SRC` (everything except
  `main.c`) + `CLI_SRC` (just `main.c`). `libshrike.a` produced with
  `ar rcs` + `ranlib`.
- `tests/Makefile` depends on `../libshrike.a` and links each test
  binary against the archive instead of recompiling every source
  file inline. Faster incremental tests.
- ASan / UBSan CI job rebuilds the whole tree with sanitizer flags
  so the library (not just the test driver) is instrumented.
- Fuzz harness unchanged — it builds a single translation unit
  (`xdec.c`) directly to get AFL / libFuzzer instrumentation.

### Not yet
Public headers still live in `include/*.h` (not `include/shrike/*.h`).
That — plus the `shrike/version.h` macros — lands in v1.1.1.

## [1.0.0] — 2026-04-18

**First stable release.** API, JSON schema, SARIF shape, and
exit-code contract frozen under [STABILITY.md](STABILITY.md).

Every feature shipped in the 0.x line is carried forward.

### Highlights of what's stable
- x86-64 + AArch64 scanners
- 8-way category classifier
- CET / BTI via `.note.gnu.property`
- Register-control index (text / pwntools / JSON)
- `--recipe` DSL chain composer
- Stack pivot atlas · binary `--diff` · `--raw` blob mode
- Text · JSON-Lines · SARIF 2.1.0 · pwntools Python · CycloneDX
- Canonical semantic dedup
- Ghidra import script
- HTTP gateway
- Docker / deb / rpm packaging
- AFL++ + libFuzzer harness
- Signed release artefacts (minisign)

## 0.x releases

29 tagged minors from v0.10 to v0.33 built the 1.0 surface.

- 0.1-0.9 — scanner foundation, CI, diff, categories, filters,
  arch support, SVG heroes, packaging
- 0.10 — register-control index
- 0.11 — recipe DSL
- 0.12 — pwntools output
- 0.13 — SARIF output
- 0.14 — stack pivot atlas
- 0.15 — canonical semantic dedup
- 0.16 — `--wx-check`
- 0.17 — ROPecker density heatmap
- 0.18 — `--jop` shortcut
- 0.19 — `--cet-posture`
- 0.20 — `--intersect`
- 0.21 — `--raw` headerless blobs
- 0.22 / 0.23 — PE + Mach-O detection hints
- 0.24 — RISC-V detection hint
- 0.25 — Ghidra import script
- 0.26 — CycloneDX enrichment
- 0.27 — HTTP gateway
- 0.28 — packaging (Docker + deb + rpm)
- 0.29 — fuzz harness
- 0.30 — benchmarks
- 0.31 — man page + examples
- 0.32 — release channel + SECURITY.md
- 0.33 — launch kit
