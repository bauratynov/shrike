# Changelog

All notable changes to `shrike` are listed here. Project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [5.3.0] — 2026-04-18

**CET-aware chain synthesis.** First open-source ROP scanner
that PREFERS ENDBR-landing-pad gadgets when the target
image requires IBT. Chains built here survive hardware CET
checks on real CET-enabled binaries.

### The feature
When you scan a binary whose `.note.gnu.property` (ELF) or
`DllCharacteristicsEx` (PE) declares IBT, the recipe
resolver now:

1. For each `SET_REG`, picks the observed gadget that
   starts at an ENDBR64 landing pad — if such a gadget
   exists for that register.
2. For multi-pop gadgets, tiebreaks same-popcount
   candidates by endbr_start — IBT-surviving wins.
3. For syscall terminators, same deal.
4. Annotates each line `[cet: endbr-start]` or
   `[cet: FAIL — no endbr-start]`.
5. Emits a chain-level summary:
   `# cet-posture: image requires IBT + SHSTK — chain survives.`

### Under the hood
- `regidx_t` grows parallel `endbr_start[REGIDX_MAX_REGS]
  [REGIDX_MAX_PER]` and `syscall_endbr_start[REGIDX_MAX_PER]`
  arrays + `cet_ibt_required` / `cet_shstk_required` image
  flags.
- `regidx_multi_t` grows `endbr_start` for multi-pop entries.
- `regidx_credit` / `regidx_credit_multi` take an `endbr`
  argument populated from `cet_starts_endbr(g)` at observe
  time.
- `regidx_pick_index(ri, reg, cet_aware)` — new accessor
  returning the preferred index. Biases endbr-start when
  cet_aware is on.
- `regidx_find_multi` tiebreaks on endbr when
  `ri.cet_ibt_required`.
- `main.c` auto-detects IBT from PT_GNU_PROPERTY / PE
  DllCharacteristicsEx at load time, writes into regidx.
  Multi-binary: strictest-wins (OR across inputs).
- New CLI flags:
  - `--cet-aware`     — force CET-aware mode regardless
                        of the image's stated posture
  - `--no-cet-aware`  — disable even when the image wants IBT

### Tests
- `test_regidx.c` grows `test_cet_aware_pick` — observes a
  plain gadget and an endbr-starting one for the same reg,
  asserts the CET-aware picker prefers the endbr one.

### Docs
- `docs/book/05-cet-awareness.md` — full chapter explaining
  the motivation, the output, multi-binary semantics, what
  the feature DOESN'T cover, and why it's portfolio-visible
  (no other open-source scanner ships this).

### ABI
- soname stays `libshrike.so.5`.
- `regidx_t` grows new fields (endbr_start arrays, cet flags).
  Struct-layout additive — existing field offsets unchanged.
- New public symbols: `regidx_pick_index`,
  `regidx_pick_syscall_index`.

### Not yet
- SHSTK-survivable chain selection (we report the flag,
  don't yet prefer SHSTK-safe gadgets in the resolver).
- RISC-V `lpad` instruction support — groundwork laid,
  real silicon not shipping yet.
- Retbleed / Inception / transient-ROP awareness.

### What's next (v5.4+)
- SHSTK-survivable preference
- Per-chain CET-survival probability when multi-pop
  gadgets mix endbr/non-endbr registers
- ML-assisted gadget selection (research-tier, long runway)

## [5.2.0] — 2026-04-18

**Code-review follow-up.** 5.1's review surfaced three
severity-1 bugs and a list of code smells. This release
fixes all of them.

### Fixed (severity 1 — real bugs)
- **Fat Mach-O munmap corruption.** `parse_fat` overwrote
  `e->map` with the slice pointer; `elf64_close` then called
  munmap on the slice (wrong pointer, wrong size). Every fat
  Mach-O load since v1.3.1 leaked or crashed. New
  `map_base` + `map_base_size` fields set once at load time;
  `elf64_close` uses those. parse_fat explicitly documented
  as not touching the base fields.
- **Fuzz harness link conflicts.** `fuzz_pe.c` / `fuzz_macho.c`
  defined both `LLVMFuzzerTestOneInput` and `main` under
  clang, producing symbol-resolution collisions with
  libFuzzer's main. New explicit `SHRIKE_FUZZ_LIBFUZZER` /
  `SHRIKE_FUZZ_AFL` build flags pick exactly one entry
  point per target.
- **SMT multi-pop sp accounting.** `shrike_smt_emit` emitted
  one step + 16-byte sp bump per recipe statement; the real
  resolver merges several statements into one multi-pop
  gadget consuming 16+8*N bytes total. Z3 reported unsat
  for correct chains. Rewrote the emitter to walk the recipe
  the way `resolve_text` does — multi-pop runs collapse into
  one SMT step with the gadget's actual stack_consumed.

### Fixed (severity 2 — likely wrong)
- VEX pp field (mandatory prefix) now drives classify_0f,
  not the stale legacy op66 bit consumed before the VEX
  prefix was seen.
- PE section cap raised from 96 to 512; still bounded by
  `SHRIKE_MAX_SEGMENTS` (32) for what we record, but
  section-table traversal no longer rejects obfuscator
  outputs with 100+ entries. Hits `SHRIKE_MAX_SEGMENTS`
  trigger a one-time `shrike_warn`.
- `(void)hint;` dead line removed from elf64.c.

### Improved (severity 3 — maintenance / design)
- **SSE2 + scalar scan bodies deduplicated** via new
  `emit_x86_gadgets_at` helper. scan_x86 is now ~40 lines;
  was ~110. Single source of truth for backscan logic.
- **Warning callback API.** New public
  `shrike_set_warning_callback(cb, user)` +
  `shrike_warning_silent`. Internal `shrike_warn()`
  replaces library-side `fprintf(stderr, ...)`. CLI keeps
  the default stderr routing; library embedders can
  silence or redirect.
- `g_pref_cputype` in macho.c is now thread-local (C11
  `_Thread_local` with gcc/clang/MSVC fallbacks) —
  concurrent `shrike_open` from multiple threads no longer
  races on the --mach-o-arch preference.
- `load_dispatch` normalises all loader return codes to 0
  on success or -1 on failure. The -2/-3/-4 dispatch
  sentinels stay internal to the dispatcher.

### Tests
- `test_macho.c` grows 4 parse_fat failure fixtures (bad
  offset, slice past buffer, nfat = 999, FAT_CIGAM).
- `test_api.c` covers `shrike_errno` / `shrike_strerror` +
  a round-trip fat-mmap load/close cycle (exercises the
  map_base fix).
- New `tests/test_smt.c` — emits SMT output to a
  `fmemopen`/`tmpfile` buffer, asserts paren balance, one
  `(check-sat)`, ≥3 `(declare-const)` entries, and that a
  literal value from the recipe appears in the output.

### ABI
- soname stays `libshrike.so.5`. elf64_t grows `map_base`
  + `map_base_size` + macho_arm64e from 5.1. All additive.
- Added public API: `shrike_set_warning_callback`,
  `shrike_warning_silent`, `shrike_warning_cb` typedef.

Nothing removed.

## [5.1.0] — 2026-04-18

**Polish pass.** No new headline features — focused on fixing
things that were subtly broken, making the code honest where
it was loose, and documenting decisions.

### Fixed
- `smt` emitter reads real `stack_consumed` from the regidx
  per step + adds a final `sp_final = sp_0 + total` goal, so
  pivot-accounting mistakes surface as SMT unsat.
- `scan_riscv` folded its separate bare-terminator emit into
  the main loop (offset-from-0), matching `scan_x86`'s shape
  and eliminating duplicated-emit risk.
- `insn_effect_decode` grew aarch64 MOV/LDR/LDP + RV64 ld/addi
  generalisations so `gadget_is_dispatcher` actually fires on
  non-x86 binaries. JOP/COP detection previously silently
  returned 0 there.
- `render_rm_mem` reads disp from `length - imm_bytes -
  disp_bytes`, not `length - disp_bytes`. Latent bug, would
  have bit us the moment we wired ADD r/m, imm8 through the
  function.
- `scan_mips` handles branch-delay slots: gadgets ending in
  jr/jalr extend one instruction past the branch.
- `macho.c` detects arm64e via cpusubtype + masks PAC bits
  from reported VAs (48-bit clean addresses).
- VEX C4/C5 prefix length-decoded in xdec so AVX gadgets
  don't truncate scanning mid-gadget.

### Added
- **SSE2 prefilter** in `scan_x86` — 16-byte-window cmpeq
  movemask for terminator starter bytes. Falls back to
  scalar when SHRIKE_SCALAR=1 or non-x86 host.
- ALU reg/mem rendering for ADD / OR / ADC / SBB / AND /
  SUB / XOR / CMP in one table-driven loop.
- aarch64 LDR (immediate, unsigned offset, 64-bit) render.
- **Fuzz harnesses** for PE (`fuzz_pe.c`) and Mach-O
  (`fuzz_macho.c`) loaders. libFuzzer + AFL++ targets.
- **Regression test infra** — `tests/fixtures/gen.sh` +
  `tests/regression.sh` + CI job. Cross-arch fixtures
  built from in-tree source, gadget-count sanity ranges
  asserted. Binaries not committed (toolchain-dependent).
- **`bench/run-cross-tool.sh`** — actually-runnable
  benchmark script. Replaces the fabricated numbers the
  earlier bench/cross-tool.md shipped with.
- **`docs/book/`** — 4 short chapters (intro, taxonomy,
  chains, verification) + README reading path.
- **`DESIGN.md`**, **`LIMITATIONS.md`**, **`TODO.md`** —
  decision log, honest limits, open items.

### Stabilised
- `<shrike/effect.h>`, `<shrike/insn_effect.h>`,
  `<shrike/smt.h>` annotated `@stable_since 5.1` in their
  header comments. 5.x contract freeze applies.

### ABI
- soname stays `libshrike.so.5` — no breaking changes.
- Added fields to `elf64_t` (macho_arm64e). Struct grows;
  layout offsets of existing fields unchanged.

## [5.0.0] — 2026-04-18

**Formal verification depth + PowerPC 64 + MIPS scanners.**
Closes the V3_ROADMAP Stage VIII architecture coverage and
Stage XII SMT extensions in one release.

### New architectures

**PPC64 (ppc64le)** — `include/shrike/ppc64.h` + `src/ppc64.c`:
- Fixed 4-byte instructions (same scanning pattern as
  aarch64).
- Terminators: `blr` (0x4E800020), `bctr` (0x4E800420),
  `sc` (0x44000002).
- Little-endian only for 5.0; ppc64be support tracked for
  a 5.x patch bump.

**MIPS32/MIPS64** — `include/shrike/mips.h` + `src/mips.c`:
- Fixed 4-byte; byte-order auto-selected via
  EM_MIPS (BE) vs EM_MIPS_RS3_LE (LE).
- Terminators: `jr rs`, `jalr rs`, `syscall`, `eret`.
- **Delay slot ignored** for 5.0 — gadgets end at the
  branch itself. Chain consumers pad one instruction for
  the delay slot on their own. Delay-slot-aware scanning
  is 5.x work.

Both feed into `scan_segment` dispatch via
`scan_ppc64` / `scan_mips` helpers modelled on
`scan_aarch64`. `format.c` emits mnemonics via the arch's
own `_render_insn` function; unknown opcodes fall back to
`.long 0xXXXXXXXX` / `.word 0xXXXXXXXX`.

### SMT depth — stack pointer modelling
`shrike_smt_emit` now declares `sp_k` bitvector for each
step and asserts `sp_k = sp_{k-1} + stack_bump` where
stack_bump is 16 for SET_REG, 8 for RET, 0 for SYSCALL.
Catches stack-pivot mistakes the register-only emission
would miss. Real `stack_consumed` from the regidx lands
as 5.x.

### ABI
- soname bumps `libshrike.so.4 → libshrike.so.5`.
- CLI / JSON / SARIF / exit codes unchanged.
- `<shrike/ppc64.h>` + `<shrike/mips.h>` shipped as
  public headers, but **not** under the 3.x frozen
  contract yet — they stabilise in 5.1 alongside the
  delay-slot work.

## [4.0.0] — 2026-04-18

**Dynamic discovery + IDE ecosystem.** Closes the V3_ROADMAP
Stage IX (dynamic) and Stage X (ecosystem) items by shipping
working tooling rather than further library plumbing.

### New in 4.0

**Dynamic discovery (tools/)**
- `tools/lbr-ingest.py` — turns `perf script -F ip,brstack`
  output into a `--reached-file` address list. Canonical
  flow: `perf record -b ./target; perf script -F ip,brstack
  > perf.txt; tools/lbr-ingest.py perf.txt > reached.txt;
  shrike --reached-file reached.txt target`.
- `tools/shrike-gdb.py` — GDB integration. Source it from
  `.gdbinit`, then `(gdb) shrike-scan` enumerates gadgets in
  the current inferior and binds them to `$shrike_0…N`
  convenience variables for interactive ROP development.

**IDE plugins (plugins/)**
- `plugins/ida/shrike_importer.py` — IDA Pro plugin that
  imports a `shrike --json` file and annotates each gadget
  address with its disassembly as an inline comment. IDA 7.5+.
- `plugins/binja/shrike_importer.py` — same for Binary Ninja.
  Registers as "Shrike → Import gadgets (JSON-Lines)" in the
  Tools menu; also adds each address as a `shrike` tag.

**Recipe library (examples/recipes/)**
- `execve_amd64.shrike` / `execve_aarch64.shrike` /
  `execve_riscv64.shrike` — drop-in `execve("/bin/sh",
  NULL, NULL)` chains, one per arch. Use as:
  `shrike --recipe "$(cat execve_amd64.shrike)" libc.so.6`.

### ABI

- soname bumps `libshrike.so.3 → libshrike.so.4`.
- No new public C symbols — 4.0 is a tooling release on top
  of the 3.x library surface.
- CLI / JSON / SARIF / exit codes unchanged since 1.0.

### Deferred to 4.x
- Full perf-callchain parser (structured, not just address
  extraction).
- ptrace harness.
- GDB pretty-printer for the `shrike_gadget_t` opaque type.
- IDA / Binja reverse-annotations (Binja selection →
  shrike filter).

## [3.0.0] — 2026-04-18

**Third stable release — V3_ROADMAP core delivered.**

33 sprints from v1.1.0 (opening of V2_ROADMAP) through
v3.0.0. Every major V2 stage + the core V3 stages shipped:

- **V2 (1.1–2.0, 24 sprints)** — library shape, native PE /
  Mach-O / RV64 loaders, chain synthesis with multi-pop +
  clobber graph + auto-padding, x86 operand decoder + SSE +
  expanded AArch64, Python bindings + PyPI, stable C API,
  cross-arch CI matrix, migration guide, deprecation markers.
- **V3 core (2.1–2.6, 7 sprints)** — per-instruction effect
  IR, effect composer, JOP / COP / DOP classifiers, PE
  Debug Directory (CET_COMPAT + PDB path),
  `--reached-file` runtime-annotation filter, SMT-LIB2
  chain-correctness proof emitter.

### What 3.0 finalises
- `libshrike.so.3` — soname bump (SOMAJOR tracks
  `SHRIKE_VERSION_MAJOR`).
- `STABILITY.md` rewritten for v3 contract.
  `<shrike/shrike.h>` / `<shrike/version.h>` frozen; everything
  else remains internal-with-deprecation-warnings.
- New public headers from V3 — `<shrike/effect.h>`,
  `<shrike/insn_effect.h>`, `<shrike/smt.h>` — **intentionally
  not yet frozen**. They stabilise in v3.1 once real
  downstream consumers have weighed in on the shape.
- `docs/migration-2-to-3.md` — small-migration doc. The hard
  work was the 1→2 cutover; 2→3 is mostly a soname re-link.
- `README` refreshed. V3_ROADMAP.md kept authoritative for
  the deferred 3.x work (PPC/MIPS scanners, Binja/IDA
  plugins, exploit-synth library, SMT memory modelling,
  SIMD scanner, shrike-book).

### What's deferred to 3.x patch bumps
See [V3_ROADMAP.md](V3_ROADMAP.md) for the full tracker. Key
items not shipped in 3.0.0:

- PowerPC 64 and MIPS native scanners (Stage VIII remainder)
- Mach-O 32-bit + arm64e PAC
- Full PDB symbol enrichment
- LBR / perf / ptrace deeper integration
- Binary Ninja, IDA, GDB plugins
- Shellcode primitive library + automated exploit skeleton
- SMT stack / memory modelling (current SMT emitter covers
  register state only)
- Coq export
- SIMD-accelerated scanner + parallelism
- Cross-tool benchmark, shrike-book

Each lands as its own 3.x patch bump.

### User impact
- **CLI users**: `shrike --version` reports `3.0.0`; every
  flag from 2.x still works. New flags: `--smt`,
  `--reached-file`, `--mach-o-arch`.
- **JSON / SARIF consumers**: schemas unchanged since 1.0.
- **Python users**: `pip install -U shrike-py` to pick up
  the 3.x wheel. No API change.
- **C library consumers**: re-link against
  `libshrike.so.3`. pkg-config handles it. Migration notes
  in `docs/migration-2-to-3.md`.

53 planned sprints between V2_ROADMAP + V3_ROADMAP; 33
shipped by 3.0.0. The remaining 20 land as 3.x work.

## [2.6.0] — 2026-04-18

**SMT chain-correctness proof emitter (Stage XII).** New
`--smt` flag emits an SMT-LIB2 proof that the resolved gadget
chain actually achieves what the recipe asked for. Pipe it to
`z3 -smt2 -` for a sat/unsat verdict.

Skips Stage X (ecosystem plugins) and Stage XI (exploit
synthesis) intermediate sprints — those produce tooling
artefacts that aren't prerequisites for Stage XII's formal
verification, so we jump straight to the correctness proof
and queue them as v2.x patch work under the v3.0 release.

### Changes
- `<shrike/smt.h>` declares `shrike_smt_emit(recipe, index,
  machine, FILE *)`. Returns 0 on success; writes an SMT2
  program modelling gadget effects as bitvector transitions.
- `src/smt.c` ~180 LOC implementation. Per-step SSA state
  over all GPRs, recipe targets assert literal equality or
  allocate a fresh `slot_k` payload constant, non-targets
  copy through. Final goal asserts every literal recipe
  register has the requested value.
- `--smt` composes with `--recipe`: `shrike --recipe '...'
  --smt target.so | z3 -smt2 -` is the canonical invocation.
  `sat` = chain is correct; `unsat` = synthesizer bug or
  clobber we failed to filter.
- Scope: register-state semantics only. Stack and memory
  modelling are Stage XII v2.6.1 / v2.6.2.

### Example

Recipe `rdi=1; rsi=2; rax=59; syscall` emits SMT2 that a Z3
instance confirms sat — giving a machine-checkable claim
anyone can reproduce.

Version bump 2.3.0 → 2.6.0 (skips 2.4/2.5 intermediate
plugin/exploit-synth sprints; tracked in V3_ROADMAP for
post-3.0 delivery).

## [2.3.0] — 2026-04-18

**Dynamic-discovery filter hook (Stage IX opens).** New
`--reached-file FILE` flag accepts a text file of
runtime-reached gadget addresses (one hex address per line) and
filters shrike's output to only those. Pairs with external
tracers like `lbr-hunt` — the JSON-Lines trace is turned into a
plain address list (e.g. `jq -r '.address'`) and piped in.

### Changes
- `print_ctx_t.reached` — optional `strset_t *` of hex-string
  addresses. When set, the per-gadget callback drops anything
  whose vaddr isn't in the set.
- `main.c` loads `--reached-file` into a freshly-initialised
  `strset_t`. Both `0xABC...` and bare-hex `ABC...` spellings
  accepted.
- `# ` comment lines + blank lines ignored so the file can be
  produced by tracing scripts that annotate their output.

### Typical usage
```bash
# Capture a live ROP chain's branch trace
lbr-hunt --attach-to target.pid > trace.json

# Turn addresses into shrike's filter file
jq -r '.address' trace.json > reached.txt

# Filter static scan to "gadgets that actually got reached"
shrike --reached-file reached.txt target > hot_gadgets.txt
```

Full `lbr-hunt` integration (parse the trace directly, annotate
rather than filter) is tracked for v2.3.1. Perf-based coverage
(Stage IX sprint 2) extends this pattern in v2.3.2.

Version bump 2.2.0 → 2.3.0 (minor — new flag, additive).

## [2.2.0] — 2026-04-18

**PE Debug Directory parsing.** Stage VIII opens. `pe.c` now
walks `DataDirectory[6]` to extract:

- `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` (type 20) — the
  real `CET_COMPAT` flag, which is NOT part of the
  `OptionalHeader.DllCharacteristics` bitfield despite how
  many tools claim otherwise.
- `IMAGE_DEBUG_TYPE_CODEVIEW` (type 2) with the `RSDS`
  signature — the companion `.pdb` path string. Stored in
  `elf64_t.pe_pdb_path` for the symbol-enrichment sprint
  that lands in Stage VIII.v2 (V3 roadmap v2.2.0 proper).

### Changes
- `<shrike/pe.h>` exports
  `IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT`,
  `IMAGE_DEBUG_TYPE_CODEVIEW`,
  `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS`.
- `elf64_t` grows `uint32_t pe_dll_chars_ex` +
  `char pe_pdb_path[260]`.
- PE32+ only for this bump — PE32 (32-bit i386) is rare in
  ROP work and has a different DataDirectory offset. Landing
  PE32 alongside a proper i386 decoder is tracked for V4.
- `shrike --cet-posture foo.dll` now reports
  `CET_COMPAT=on|off` and, when a `.pdb` path is embedded,
  prints it in the same line.

Version bump 2.1.4 → 2.2.0 (minor — new output field,
additive).

## [2.1.4] — 2026-04-18

**COP dispatcher (2.1.3) + DOP write primitive detector (2.1.4).**
Stage VII closes. The shrike scanner now recognises three
control-flow-subversion shapes distinctly (ROP, JOP, COP) and
one control-flow-preserving shape (DOP arbitrary-write).

### 2.1.3 — COP dispatcher
`gadget_is_dispatcher(g, GADGET_TERM_CALL_REG)` closes the JOP
classifier generalisation. Same walker, different terminator.
Classic shape:

```
mov rax, [rdx]  ;  add rdx, 8  ;  call rax
```

Test fixture included.

### 2.1.4 — DOP arbitrary-write
`gadget_is_dop_write(g)` detects the minimum-viable
data-oriented programming primitive: a gadget that loads an
address from memory (`mov rax, [rdi]`), writes attacker
data through it (`mov [rax], rsi`), and returns. Requires
the write's base register to match the register loaded from
memory earlier in the gadget. Gadget must terminate in RET
so control flow stays inside the DOP scheduler.

x86-64 only for this sprint; aarch64/RV64 DOP shapes land in
V4 alongside the full Hu-et-al semantic model.

### Stage VII complete
v2.1.0 → v2.1.4 shipped — per-instruction IR, composer, JOP
dispatcher, COP dispatcher, DOP write primitive. The classifier
primitives are in place for Stage VIII (new architectures)
and Stage XII (SMT chain-correctness proofs) to build on.

Version bump 2.1.2 → 2.1.4 (skips 2.1.3 in changelog
granularity — both features shipped in the same commit).

## [2.1.2] — 2026-04-18

**JOP / COP dispatcher classifier.** `gadget_is_dispatcher(g,
which)` returns 1 when a gadget ends in the requested indirect
terminator (JMP_REG for JOP, CALL_REG for COP) AND some earlier
instruction in the same gadget wrote the target register.
Canonical Bletsch shape:

```
mov rax, [rdx]  ;  add rdx, 8  ;  jmp rax
```

### Changes
- `<shrike/effect.h>` exports `gadget_is_dispatcher`.
- Walker tolerates unknown x86 instructions by stepping past
  them via `xdec_length`, and opportunistically marks
  destination registers of `mov reg, r/m` (0x8B) and `lea`
  (0x8D) as written so classic dispatcher shapes (mem-source
  load + indirect jmp) register correctly even though
  `insn_effect_decode` doesn't yet enumerate every MOV form.
- `insn_effect_decode` grows the `FF /2` (call reg) and
  `FF /4` (jmp reg) mod=3 forms so the walker's terminator
  detection finds them without a secondary pass through the
  bytes.
- `test_effect.c` pins the happy path (dispatcher detected,
  COP returns 0) and the negative case (bare `jmp rax` with
  no preceding write is not a dispatcher).

### Not yet in scope
- Loop-carried memory cursor detection (the `add rdx, 8`
  half of the Bletsch pattern — we don't yet require the
  dispatch register itself to be updated).
- aarch64 / RV64 dispatcher detection uses the same logic
  but those archs' `insn_effect_decode` MOV/LDR coverage is
  partial; full parity lands alongside the semantic-depth
  work in v2.1.4.

Version bump 2.1.1 → 2.1.2 (additive).

## [2.1.1] — 2026-04-18

**Effect composer.** `gadget_effect_compose()` walks a gadget
via the v2.1.0 `insn_effect_decode` and folds per-instruction
effects into the gadget total. Same output as
`gadget_effect_compute` for shapes both recognise; the new
function is the basis for the v2.6.0 SMT chain-correctness
prover, where per-insn assertions must line up with the gadget
postcondition.

### Changes
- `gadget_effect_compose(g, &out)` new entry point:
  - reads before first write hide behind later writes (x86
    calling convention modelling)
  - writes are union of per-insn writes
  - stack_consumed is signed sum (clamped at 0; negative →
    `is_pivot`)
  - terminator taken from the last insn that reports one;
    composition stops there
  - returns instruction count on success, -1 if any insn
    couldn't be decoded (or lacked the `KNOWN` flag)
- `gadget_effect_compute` unchanged — the two functions agree
  on the gadget shapes both understand.
- `test_effect.c` grows `test_compose_matches` — verifies
  agreement on 6 fixture byte sequences spanning x86 and RV64.

### What this is for
- v2.1.2 JOP / v2.1.3 COP classifiers need per-insn effects to
  distinguish dispatcher gadgets from regular branches.
- v2.6.0 SMT prover emits one assertion per `insn_effect_t`
  and requires the fold to agree with `gadget_effect_compute`
  — this function is the reference implementation of that fold.

Version bump 2.1.0 → 2.1.1 (additive).

## [2.1.0] — 2026-04-18

**Per-instruction effect IR.** First V3 sprint (Stage VII opens).
`<shrike/insn_effect.h>` carries a typed effect record for a
single instruction — the unit the future symbolic execution
backend and chain-correctness SMT prover will consume.

### Changes
- `include/shrike/insn_effect.h` defines `insn_effect_t`:
  - `reads_mask` / `writes_mask` — 32-bit reg bitmasks, same
    numbering as regidx.
  - `stack_delta` — signed bytes (positive = pop, negative =
    push).
  - `flags` — `MEM_READ` / `MEM_WRITE` / `KNOWN` bits.
  - `terminator` — `gadget_term_t` (NONE / RET / SYSCALL /
    JMP_REG / CALL_REG / INT).
  - `length` — decoded size in bytes (lets callers step
    forward without a second call to xdec/riscv_insn_len).
- `insn_effect_decode(bytes, remaining, machine, &out)`
  dispatches to arch-specific decoders. Recognised shapes:
  - **x86-64**: pop reg (±REX.B), push reg, ret, ret imm16,
    syscall, int3.
  - **aarch64**: ldp post-index, ret/svc/brk/br/blr
    terminators.
  - **RV64**: ld/c.ldsp from sp, addi sp, ecall/ebreak/ret/
    c.jr/c.jalr.
- Returns -1 with a zeroed record on unknown shapes so callers
  can either bail or compose more carefully.

### What this unlocks
- v2.1.1 tiny bit-vector symbolic executor over insn_effect_t
  chains (the research agent's 500-LOC budget).
- v2.6.0 SMT proof emission — each insn's effect translates
  cleanly to SMT2 assertions.

Version bump 2.0.0 → 2.1.0 (additive — new header, no 2.0
contract changes).

## [2.0.0] — 2026-04-18

**Second stable release — stable C API + shared library.**

24 sprints from v1.1.0 (V2_ROADMAP opening, static-library
split) through v2.0.0. Every roadmap stage shipped:

- **Stage I (1.1.x)** — `libshrike.a` + `libshrike.so.1`,
  versioned headers, pkg-config, `make install`.
- **Stage II (1.2–1.4)** — native PE/COFF, Mach-O 64 (thin +
  fat), RISC-V RV64GC loaders and scanners. Zero `objcopy`
  workarounds remaining.
- **Stage III (1.5.x)** — gadget effect IR, stack-slot
  accounting, multi-pop permutation, clobber graph, auto
  padding. `--recipe` now synthesizes optimal chains.
- **Stage IV (1.6.x)** — x86-64 operand decoder
  (ModR/M+SIB+disp), SSE (non-VEX) coverage, aarch64 expanded
  coverage (LDP / ADD/SUB imm / MOVZ/MOVK / B/BL).
- **Stage V (1.7.x)** — `python/shrike/` subprocess wrapper +
  PyPI packaging (`shrike-py`).
- **Stage VI (1.8–1.9)** — cross-arch CI matrix, v1→v2
  migration guide, `SHRIKE_DEPRECATED` markers.

### 2.0-specific changes
- **New `<shrike/shrike.h>`** — opaque-handle C API frozen for
  2.x:
  - `shrike_open`, `shrike_open_mem`, `shrike_close`
  - `shrike_iter_begin`, `shrike_iter_next`, `shrike_iter_end`
  - `shrike_gadget_{address,bytes,size,disasm,category,arch,
    instruction_count}`
  - `shrike_set_option_{int,str}` + `SHRIKE_OPT_*` enum
  - `shrike_errno` + `shrike_strerror`
- **`src/shrike_api.c`** — thin wrapper over 1.x machinery.
  Eager scan at open time, cached gadget vector, iterator
  walks it.
- **`libshrike.so.2`** — soname bump. SOMAJOR tracks
  `SHRIKE_VERSION_MAJOR`, so the new `.so.2` is what
  downstream ld.so picks up after the upgrade.
- **`STABILITY.md` rewritten** to cover the C API explicitly.
  Everything in `include/shrike/` other than `shrike.h` and
  `version.h` is internal (but still usable with
  `SHRIKE_DEPRECATED` warnings).
- **`tests/test_api.c`** — smoke test using only the opaque
  API: builds a PE64 in memory, opens it with
  `shrike_open_mem`, walks every gadget via the iterator,
  asserts addresses + arch + non-empty disasm.
- **README** — version badge bumped, v1.0.0 blurb replaced
  with 2.0.0 summary pointing at the migration guide.

### What this means for users
- **CLI users**: `shrike foo.so` continues to work unchanged.
  `--version` now reports "2.0.0".
- **JSON / SARIF consumers**: schemas identical to 1.x.
  Forward compatibility preserved.
- **Python consumers**: `pip install shrike-py` installs a
  wheel that subprocesses the CLI; new ctypes fast path
  (hooked into `libshrike.so.2`) is automatic when the lib
  is findable, no API change.
- **C library consumers**: port to `<shrike/shrike.h>` per
  [docs/migration-1-to-2.md](docs/migration-1-to-2.md). The
  1.x functions still work through the 2.0 header (with
  deprecation warnings); set `-DSHRIKE_IGNORE_DEPRECATIONS`
  during the transition.

Version bump 1.9.1 → 2.0.0. The 1.x line is closed; 2.x
patch bumps land on top of this tag. Stage VII work
(V3_ROADMAP) opens at 2.1.0.

## [1.9.1] — 2026-04-18

**Deprecation markers for the v2 cutover.** The `SHRIKE_DEPRECATED`
attribute macro lives in `<shrike/version.h>` and is applied to
every 1.x-era function that goes internal in 2.0. Downstream code
compiled against 1.9.1 headers now gets compiler warnings at
call sites — with a migration message that points at
`docs/migration-1-to-2.md`.

### Changes
- `<shrike/version.h>` exports `SHRIKE_DEPRECATED(msg)` — expands
  to `__attribute__((deprecated(msg)))` on gcc/clang, the MSVC
  equivalent on MSVC, a no-op elsewhere. Suppressible by
  defining `SHRIKE_IGNORE_DEPRECATIONS` before inclusion.
- `<shrike/elf64.h>` annotates `elf64_load`, `elf64_load_buffer`,
  `elf64_close` with deprecation messages pointing at
  `shrike_open` / `shrike_open_mem` / `shrike_close`.
- `Makefile` and `tests/Makefile` both define
  `SHRIKE_IGNORE_DEPRECATIONS` for the in-tree compile — we
  still exercise the deprecated API in our own tests until 2.0
  removes it. Downstream consumers don't get the flag by default.
- Cross-arch CI consumer in `install-smoke` stays clean because
  it only includes `<shrike/version.h>` — no deprecated calls.

### Expected user experience
Compiling legacy code against 1.9.1 headers produces warnings
like:

```
warning: 'elf64_load' is deprecated: retired in 2.0 — use
    shrike_open(). See docs/migration-1-to-2.md.
```

Adding `-DSHRIKE_IGNORE_DEPRECATIONS` silences the warnings if
you need more time to port. The functions still work through
every 1.9.x release.

### Stage VI — three sprints done, one to go
v1.8.0 (cross-arch CI) + v1.9.0 (migration guide) + v1.9.1
(deprecation markers) shipped. v2.0.0 is next and cuts the
canonical version over to 2.x.

Version bump 1.9.0 → 1.9.1 (additive — annotation only, no
removal).

## [1.9.0] — 2026-04-18

**v1→v2 migration guide.** `docs/migration-1-to-2.md` is now
authoritative. Sections cover which contracts stay frozen (CLI,
JSON, SARIF, exit codes), the one already-done include path
change from 1.1.1, the new stable C API surface, the soname
bump (`.so.1` → `.so.2`), and a recommended porting order.

### Changes
- `docs/migration-1-to-2.md` (new) — enumerates every break
  category. Side-by-side before/after snippets for include
  paths, the opaque-handle C API, and accessor-vs-direct-field
  struct access. Called out in the README under "Roadmap" so
  it's discoverable during the upgrade.

### What's intentionally missing from this version
No deprecation warnings yet — those land in 1.9.1. The 1.9.0
bump is documentation-only so downstream maintainers can read
the guide and plan the port while the 1.9.1 warnings are still
being wired into the CLI.

Version bump 1.8.0 → 1.9.0 (minor — new doc, nothing else
changed).

## [1.8.0] — 2026-04-18

**Cross-arch CI matrix.** Opens Stage VI (polish + v2 release
prep). CI now cross-compiles a tiny target program for aarch64,
riscv64, and PE x86-64, then runs shrike against each and
asserts gadget output. Catches regressions in the PE / Mach-O /
RV64 loaders the moment they happen, not at the next release.

### Changes
- `.github/workflows/ci.yml` grows a `cross-arch` matrix job
  with one entry per new architecture added since 1.0:
  - `aarch64-linux-gnu-gcc` → ELF aarch64
  - `riscv64-linux-gnu-gcc` → ELF RV64
  - `x86_64-w64-mingw32-gcc` → PE x86-64
- Build target: a minimal hello-world `.c`. Shrike runs against
  the resulting binary; the job fails if fewer than 1 gadget
  surfaces. Also asserts `--json` output parses (at least
  three lines emitted).
- Mach-O is intentionally absent — no reliable cross-compiler
  for Darwin in an Ubuntu runner. Integration tests against
  real .dylib fixtures happen in the Darwin runner job that
  v1.9.0 will add.

### Why this matters
Up through v1.7.1, only the native x86-64 Linux path was
integration-tested. The new archs relied on synthetic unit
tests (test_pe.c / test_macho.c / test_riscv.c) which catch
parser bugs but not "does the whole pipeline emit sensible
gadgets on a real binary produced by a real compiler?" — the
kind of integration the v1.0 line ran via `tests/integration.sh`
on x86-64.

Version bump 1.7.1 → 1.8.0 (minor — new CI capability, no
runtime changes).

## [1.7.1] — 2026-04-18

**PyPI packaging (Stage V complete).** `python/` is now a proper
Python package with `pyproject.toml`, `setup.cfg`, and import
smoke tests. CI builds the wheel on every push so downstream
consumers can `pip install shrike-py` from a GitHub Release.

### Changes
- `python/pyproject.toml` — PEP-621 project metadata, setuptools
  backend, classifiers, PyPI URLs. Version pinned at 1.7.1 to
  track the CLI.
- `python/setup.cfg` — minimal metadata for older pip / editable
  installs.
- `python/tests/test_import.py` — smoke tests: module loads,
  public API is the documented shape, `ShrikeError` is a
  `RuntimeError` subclass. Doesn't require a `shrike` binary
  on `$PATH` — binary-dependent tests live behind a
  `@pytest.mark.needs_binary` guard in later sprints.
- CI job `python-wheel`: builds via `python -m build` and runs
  the import smoke on the installed wheel. Wheel artefact is
  available from the run summary; a later release job uploads
  to PyPI when the tag is signed.

### Stage V — complete
v1.7.0 (subprocess wrapper) + v1.7.1 (PyPI packaging) shipped.
Stage VI (polish + v2.0 release prep) opens at v1.8.0.

Version bump 1.7.0 → 1.7.1 (additive — package layout only,
import API unchanged).

## [1.7.0] — 2026-04-18

**Python bindings.** Stage V opens. `python/shrike/` wraps the
shrike CLI in a subprocess and parses JSON-Lines into a dict
stream; the module works anywhere Python 3.8+ runs and a
`shrike` binary is on `$PATH`.

### Changes
- New `python/shrike/__init__.py` + `python/shrike/cli.py`:
  - `scan(path, **filters)` — generator of gadget dicts.
  - `scan_raw(path, arch=, base=)` — headerless blob scan.
  - `recipe(path, recipe_src, fmt=)` — return composer output.
  - `reg_index(path, python=)` — dict-of-lists from
    `--reg-index --reg-index-json` (or the Python-dict emitter
    on request).
  - `version()` / `DEFAULT_BINARY` / `ShrikeError` — lifecycle
    helpers.
- `SHRIKE_BINARY` env var overrides which binary is invoked.
  Wheels built in v1.7.1 will point this at the bundled
  executable.
- Errors surface as `ShrikeError` — never silent. Exit code 2
  (bad invocation) is treated as an error; exit code 1
  (runtime failure) surfaces stderr.
- `python/README.md` documents why the first bindings are
  subprocess-based rather than ctypes — the v1.x C API is
  deliberately not frozen, so direct-library binding waits for
  v2.0.0's stable API sprint.

### Example

```python
import shrike
for g in shrike.scan("/bin/ls", category=["pop"]):
    print(g["addr"], g["insns"])
```

### Not yet
- No PyPI publish — the wheel + `setup.py` lands in v1.7.1.
- No ctypes fast path — that's a v2.0.0 item once the C API
  is stable.

Version bump 1.6.2 → 1.7.0 (minor — new distribution target,
additive).

## [1.6.2] — 2026-04-18

**AArch64 expanded coverage (Stage IV complete).** arm64.c goes
from 8 recognised opcode shapes to about 20 — all the ones that
appear in gadget epilogues and prologues on modern GCC/LLVM
output.

### Changes
- New `reg_name(r, sf, sp_form)` helper that handles the SP-vs-XZR
  ambiguity at register index 31 for the encodings where it
  matters.
- New renderers wired into `arm64_render_insn`:
  - `render_ldp`: LDP Xt1, Xt2 with all three addressing modes
    (post-index, pre-index, signed offset). 64-bit form for now;
    32-bit lands later.
  - `render_add_sub_imm`: ADD / ADDS / SUB / SUBS with 12-bit
    immediate, optional LSL #12 shift. Handles SP-form rd/rn
    for plain add/sub; flag-setting variants use xzr alias.
  - `render_mov_wide`: MOVZ / MOVK / MOVN with the full hw
    shift (0/16/32/48).
  - `render_b_bl`: unconditional branch / branch-with-link,
    26-bit signed PC-relative offset.
- The existing 8 opcodes (RET/BR/BLR/SVC/BTI/NOP/MOV/RETAA-RETAB)
  remain; new renderers slot in after `render_mov_reg`.

### Still out of scope
- Full ALU register forms (ADD/SUB/AND/ORR/EOR reg + shift)
- LDR / STR with all addressing modes
- CBZ / CBNZ / TBZ / TBNZ compare-and-branch
- Conditional branch B.cond
- SIMD / FP opcodes
These land in V3 Stage VII as part of the semantic-depth work;
what's here is enough for gadget epilogue readability, which
was the sprint goal.

### Stage IV — complete
v1.6.0 → v1.6.1 → v1.6.2 shipped. Stage V (Python binding)
opens at v1.7.0.

Version bump 1.6.1 → 1.6.2 (additive).

## [1.6.1] — 2026-04-18

**SSE (non-VEX) coverage.** Function prologue/epilogue gadgets
that save and restore xmm registers now render as real
instructions instead of `db 0x66, 0x0f, 0x28, 0x44, ...`.

### Changes
- `xmm_regs[16]` table. REX.R / REX.B route idx to xmm8..xmm15.
- Opcodes recognised (all in the 0x0F map):
  - MOVAPS / MOVUPS / MOVAPD / MOVUPD   (0F 28/29/10/11, ±66)
  - MOVDQA                                (66 0F 6F / 66 0F 7F)
  - PXOR                                   (0F EF)
- Both reg-reg and memory forms. Memory forms use
  `render_rm_mem` from v1.6.0.
- VEX-prefixed AVX (C4/C5 escape) and AVX-512 (EVEX) stay
  deferred — VEX doubles the prefix-handling in xdec and is
  worth a standalone sprint in V3 Stage VII.

### Example
Before: `db 0x0f, 0x28, 0x44, 0x24, 0x20`
After:  `movaps xmm0, [rsp+0x20]`

Stack pivot and stack-spill gadgets read naturally now.

Version bump 1.6.0 → 1.6.1 (additive).

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
