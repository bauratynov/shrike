# Changelog

All notable changes to `shrike` are listed here. Project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
