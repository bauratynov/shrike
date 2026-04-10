# Changelog

All notable changes to `shrike` are listed here. Project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
