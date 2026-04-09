# shrike 2.0 — 24-sprint roadmap

**From v1.0.0 (stable CLI, static binary) → v2.0.0 (stable C API +
native loaders + chain synthesis + deeper disassembler).**

v2 is allowed to break anything documented in STABILITY.md. What
we're buying: a proper shared library, three new platforms, and a
real chain-composition engine.

Sprint discipline stays the same as the 0.10 → 1.0 run:
`research agent → design → code → commit → tag → CI green → push`.

Pre-1.0 releases (v1.0 → v1.9) ship iteratively as minor bumps;
v2.0.0 is the cutover that makes the new layout canonical.

---

## Stage I — Library shape (v1.1.x, 4 sprints)

Split the single-binary layout into **`libshrike.a`** (and later
`libshrike.so`) + `shrike` CLI, plus clean public headers.

### v1.1.0 — static-library split
- **Goal:** `make` builds both `libshrike.a` and `shrike`; the
  binary links against the library; `ar rcs libshrike.a obj/...`.
- **Research Q:** What's the minimal stable C ABI surface that
  downstream tools actually need? Survey ropr/ROPgadget library APIs.

### v1.1.1 — versioned public headers
- **Goal:** move `include/*.h` → `include/shrike/*.h`; add
  `shrike/version.h` with `SHRIKE_VERSION_MAJOR/MINOR/PATCH`.
- **Research Q:** Best practice for C library header versioning
  (liblzma, libssh2, libsodium).

### v1.1.2 — pkg-config + install
- **Goal:** `shrike.pc` template; `make install` places headers in
  `/usr/include/shrike/`, library in `/usr/lib/`, binary in
  `/usr/bin/`; `DESTDIR` respected.

### v1.1.3 — shared library (libshrike.so.1)
- **Goal:** build `libshrike.so.1` alongside the `.a`; proper
  `soname`; link the CLI against the shared version; add rpath
  handling.

## Stage II — Native platform loaders (v1.2.x–v1.4.x, 6 sprints)

Replace the `--raw` workflow for PE/COFF, Mach-O and RISC-V with
first-class native loaders and scanners.

### v1.2.0 — PE/COFF loader
- **Goal:** parse DOS stub → NT headers → sections; identify
  executable sections; feed them into the existing scanner.
- **Research Q:** Minimum PE parsing depth for .text enumeration;
  ImageBase vs VA; section table layout.

### v1.2.1 — PE scanner integration
- **Goal:** `shrike foo.dll` works end-to-end; CET flag parsing
  from `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` / `_GUARD_CF`.

### v1.3.0 — Mach-O 64-bit loader
- **Goal:** parse Mach-O header + load commands; extract
  `__TEXT,__text`.
- **Research Q:** `MH_EXECUTE` vs `MH_DYLIB`; arm64e PAC
  considerations; `LC_SEGMENT_64` layout.

### v1.3.1 — Mach-O universal (fat) binaries
- **Goal:** auto-pick the right slice or emit a warning if
  `--mach-o-arch` unspecified on a fat.

### v1.4.0 — RISC-V RV64GC length decoder
- **Goal:** fixed-32-bit primary encoding + 16-bit compressed
  (RVC) extension; `jalr` + `ecall` terminator recognition.
- **Research Q:** What's the canonical gadget shape on RISC-V
  (epilogue patterns in GCC / LLVM output)?

### v1.4.1 — RISC-V scanner + recipe
- **Goal:** wire RV64 into `scan_segment` dispatch;
  register-control index covers `a0..a7` + `s0..s11`; recipe DSL
  accepts `a0=*; a7=59; ecall`.

## Stage III — Chain synthesis (v1.5.x, 5 sprints)

The pwntools-style optimal chain composer. Replaces the greedy
per-register pass from v0.11.

### v1.5.0 — gadget semantics representation
- **Goal:** typed effect description for each gadget
  (`{writes: [rdi, rsi], reads_stack: 16 bytes, ...}`).
- **Research Q:** angrop's chain synthesis; minimum effect
  representation to drive a permutation solver.

### v1.5.1 — stack-slot accounting
- **Goal:** every gadget exposes `stack_consumed`; emitter
  inserts dummy slots between gadgets that need it.

### v1.5.2 — multi-pop permutation search
- **Goal:** picker finds `pop rdi ; pop rsi ; pop rdx ; ret`
  when recipe calls for all three and prefers it over three
  single-pop gadgets.

### v1.5.3 — clobber graph
- **Goal:** refuse to pick gadgets that clobber
  already-committed registers; backtrack to a different
  permutation.

### v1.5.4 — automatic padding insertion
- **Goal:** when a multi-pop gadget sets one needed reg and one
  ignored reg, emitter auto-fills the ignored slot with
  `0xdeadbeef` (configurable).

## Stage IV — Disassembler depth (v1.6.x, 3 sprints)

### v1.6.0 — full x86-64 operand decoder
- **Goal:** rename current "format" to "lite format"; add a
  proper decoder that renders every ModR/M + SIB + disp + imm
  combo (memory forms, RIP-relative, scaled index).

### v1.6.1 — SSE / AVX (non-VEX) coverage
- **Goal:** recognise common SSE gadgets like
  `movaps xmm0, [rsp+0x20] ; ret` inside prologue/epilogue
  chains; don't just fall back to `db`.

### v1.6.2 — aarch64 expanded coverage
- **Goal:** full ALU immediate + register forms, load/store pair,
  branch immediate; the current arm64.c is ~8 opcodes.

## Stage V — Python binding (v1.7.x, 2 sprints)

Thin ctypes wrapper that makes shrike scriptable from Python.

### v1.7.0 — ctypes shim
- **Goal:** `python -c "import shrike; shrike.scan('/bin/ls')"`
  walks the JSON-Lines output as a dict stream.

### v1.7.1 — setup.py + PyPI
- **Goal:** publishable `shrike-py` package that bundles the
  shared library (wheel-manylinux).

## Stage VI — Polish & ship (v1.8 → v2.0, 4 sprints)

### v1.8.0 — comprehensive test matrix
- **Goal:** integration tests for PE, Mach-O, RV64 against real
  distro binaries (cross-compiled from source in CI).

### v1.9.0 — migration guide
- **Goal:** `docs/migration-1-to-2.md` enumerating every breaking
  change between 1.x and 2.0.

### v1.9.1 — SemVer audit + deprecation warnings
- **Goal:** every flag that's being removed or renamed in 2.0
  emits a stderr deprecation warning when invoked in 1.9.

### v2.0.0 — release
- **Goal:** CLI freeze at 2.x; C API stability doc added to
  STABILITY.md; migration guide promoted to README.

---

## Execution protocol (same as 0.10 → 1.0)

For each sprint `N → N+1`:

1. **Research agent** investigates the Research Q for sprint N+1.
2. Findings guide sprint scope + design choices.
3. Implementation → commit → tag → CI green → push.
4. CHANGELOG entry, README + roadmap tick.

Total: **24 sprints** from v1.1.0 to v2.0.0.

Expected calendar time at one focused-day per sprint: **5-6 weeks
wall clock**. The emulator and native platform loaders are the
critical path; the library-shape and doc sprints are cheap.

---

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| PE/Mach-O loaders balloon in scope | high | ship the happy path (ELF-analogous sections only); punt PEs with overlays / encrypted sections |
| Chain solver becomes angrop-sized | medium | keep it greedy + single-permutation; document that full search is out of scope |
| Python binding drags in build-time deps | medium | ctypes-only, no Cython, no C++ |
| SemVer regrets after 2.0 | low-medium | generous deprecation window in v1.9.x; `--legacy` compatibility flag retained through 2.x |
