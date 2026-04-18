# Migrating from shrike 2.x to 3.0

shrike 3.0 is a much smaller migration than 1→2. The C API
from 2.0 (`<shrike/shrike.h>`) remains the 3.x contract; no
function renames, no struct-layout churn, no soname bump in
spirit — 3.0 just formalises what Stage VII and Stage VIII of
the V3 roadmap already added and bumps the major version to
track the soname.

If you consume shrike as a CLI (`shrike foo.so`), as JSON-Lines,
as SARIF, or via the `shrike-py` Python package: **no migration
is needed**. The CLI flag set from 2.x is preserved.

If you link against `libshrike.so.2`: relink against
`libshrike.so.3` (pkg-config handles this for you) and read
the one-liner under "Stable C API" below. That's it.

---

## 1. What actually changed

- **soname bump** `libshrike.so.2 → libshrike.so.3`. This
  matches the `SOMAJOR = SHRIKE_VERSION_MAJOR` convention
  established at v1.1.3. Downstream binaries built against
  `libshrike.so.2` keep working as long as `libshrike.so.2`
  is still installed — soname bumps don't remove older
  libraries, they add a newer one.

- **New CLI flags stabilised**:
  - `--mach-o-arch` (added 1.3.1) — no change, just confirmed
    in the frozen flag list.
  - `--reached-file` (added 2.3.0) — no change.
  - `--smt` (added 2.6.0) — no change.

- **New CLI flags still informal in 3.0**:
  - `--jop-only` / `--cop-only` (Stage VII filter helpers) —
    defined but not yet frozen. May change in v3.x.

- **Public headers** (`<shrike/shrike.h>`, `<shrike/version.h>`)
  — unchanged. The new Stage VII functions
  (`gadget_is_dispatcher`, `gadget_is_dop_write`,
  `gadget_effect_compose`, `insn_effect_decode`) and the
  Stage XII SMT emitter (`shrike_smt_emit`) live in their own
  headers (`<shrike/effect.h>`, `<shrike/insn_effect.h>`,
  `<shrike/smt.h>`) and are **not** part of the frozen 3.x ABI
  yet. They stabilise in v3.1 once downstream consumers have
  given feedback on the shape.

## 2. What's deferred to v3.x

The V3_ROADMAP had 29 planned sprints. v3.0.0 ships with 7
of them as proper features and 4 more as infrastructure
(V3_ROADMAP.md itself, cross-arch CI matrix, migration guide,
deprecation markers):

**Shipped by v3.0:**

- v2.1.0 — per-instruction effect IR
- v2.1.1 — effect composer
- v2.1.2 — JOP dispatcher classifier
- v2.1.3 — COP dispatcher classifier
- v2.1.4 — DOP arbitrary-write detector
- v2.2.0 — PE Debug Directory → CET_COMPAT + PDB path
- v2.3.0 — `--reached-file` runtime-annotation filter
- v2.6.0 — SMT chain-correctness proof emitter

**Deferred to 3.x patch bumps** (tracked in V3_ROADMAP.md):

- PowerPC 64 scanner
- MIPS32 / MIPS64 scanner
- Mach-O 32-bit + arm64e PAC
- Full PDB symbol enrichment
- LBR / perf / ptrace deeper integration beyond
  `--reached-file`
- Binary Ninja / IDA / GDB plugins
- Shellcode primitive library
- Automated exploit skeleton generator
- Binary patching output
- SMT extension to stack + memory
- Coq export
- SIMD-accelerated scanner
- Parallelism
- Cross-tool benchmark against angrop / ropr / rp++
- `shrike-book` long-form guide

Each of these gets its own sprint under the 3.x line. 4.0
is when V4_ROADMAP opens — not planned yet.

## 3. Porting checklist

1. **Package maintainers** — bump your dependency from
   `libshrike.so.2 → libshrike.so.3`. pkg-config does the
   right thing if you consumed `shrike.pc` properly at 2.x.
2. **Linker callers** — `-lshrike` still works; the
   unversioned symlink points at libshrike.so.3 after install.
3. **Python users** — `pip install -U shrike-py` pulls a
   3.x wheel that points at `SHRIKE_BINARY=shrike` → 3.x
   CLI. No code change.
4. **CI** — if you pinned `libshrike.so.2`, switch to
   `libshrike.so.*` or pkg-config.

If you were using any of the Stage VII public headers
(`<shrike/effect.h>`, `<shrike/insn_effect.h>`,
`<shrike/smt.h>`), pin to the 3.0 symbol set and watch for
renames in 3.1 — those functions aren't under the 3.0 freeze
yet, deliberately, so the API has room to improve.

## 4. Summary

3.0 is a soname-bump release that promotes seven V3-roadmap
sprints to a tagged stable baseline. The hard work (stable
2.x C API, cross-arch native loaders, chain synthesis, Python
bindings) was finished at 2.0. 3.x is about depth: semantic
IR, dispatcher classifiers, runtime annotation, formal
verification. Expect 3.x patch bumps over the coming period
to fill in the deferred V3_ROADMAP items.
