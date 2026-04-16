# Migrating from shrike 1.x to 2.0

shrike 2.0 freezes a set of contracts that were explicitly left
open in 1.x. Most users — those consuming shrike as a CLI
(`shrike foo.so`) or reading its JSON-Lines / SARIF output —
see *no* breaking changes. The migration work is concentrated
in a single group: **downstream C/C++ code that links against
`libshrike.a` or `libshrike.so`**.

This document enumerates every break category, with concrete
before/after snippets and a recommended porting order.

---

## 1. Stable contracts — no change

The following were frozen in 1.0 by [STABILITY.md](../STABILITY.md).
They stay frozen in 2.0:

- **CLI flags.** Every `shrike --*` invocation that worked in
  1.x works in 2.x. New flags may appear (`--mach-o-arch` was
  added in 1.3.1, for example). Flags marked deprecated in
  1.9.1 continue to work through 2.x but emit a stderr warning.
- **Exit codes.** `0` ok / `1` runtime error / `2` bad
  invocation.
- **JSON-Lines schema** from `--json`. Field names, types, and
  semantics unchanged.
- **SARIF 2.1.0 shape** from `--sarif`. Unchanged.
- **pwntools Python output** from `--format pwntools`.
  Unchanged (may gain new recipe forms).

If you read shrike's output through `grep` / `jq` / SARIF
viewers / pwntools, you're done — no migration needed.

---

## 2. Include path — already done at 1.1.1

Between 1.1.0 and 1.1.1 we moved public headers from a flat
`include/` to `include/shrike/`:

**Before (shrike 1.0.0, 1.1.0):**
```c
#include <scan.h>
#include <format.h>
```

**After (shrike 1.1.1 and later, including 2.x):**
```c
#include <shrike/scan.h>
#include <shrike/format.h>
```

If you skipped 1.1.x and jumped straight from 1.0 to 2.0, this
is the one change that affects your `#include` directives.

`pkg-config --cflags shrike` produces `-I/usr/include`; the
headers live under `shrike/`, so the include directive must
name the subdirectory. Most build systems (CMake find_package,
meson dependency) handle this automatically once they consume
the pc file.

---

## 3. Stable C API — **frozen for the first time**

The 1.x line shipped `libshrike.a` (from 1.1.0) and
`libshrike.so.1` (from 1.1.3), but
[STABILITY.md](../STABILITY.md) explicitly said the library
ABI was *not* covered. In practice this meant:

- Function names could change without warning.
- Struct layouts could change without warning.
- Internal helpers were exported alongside intended public API.

**2.0 changes this.** The 2.x stable C API is a *subset* of
what 1.x exposed, wrapped in an opaque-handle design similar
to capstone:

```c
#include <shrike/shrike.h>

shrike_ctx_t *ctx;
shrike_open("/bin/ls", &ctx);

shrike_iter_t *it = shrike_iter_begin(ctx);
const shrike_gadget_t *g;
while ((g = shrike_iter_next(it))) {
    printf("0x%" PRIx64 "  %s\n",
           shrike_gadget_address(g),
           shrike_gadget_disasm(g));
}
shrike_iter_end(it);
shrike_close(ctx);
```

### Functions retired from the public surface

Everything *not* exported by `<shrike/shrike.h>` becomes
internal in 2.0 and may be removed or renamed in later 2.x
patch bumps. Specifically:

| 1.x symbol                      | 2.x disposition |
|---------------------------------|-----------------|
| `elf64_load` / `elf64_close`    | internal — `shrike_open` handles dispatch |
| `pe_load` / `macho_load`        | internal — same |
| `scan_segment`                  | internal — iterator API replaces it |
| `regidx_t` struct layout        | internal — accessors only |
| `gadget_effect_compute`         | stays public under the same name |
| `recipe_parse` / `recipe_resolve` | stays public, unchanged |

If you were calling `elf64_load` + `scan_segment` by hand,
port to the opaque-handle flow above. The behaviour is
unchanged; the surface is smaller.

### Struct layouts

`gadget_t` as it exists in `<shrike/scan.h>` today is
**opaque** in 2.0 — accessed only via `shrike_gadget_*`
getters. If you read fields directly (`g->vaddr`,
`g->bytes`, `g->length`), replace them with
`shrike_gadget_address(g)`, `shrike_gadget_bytes(g)`,
`shrike_gadget_size(g)`.

`regidx_t` likewise becomes opaque — replace direct field
access with `shrike_reg_*` functions that ship alongside the
v2.0 header.

### Version checks

Use `SHRIKE_VERSION` for compile-time guards and
`shrike_version_number()` for runtime checks:

```c
#if SHRIKE_VERSION >= SHRIKE_MK_VERSION(2, 0, 0)
    /* 2.x-only code path */
#endif

if (shrike_version_number() < SHRIKE_MK_VERSION(2, 0, 0)) {
    fprintf(stderr, "shrike library too old\n");
    exit(1);
}
```

---

## 4. Python bindings — source-compatible

`import shrike` keeps the 1.7.0/1.7.1 API:

```python
for g in shrike.scan("/bin/ls"): ...
shrike.recipe(...)
shrike.reg_index(...)
```

The subprocess-based implementation continues working against
the 2.x `shrike` binary. A new fast path that uses ctypes to
call `libshrike.so.2` directly is available starting 2.0 and
auto-selects when the shared library is findable — no API
change for callers.

---

## 5. Build system

### pkg-config name

`shrike.pc` still installs as `shrike.pc`. The `Libs:` line
now reports the installed `libshrike.so.2` instead of
`.so.1`; bump your linker invocations if you hardcoded the
soname.

### soname bump

`libshrike.so.1 → libshrike.so.2`. If you linked with
`-l:libshrike.so.1`, switch to plain `-lshrike` + pkg-config.

### Static library

`libshrike.a` is still shipped alongside the shared library
and is unaffected by the soname bump. Consumers who want
static linking continue to use `-Wl,-Bstatic -lshrike
-Wl,-Bdynamic` or equivalent.

---

## 6. Recommended porting order

1. Update `#include` directives if you skipped 1.1.1
   (`<scan.h>` → `<shrike/scan.h>`).
2. Audit for direct field access on `gadget_t` / `regidx_t` /
   `elf64_t`. Replace with 2.0 accessor functions.
3. Replace manual `elf64_load` + `scan_segment` loops with
   `shrike_open` + `shrike_iter_begin`/`_next`/`_end`.
4. Rebuild against `libshrike.so.2`. Update hardcoded sonames
   if any.
5. Add a `SHRIKE_VERSION` compile-time guard so the same
   source file can build against 1.x and 2.x during the
   transition.

Most projects should land in under 100 lines of diff. If you
discover something we missed, please file an issue — 2.0.x
patch bumps can still clarify the migration guide without
breaking the freeze.

---

## 7. Deprecation warnings in 1.9.x

shrike 1.9.x emits a stderr deprecation warning when you
invoke any CLI flag or library symbol that's being retired in
2.0. Run your test suite against 1.9.x before upgrading to
2.0 — the warnings tell you exactly where to port.
