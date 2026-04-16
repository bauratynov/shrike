# shrike 2.x stability contract

Starting at **2.0.0**, the following interfaces are guaranteed
not to change in a breaking way without a major version bump
to 3.0.0. 2.0 inherits everything 1.0 already froze (CLI, JSON,
SARIF, exit codes) and adds the C API on top.

## CLI surface (frozen since 1.0)

Every flag documented in `shrike --help` and `docs/shrike.1` as
of the 2.0.0 tag. Adding new flags is a minor-version change;
removing or renaming any of them is a major-version change.

The frozen flag families (unchanged from 1.x):

- **Scan configuration** — `--max-insn`, `--back`, `--no-syscall`,
  `--no-int`, `--no-ind`
- **Filtering** — `--filter`, `--regex`, `--unique`, `--canonical`,
  `--limit`, `--quiet`, `--category`, `--bad-bytes`
- **CET/BTI** — `--shstk-survivable`, `--endbr`, `--cet-tag`,
  `--cet-posture`
- **Specialised modes** — `--reg-index` + `-python` + `-json`,
  `--recipe`, `--format`, `-p`, `--sarif`, `--sarif-cap`,
  `--pivots` + `-json`, `--diff`, `--raw` + `--raw-arch`
  + `--raw-base`, `--cdx-props`, `--density`, `--wx-check`,
  `--intersect`
- **Multi-binary** — positional path list, `--src-tag`
- **Loaders (added in 1.x)** — `--mach-o-arch`
- **Meta** — `--version` / `-V`

## JSON output (frozen since 1.0)

Every top-level key emitted by `shrike --json` on a single
gadget:

```
addr, arch, insns, bytes, insn_count, shstk_blocked,
starts_endbr, category, src
```

Shape guarantees:

- `addr` is always a 0x-prefixed hex string
- `arch` is one of `x86_64`, `aarch64`, `riscv64`
- `category` is one of `other`, `ret_only`, `pop`, `mov`,
  `arith`, `stack_pivot`, `syscall`, `indirect`
- `shstk_blocked`, `starts_endbr` are booleans
- `insn_count` is an integer ≥ 1

Adding new keys is a minor-version change. Removing or renaming
any of the above is a major-version change.

## SARIF output (frozen since 1.0)

Rule IDs:

```
SHRIKE.RET_ONLY, SHRIKE.POP, SHRIKE.MOV, SHRIKE.ARITH,
SHRIKE.STACK_PIVOT, SHRIKE.SYSCALL, SHRIKE.INDIRECT, SHRIKE.OTHER
```

The SARIF schema version is pinned to **2.1.0**. Future major
versions may move to newer SARIF if the ecosystem demands.

## Exit codes (frozen since 1.0)

| code | meaning                                               |
|------|-------------------------------------------------------|
| 0    | clean run, no policy violations                       |
| 1    | runtime error, W^X violation, recipe missing gadget   |
| 2    | bad invocation / flag parsing error                   |

## C API (frozen at 2.0)

`<shrike/shrike.h>` is the 2.x ABI contract. Functions and types
declared there do not change between 2.0.0 and 3.0.0:

### Opaque handle types

```
shrike_ctx_t, shrike_iter_t, shrike_gadget_t
```

The struct layouts behind these names are **not** part of the
ABI and may evolve across 2.x patch bumps without breaking
downstream binaries.

### Lifecycle functions

```
int  shrike_open(const char *path, shrike_ctx_t **out);
int  shrike_open_mem(const uint8_t *buf, size_t size,
                     shrike_ctx_t **out);
void shrike_close(shrike_ctx_t *ctx);
```

### Options

```
int shrike_set_option_int(shrike_ctx_t *, shrike_option_t, int);
int shrike_set_option_str(shrike_ctx_t *, shrike_option_t, const char *);
```

New options may be added with new enum values; existing values
are never renumbered.

### Iteration

```
shrike_iter_t *shrike_iter_begin(shrike_ctx_t *ctx);
const shrike_gadget_t *shrike_iter_next(shrike_iter_t *it);
void shrike_iter_end(shrike_iter_t *it);
```

### Gadget accessors

All gadget fields are accessed via getters:

```
uint64_t       shrike_gadget_address(const shrike_gadget_t *g);
const uint8_t *shrike_gadget_bytes(const shrike_gadget_t *g);
size_t         shrike_gadget_size(const shrike_gadget_t *g);
const char    *shrike_gadget_disasm(const shrike_gadget_t *g);
int            shrike_gadget_instruction_count(const shrike_gadget_t *g);
shrike_category_t shrike_gadget_category(const shrike_gadget_t *g);
shrike_arch_t  shrike_gadget_arch(const shrike_gadget_t *g);
```

### Errors

```
int         shrike_errno(const shrike_ctx_t *ctx);
const char *shrike_strerror(int err);
```

### Everything else in `include/shrike/` is internal

`elf64.h`, `pe.h`, `macho.h`, `scan.h`, `regidx.h`, `recipe.h`,
`sarif.h`, `pivots.h`, `format.h`, `effect.h`, `xdec.h`,
`arm64.h`, `riscv.h`, `category.h`, `cet.h`, `strset.h` are
headers used by the library itself. They remain present so
downstream can still compile 1.x-era code against 2.x
temporarily, but each 1.x-era public function is annotated
`SHRIKE_DEPRECATED`. Expect removal in 3.0.

See [docs/migration-1-to-2.md](docs/migration-1-to-2.md) for
the porting guide.

## Shared library soname

`libshrike.so.2` ships with SONAME `libshrike.so.2`. Downstream
dynamic linkers pick up the right major at load time. Patch
bumps within 2.x ship as `libshrike.so.2.x.y` with the same
soname; minor bumps likewise.

## Python bindings

`pip install shrike-py` installs the subprocess-backed wrapper
(from 1.7.0) plus, starting 2.0.0, a ctypes fast path that
calls `libshrike.so.2` directly when it can find it. The Python
API surface is unchanged — `shrike.scan(...)`, `shrike.recipe(...)`,
`shrike.reg_index(...)`, `shrike.version(...)`, `ShrikeError`,
`DEFAULT_BINARY`. No ctypes-vs-subprocess logic leaks into
user code.

## Deprecation policy

Flags, keys, or C API functions may be marked deprecated in a
minor release. They will continue to work (possibly with a
stderr warning or compiler warning) for at least one minor
version before being a candidate for removal at the next
major.
