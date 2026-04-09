# shrike 1.x stability contract

Starting at **1.0.0**, the following interfaces are guaranteed not
to change in a breaking way without a major version bump to 2.0.0.

## CLI surface (frozen)

Every flag documented in `shrike --help` and `docs/shrike.1` as of
the 1.0.0 tag. Adding new flags is a minor-version change; removing
or renaming any of them is a major-version change.

The frozen flag families:

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

## JSON output (frozen)

Every top-level key emitted by `shrike --json` on a single gadget:

```
addr, arch, insns, bytes, insn_count, shstk_blocked,
starts_endbr, category, src
```

Shape guarantees:

- `addr` is always a 0x-prefixed hex string
- `arch` is one of `x86_64`, `aarch64`
- `category` is one of `other`, `ret_only`, `pop`, `mov`,
  `arith`, `stack_pivot`, `syscall`, `indirect`
- `shstk_blocked`, `starts_endbr` are booleans
- `insn_count` is an integer ≥ 1

Adding new keys is a minor-version change. Removing or renaming
any of the above is a major-version change.

## SARIF output (frozen)

Rule IDs:

```
SHRIKE.RET_ONLY, SHRIKE.POP, SHRIKE.MOV, SHRIKE.ARITH,
SHRIKE.STACK_PIVOT, SHRIKE.SYSCALL, SHRIKE.INDIRECT, SHRIKE.OTHER
```

The SARIF schema version is pinned to **2.1.0**. Future major
versions may move to newer SARIF if the ecosystem demands.

## Exit codes (frozen)

| code | meaning                                               |
|------|-------------------------------------------------------|
| 0    | clean run, no policy violations                       |
| 1    | runtime error, W^X violation, recipe missing gadget   |
| 2    | bad invocation / flag parsing error                   |

## C API (pre-1.0; currently informal)

The headers in `include/` are used by the test suite and the
plugins. They are currently stable-by-convention but are **not**
part of the 1.0 contract. A proper versioned C API is tracked
for 2.0.

## Deprecation policy

Flags or keys may be marked deprecated in a minor release. They
will continue to work (possibly with a stderr warning) for at
least two minor versions before being a candidate for removal at
the next major.
