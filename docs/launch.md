# shrike — launch kit

Copy-paste-ready material for a v1.0 announcement (HN, Reddit
`r/programming` + `r/exploitdev`, Twitter/X, LinkedIn, dev.to).

## One-liner

A freestanding C99 ROP gadget scanner for Linux ELF64 binaries —
dual-arch (x86-64 + aarch64), CET/BTI-aware, with pwntools,
SARIF, CycloneDX, and Ghidra interoperability. One static binary,
zero runtime dependencies.

## 280-character pitch

`shrike` finds ROP gadgets in Linux binaries. 6000 LOC of C99, zero
deps, dual-arch. Emits pwntools Python, SARIF for GitHub Code
Scanning, CycloneDX properties, plus a `--recipe` DSL that composes
execve chains. MIT. github.com/bauratynov/shrike

## Long description (500 words)

Twenty years after Shacham's original ROP paper, most of the gadget
tooling still lives inside Python ecosystems. That's fine on a dev
laptop and awful on a hardened production host, a distroless
Docker image, or a FIPS-reviewed build environment.

`shrike` is what happens when you bring the tool to the
environment instead. It's a single static binary. It understands
x86-64 and AArch64. It knows about CET IBT, CET SHSTK, and ARMv8.5
BTI. It emits:

- plain text, one gadget per line, like the tool you already use
- `--json` / JSON-Lines per gadget, ready for `jq`
- `--format pwntools` — a self-sufficient Python exploit skeleton
  with `cyclic()` placeholders, so you paste it into an exploit
  workbench and `cyclic_find(pc)` tells you which slot leaked
- `--sarif` that GitHub Code Scanning ingests as inline findings
- `--reg-index-python` — a pwntools-shaped dict of every register
  you can control and the addresses that do it
- `--pivots` — stack-pivot atlas sorted by delta
- `--recipe 'rdi=*; rax=59; syscall'` — a tiny DSL that composes a
  chain from the scanned binary and its shared libraries

All of that runs on headerless blobs too (PE `.text` extracted
with `objcopy`, Mach-O `__TEXT,__text` from `otool`, firmware
images) via `--raw --raw-arch ARCH --raw-base ADDR`.

What it is not: a full disassembler, a symbolic executor, or an
exploit generator. It's a scanner. It does one thing. The scope
is deliberate.

Built in 34 tagged releases (v0.1 through v1.0). Each release has
green CI on gcc + clang across Ubuntu 22.04 / 24.04 with
AddressSanitizer, UndefinedBehaviorSanitizer, cppcheck static
analysis, an AFL++ fuzz harness, and integration tests against
real distro binaries.

## Screenshots

- `docs/hero.svg` — sample gadget list with classification
  annotations.
- (TODO v1.0.1): animated GIF of the execve recipe being composed
  and the resulting exploit skeleton running against a CTF target.

## FAQ

**Why not ROPgadget / Ropper / ropr?** They're great. `shrike`
exists for the environments where their Python / Rust runtime is
either unavailable or audit-prohibited. It also ships CET/BTI
semantic classification, SARIF, and a pwntools emitter — primitives
none of them have today.

**Does it support Windows / macOS binaries?** Extract the .text
section and pass `--raw`. Native PE/Mach-O loaders are not on the
1.x roadmap.

**Is the ROP recipe a full chain builder?** No. It's a per-register
greedy resolver, deliberately. For multi-pop permutation search and
stack-slot accounting, pipe the `--reg-index-python` output into
pwntools' own solver — `shrike` lays the data, `pwntools` builds
the payload.

## Credits

Research that informed specific releases:

- v0.11 chain composer — pwntools `ROP.chain()` source
- v0.13 SARIF — OASIS SARIF 2.1.0 spec
- v0.14 pivot atlas — 0vercl0k/rp and P0's Chrome JITsploit series
- v0.15 canonical dedup — absence in Ropper / ROPgadget (none ship
  semantic dedup); design is original

## Contact

Issues: github.com/bauratynov/shrike/issues
Email: bauratynov@gmail.com
