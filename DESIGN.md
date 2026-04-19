# Design notes

Stuff I thought about while writing shrike, preserved so I don't
rediscover the same tradeoffs in six months. Not a roadmap — see
`V2_ROADMAP.md` / `V3_ROADMAP.md` for that.

## Why roll the ELF / PE / Mach-O parsers

Seriously considered linking libbfd at the start. Killed it in a
week:

- **GPLv3**. shrike is MIT by choice — a GPL link would poison
  downstream integration. ropr hit the same wall and rolled their
  own.
- **Size**. A minimal libbfd link adds ~400 KB to a scratch
  container image. shrike's whole job is "drop one static binary
  on a hardened host"; that ratio matters.
- **Threading**. libbfd carries thread-local state that breaks
  `fork()` in weird ways. We don't multithread yet, but the
  option is on the table for v2.7+, and I don't want a
  20-year-old library vetoing that.

So: bounded, hand-written parsers with size checks before every
deref. `src/elf64.c` is 130 lines, `src/pe.c` is 270, `src/macho.c`
is 200. Fine.

Reference I wish I'd found earlier: sean barrett's stb libraries
for the "bounded advance is a discipline, not a pattern" framing.

## Length decoder, not a disassembler

`src/xdec.c` is a **length decoder**. It tells you how big an
instruction is, which prefixes it carries, and not much else.
`src/format.c` does the mnemonic rendering on top.

Two decoders would be easier to debug — length logic is table-
driven and cheap to get right, rendering is where hairy edge cases
live. Mixing them (what ROPgadget does via distorm3) creates
coupled failures: a rendering bug corrupts the length, scanning
loses alignment, you emit garbage gadgets. Keeping them separate
means a broken renderer emits `db 0x48, 0x8b, 0x??` and the
scanner keeps working.

Downside: two tables of opcodes to keep in sync. Accepted cost.

## Why greedy recipe resolver, not an SMT solver

Early prototype used Z3 via `PyObject_Call` on a minimal symbolic
state. Cut it for three reasons:

1. **Runtime dependency.** Z3 is ~15 MB shared lib, not default
   installed on any distro I target. Shrike claims "zero deps";
   keeping Z3 breaks that.
2. **Latency.** Single-recipe solve was 200-800ms on a 400MB libc.
   Interactive ROP dev wants <50ms — I lose flow otherwise.
3. **Greedy is enough for 95% of recipes.** angrop's full-solver
   approach pays off on multi-constraint chains (e.g. ensuring
   payload fits into 128 bytes while avoiding bad-bytes across
   every address). For the common `pop rdi; pop rsi; ...; syscall`
   shape, greedy + clobber graph handles it.

Full SMT is shipped as `shrike_smt_emit` (v2.6.0) for the 5% case
where you do want machine-checkable correctness — external Z3
invocation keeps the hard dependency out of the core path.

## Canonical dedup is opt-in, not default

`--canonical` collapses `xor rax, rax` and `mov rax, 0` (both zero
rax) into one entry. Useful — but I default it off because
exploit-dev users often **want** to see every byte variant to
pick one that avoids their bad-byte set. If dedup was on by
default, `--bad-bytes 0x00` would silently starve them of
valid `mov rax, 0` gadgets because the canonical form happened
to pick the xor encoding.

Trade: more noise in the default output, fewer surprises in
downstream pipelines. I think it's right.

## Stage II: PE/Mach-O/RV64 loaders, why three at once

Original plan was PE, then much later Mach-O + RV64. I flipped it
because all three converge on the same internal shape
(`elf64_segment_t`) and once I'd done PE correctly, the shared
`segs[] + machine` interface was clear. The `elf64_t` name is now
a lie — it holds any executable format — but renaming it is a
2.0-era API break I'm not ready for. 3.x might tackle it.

Reference: LIEF's code is the best "what does each field
actually mean in practice" doc I've found. Microsoft's PE/COFF
spec misses things that LIEF handles (EX_DLLCHARACTERISTICS,
for one).

## The JOP dispatcher detector almost isn't there

Stage VII's `gadget_is_dispatcher` is deliberately tight. The
Bletsch paper describes a richer dispatcher shape with a
loop-carried memory cursor; shrike's version just checks for a
write-before-branch on the target reg. That catches the
common case.

Full detection requires modelling at least one memory effect
(the `add rdx, 8`). Doing that correctly means the insn_effect
walker grows a memory model, which is V3 Stage XII territory.
Marking the tighter shape as "dispatcher" and missing some real
ones is better than over-detecting, because downstream
chain-composers trust the flag and do dangerous things with it.

## Scope decisions that feel wrong but are right

- **No AVX-512 / VEX rendering.** The prefix byte acrobatics for
  VEX double xdec's code size. 90% of gadgets in real binaries
  are still legacy x86 + SSE. VEX lands when a real exploit-dev
  use case needs it (and they file an issue).
- **Stack pivot "atlas" is a filter, not a synthesizer.** I know
  `--pivots` users eventually want "compose a pivot chain for
  me." No plans. It's a different problem and the library of
  tricks varies per exploit. Keep the atlas honest; let humans
  compose.
- **No Python interactive REPL.** `shrike-py` subprocesses the
  CLI. It's the right architecture for 1.x. Making it a REPL
  means rebuilding the CLI in Python → maintenance nightmare.

## Things I'd do differently

1. **Rename `elf64_t` to `shrike_image_t` earlier.** The struct
   name baked into 1.0 before I added PE/Mach-O. Now the public
   header has `elf64_t` everywhere for three formats. Costs one
   `typedef` and some typo tolerance but grates.
2. **Pick `segs[]` fixed size of 64, not 32.** Modern PE DLLs
   can exceed the 32 executable-segment limit I picked. Hasn't
   bitten me yet but it will.
3. **Write the scanner before the format.** I did it
   format-first because I wanted pretty output to debug
   against. Slowed me down when the scanner logic needed
   redesign — every change cascaded through format rendering.
