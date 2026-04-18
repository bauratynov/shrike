# Chapter 1 — ROP in 2026: problem, tools, where shrike fits

## The problem

Return-oriented programming is the old wound that won't scar
over. It was called out in Shacham's 2007 paper — "given any
sufficiently complex program, an attacker can stitch together
the program's own epilogue fragments into arbitrary behaviour"
— and every compiler flag, every hardware mitigation
(CET / PAC / BTI / SHSTK), every sandboxing scheme since has
been a partial response. None of them eliminate gadget reuse.
They raise the cost.

In 2026 the economics are:

- **Kernel ROP is effectively dead** on up-to-date Linux with
  KPTI + CET-IBT + CONFIG_RETHUNK. You can still find gadgets
  but the landing-pad constraint turns most of them into
  unpivotable terminators.
- **Userland ROP is not dead**. glibc ships without CET on most
  distros (the compile flag exists, the packagers don't flip it).
  musl has CET_COMPAT flipped on x86_64. The mix is inconsistent.
- **Exploit kits** still include a ROP stage, typically a small
  pivot + a mprotect chain to flip W^X on a shellcode buffer.
  Modern exploits are dominated by heap-massage + JOP but the
  initial pivot remains ROP-shaped.
- **CTF traffic is the biggest honest user.** Someone ships a
  binary with RELRO but not CET, players build a chain, writeups
  document which gadget they picked and why. Tools for this
  workflow matter in aggregate more than you'd guess from the
  exploit-kit literature.

## What tools exist

| tool | language | fast | semantic depth | arch | maintained |
|------|----------|:----:|:--------------:|------|:----------:|
| ROPgadget | Python | × | poor | multi | active |
| Ropper | Python | × | moderate | multi | active |
| rp++ | C++ | ✓ | poor | x86 + PE focus | slow |
| ropr | Rust | ✓✓ | poor | Linux x86/ARM | active |
| angrop | Python | × | deep (SMT) | multi | active |
| shrike | C99 | ✓ | moderate | multi | this is me |

Two axes: raw scanning speed (how fast does it find all gadgets)
and semantic depth (how much does it understand about what each
gadget does). No tool is top in both.

ropr wins raw speed by a wide margin — SIMD-accelerated byte
scan, Rust's zero-cost abstractions, sensible design. angrop
wins semantic depth — it uses angr's full symbolic-execution
backend to solve for multi-constraint chain problems. Everyone
in between makes tradeoffs.

## Where shrike fits

shrike's thesis: **middle of the Venn diagram**.

- Faster than the Python tools because it's freestanding C.
- More semantic than ropr because it has a typed gadget-effect
  IR (`gadget_effect_t`, per-insn `insn_effect_t`) that feeds
  into a multi-pop / clobber-graph / auto-padding chain
  synthesizer and an SMT-LIB2 proof emitter.
- Slower than ropr because we spend cycles on those semantics.
- Less semantic than angrop because we stop well short of
  full symbolic execution.

Two more concrete aims:

1. **Zero runtime deps.** One static binary, no libbfd, no
   Python, no Z3 at scan time (Z3 is optional for the proof
   step). Drop on any Linux host including hardened FIPS /
   air-gapped environments. This constraint drives a lot of
   the architectural choices you'll see in later chapters.

2. **Stable contracts.** CLI flags, JSON schema, SARIF shape,
   exit codes, and the `<shrike/shrike.h>` C API are all
   frozen under [STABILITY.md](../../STABILITY.md). Downstream
   tooling can rely on the shape; we earn semver credit by
   respecting it.

## Who this book is for

- Exploit-dev and CTF folks who already know the basics and
  want to know how to use shrike specifically.
- Tool authors considering integrating shrike into their
  workflows.
- Curious engineers who saw shrike on someone's portfolio and
  wondered how it works internally.

It is NOT a general "intro to ROP" book. Read Shacham 2007,
LiveOverflow's stack-smashing series, or nightmare.josephkirwin
for that. This book assumes you know what a gadget is and why
you'd want one.

## Book structure

- Chapter 2 — Gadget taxonomy, 8 categories, canonical dedup.
- Chapter 3 — Chain composition: recipe DSL, multi-pop,
  clobber graph, auto-padding.
- Chapter 4 — Verification: SMT emitter, Z3 flow, how to read
  a proof.
- Chapter 5 — Loaders (ELF, PE, Mach-O, RV64, PPC, MIPS).
  *(stub — written when a real user asks)*
- Chapter 6 — Integration: Python, IDA, Binary Ninja, GDB.
  *(stub — same)*

Each chapter is short by design. If a section grows past
~2000 words, it becomes its own appendix.
