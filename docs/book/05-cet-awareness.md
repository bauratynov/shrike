# Chapter 5 — Mitigation-aware chain synthesis

> v5.4.0 extended the CET-IBT story to cover SHSTK (shadow
> stack) and arm64e PAC in the same resolver pass. The
> chapter focuses on IBT for continuity with earlier docs,
> but the same annotations surface for the other two
> mitigations. See the "Beyond IBT" section at the end.

New in v5.3.0. Intel CET (and its cousins ARM BTI, RISC-V
Zicfiss) aren't just detection — shrike now PREFERS gadgets
that survive the hardware check when the target image
demands it.

## The problem

Intel CET-IBT ships on most x86 CPUs since Tiger Lake (2020).
glibc enables it via `--enable-cet` in most distros from
2023 onward. When a process has IBT on:

```
indirect jump → target instruction is ENDBR64 → continue
indirect jump → target is NOT ENDBR64          → #CP (exception) → SIGSEGV
```

A ROP chain's every gadget address is an indirect branch target
from the CPU's perspective. If ANY gadget's first instruction
isn't ENDBR64, the chain terminates the process at that step.

Most ROP tools (ropr, ROPgadget, rp++) don't distinguish. They
emit "pop rdi ; ret at 0x401234" without caring whether the
byte at 0x401234 is an ENDBR. You build the chain, it crashes
at runtime, you spend a debug evening figuring out which gadget
died to IBT.

## The fix

shrike scans each gadget for the ENDBR prefix and records a
bit alongside its address. When the target image has IBT in
its .note.gnu.property (ELF) or DllCharacteristicsEx (PE),
the resolver prefers endbr-start gadgets:

```
$ shrike --recipe 'rdi=1; rsi=2; rax=59; syscall' libc.so.6

# shrike chain from recipe  (arch: x86_64)
0x00007ffff7a3b120  # pop rdi ; ret  (stack: 16 bytes) [cet: endbr-start]
0x0000000000000001  # rdi = 0x1
0x00007ffff7a3e280  # pop rsi ; ret  (stack: 16 bytes) [cet: endbr-start]
0x0000000000000002  # rsi = 0x2
0x00007ffff7a41400  # pop rax ; ret  (stack: 16 bytes) [cet: endbr-start]
0x000000000000003b  # rax = 0x3b
0x00007ffff7b02730  # syscall [cet: endbr-start]
# cet-posture: image requires IBT + SHSTK — chain survives.
```

Every gadget picked lands on an ENDBR. The chain-level summary
at the bottom confirms survivability.

## When a gadget can't be found

Not every register has an endbr-start POP gadget. If you need
a register that only has non-endbr gadgets available:

```
0x00007ffff7a3b120  # pop r15 ; ret  (stack: 16) [cet: FAIL — no endbr-start]
```

The `FAIL` annotation, and a chain-level:

```
# cet-posture: image requires IBT + SHSTK — chain NOT survivable.
```

means you need either:
- A different register (pull the value via xchg later)
- More binaries in the scan (`shrike libc.so.6 ld.so.2 ...` —
  adding modules grows the gadget pool)
- Accept the chain won't work under CET and disable IBT at the
  target level (requires an earlier exploit primitive)

## Opt-out

Sometimes you want the non-CET-aware chain — e.g. you're
building a primitive that will flip off IBT first, then run
the "real" chain. Pass `--no-cet-aware`:

```
shrike --recipe '...' --no-cet-aware libc.so.6
```

Or force CET-aware on a binary that doesn't require it
(useful for dry-run testing of CET-survivable variants):

```
shrike --recipe '...' --cet-aware libc.so.6
```

Default is auto-detect based on the binary's own flags.

## Multi-binary OR semantics

When you scan multiple binaries, the image-wide CET posture
is the **strictest** across them. If any single module has
IBT enabled, the chain must survive IBT for that module's
gadgets — and since chains can hop between modules, the
whole chain has to be IBT-survivable.

```
# libc-noproxy.so.6 has IBT, bash does not.
# The "strictest" rule: if any module wants IBT, the chain
# respects it.
shrike --recipe '...' libc-noproxy.so.6 bash
```

## What the implementation actually checks

- **x86-64**: `F3 0F 1E FA` (ENDBR64) or `F3 0F 1E FB`
  (ENDBR32). The prefix appears at the very first byte of
  the gadget.
- **aarch64**: `BTI c` (0xD503245F), `BTI j` (0xD503249F),
  `BTI jc` (0xD50324DF), or a plain `BTI` (0xD503241F).
  Aarch64 BTI differentiates by what kind of indirect
  branch is allowed to land — `c` for indirect call, `j`
  for indirect jump, `jc` for either. The POP gadget we're
  building chains out of is reached via indirect call/jmp
  depending on the composition; `jc` is safest but rare.
  shrike treats any BTI as "good enough" for v5.3.
- **RISC-V Zicfiss**: not yet implemented in real silicon
  at time of writing; the groundwork is laid (same
  `endbr_start` bit infrastructure) for when `lpad`
  instruction becomes deployed.

## Beyond IBT — SHSTK and PAC (v5.4.0)

The same resolver pass now scores every candidate against
three mitigations:

- **CET IBT**: as above. `endbr_start` gets preferred when
  image's .note.gnu.property declares IBT.
- **CET SHSTK**: prefer gadgets whose terminator doesn't
  pop from the shadow stack. The `shstk_blocked` field (v0.19)
  inverted becomes `shstk_safe`; resolver selects on it.
- **arm64e PAC**: on Mach-O binaries with cpusubtype
  `CPU_SUBTYPE_ARM64E`, gadgets whose body contains an
  AUT* instruction are `pac_hostile` — they'll fault
  without a sign oracle. Resolver avoids them.

Score weights:
  `IBT (8)  >  SHSTK (4)  >  PAC (2)`

A gadget satisfying all three scores 14; a gadget failing
IBT but passing SHSTK + PAC scores 6; the picker takes the
highest. Tiebreak goes to first observation.

Output annotations distinguish which mitigation was satisfied
or failed. Chain-level summary lists every active mitigation:

```
# mitigations: image requires IBT SHSTK — chain survives.
```

or

```
# mitigations: image requires IBT PAC — chain NOT survivable.
```

## What this doesn't protect against

- **SHSTK bypass techniques.** SHSTK can be defeated by
  abusing control-flow constructs the CPU doesn't check
  (e.g. signal handlers, sigreturn on Linux). shrike's
  `shstk_safe` flag is about the gadget itself not
  triggering SHSTK; it doesn't model bypass primitives.
- **Bypass techniques.** There's a growing literature of
  ways to turn CET-enabled binaries into ROP-exploitable
  targets anyway: retbleed (transient-execution ROP),
  Inception (training BTB), LBR-based gadget discovery.
  shrike doesn't model any of these; its job is "build
  chains that survive in-production CET."

## Why this matters for portfolio

As of 5.3.0, as far as I know, no other open-source ROP
scanner does CET-aware chain selection. ropr doesn't
classify. ROPgadget doesn't classify. rp++ reports the
prefix in output but doesn't USE it in chain building.
angrop could but doesn't ship a preference.

shrike is (by design) the first open-source scanner that
writes a CET-survivable chain without the user having to
manually filter.

Submission target: Black Hat Arsenal 2026. Pitch angle:
"You run glibc-2.39 on Ubuntu 24.04. Your old ROP chain
crashes the moment the kernel starts IBT. Here's the tool
that makes your chain survive."
