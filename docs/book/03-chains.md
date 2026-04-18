# Chapter 3 — Chain composition

shrike's `--recipe` flag takes a tiny DSL describing "what
registers do I need set, and what's the final terminator,"
and the resolver synthesises a gadget chain satisfying it.

## The DSL

```
recipe := statement (';' statement)*
statement := set_reg | terminator
set_reg := REG '=' VALUE
VALUE := integer_literal | '*'
terminator := 'syscall' | 'svc' | 'ecall' | 'ret'
REG := any architectural register name
```

Arch-agnostic aliases: `syscall`, `svc`, `ecall` all map to
the same RSTMT_SYSCALL op — the picker emits the right
architecturally-correct terminator based on the input binary.

Examples:

```bash
# execve("/bin/sh", NULL, NULL) on Linux x86_64
shrike --recipe 'rdi=*; rsi=0; rdx=0; rax=59; syscall' \
       libc.so.6

# same on aarch64 — different syscall number, same DSL
shrike --recipe 'rdi=*; rsi=0; rdx=0; rax=221; svc' \
       libc.so.6

# on RV64
shrike --recipe 'a0=*; a1=0; a2=0; a7=221; ecall' \
       libc.so.6
```

`*` means "attacker-controlled wildcard" — the synthesizer
emits a placeholder that you fill in at exploit time. The
pwntools emitter uses pwntools `cyclic()` for these.

## What the resolver does

Four phases (v1.5.0 → v1.5.4):

### 1. Parse & typed effects (v1.5.0)

Each statement becomes a `recipe_stmt_t`. The binary is
scanned, every gadget gets a `gadget_effect_t` summarising
writes_mask, stack_consumed, terminator. The register-
control index + multi-pop index are populated.

### 2. Stack-slot accounting (v1.5.1)

Each gadget in the index carries its `stack_consumed`. The
emitter uses this to thread padding slots between gadgets —
a `pop rdi ; pop rsi ; ret` gadget eats 24 bytes (3 slots),
so the emitter writes 24 bytes of payload after its address.

### 3. Multi-pop permutation (v1.5.2)

Before falling back to per-register single-pop gadgets, the
resolver checks: is there a multi-pop gadget that covers a
contiguous run of SET_REG statements? If so, use it. Output
gets shorter chains.

Exact match first: needed = {rdi, rsi, rdx}, gadget covers
exactly {rdi, rsi, rdx}. Then the clobber graph checks
against `committed_mask` (what's already set by earlier
steps) and filters.

### 4. Subset match + auto-padding (v1.5.4)

If no exact match, try subset cover: gadget that covers
{rdi, rsi, rdx, r15} satisfies the {rdi, rsi, rdx} recipe
if r15 wasn't requested and nothing else has committed r15
yet. The extra slot gets filled with 0xdeadbeef padding.

## Output formats

### Text (default)

```
# shrike chain from recipe  (arch: x86_64)
0x000000000040194a  # multi-pop gadget  (stack: 32 bytes)
0x0000000000000001  # rdi = 0x1
0x0000000000000002  # rsi = 0x2
0x0000000000000003  # rdx = 0x3
0x00000000deadbeef  # r15 (padding, gadget covers extra)
0x000000000040110c  # pop rax ; ret  (stack: 16 bytes)
0x000000000000003b  # rax = 0x3b
0x000000000041a1c3  # syscall
```

Each line is one payload slot. `<value>` placeholders show
where wildcards go. Comments document which register each
value sets.

### pwntools (--format pwntools)

```python
from pwn import *

rop = ROP([ELF('/lib/x86_64-linux-gnu/libc.so.6')])
rop.raw(0x000000000040194a)
rop.raw(cyclic(8))         # rdi
rop.raw(0)                  # rsi
rop.raw(0)                  # rdx
rop.raw(0xdeadbeef)         # r15 padding
rop.raw(0x000000000040110c)
rop.raw(59)                 # rax
rop.raw(0x000000000041a1c3) # syscall
```

Drop into an existing pwntools exploit. `cyclic()` for
wildcards lets you identify offsets if the chain fires at
the wrong spot.

## Why greedy, not full SMT

The picker is deliberately greedy. Full constraint-solving
(angrop) would sometimes find a shorter chain, but:

- Runtime: 50ms greedy vs 400-800ms SMT. For interactive
  ROP dev, 50ms wins by a lot.
- Zero deps: Z3 isn't on the `apt install` list for most
  distros. Greedy runs anywhere.
- The 95% case is handled. A greedy picker that's clobber-
  aware and does multi-pop subset match satisfies almost
  every real recipe.

For the 5% case where greedy misses, `--smt` emits an
SMT-LIB2 proof of the resolved chain. If `sat`, the chain
is correct; if `unsat`, the synthesizer picked wrong — a
reviewer can feed the unsat into Z3, get a model, and see
exactly which register got clobbered at which step.

See chapter 4 for the SMT side.

## Tips

- **Order matters.** `rax=59; rdi=*` and `rdi=*; rax=59`
  produce different chains. The synthesizer commits left-
  to-right. Prefer setting the scratch-free registers first
  so clobber pressure is lower for the constrained ones.
- **Wildcards are cheaper than literals.** A `*` gets a
  fresh slot; a literal needs a matching POP-able register.
  If you can, leave multi-arg slots as wildcards and fill
  them in the pwntools side.
- **Check stderr.** The synthesizer emits `# MISSING: ...`
  comments when a recipe register has no corresponding POP
  gadget. Read them.
- **Multi-binary is your friend.** `shrike libc.so.6 bash`
  merges the gadget pools. If libc has no `pop rdx` but
  bash does, the chain works.
