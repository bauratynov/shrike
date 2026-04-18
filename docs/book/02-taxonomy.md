# Chapter 2 — Gadget taxonomy

shrike classifies every emitted gadget into one of eight
categories. The taxonomy is load-bearing: the chain composer
uses it to prefer certain shapes, the SARIF output uses it as
rule IDs, `--category` lets you filter.

## The eight categories

```
CAT_OTHER       = 0
CAT_RET_ONLY    = 1   ret (or retaa / retab / c.jr x1)
CAT_POP         = 2   first insn is pop reg / ldp sp / ld ... sp
CAT_MOV         = 3   first insn is mov reg, reg
CAT_ARITH       = 4   first insn is add / sub / xor reg, reg
CAT_STACK_PIVOT = 5   first insn modifies sp / rsp
CAT_SYSCALL     = 6   terminator is syscall / svc / int / ecall
CAT_INDIRECT    = 7   terminator is call reg / jmp reg / br / blr
```

Classification is first-instruction-plus-terminator. It's
deliberately syntactic — we don't symbolically execute the
gadget's middle. If the first and last instructions match a
category, gadget's category is set; otherwise it's OTHER.

## Why these eight

They cover the shapes that matter for chain construction:

- **POP**: "how do I set register R?" The register-control
  index is built from POP gadgets.
- **STACK_PIVOT**: "how do I move to an attacker-controlled
  stack?" Stage-1 exploit primitive. The pivot atlas
  (`--pivots`) shows just these.
- **SYSCALL**: "how do I invoke the kernel?" Terminal step of
  most chains.
- **INDIRECT**: JOP / COP gadgets. Indirect branches into
  attacker-controlled targets.
- **RET_ONLY**: landing pad between other gadgets, or the
  single-byte `ret` at address 0x... you need as a
  retaddr-only slot.
- **MOV**: register-to-register transfer. Useful when the
  binary has no POP for the target reg (rare but real).
- **ARITH**: `add / sub / xor` — setup for a specific immediate
  that POP can't deliver.
- **OTHER**: everything else. Structurally interesting but
  semantically the composer can't use it directly.

## Canonical dedup (--canonical)

Two gadgets can be bit-identical but render differently
because of trailing NOPs or prefix redundancy. They can also
be bit-different but semantically equivalent — `xor rax, rax`
and `mov rax, 0` both zero rax. shrike's `--canonical` mode
collapses these.

The canonicalisation rules, as of 5.1:

- **ret-family collapse.** `retf`, `retaa`, `retab`, `c.jr x1`
  all hash to the same `ret` form. Cross-architectural ret
  variants line up so the dedup works across multi-binary
  diffs.
- **xor zero-idiom.** `xor reg, reg` canonicalises to
  `mov reg, 0` in the dedup hash so the two gadgets are
  treated as one.
- **Leading prefix redundancy**: 0x66 operand-size prefix on
  byte-sized opcodes gets stripped for hash purposes.

Canonicalisation is **off by default**. Exploit-dev users
often want to see every byte variant — two gadgets that
canonicalise to the same form might differ in bad-bytes. If
you're diffing two libc versions or building a SARIF report,
turn it on.

## Inside shrike

The classifier lives in `src/category.c`. It's a ~150-line
file because the per-arch first-insn detectors are factored
separately (`is_pop_x86`, `is_pop_a64`, `is_pop_rv`, etc.).

```c
gadget_category_t gadget_categorize(const gadget_t *g);
```

Covered by the v3 stable C API via `shrike_gadget_category()`.

## Known limits

- **Category_MOV vs MOV into memory.** `mov [rax], rbx`
  doesn't count — we're tracking register control, not
  memory writes. DOP-style gadgets with memory writes are
  detected separately via `gadget_is_dop_write()`.
- **ARITH doesn't distinguish useful from useless.** `add
  rax, rcx` and `add rax, 1` both classify as ARITH. The
  composer handles the literal-vs-register distinction
  elsewhere.
- **Multi-category gadgets.** A gadget that starts with POP
  and ends in SYSCALL gets classified as SYSCALL, not POP.
  Terminator wins in the ambiguous case. This is occasionally
  surprising; use `--reg-index` to find pop-gadgets regardless
  of terminator.

## Worked example

```bash
$ shrike --json /bin/bash | jq -r '.category' | sort | uniq -c
  34281 ret_only
  12937 pop
   5423 mov
   3201 arith
   1923 indirect
    412 syscall
    187 stack_pivot
   2873 other
```

About 60% RET_ONLY is typical — most terminators in a libc
are bare returns with only a byte or two of prologue.

## Filter in practice

```bash
# only pop gadgets — for building a register-control chain
shrike --category pop /bin/bash

# only stack pivots — for stage 1
shrike --pivots /bin/bash

# everything but ret_only — where the real content is
shrike --json /bin/bash | jq 'select(.category != "ret_only")'
```
