# Chapter 4 — Verification via SMT

The chain composer is greedy. Most of the time that's fine.
For the times when you want a machine-checkable answer to "is
this chain actually correct," shrike can emit an SMT-LIB2
proof.

## The one-line summary

```bash
shrike --recipe 'rdi=1; rsi=2; rdx=3; rax=59; syscall' \
       --smt libc.so.6 | z3 -smt2 -
```

`sat` → chain is correct. `unsat` → chain is broken.

## What's in the proof

The SMT output models each recipe step as a transition on a
register state:

```smt
(declare-const r0_0 (_ BitVec 64))     ; rax initial
(declare-const r1_0 (_ BitVec 64))     ; rcx
...
(declare-const sp_0 (_ BitVec 64))     ; sp initial

; step 1: rdi = 1 (rdi = reg 7)
(declare-const r7_1 (_ BitVec 64))
(declare-const sp_1 (_ BitVec 64))
(assert (= sp_1 (bvadd sp_0 (_ bv16 64))))
(assert (= r7_1 (_ bv1 64)))
; every other reg unchanged
(assert (= r0_1 r0_0))
(assert (= r1_1 r1_0))
...

; step 2: rsi = 2 (reg 6)
; same shape
...

; goals
(assert (= r7_4 (_ bv1 64)))        ; rdi == 1
(assert (= r6_4 (_ bv2 64)))        ; rsi == 2
(assert (= r2_4 (_ bv3 64)))        ; rdx == 3
(assert (= r0_4 (_ bv59 64)))       ; rax == 59
(assert (= sp_4 (bvadd sp_0 (_ bv56 64))))

(check-sat)
```

Per-step SSA: every register gets a fresh 64-bit bitvector at
each step. Transitions assert post-state in terms of pre-state.
Final check: the goal clauses match what the recipe asked for.

## Why this catches bugs

### Clobber bug

Suppose the synthesizer picks a gadget that, as a side
effect, writes to a register we'd already committed. The
per-step "everything else copies through unchanged"
assertions contradict the "that register holds value V"
earlier goal.

```
(assert (= r0_3 r0_2))            ; step 3 said rax unchanged
(assert (= r0_2 (_ bv59 64)))     ; step 2 set rax=59
(assert (= r0_3 (_ bv0 64)))      ; but gadget actually zeroed it
```

Z3 reports `unsat`. `(get-model)` shows the contradiction.

### Stack-pivot bug

`sp_k = sp_{k-1} + stack_bump` per step; final `sp_4 =
sp_0 + 56`. If the synthesizer's stack accounting was wrong
(e.g. forgot that the multi-pop eats 24 bytes not 16), the
accumulated sum doesn't match the expected total and the
final sp assertion fails.

### What it does NOT catch

- **Memory aliasing.** Shrike's SMT models register state
  only. If your chain's gadget dereferences memory
  (e.g. DOP arbitrary-write primitives), the proof is
  silent about that.
- **Semantic side effects.** Flags register (RFLAGS / NZCV)
  effects aren't modelled. A gadget that depends on a
  specific flag state will silently fail at runtime.
- **Linker relocations.** If the gadget address is in a
  PIE binary and the base differs at runtime, the proof
  says nothing — it's about what the gadgets do, not where
  they live.
- **Syscall/ret semantics.** Marked as "GP state is
  unchanged" in the SMT. Technically that's a lie for
  syscall (kernel can clobber registers), but for proof-
  of-register-setup purposes it's the right abstraction.

## Running the proof

Install Z3:

```bash
# Ubuntu / Debian
sudo apt install z3

# macOS
brew install z3

# Check
z3 --version
```

Run the proof:

```bash
shrike --recipe '...' --smt target > chain.smt
z3 -smt2 chain.smt
```

Expected: `sat` followed by nothing else (unless you added
`(get-model)`).

For a broken chain:

```
unsat
```

At that point add `(get-model)` to the SMT file and re-run
to see which assertion fails. Or dump the file to someone
else and get them to look.

## Machine-checkability as documentation

The proof file is self-contained. A colleague or reviewer
doesn't need shrike installed to verify your chain — they
need Z3 and the SMT file. The provenance comments in the
output name which gadget the synthesizer picked per step,
so a reviewer can cross-reference against the disassembly
independently.

This is the main reason shrike bothers with SMT: not
because the synthesizer needs external help, but because
the synthesized chain needs an artefact to be re-examined
by an adversarial reviewer years later.

## What's not proved yet

- **Memory modelling.** Tracked for 5.x — extends the
  bitvector state to include a simple memory array for
  DOP primitive proofs.
- **Concrete execution.** Prove that with concrete initial
  state X, the chain produces concrete final state Y.
  Future work.
- **Coq / Lean export.** Downstream formal-verification
  folks have asked for exports in their native formats.
  Not started.
