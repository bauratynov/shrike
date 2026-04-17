/*
 * effect.h — typed per-gadget effect record.
 *
 * The register-control index (regidx.c) answers "which gadgets
 * can I use to set register R?" by looking at the final bytes
 * and classifying. That's fine for the single-register case, but
 * the Stage III chain synthesizer needs more: for each gadget,
 * which registers does it write, which does it read, how many
 * stack bytes does it consume, does it end in a syscall or a
 * ret or a pivot?
 *
 * gadget_effect_t is the minimum viable answer — enough to drive
 * the multi-pop permutation search (v1.5.2) and the clobber
 * graph (v1.5.3) without pulling in a full symbolic executor.
 * More fields (reads_mask, mem_read/write ranges, flag effects)
 * will get added in the V3 Stage VII semantic-depth sprints.
 *
 * Register numbering matches regidx: x86 uses 0..15 (rax..r15),
 * aarch64 uses 0..31 (x0..x30 + sp), RV64 uses 0..31 (x0..x31,
 * ABI names a0..a7 at indices 10..17 and s0..s11 at 8..9 +
 * 18..27 — same as the canonical calling convention).
 */
#ifndef SHRIKE_EFFECT_H
#define SHRIKE_EFFECT_H

#include <shrike/format.h>
#include <shrike/elf64.h>

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GADGET_TERM_NONE = 0,
    GADGET_TERM_RET,
    GADGET_TERM_SYSCALL,
    GADGET_TERM_JMP_REG,     /* x86 jmp reg / a64 br / rv c.jr      */
    GADGET_TERM_CALL_REG,    /* x86 call reg / a64 blr / rv c.jalr  */
    GADGET_TERM_INT          /* int3 / ebreak / brk                 */
} gadget_term_t;

typedef struct {
    /* One bit per register index — bit N means "this gadget
     * writes architectural register N as its net effect." Write
     * means "pops from stack" or "c.ldsp-reg-from-sp" etc; reads
     * are tracked separately in the reads_mask field. Fits all
     * three archs: x86 needs 16 bits, aarch64 + RV64 each need
     * 32, so uint32_t is sufficient. */
    uint32_t writes_mask;
    uint32_t reads_mask;

    /* Bytes of stack the gadget consumes while executing. For a
     * `pop rdi ; ret` gadget this is 16 (8 for the pop, 8 for the
     * ret). For `ret` alone, 8. For `ret 0x10`, 24. The chain
     * emitter uses this to thread payload slots without dead
     * reckoning. */
    uint32_t stack_consumed;

    /* What the gadget ends with. Redundant with the existing
     * category classifier but normalised across archs into a
     * single enum — saves the synthesizer from re-parsing bytes. */
    gadget_term_t terminator;

    /* Sticky flags that mark gadgets the synthesizer should treat
     * specially. is_pivot = anything that writes SP/RSP/x2 from
     * a non-immediate source. has_syscall = gadget's terminator
     * is a system call. */
    uint8_t is_pivot;
    uint8_t has_syscall;
} gadget_effect_t;

/* Compute the effect record for `g`. Returns 0 on success; if the
 * arch isn't one we model effects for, sets terminator to
 * GADGET_TERM_NONE and everything-else to zero and returns 0
 * anyway — callers don't need to special-case architectures. */
int gadget_effect_compute(const gadget_t *g, gadget_effect_t *out);

/* v2.1.2: dispatcher-shape classifier. Returns 1 when the
 * gadget's last instruction is an indirect JMP (JOP) or CALL
 * (COP) and some earlier instruction wrote to that same target
 * register — the canonical Bletsch dispatcher pattern
 *   `mov rax, [rdx] ; add rdx, 8 ; jmp rax`
 * where the jump target is loaded from memory or a register
 * that itself got set in the same gadget. Used to
 * prioritise gadgets suitable for JOP/COP payload scheduling
 * over stray indirect branches.
 *
 * which is GADGET_TERM_JMP_REG for JOP, GADGET_TERM_CALL_REG
 * for COP — callers pass whichever they're looking for. */
int gadget_is_dispatcher(const gadget_t *g, gadget_term_t which);

/* v2.1.1: compositional variant. Walks the gadget via
 * insn_effect_decode() and folds per-instruction effects into
 * the gadget total. Produces the same gadget_effect_t as
 * gadget_effect_compute on the shapes both recognise, but makes
 * "did we hit an unknown instruction in the middle" explicit via
 * the return value — returns the instruction count on success,
 * -1 if any instruction couldn't be decoded.
 *
 * Used by the chain-correctness prover (v2.6.0) where per-insn
 * SMT assertions must line up with the gadget postcondition. */
int gadget_effect_compose(const gadget_t *g, gadget_effect_t *out);

/* Test helpers: convenience predicates for common questions. */
static inline int gadget_effect_writes(const gadget_effect_t *e, int r)
{
    return (r >= 0 && r < 32) ? ((e->writes_mask >> r) & 1) : 0;
}

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_EFFECT_H */
