/*
 * regidx.h — register-control index for POP-class gadgets.
 *
 * For every gadget classified as CAT_POP, extract which architectural
 * register the pop targets and accumulate the gadget's virtual address
 * under that register. The index answers the single most common
 * question in ROP development: "given this binary, which registers
 * can I pop into, and at which addresses?"
 *
 * x86-64: PUSH/POP regs 0..15 (rax..r15). A "pop reg" gadget starts
 *         with either 0x58-0x5F (r0..r7, no REX) or 0x41 0x58-0x5F
 *         (r8..r15 via REX.B).
 * aarch64: "POP" is really LDP Xt1, Xt2, [SP], #imm (post-indexed) or
 *          LDP ..., [SP], #N. We record Xt1 as the primary target.
 */
#ifndef SHRIKE_REGIDX_H
#define SHRIKE_REGIDX_H

#include "scan.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define REGIDX_MAX_REGS  32
#define REGIDX_MAX_PER   64   /* addresses per register we remember */
#define REGIDX_MAX_MULTI 256  /* v1.5.2: multi-pop gadget slots */

/* v1.5.2: every gadget that writes 2+ registers in one execution
 * gets an entry here. The chain resolver looks through this list
 * when a recipe asks for several registers in a row — a single
 * multi-pop gadget is always preferred over N single-pops
 * (shorter chain, easier ASLR survivability, less stack). */
#define REGIDX_MAX_POP_ORDER 16

typedef struct {
    uint32_t writes_mask;      /* bit N set means "writes reg N" */
    uint32_t stack_consumed;
    uint64_t addr;
    /* v1.5.4: ordered list of popped registers, in the order they
     * appear on the stack. Needed for auto-padding so the emitter
     * knows which slots correspond to recipe registers vs filler. */
    uint8_t  pop_order[REGIDX_MAX_POP_ORDER];
    uint8_t  pop_count;
} regidx_multi_t;

typedef struct {
    uint64_t   addrs[REGIDX_MAX_REGS][REGIDX_MAX_PER];
    /* v1.5.1: parallel array carrying the gadget's stack_consumed.
     * Required by the chain emitter to thread dummy payload slots
     * between gadgets whose stack footprint isn't the default 16
     * bytes (e.g. `pop rdi ; pop rsi ; ret` needs 24, not 16). */
    uint32_t   stack_consumed[REGIDX_MAX_REGS][REGIDX_MAX_PER];
    uint16_t   counts[REGIDX_MAX_REGS];
    uint16_t   machine;
    /* terminator helpers */
    uint64_t   syscall_addrs[REGIDX_MAX_PER];
    uint16_t   syscall_count;

    /* v1.5.2: multi-pop index. */
    regidx_multi_t multi[REGIDX_MAX_MULTI];
    uint16_t       multi_count;
} regidx_t;

void regidx_init(regidx_t *ri, uint16_t machine);

/* Update the index with a gadget. No-op if the gadget is not a
 * recognised single-pop-ret shape. */
void regidx_observe(regidx_t *ri, const gadget_t *g);

/* Name the arch register at index r (0..31). Returns NULL for out-of-range. */
const char *regidx_reg_name(uint16_t machine, int r);

/* Inverse lookup: return the register index for a name, or -1. */
int         regidx_reg_lookup(uint16_t machine, const char *name);

/* Print a human-readable table of reg -> addresses. */
void regidx_print(const regidx_t *ri, FILE *f);

/* JSON serialisation. */
void regidx_print_json(const regidx_t *ri, FILE *f);

/* pwntools-compatible Python dict literal. */
void regidx_print_python(const regidx_t *ri, FILE *f);

/* v1.5.2: find a multi-pop gadget whose writes_mask equals the
 * requested `needed` mask exactly. Returns a pointer into the
 * regidx or NULL if no such gadget was observed. Exact match
 * (not cover) keeps this sprint scope tight — subset-match with
 * padding is v1.5.4's job. */
const regidx_multi_t *regidx_find_multi_exact(const regidx_t *ri,
                                              uint32_t needed);

/* v1.5.3: clobber-aware variant. Returns the first multi-pop
 * gadget that covers every bit in `needed` and whose writes_mask
 * shares no bits with `committed` (i.e. it cannot stomp on any
 * already-set register). `strict_cover` selects between:
 *   1 — exact match (same as regidx_find_multi_exact)
 *   0 — subset cover allowed (gadget may write extra regs
 *       beyond `needed`; those turn into padding slots)
 * Returns NULL if nothing qualifies. */
const regidx_multi_t *regidx_find_multi(const regidx_t *ri,
                                        uint32_t needed,
                                        uint32_t committed,
                                        int      strict_cover);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_REGIDX_H */
