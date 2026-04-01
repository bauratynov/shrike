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

#define REGIDX_MAX_REGS 32
#define REGIDX_MAX_PER  64   /* addresses per register we remember */

typedef struct {
    uint64_t   addrs[REGIDX_MAX_REGS][REGIDX_MAX_PER];
    uint16_t   counts[REGIDX_MAX_REGS];
    uint16_t   machine;
    /* terminator helpers */
    uint64_t   syscall_addrs[REGIDX_MAX_PER];
    uint16_t   syscall_count;
} regidx_t;

void regidx_init(regidx_t *ri, uint16_t machine);

/* Update the index with a gadget. No-op if the gadget is not a
 * recognised single-pop-ret shape. */
void regidx_observe(regidx_t *ri, const gadget_t *g);

/* Name the arch register at index r (0..31). Returns NULL for out-of-range. */
const char *regidx_reg_name(uint16_t machine, int r);

/* Print a human-readable table of reg -> addresses. */
void regidx_print(const regidx_t *ri, FILE *f);

/* JSON serialisation. */
void regidx_print_json(const regidx_t *ri, FILE *f);

/* pwntools-compatible Python dict literal. */
void regidx_print_python(const regidx_t *ri, FILE *f);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_REGIDX_H */
