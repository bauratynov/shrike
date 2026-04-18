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
    /* v5.3.0: CET-aware preference bit. Same meaning as the
     * per-reg endbr_start: set iff the multi-pop gadget's
     * address is a valid IBT landing pad. */
    uint8_t  endbr_start;
    uint8_t  shstk_safe;
    uint8_t  pac_hostile;
} regidx_multi_t;

typedef struct {
    uint64_t   addrs[REGIDX_MAX_REGS][REGIDX_MAX_PER];
    /* v1.5.1: parallel array carrying the gadget's stack_consumed.
     * Required by the chain emitter to thread dummy payload slots
     * between gadgets whose stack footprint isn't the default 16
     * bytes (e.g. `pop rdi ; pop rsi ; ret` needs 24, not 16). */
    uint32_t   stack_consumed[REGIDX_MAX_REGS][REGIDX_MAX_PER];
    /* v5.3.0: parallel array for CET landing-pad compatibility.
     * endbr_start[r][i] == 1 iff addrs[r][i] is the address of a
     * gadget whose first instruction is ENDBR64 / ENDBR32 (x86)
     * or BTI c/j/jc (aarch64). When CET-aware mode is on, the
     * resolver prefers these when picking among multiple gadgets
     * for the same register — non-endbr gadgets die to the
     * hardware IBT check at runtime. */
    uint8_t    endbr_start[REGIDX_MAX_REGS][REGIDX_MAX_PER];
    /* v5.4.0: mitigation-survival flags per observed gadget.
     * shstk_safe: gadget's terminator isn't a bare RET that
     *   would pop from the shadow stack (i.e. terminator is
     *   syscall / indirect-jmp / ret-gated-by-auth). 1 means
     *   safe under SHSTK.
     * pac_hostile: gadget contains an AUT* instruction that
     *   would fault without a valid sign oracle. 1 means the
     *   chain needs PAC bypass to use this gadget. */
    uint8_t    shstk_safe[REGIDX_MAX_REGS][REGIDX_MAX_PER];
    uint8_t    pac_hostile[REGIDX_MAX_REGS][REGIDX_MAX_PER];
    uint16_t   counts[REGIDX_MAX_REGS];
    uint16_t   machine;
    /* terminator helpers */
    uint64_t   syscall_addrs[REGIDX_MAX_PER];
    uint8_t    syscall_endbr_start[REGIDX_MAX_PER];
    uint8_t    syscall_shstk_safe[REGIDX_MAX_PER];
    uint8_t    syscall_pac_hostile[REGIDX_MAX_PER];
    uint16_t   syscall_count;

    /* v1.5.2: multi-pop index. */
    regidx_multi_t multi[REGIDX_MAX_MULTI];
    uint16_t       multi_count;

    /* v5.3.0: summary CET flags for the containing image. Set
     * by the caller (main.c cet-posture path); the resolver
     * reads them to decide whether to prefer endbr gadgets. */
    uint8_t    cet_ibt_required;   /* .note.gnu.property IBT bit */
    uint8_t    cet_shstk_required; /* .note.gnu.property SHSTK bit */
    /* v5.4.0: arm64e PAC is on. Source: Mach-O cpusubtype ==
     * CPU_SUBTYPE_ARM64E sets macho_arm64e on the elf64_t;
     * main.c ORs it here. Resolver avoids pac_hostile gadgets
     * (AUT* bodies) when this is set. */
    uint8_t    pac_required;
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

/* v5.3.0 + v5.4.0: mitigation-aware picker. Returns the
 * preferred index into ri->addrs[r][] for the given register.
 *
 * Selection priority when the matching flags on the regidx
 * are set:
 *   1. prefer endbr_start == 1 if cet_ibt_required
 *   2. prefer shstk_safe == 1 if cet_shstk_required
 *   3. prefer pac_hostile == 0 if pac_required
 *   4. first-observed wins among ties
 *
 * When the image doesn't require any of these, returns 0
 * (pre-5.3 behaviour). -1 if the register has no entries. */
int regidx_pick_index(const regidx_t *ri, int reg, int cet_aware);

/* Same for syscall terminators. -1 if none. */
int regidx_pick_syscall_index(const regidx_t *ri, int cet_aware);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_REGIDX_H */
