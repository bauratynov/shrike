/*
 * arm64.c — AArch64 gadget primitives.
 *
 * We cover the handful of encodings that actually matter for
 * ROP / JOP gadget enumeration:
 *   - Branches to register  (RET / BR / BLR)  ARM ARM C4.1.3
 *   - Exception generation  (SVC)             ARM ARM C6.2
 *   - PAC returns           (RETAA / RETAB)   ARMv8.3-A
 *   - BTI landing pads      (BTI c/j/jc)      ARMv8.5-A
 *
 * Other instructions are printed as ".word 0xXXXXXXXX"; that keeps
 * shrike honest about what it does and doesn't recognise without
 * pretending to be a full disassembler.
 */

#include "arm64.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t arm64_read_insn(const uint8_t *buf)
{
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] <<  8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

/* ---------- classifiers ---------- */

/* RET Xn:       1101 0110 0101 1111 0000 00nn nnn0 0000
 *   mask        FFFF FC 1F
 *   pattern     D65F 00 00
 * RETAA / RETAB add op3=0b000010 / 0b000011 in bits 11:10 but still
 * pattern-match under a looser mask; we treat both as RET variants. */
static int is_ret(uint32_t insn)
{
    /* Unconditional branch (register), opc = 0b0010, op2=0b11111 */
    if ((insn & 0xFFFFFC00u) == 0xD65F0000u) return 1;
    /* RETAA / RETAB (ARMv8.3-A) — opc differs but branch type stays */
    if ((insn & 0xFFFFFBFFu) == 0xD65F0BFFu) return 1;
    return 0;
}

static int is_br(uint32_t insn)
{
    return (insn & 0xFFFFFC1Fu) == 0xD61F0000u;
}

static int is_blr(uint32_t insn)
{
    return (insn & 0xFFFFFC1Fu) == 0xD63F0000u;
}

static int is_svc(uint32_t insn)
{
    /* SVC #imm16: 1101 0100 000i iiii iiii iiii iii0 0001 */
    return (insn & 0xFFE0001Fu) == 0xD4000001u;
}

int arm64_is_terminator(uint32_t insn)
{
    return is_ret(insn) || is_br(insn) || is_blr(insn) || is_svc(insn);
}

int arm64_is_bti(uint32_t insn)
{
    /* HINT space: BTI c/j/jc encode as 1101 0101 0000 0011 0010 01xx 0001 1111
     * Concrete values:
     *   BTI    (no target):    0xD503241F
     *   BTI c  (call targets): 0xD503245F
     *   BTI j  (jump targets): 0xD503249F
     *   BTI jc (both):         0xD50324DF
     */
    return (insn & 0xFFFFFF3Fu) == 0xD503241Fu;
}

/* ---------- rendering ---------- */

static int render_svc(char *buf, size_t buflen, uint32_t insn)
{
    uint32_t imm = (insn >> 5) & 0xFFFF;
    return snprintf(buf, buflen, "svc #0x%x", imm);
}

static int render_bti(char *buf, size_t buflen, uint32_t insn)
{
    static const char *targets[4] = { "", " c", " j", " jc" };
    uint32_t t = (insn >> 6) & 3;
    return snprintf(buf, buflen, "bti%s", targets[t]);
}

static int render_ret(char *buf, size_t buflen, uint32_t insn)
{
    /* RETAA / RETAB */
    if ((insn & 0xFFFFFBFFu) == 0xD65F0BFFu) {
        int aa = (insn & 0x00000400u) == 0;
        return snprintf(buf, buflen, aa ? "retaa" : "retab");
    }
    uint32_t rn = (insn >> 5) & 0x1F;
    if (rn == 30) return snprintf(buf, buflen, "ret");
    return snprintf(buf, buflen, "ret x%u", rn);
}

static int render_br_blr(char *buf, size_t buflen,
                         uint32_t insn, const char *mnemo)
{
    uint32_t rn = (insn >> 5) & 0x1F;
    return snprintf(buf, buflen, "%s x%u", mnemo, rn);
}

/* MOV (register): this is actually ORR Xd, XZR, Xm — ARM encodes "mov
 * reg, reg" as a variant of ORR. Detect it so prologues read naturally. */
static int render_mov_reg(char *buf, size_t buflen, uint32_t insn)
{
    /* 64-bit ORR shifted register with Rn=XZR(31), no shift, amount=0:
     *   sf=1 opc=01 01010 shift=00 N=0 Rm imm6=000000 Rn=11111 Rd
     * Fixed bits: 31..21, 15..5 ; variable: Rm (20..16) and Rd (4..0).
     * Mask 0xFFE0FFE0 preserves the fixed bits; pattern 0xAA0003E0. */
    if ((insn & 0xFFE0FFE0u) == 0xAA0003E0u) {
        uint32_t rd = insn & 0x1F;
        uint32_t rm = (insn >> 16) & 0x1F;
        return snprintf(buf, buflen, "mov x%u, x%u", rd, rm);
    }
    return -1;
}

int arm64_render_insn(char *buf, size_t buflen, uint32_t insn)
{
    if (buflen == 0) return 0;

    /* NOP is a hint, very common in padding */
    if (insn == 0xD503201Fu) return snprintf(buf, buflen, "nop");

    /* Terminators */
    if (is_ret(insn)) return render_ret(buf, buflen, insn);
    if (is_br(insn))  return render_br_blr(buf, buflen, insn, "br");
    if (is_blr(insn)) return render_br_blr(buf, buflen, insn, "blr");
    if (is_svc(insn)) return render_svc(buf, buflen, insn);

    /* BTI */
    if (arm64_is_bti(insn)) return render_bti(buf, buflen, insn);

    /* MOV reg, reg */
    int n = render_mov_reg(buf, buflen, insn);
    if (n >= 0) return n;

    /* Fallback */
    return snprintf(buf, buflen, ".word 0x%08x", insn);
}
