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

#include <shrike/arm64.h>

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

/* v1.6.2: format a register name that respects SP at index 31
 * (some encodings use SP instead of XZR when Rn/Rd == 31). */
static const char *
reg_name(uint32_t r, int sf, int sp_form)
{
    static const char *x_regs[32] = {
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "x8", "x9","x10","x11","x12","x13","x14","x15",
       "x16","x17","x18","x19","x20","x21","x22","x23",
       "x24","x25","x26","x27","x28","x29","x30", NULL
    };
    static const char *w_regs[32] = {
        "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
        "w8", "w9","w10","w11","w12","w13","w14","w15",
       "w16","w17","w18","w19","w20","w21","w22","w23",
       "w24","w25","w26","w27","w28","w29","w30", NULL
    };
    if (r == 31) {
        if (sp_form) return sf ? "sp" : "wsp";
        return sf ? "xzr" : "wzr";
    }
    return sf ? x_regs[r] : w_regs[r];
}

/* LDP Xt1, Xt2, [Xn{, #imm}]! / LDP ..., [Xn], #imm  (post-index).
 * Encoding root (64-bit): 1010100 CLM imm7 Rt2 Rn Rt1
 *   post-idx : bits 24..23 = 01  (A8C / A8C in hex partial)
 *   pre-idx  : bits 24..23 = 11
 *   signed   : bits 24..23 = 10  (signed offset, no writeback) */
static int
render_ldp(char *buf, size_t buflen, uint32_t insn)
{
    uint32_t opc   = (insn >> 30) & 0x3;    /* 10 = 64-bit x-regs */
    uint32_t v     = (insn >> 26) & 1;      /* 1 = simd/fp — we skip */
    uint32_t base  = (insn >> 22) & 0x7F;   /* match for LDP family */
    uint32_t idx23 = (insn >> 23) & 0x3;    /* addressing mode */
    uint32_t L     = (insn >> 22) & 1;      /* 1 = load */

    if (opc != 2 || v != 0) return -1;
    if (((base >> 1) & 0x1Fu) != 0x05u) return -1;   /* 0b1010100?? */
    if (L != 1) return -1;

    int imm7 = (int)((insn >> 15) & 0x7F);
    if (imm7 & 0x40) imm7 -= 0x80;
    int offset = imm7 * 8;

    uint32_t rt2 = (insn >> 10) & 0x1F;
    uint32_t rn  = (insn >>  5) & 0x1F;
    uint32_t rt1 =  insn        & 0x1F;

    const char *x1  = reg_name(rt1, 1, 0);
    const char *x2  = reg_name(rt2, 1, 0);
    const char *base_s = reg_name(rn, 1, 1);

    switch (idx23) {
    case 1:  /* post-index */
        return snprintf(buf, buflen,
            "ldp %s, %s, [%s], #%d", x1, x2, base_s, offset);
    case 3:  /* pre-index */
        return snprintf(buf, buflen,
            "ldp %s, %s, [%s, #%d]!", x1, x2, base_s, offset);
    case 2:  /* signed offset */
        if (offset == 0) {
            return snprintf(buf, buflen,
                "ldp %s, %s, [%s]", x1, x2, base_s);
        }
        return snprintf(buf, buflen,
            "ldp %s, %s, [%s, #%d]", x1, x2, base_s, offset);
    default:
        return -1;
    }
}

/* ADD / SUB (immediate).
 * Root: sf op S 100010 sh imm12 Rn Rd
 *   op=0 → ADD, op=1 → SUB
 *   S=0  → flags not set, S=1 → adds/subs
 *   sh=0 → imm12 as-is, sh=1 → imm12 << 12
 */
static int
render_add_sub_imm(char *buf, size_t buflen, uint32_t insn)
{
    uint32_t sf  = (insn >> 31) & 1;
    uint32_t op  = (insn >> 30) & 1;
    uint32_t S   = (insn >> 29) & 1;
    uint32_t tag = (insn >> 23) & 0x3F;
    if (tag != 0x22 /* 100010 */) return -1;

    uint32_t sh    = (insn >> 22) & 1;
    uint32_t imm12 = (insn >> 10) & 0xFFF;
    uint32_t rn    = (insn >>  5) & 0x1F;
    uint32_t rd    =  insn        & 0x1F;
    uint32_t imm   = sh ? (imm12 << 12) : imm12;

    const char *mnemo = op ? (S ? "subs" : "sub")
                           : (S ? "adds" : "add");
    const char *rd_s = reg_name(rd, sf, S ? 0 : 1);
    const char *rn_s = reg_name(rn, sf, S ? 0 : 1);
    return snprintf(buf, buflen, "%s %s, %s, #0x%x",
                    mnemo, rd_s, rn_s, imm);
}

/* MOVZ / MOVK / MOVN (wide immediate).
 * Root: sf opc(2) 100101 hw imm16 Rd
 *   opc=00 MOVN
 *   opc=10 MOVZ
 *   opc=11 MOVK
 *   hw     shift amount (0,16,32,48)
 */
static int
render_mov_wide(char *buf, size_t buflen, uint32_t insn)
{
    uint32_t sf   = (insn >> 31) & 1;
    uint32_t opc  = (insn >> 29) & 0x3;
    uint32_t tag  = (insn >> 23) & 0x3F;
    if (tag != 0x25 /* 100101 */) return -1;
    if (opc == 1) return -1;  /* reserved */

    uint32_t hw   = (insn >> 21) & 0x3;
    uint32_t imm  = (insn >>  5) & 0xFFFF;
    uint32_t rd   = insn & 0x1F;
    const char *mnemo = (opc == 0) ? "movn" : (opc == 2) ? "movz" : "movk";
    const char *rd_s  = reg_name(rd, sf, 0);

    if (hw == 0) {
        return snprintf(buf, buflen, "%s %s, #0x%x",
                        mnemo, rd_s, imm);
    }
    return snprintf(buf, buflen, "%s %s, #0x%x, lsl #%u",
                    mnemo, rd_s, imm, hw * 16);
}

/* B / BL (unconditional branch, immediate).
 * Root: op(1) 00101 imm26 — op=0 B, op=1 BL.
 * imm26 is a signed word offset from current PC. Rendered as
 * a relative offset in bytes since we have no absolute PC here. */
static int
render_b_bl(char *buf, size_t buflen, uint32_t insn)
{
    uint32_t op  = (insn >> 31) & 1;
    uint32_t tag = (insn >> 26) & 0x3F;
    if ((tag & 0x3E) != 0x5 /* 00101? */) return -1;

    int32_t imm26 = (int32_t)(insn & 0x3FFFFFF);
    if (imm26 & 0x2000000) imm26 -= 0x4000000;
    int32_t off = imm26 * 4;

    return snprintf(buf, buflen, "%s #%s0x%x",
                    op ? "bl" : "b",
                    off < 0 ? "-" : "+",
                    (unsigned)(off < 0 ? -off : off));
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

    /* v1.6.2: expanded coverage — try LDP, add/sub imm, mov-wide,
     * branch-immediate in order. */
    n = render_ldp(buf, buflen, insn);
    if (n >= 0) return n;
    n = render_add_sub_imm(buf, buflen, insn);
    if (n >= 0) return n;
    n = render_mov_wide(buf, buflen, insn);
    if (n >= 0) return n;
    n = render_b_bl(buf, buflen, insn);
    if (n >= 0) return n;

    /* Fallback */
    return snprintf(buf, buflen, ".word 0x%08x", insn);
}
