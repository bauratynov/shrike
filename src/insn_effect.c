/*
 * insn_effect.c — per-instruction effect decoder.
 *
 * Keeps the same narrow scope policy as effect.c and the arch
 * renderers: we recognise what shows up in real gadgets, and
 * return (-1, zero struct) for everything else. Analyses that
 * care about "did we miss something" can check the KNOWN flag.
 */

#include <shrike/insn_effect.h>
#include <shrike/effect.h>
#include <shrike/elf64.h>
#include <shrike/arm64.h>
#include <shrike/riscv.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ---------- x86-64 ---------- */

static int
decode_x86(const uint8_t *b, size_t max, insn_effect_t *o)
{
    if (max < 1) return 0;
    uint8_t op = b[0];

    /* pop rN (0x58..0x5F, reg 0..7) */
    if (op >= 0x58 && op <= 0x5F) {
        o->writes_mask = 1u << (op - 0x58);
        o->stack_delta = 8;
        o->flags       = INSN_EFFECT_MEM_READ | INSN_EFFECT_KNOWN;
        o->length      = 1;
        return 1;
    }
    /* REX.B pop r8..r15 */
    if (op == 0x41 && max >= 2 && b[1] >= 0x58 && b[1] <= 0x5F) {
        o->writes_mask = 1u << (8 + (b[1] - 0x58));
        o->stack_delta = 8;
        o->flags       = INSN_EFFECT_MEM_READ | INSN_EFFECT_KNOWN;
        o->length      = 2;
        return 2;
    }
    /* push rN (0x50..0x57) */
    if (op >= 0x50 && op <= 0x57) {
        o->reads_mask   = 1u << (op - 0x50);
        o->stack_delta  = -8;
        o->flags        = INSN_EFFECT_MEM_WRITE | INSN_EFFECT_KNOWN;
        o->length       = 1;
        return 1;
    }
    /* ret (0xC3) */
    if (op == 0xC3) {
        o->stack_delta = 8;
        o->flags       = INSN_EFFECT_MEM_READ | INSN_EFFECT_KNOWN;
        o->terminator  = GADGET_TERM_RET;
        o->length      = 1;
        return 1;
    }
    /* ret imm16 (0xC2 ib ib) */
    if (op == 0xC2 && max >= 3) {
        uint16_t imm = (uint16_t)b[1] | ((uint16_t)b[2] << 8);
        o->stack_delta = 8 + (int32_t)imm;
        o->flags       = INSN_EFFECT_MEM_READ | INSN_EFFECT_KNOWN;
        o->terminator  = GADGET_TERM_RET;
        o->length      = 3;
        return 3;
    }
    /* syscall (0x0F 0x05) */
    if (op == 0x0F && max >= 2 && b[1] == 0x05) {
        o->flags       = INSN_EFFECT_KNOWN;
        o->terminator  = GADGET_TERM_SYSCALL;
        o->length      = 2;
        return 2;
    }
    /* int3 */
    if (op == 0xCC) {
        o->flags      = INSN_EFFECT_KNOWN;
        o->terminator = GADGET_TERM_INT;
        o->length     = 1;
        return 1;
    }
    return -1;
}

/* ---------- AArch64 ---------- */

static int
decode_a64(const uint8_t *b, size_t max, insn_effect_t *o)
{
    if (max < 4) return 0;
    uint32_t w = arm64_read_insn(b);

    /* ldp Xt1, Xt2, [sp], #imm  post-index */
    if ((w & 0xFFC003E0u) == 0xA8C003E0u) {
        uint32_t rt1 = w & 0x1f;
        uint32_t rt2 = (w >> 10) & 0x1f;
        int imm7 = (int)((w >> 15) & 0x7f);
        if (imm7 & 0x40) imm7 -= 0x80;
        o->writes_mask = (1u << rt1) | (1u << rt2);
        o->stack_delta = imm7 * 8;
        o->flags       = INSN_EFFECT_MEM_READ | INSN_EFFECT_KNOWN;
        o->length      = 4;
        return 4;
    }
    /* ret (xn) */
    if (arm64_is_terminator(w)) {
        o->flags = INSN_EFFECT_KNOWN;
        if ((w & 0xFFE0001Fu) == 0xD4000001u) {
            o->terminator = GADGET_TERM_SYSCALL;
        } else if ((w & 0xFFFFFC1Fu) == 0xD61F0000u) {
            o->terminator = GADGET_TERM_JMP_REG;
        } else if ((w & 0xFFFFFC1Fu) == 0xD63F0000u) {
            o->terminator = GADGET_TERM_CALL_REG;
        } else {
            o->terminator = GADGET_TERM_RET;
        }
        o->length = 4;
        return 4;
    }
    return -1;
}

/* ---------- RV64 ---------- */

static int
decode_rv(const uint8_t *b, size_t max, insn_effect_t *o)
{
    size_t il = riscv_insn_len(b, max);
    if (il == 0) return 0;

    if (il == 4) {
        uint32_t w = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
                     ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        uint32_t opcode = w & 0x7f;
        uint32_t funct3 = (w >> 12) & 0x7;
        uint32_t rs1    = (w >> 15) & 0x1f;
        uint32_t rd     = (w >> 7)  & 0x1f;

        /* ld rd, imm(sp) */
        if (opcode == 0x03 && funct3 == 0x3 && rs1 == 2) {
            if (rd != 0) o->writes_mask = 1u << rd;
            o->flags  = INSN_EFFECT_MEM_READ | INSN_EFFECT_KNOWN;
            o->length = 4;
            return 4;
        }
        /* addi sp, sp, imm */
        if (opcode == 0x13 && funct3 == 0 && rd == 2 && rs1 == 2) {
            int32_t imm = (int32_t)(w >> 20);
            if (imm & 0x800) imm -= 0x1000;
            o->stack_delta = imm;
            o->flags       = INSN_EFFECT_KNOWN;
            o->length      = 4;
            return 4;
        }
        if (riscv_is_ret(b, il)) {
            o->flags      = INSN_EFFECT_KNOWN;
            o->terminator = GADGET_TERM_RET;
            o->length     = 4;
            return 4;
        }
        riscv_term_t k = riscv_classify_terminator(b, il);
        if (k == RV_TERM_ECALL)  { o->terminator = GADGET_TERM_SYSCALL; goto term; }
        if (k == RV_TERM_EBREAK) { o->terminator = GADGET_TERM_INT;     goto term; }
        if (k == RV_TERM_JALR)   { o->terminator = GADGET_TERM_CALL_REG; goto term; }
        return -1;
term:
        o->flags  = INSN_EFFECT_KNOWN;
        o->length = 4;
        return 4;
    }

    /* 2-byte RVC */
    uint16_t h = (uint16_t)(b[0] | (b[1] << 8));
    if ((h & 0xe003) == 0x6002) {
        /* c.ldsp rd, imm(sp) */
        uint32_t rd = (h >> 7) & 0x1f;
        if (rd != 0) o->writes_mask = 1u << rd;
        o->flags  = INSN_EFFECT_MEM_READ | INSN_EFFECT_KNOWN;
        o->length = 2;
        return 2;
    }
    if (riscv_is_ret(b, 2)) {
        o->flags      = INSN_EFFECT_KNOWN;
        o->terminator = GADGET_TERM_RET;
        o->length     = 2;
        return 2;
    }
    riscv_term_t k = riscv_classify_terminator(b, 2);
    if (k == RV_TERM_C_JR)   { o->flags=INSN_EFFECT_KNOWN; o->terminator=GADGET_TERM_JMP_REG;  o->length=2; return 2; }
    if (k == RV_TERM_C_JALR) { o->flags=INSN_EFFECT_KNOWN; o->terminator=GADGET_TERM_CALL_REG; o->length=2; return 2; }
    return -1;
}

int
insn_effect_decode(const uint8_t *bytes, size_t remaining,
                   uint16_t machine, insn_effect_t *out)
{
    memset(out, 0, sizeof *out);
    if (!bytes || remaining == 0) return 0;

    if (machine == EM_AARCH64) return decode_a64(bytes, remaining, out);
    if (machine == EM_RISCV)   return decode_rv(bytes, remaining, out);
    return decode_x86(bytes, remaining, out);
}
