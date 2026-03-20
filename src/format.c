/*
 * format.c — tiny x86-64 mnemonic printer.
 *
 * We recognise a vocabulary of ~30 opcodes that cover the majority
 * of gadget bodies: push/pop, mov reg/reg, arithmetic between
 * registers, call/ret/jmp, syscall, nop, leave. For anything else
 * we fall back to "db 0x..." so the output stays readable without
 * turning this file into a full disassembler.
 */

#include "format.h"
#include "xdec.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

static const char *reg64[8] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"
};
static const char *reg32[8] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"
};
static const char *reg16[8] = {
    "ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di"
};
static const char *reg8_nohi[8] = {
    "al",  "cl",  "dl",  "bl",  "spl", "bpl", "sil", "dil"
};

static const char *pick_reg(int w, int b16, int b8, int rex, int idx)
{
    if (w)          return reg64[idx & 7];
    if (b16)        return reg16[idx & 7];
    if (b8)         return reg8_nohi[idx & 7];
    if (rex)        return reg64[idx & 7];
    return reg32[idx & 7];
}

/* Print one decoded instruction to `f`. Returns the length consumed
 * (so the caller can advance). Returns <= 0 on decode failure. */
static int emit_one(FILE *f, const uint8_t *buf, size_t max)
{
    xdec_info_t info;
    if (xdec_full(buf, max, &info) < 0) return -1;

    uint8_t op = info.opcode;
    int     w  = info.rex_w;
    int     op66 = info.op66;

    if (info.map == 1) {
        /* PUSH reg (0x50 - 0x57) */
        if (op >= 0x50 && op <= 0x57) {
            fprintf(f, "push %s", pick_reg(1, op66, 0, info.rex, op - 0x50));
            return info.length;
        }
        /* POP reg (0x58 - 0x5F) */
        if (op >= 0x58 && op <= 0x5F) {
            fprintf(f, "pop %s", pick_reg(1, op66, 0, info.rex, op - 0x58));
            return info.length;
        }
        /* NOP / XCHG rAX, reg (0x90-0x97) */
        if (op == 0x90) { fprintf(f, "nop"); return info.length; }
        if (op >= 0x91 && op <= 0x97) {
            fprintf(f, "xchg %s, %s",
                    pick_reg(w, op66, 0, info.rex, 0),
                    pick_reg(w, op66, 0, info.rex, op - 0x90));
            return info.length;
        }
        /* returns */
        if (op == 0xC3) { fprintf(f, "ret");        return info.length; }
        if (op == 0xCB) { fprintf(f, "retf");       return info.length; }
        if (op == 0xC2) {
            uint16_t imm = (uint16_t)buf[info.length - 2]
                         | ((uint16_t)buf[info.length - 1] << 8);
            fprintf(f, "ret 0x%x", imm);
            return info.length;
        }
        if (op == 0xCA) {
            uint16_t imm = (uint16_t)buf[info.length - 2]
                         | ((uint16_t)buf[info.length - 1] << 8);
            fprintf(f, "retf 0x%x", imm);
            return info.length;
        }
        /* LEAVE */
        if (op == 0xC9) { fprintf(f, "leave"); return info.length; }
        /* INT */
        if (op == 0xCC) { fprintf(f, "int3");  return info.length; }
        if (op == 0xCD) {
            fprintf(f, "int 0x%x", buf[info.length - 1]);
            return info.length;
        }
        /* JMP/CALL rel */
        if (op == 0xEB) { fprintf(f, "jmp rel8");     return info.length; }
        if (op == 0xE9) { fprintf(f, "jmp rel32");    return info.length; }
        if (op == 0xE8) { fprintf(f, "call rel32");   return info.length; }
        /* JMP/CALL indirect */
        if (op == 0xFF) {
            uint8_t reg = (info.modrm >> 3) & 7;
            uint8_t mod = info.modrm >> 6;
            uint8_t rm  = info.modrm & 7;
            const char *mnemo = (reg == 2 || reg == 3) ? "call" : "jmp";
            if (mod == 3) {
                fprintf(f, "%s %s", mnemo,
                        pick_reg(1, 0, 0, info.rex, rm));
            } else {
                fprintf(f, "%s [mem]", mnemo);
            }
            return info.length;
        }
        /* MOV reg imm (B0-BF): we know size from flags */
        if (op >= 0xB0 && op <= 0xB7) {
            fprintf(f, "mov %s, 0x%x",
                    reg8_nohi[op - 0xB0],
                    buf[info.length - 1]);
            return info.length;
        }
        if (op >= 0xB8 && op <= 0xBF) {
            fprintf(f, "mov %s, imm",
                    pick_reg(w, op66, 0, info.rex, op - 0xB8));
            return info.length;
        }
        /* MOV r, r/m (8B) and MOV r/m, r (89) — reg-reg form only */
        if ((op == 0x89 || op == 0x8B) && (info.modrm >> 6) == 3) {
            uint8_t reg = (info.modrm >> 3) & 7;
            uint8_t rm  = info.modrm & 7;
            const char *dst = (op == 0x89) ? pick_reg(w, op66, 0, info.rex, rm)
                                           : pick_reg(w, op66, 0, info.rex, reg);
            const char *src = (op == 0x89) ? pick_reg(w, op66, 0, info.rex, reg)
                                           : pick_reg(w, op66, 0, info.rex, rm);
            fprintf(f, "mov %s, %s", dst, src);
            return info.length;
        }
        /* XOR reg, reg (0x31 / 0x33) reg-reg form */
        if ((op == 0x31 || op == 0x33) && (info.modrm >> 6) == 3) {
            uint8_t reg = (info.modrm >> 3) & 7;
            uint8_t rm  = info.modrm & 7;
            const char *dst = (op == 0x31) ? pick_reg(w, op66, 0, info.rex, rm)
                                           : pick_reg(w, op66, 0, info.rex, reg);
            const char *src = (op == 0x31) ? pick_reg(w, op66, 0, info.rex, reg)
                                           : pick_reg(w, op66, 0, info.rex, rm);
            fprintf(f, "xor %s, %s", dst, src);
            return info.length;
        }
        /* ADD reg, reg (0x01 / 0x03) */
        if ((op == 0x01 || op == 0x03) && (info.modrm >> 6) == 3) {
            uint8_t reg = (info.modrm >> 3) & 7;
            uint8_t rm  = info.modrm & 7;
            const char *dst = (op == 0x01) ? pick_reg(w, op66, 0, info.rex, rm)
                                           : pick_reg(w, op66, 0, info.rex, reg);
            const char *src = (op == 0x01) ? pick_reg(w, op66, 0, info.rex, reg)
                                           : pick_reg(w, op66, 0, info.rex, rm);
            fprintf(f, "add %s, %s", dst, src);
            return info.length;
        }
        /* HLT */
        if (op == 0xF4) { fprintf(f, "hlt"); return info.length; }
    } else if (info.map == 2) {
        if (op == 0x05) { fprintf(f, "syscall"); return info.length; }
        if (op == 0x07) { fprintf(f, "sysret");  return info.length; }
    }

    /* Unknown: emit raw bytes */
    fprintf(f, "db");
    for (int i = 0; i < info.length; i++) {
        fprintf(f, " 0x%02x%s", buf[i], i + 1 < info.length ? "," : "");
    }
    return info.length;
}

void format_gadget_insns(FILE *f, const gadget_t *g)
{
    size_t p = 0;
    int first = 1;
    while (p < g->length) {
        if (!first) fprintf(f, " ; ");
        int n = emit_one(f, g->bytes + p, g->length - p);
        if (n <= 0) { fprintf(f, "?"); return; }
        p += (size_t)n;
        first = 0;
    }
}

void format_gadget(FILE *f, const gadget_t *g)
{
    fprintf(f, "0x%016" PRIx64 ": ", g->vaddr);
    format_gadget_insns(f, g);
    fputc('\n', f);
}
