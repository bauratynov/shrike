/*
 * format.c — tiny x86-64 mnemonic printer.
 *
 * Recognised (v0.2.0):
 *   push/pop reg (50-57, 58-5F)
 *   nop (90), xchg rAX, reg (91-97)
 *   ret / retf (C3, CB), ret imm16 / retf imm16 (C2, CA)
 *   leave (C9), int3 (CC), int imm8 (CD)
 *   jmp rel8/rel32 (EB, E9), call rel32 (E8)
 *   jmp/call indirect (FF /2..5)
 *   mov r,imm (B0-BF)
 *   mov reg, reg  (89, 8B mod=11)
 *   xor reg, reg  (31, 33 mod=11)
 *   add reg, reg  (01, 03 mod=11)
 *   lea reg, [reg+disp8]  (8D with mod=01 and rm != 4)
 *   cmovcc reg, reg       (0F 40-4F mod=11)
 *   shld r/m, r, imm8     (0F A4)
 *   shrd r/m, r, imm8     (0F AC)
 *   bt/bts/btr/btc r/m, imm8 (0F BA + reg field)
 *   hlt (F4), syscall (0F 05), sysret (0F 07)
 *
 * Everything else → "db 0x.., 0x.." fallback.
 */

#include <shrike/format.h>
#include <shrike/cet.h>
#include <shrike/xdec.h>
#include <shrike/arm64.h>
#include <shrike/riscv.h>
#include <shrike/ppc64.h>
#include <shrike/mips.h>
#include <shrike/elf64.h>

#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* --- tiny strbuf with overflow flag, no heap --- */

typedef struct {
    char   *buf;
    size_t  cap;
    size_t  len;
    int     overflowed;
} strbuf_t;

static void sb_vprintf(strbuf_t *sb, const char *fmt, va_list ap)
{
    if (sb->overflowed || sb->cap == 0) return;
    size_t remaining = sb->cap - sb->len;
    int n = vsnprintf(sb->buf + sb->len, remaining, fmt, ap);
    if (n < 0 || (size_t)n >= remaining) {
        sb->overflowed = 1;
        if (sb->cap > 0) sb->buf[sb->cap - 1] = '\0';
        return;
    }
    sb->len += (size_t)n;
}

static void sb_printf(strbuf_t *sb, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    sb_vprintf(sb, fmt, ap);
    va_end(ap);
}

/* --- register name tables --- */

static const char *reg64[16] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
};
static const char *reg32[16] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d","r11d","r12d","r13d","r14d","r15d"
};
static const char *reg16[16] = {
    "ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di",
    "r8w", "r9w", "r10w","r11w","r12w","r13w","r14w","r15w"
};
static const char *reg8_nohi[16] = {
    "al",  "cl",  "dl",  "bl",  "spl", "bpl", "sil", "dil",
    "r8b", "r9b", "r10b","r11b","r12b","r13b","r14b","r15b"
};

static const char *pick_reg(int w, int b16, int b8, int rex, int idx)
{
    if (w)   return reg64[idx & 15];
    if (b16) return reg16[idx & 15];
    if (b8)  return reg8_nohi[idx & 15];
    if (rex) return reg64[idx & 15];
    return reg32[idx & 15];
}

/* v1.6.0: render the r/m operand as a memory expression.
 * Caller guarantees mod != 3 (register form).
 * Writes "[base + index*scale + disp]" / "[rip+disp]" etc.
 * into sb; returns 0 on success, -1 if the operand shape is
 * something we don't render (e.g. 16-bit addressing). */
static int
render_rm_mem(strbuf_t *sb, const xdec_info_t *info, const uint8_t *buf)
{
    uint8_t mod = (info->modrm >> 6) & 3;
    uint8_t rm  = info->modrm & 7;
    int rex_b   = (info->rex >> 0) & 1;
    int rex_x   = (info->rex >> 1) & 1;

    const char *base_s  = NULL;
    const char *index_s = NULL;
    int scale = 1;

    if (info->sib_present) {
        uint8_t ss = (info->sib >> 6) & 3;
        uint8_t ix = (info->sib >> 3) & 7;
        uint8_t bs = info->sib & 7;
        scale = 1 << ss;
        /* base field == 5 + mod == 0 means "no base, disp32 only". */
        if (!(bs == 5 && mod == 0))
            base_s = reg64[(rex_b << 3) | bs];
        /* index field == 4 means "no index" (SIB encodes sp as no-index). */
        if (ix != 4 || rex_x)
            index_s = reg64[(rex_x << 3) | ix];
    } else {
        /* Non-SIB. mod=0 and rm=5 is RIP-relative on x86-64. */
        if (mod == 0 && rm == 5) {
            base_s = "rip";
        } else {
            base_s = reg64[(rex_b << 3) | rm];
        }
    }

    /* Read the displacement. In the ModR/M encoding, disp comes
     * BEFORE any immediate bytes, so the position is
     * info->length - imm_bytes - disp_bytes, not
     * info->length - disp_bytes. Got this wrong originally;
     * wasn't noticed because the opcodes wired through here
     * (MOV 0x8B/0x89, LEA 0x8D) have no immediate. Fixing pre-
     * emptively so ADD/SUB r/m, imm8 forms can land without
     * another trip through this function.
     *
     * Layout:
     *   opcode  modrm  [sib]  [disp]  [imm]
     *            └──────┬──────┘
     *                   bytes whose end is info->length - imm
     */
    int32_t disp = 0;
    int     disp_end = info->length - info->imm_bytes;
    if (info->disp_bytes == 1) {
        disp = (int8_t)buf[disp_end - 1];
    } else if (info->disp_bytes == 4) {
        disp = (int32_t)((uint32_t)buf[disp_end - 4] |
                         ((uint32_t)buf[disp_end - 3] << 8) |
                         ((uint32_t)buf[disp_end - 2] << 16) |
                         ((uint32_t)buf[disp_end - 1] << 24));
    }

    sb_printf(sb, "[");
    int need_plus = 0;
    if (base_s) { sb_printf(sb, "%s", base_s); need_plus = 1; }
    if (index_s) {
        sb_printf(sb, "%s%s", need_plus ? "+" : "", index_s);
        if (scale > 1) sb_printf(sb, "*%d", scale);
        need_plus = 1;
    }
    if (disp || !need_plus) {
        if (disp < 0) {
            sb_printf(sb, "-0x%x", (unsigned)(-disp));
        } else {
            sb_printf(sb, "%s0x%x",
                      need_plus ? "+" : "", (unsigned)disp);
        }
    }
    sb_printf(sb, "]");
    return 0;
}

/* v1.6.1: SSE register names. REX.R / REX.B extend to xmm8..15. */
static const char *xmm_regs[16] = {
    "xmm0", "xmm1", "xmm2",  "xmm3",  "xmm4",  "xmm5",  "xmm6",  "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15"
};

static const char *cmov_cc[16] = {
    "cmovo",  "cmovno", "cmovb",  "cmovnb", "cmovz",  "cmovnz",
    "cmovbe", "cmova",  "cmovs",  "cmovns", "cmovp",  "cmovnp",
    "cmovl",  "cmovnl", "cmovle", "cmovg"
};

static const char *bt_grp[4] = { "bt", "bts", "btr", "btc" };

/* --- per-instruction emission --- */

/* Returns length consumed; 0 or -1 on decode failure. */
static int emit_one(strbuf_t *sb, const uint8_t *buf, size_t max)
{
    /* ENDBR64 / ENDBR32 — the IBT landing pads. Recognised before the
     * generic decoder path so the output reads naturally. */
    if (max >= 4 && buf[0] == 0xF3 && buf[1] == 0x0F &&
        buf[2] == 0x1E && (buf[3] == 0xFA || buf[3] == 0xFB)) {
        sb_printf(sb, buf[3] == 0xFA ? "endbr64" : "endbr32");
        return 4;
    }

    xdec_info_t info;
    if (xdec_full(buf, max, &info) < 0) return -1;

    uint8_t op   = info.opcode;
    int     w    = info.rex_w;
    int     op66 = info.op66;

    if (info.map == 1) {
        /* PUSH reg (0x50 - 0x57) + REX.B for r8-r15. */
        if (op >= 0x50 && op <= 0x57) {
            int rex_b = (info.rex >> 0) & 1;
            sb_printf(sb, "push %s",
                      pick_reg(1, op66, 0, info.rex,
                               (op - 0x50) | (rex_b << 3)));
            return info.length;
        }
        /* POP reg (0x58 - 0x5F) + REX.B for r8-r15. */
        if (op >= 0x58 && op <= 0x5F) {
            int rex_b = (info.rex >> 0) & 1;
            sb_printf(sb, "pop %s",
                      pick_reg(1, op66, 0, info.rex,
                               (op - 0x58) | (rex_b << 3)));
            return info.length;
        }
        if (op == 0x90) { sb_printf(sb, "nop"); return info.length; }
        if (op >= 0x91 && op <= 0x97) {
            sb_printf(sb, "xchg %s, %s",
                      pick_reg(w, op66, 0, info.rex, 0),
                      pick_reg(w, op66, 0, info.rex, op - 0x90));
            return info.length;
        }
        if (op == 0xC3) { sb_printf(sb, "ret");  return info.length; }
        if (op == 0xCB) { sb_printf(sb, "retf"); return info.length; }
        if (op == 0xC2) {
            uint16_t imm = (uint16_t)buf[info.length - 2]
                         | ((uint16_t)buf[info.length - 1] << 8);
            sb_printf(sb, "ret 0x%x", imm);
            return info.length;
        }
        if (op == 0xCA) {
            uint16_t imm = (uint16_t)buf[info.length - 2]
                         | ((uint16_t)buf[info.length - 1] << 8);
            sb_printf(sb, "retf 0x%x", imm);
            return info.length;
        }
        if (op == 0xC9) { sb_printf(sb, "leave"); return info.length; }
        if (op == 0xCC) { sb_printf(sb, "int3");  return info.length; }
        if (op == 0xCD) {
            sb_printf(sb, "int 0x%x", buf[info.length - 1]);
            return info.length;
        }
        if (op == 0xEB) { sb_printf(sb, "jmp rel8");   return info.length; }
        if (op == 0xE9) { sb_printf(sb, "jmp rel32");  return info.length; }
        if (op == 0xE8) { sb_printf(sb, "call rel32"); return info.length; }
        if (op == 0xFF) {
            uint8_t reg = (info.modrm >> 3) & 7;
            uint8_t mod = info.modrm >> 6;
            uint8_t rm  = info.modrm & 7;
            const char *mnemo = (reg == 2 || reg == 3) ? "call" : "jmp";
            if (mod == 3) {
                sb_printf(sb, "%s %s", mnemo,
                          pick_reg(1, 0, 0, info.rex, rm));
            } else {
                sb_printf(sb, "%s [mem]", mnemo);
            }
            return info.length;
        }
        if (op >= 0xB0 && op <= 0xB7) {
            sb_printf(sb, "mov %s, 0x%x",
                      reg8_nohi[op - 0xB0],
                      buf[info.length - 1]);
            return info.length;
        }
        if (op >= 0xB8 && op <= 0xBF) {
            sb_printf(sb, "mov %s, imm",
                      pick_reg(w, op66, 0, info.rex, op - 0xB8));
            return info.length;
        }
        if (op == 0x89 || op == 0x8B) {
            int rex_r   = (info.rex >> 2) & 1;
            uint8_t reg = ((info.modrm >> 3) & 7) | (rex_r << 3);
            if ((info.modrm >> 6) == 3) {
                int rex_b = (info.rex >> 0) & 1;
                uint8_t rm = (info.modrm & 7) | (rex_b << 3);
                const char *dst = (op == 0x89) ? pick_reg(w, op66, 0, info.rex, rm)
                                               : pick_reg(w, op66, 0, info.rex, reg);
                const char *src = (op == 0x89) ? pick_reg(w, op66, 0, info.rex, reg)
                                               : pick_reg(w, op66, 0, info.rex, rm);
                sb_printf(sb, "mov %s, %s", dst, src);
                return info.length;
            }
            /* v1.6.0: memory form — mov reg, [r/m] / mov [r/m], reg. */
            const char *rreg = pick_reg(w, op66, 0, info.rex, reg);
            if (op == 0x89) {
                /* dst is memory */
                sb_printf(sb, "mov ");
                render_rm_mem(sb, &info, buf);
                sb_printf(sb, ", %s", rreg);
            } else {
                sb_printf(sb, "mov %s, ", rreg);
                render_rm_mem(sb, &info, buf);
            }
            return info.length;
        }
        /* v5.1 polish: generic ALU reg + r/m render for the
         * eight primary-map opcode pairs that follow the same
         * encoding (op = store-form, op+2 = load-form).
         *   01/03  ADD
         *   09/0B  OR
         *   21/23  AND
         *   29/2B  SUB
         *   31/33  XOR
         *   39/3B  CMP
         *   11/13  ADC (not ROP-common but cheap)
         *   19/1B  SBB  ditto
         * For each, mod=3 renders "mnemo dst, src" reg-reg;
         * mod<3 renders through render_rm_mem. */
        {
            static const struct { uint8_t store, load; const char *name; } alu[] = {
                { 0x01, 0x03, "add" }, { 0x09, 0x0B, "or"  },
                { 0x11, 0x13, "adc" }, { 0x19, 0x1B, "sbb" },
                { 0x21, 0x23, "and" }, { 0x29, 0x2B, "sub" },
                { 0x31, 0x33, "xor" }, { 0x39, 0x3B, "cmp" },
            };
            for (size_t ai = 0; ai < sizeof alu / sizeof alu[0]; ai++) {
                if (op != alu[ai].store && op != alu[ai].load) continue;
                int is_store = (op == alu[ai].store);
                int rex_r = (info.rex >> 2) & 1;
                int rex_b = (info.rex >> 0) & 1;
                uint8_t reg = ((info.modrm >> 3) & 7) | (rex_r << 3);
                uint8_t rm  = (info.modrm & 7)        | (rex_b << 3);
                if ((info.modrm >> 6) == 3) {
                    const char *d = is_store ? pick_reg(w, op66, 0, info.rex, rm)
                                             : pick_reg(w, op66, 0, info.rex, reg);
                    const char *s = is_store ? pick_reg(w, op66, 0, info.rex, reg)
                                             : pick_reg(w, op66, 0, info.rex, rm);
                    sb_printf(sb, "%s %s, %s", alu[ai].name, d, s);
                    return info.length;
                }
                /* memory form */
                const char *rreg = pick_reg(w, op66, 0, info.rex, reg);
                if (is_store) {
                    sb_printf(sb, "%s ", alu[ai].name);
                    render_rm_mem(sb, &info, buf);
                    sb_printf(sb, ", %s", rreg);
                } else {
                    sb_printf(sb, "%s %s, ", alu[ai].name, rreg);
                    render_rm_mem(sb, &info, buf);
                }
                return info.length;
            }
        }
        /* LEA r, [base+index*scale+disp] — full operand render now. */
        if (op == 0x8D && (info.modrm >> 6) != 3) {
            int rex_r   = (info.rex >> 2) & 1;
            uint8_t reg = ((info.modrm >> 3) & 7) | (rex_r << 3);
            sb_printf(sb, "lea %s, ", pick_reg(w, op66, 0, info.rex, reg));
            render_rm_mem(sb, &info, buf);
            return info.length;
        }
        if (op == 0xF4) { sb_printf(sb, "hlt"); return info.length; }
    } else if (info.map == 2) {
        if (op == 0x05) { sb_printf(sb, "syscall"); return info.length; }
        if (op == 0x07) { sb_printf(sb, "sysret");  return info.length; }

        /* CMOVcc reg, reg  (0F 40..4F, mod=11) */
        if (op >= 0x40 && op <= 0x4F && (info.modrm >> 6) == 3) {
            uint8_t reg = (info.modrm >> 3) & 7;
            uint8_t rm  = info.modrm & 7;
            sb_printf(sb, "%s %s, %s", cmov_cc[op - 0x40],
                      pick_reg(w, op66, 0, info.rex, reg),
                      pick_reg(w, op66, 0, info.rex, rm));
            return info.length;
        }

        /* SHLD r/m, r, imm8 (0F A4) — reg-reg form only */
        if (op == 0xA4 && (info.modrm >> 6) == 3) {
            uint8_t reg = (info.modrm >> 3) & 7;
            uint8_t rm  = info.modrm & 7;
            sb_printf(sb, "shld %s, %s, 0x%x",
                      pick_reg(w, op66, 0, info.rex, rm),
                      pick_reg(w, op66, 0, info.rex, reg),
                      buf[info.length - 1]);
            return info.length;
        }

        /* SHRD r/m, r, imm8 (0F AC) */
        if (op == 0xAC && (info.modrm >> 6) == 3) {
            uint8_t reg = (info.modrm >> 3) & 7;
            uint8_t rm  = info.modrm & 7;
            sb_printf(sb, "shrd %s, %s, 0x%x",
                      pick_reg(w, op66, 0, info.rex, rm),
                      pick_reg(w, op66, 0, info.rex, reg),
                      buf[info.length - 1]);
            return info.length;
        }

        /* BT / BTS / BTR / BTC r/m, imm8 (0F BA, reg field selects op) */
        if (op == 0xBA && (info.modrm >> 6) == 3) {
            uint8_t reg = (info.modrm >> 3) & 7;
            uint8_t rm  = info.modrm & 7;
            if (reg >= 4 && reg <= 7) {
                sb_printf(sb, "%s %s, 0x%x",
                          bt_grp[reg - 4],
                          pick_reg(w, op66, 0, info.rex, rm),
                          buf[info.length - 1]);
                return info.length;
            }
        }

        /* v1.6.1: SSE moves and common XOR appearing in epilogues.
         * We recognise the non-VEX encodings; VEX-prefixed AVX
         * (C4/C5 prefix) stays in a future patch bump alongside
         * the mask-register work. */
        {
            int rex_r   = (info.rex >> 2) & 1;
            int rex_b   = (info.rex >> 0) & 1;
            uint8_t mod = (info.modrm >> 6) & 3;
            uint8_t reg = ((info.modrm >> 3) & 7) | (rex_r << 3);
            uint8_t rm  = (info.modrm & 7) | (rex_b << 3);

            /* MOVAPS / MOVAPD / MOVDQA — 0F 28 / 0F 29 (aps),
             * 66 0F 28 / 66 0F 29 (apd), 66 0F 6F / 66 0F 7F (dqa).
             * MOVUPS 0F 10 / 0F 11 likewise but non-aligned. */
            const char *mnemo = NULL;
            int store = 0;     /* destination is memory */
            if (op == 0x28) { mnemo = op66 ? "movapd" : "movaps"; store = 0; }
            else if (op == 0x29) { mnemo = op66 ? "movapd" : "movaps"; store = 1; }
            else if (op == 0x10) { mnemo = op66 ? "movupd" : "movups"; store = 0; }
            else if (op == 0x11) { mnemo = op66 ? "movupd" : "movups"; store = 1; }
            else if (op == 0x6F && op66) { mnemo = "movdqa"; store = 0; }
            else if (op == 0x7F && op66) { mnemo = "movdqa"; store = 1; }
            else if (op == 0xEF)         { mnemo = op66 ? "pxor" : "pxor"; store = 0; }

            if (mnemo) {
                if (mod == 3) {
                    const char *dst = store ? xmm_regs[rm]  : xmm_regs[reg];
                    const char *src = store ? xmm_regs[reg] : xmm_regs[rm];
                    sb_printf(sb, "%s %s, %s", mnemo, dst, src);
                } else {
                    if (store) {
                        sb_printf(sb, "%s ", mnemo);
                        render_rm_mem(sb, &info, buf);
                        sb_printf(sb, ", %s", xmm_regs[reg]);
                    } else {
                        sb_printf(sb, "%s %s, ", mnemo, xmm_regs[reg]);
                        render_rm_mem(sb, &info, buf);
                    }
                }
                return info.length;
            }
        }
    }

    /* Unknown: emit raw bytes */
    sb_printf(sb, "db");
    for (int i = 0; i < info.length; i++) {
        sb_printf(sb, " 0x%02x%s", buf[i], i + 1 < info.length ? "," : "");
    }
    return info.length;
}

/* --- AArch64 per-instruction emission --- */

static int emit_one_a64(strbuf_t *sb, const uint8_t *buf, size_t max)
{
    if (max < 4) return -1;
    uint32_t insn = arm64_read_insn(buf);
    char local[64];
    int n = arm64_render_insn(local, sizeof local, insn);
    if (n < 0) n = snprintf(local, sizeof local, ".word 0x%08x", insn);
    sb_printf(sb, "%s", local);
    return 4;
}

/* --- RISC-V per-instruction emission (terminator mnemonics only) --- */

static int emit_one_rv(strbuf_t *sb, const uint8_t *buf, size_t max)
{
    size_t len = riscv_insn_len(buf, max);
    if (len == 0) return -1;
    riscv_term_t k = riscv_classify_terminator(buf, len);

    if (len == 2) {
        uint16_t h = (uint16_t)(buf[0] | (buf[1] << 8));
        uint32_t rs1 = (h >> 7) & 0x1f;
        if (k == RV_TERM_C_JR && rs1 == 1) { sb_printf(sb, "ret"); return 2; }
        if (k == RV_TERM_C_JR)   { sb_printf(sb, "c.jr x%u", (unsigned)rs1); return 2; }
        if (k == RV_TERM_C_JALR) { sb_printf(sb, "c.jalr x%u", (unsigned)rs1); return 2; }
        sb_printf(sb, ".hword 0x%04x", (unsigned)h);
        return 2;
    }

    /* 4-byte */
    uint32_t w = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
                 ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    switch (k) {
    case RV_TERM_JALR: {
        uint32_t rd  = (w >> 7)  & 0x1f;
        uint32_t rs1 = (w >> 15) & 0x1f;
        int      imm = (int)(w >> 20);
        if (imm & 0x800) imm -= 0x1000;
        if (rd == 0 && rs1 == 1 && imm == 0) sb_printf(sb, "ret");
        else sb_printf(sb, "jalr x%u, x%u, %d",
                        (unsigned)rd, (unsigned)rs1, imm);
        return 4;
    }
    case RV_TERM_ECALL:  sb_printf(sb, "ecall");  return 4;
    case RV_TERM_EBREAK: sb_printf(sb, "ebreak"); return 4;
    case RV_TERM_MRET:   sb_printf(sb, "mret");   return 4;
    case RV_TERM_SRET:   sb_printf(sb, "sret");   return 4;
    default: break;
    }
    sb_printf(sb, ".word 0x%08x", (unsigned)w);
    return 4;
}

/* --- public API --- */

static void render_insns(strbuf_t *sb, const gadget_t *g)
{
    size_t p = 0;
    int    first = 1;

    while (p < g->length) {
        if (!first) sb_printf(sb, " ; ");
        int n;
        if (g->machine == EM_AARCH64)
            n = emit_one_a64(sb, g->bytes + p, g->length - p);
        else if (g->machine == EM_RISCV)
            n = emit_one_rv(sb, g->bytes + p, g->length - p);
        else if (g->machine == EM_PPC64) {
            if (g->length - p < 4) { sb_printf(sb, "?"); return; }
            char local[64];
            uint32_t insn = ppc64_read_insn(g->bytes + p);
            ppc64_render_insn(local, sizeof local, insn);
            sb_printf(sb, "%s", local);
            n = 4;
        } else if (g->machine == EM_MIPS ||
                   g->machine == EM_MIPS_RS3_LE) {
            if (g->length - p < 4) { sb_printf(sb, "?"); return; }
            char local[64];
            int le = (g->machine == EM_MIPS_RS3_LE);
            uint32_t insn = mips_read_insn(g->bytes + p, le);
            mips_render_insn(local, sizeof local, insn);
            sb_printf(sb, "%s", local);
            n = 4;
        } else
            n = emit_one(sb, g->bytes + p, g->length - p);
        if (n <= 0) { sb_printf(sb, "?"); return; }
        p += (size_t)n;
        first = 0;
    }
}

void format_gadget_insns(FILE *f, const gadget_t *g)
{
    char scratch[1024];
    strbuf_t sb = { scratch, sizeof scratch, 0, 0 };
    render_insns(&sb, g);
    fputs(scratch, f);
}

void format_gadget(FILE *f, const gadget_t *g)
{
    char scratch[1024];
    strbuf_t sb = { scratch, sizeof scratch, 0, 0 };
    sb_printf(&sb, "0x%016" PRIx64 ": ", g->vaddr);
    render_insns(&sb, g);
    fputs(scratch, f);
    fputc('\n', f);
}

int format_gadget_render(const gadget_t *g, char *buf, size_t buflen)
{
    strbuf_t sb = { buf, buflen, 0, 0 };
    sb_printf(&sb, "0x%016" PRIx64 ": ", g->vaddr);
    render_insns(&sb, g);
    if (sb.overflowed) return -1;
    return (int)sb.len;
}

/* --- canonical dedup key (v0.15.0) --- */

/* In-place substring rewrite: replace every non-overlapping `pat`
 * with `rep` inside nul-terminated `s`. `rep` length must be ≤ `pat`
 * length so we can do it in place. */
static void replace_inplace(char *s, const char *pat, const char *rep)
{
    size_t plen = strlen(pat), rlen = strlen(rep);
    if (rlen > plen) return;
    char *p;
    while ((p = strstr(s, pat)) != NULL) {
        memcpy(p, rep, rlen);
        memmove(p + rlen, p + plen, strlen(p + plen) + 1);
    }
}

int format_gadget_canonical_render(const gadget_t *g,
                                   char *buf, size_t buflen)
{
    int n = format_gadget_render(g, buf, buflen);
    if (n < 0) return -1;

    /* R1: retn/retf variants — only collapse the `0x0` imm form,
     * because `retn 0x8` is semantically different from `ret`. */
    replace_inplace(buf, "ret 0x0", "ret");
    replace_inplace(buf, "retf",    "ret");

    /* R2: zero-idiom collapse for common registers. */
    static const char *regs[] = {
        "rax","rcx","rdx","rbx","rbp","rsi","rdi",
        "r8","r9","r10","r11","r12","r13","r14","r15",
        "eax","ecx","edx","ebx","ebp","esi","edi",
        NULL
    };
    for (int i = 0; regs[i]; i++) {
        char pat[40], rep[24];
        snprintf(pat, sizeof pat, "xor %s, %s", regs[i], regs[i]);
        snprintf(rep, sizeof rep, "ZERO(%s)",  regs[i]);
        replace_inplace(buf, pat, rep);
    }

    return (int)strlen(buf);
}

/* --- JSON rendering --- */

static void json_escape_str(strbuf_t *sb, const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  sb_printf(sb, "\\\""); break;
        case '\\': sb_printf(sb, "\\\\"); break;
        case '\n': sb_printf(sb, "\\n");  break;
        case '\r': sb_printf(sb, "\\r");  break;
        case '\t': sb_printf(sb, "\\t");  break;
        default:
            if (c < 0x20) sb_printf(sb, "\\u%04x", c);
            else          sb_printf(sb, "%c", c);
        }
    }
}

/* Render a single instruction as a JSON string element (including the
 * surrounding quotes). Returns instruction length, or <= 0 on failure. */
static int emit_one_json(strbuf_t *sb, const uint8_t *buf, size_t max,
                         uint16_t machine)
{
    /* reuse the architecture emitter into a local strbuf, then escape */
    char local[128];
    strbuf_t inner = { local, sizeof local, 0, 0 };
    int n;
    if (machine == EM_AARCH64)      n = emit_one_a64(&inner, buf, max);
    else if (machine == EM_RISCV)   n = emit_one_rv(&inner, buf, max);
    else                            n = emit_one(&inner, buf, max);
    if (n <= 0) return n;

    sb_printf(sb, "\"");
    json_escape_str(sb, local);
    sb_printf(sb, "\"");
    return n;
}

static void render_json(strbuf_t *sb, const gadget_t *g)
{
    const char *arch_name = "x86_64";
    if (g->machine == EM_AARCH64) arch_name = "aarch64";
    else if (g->machine == EM_RISCV) arch_name = "riscv64";

    sb_printf(sb, "{\"addr\":\"0x%016" PRIx64 "\",\"arch\":\"%s\","
                  "\"insns\":[",
              g->vaddr, arch_name);
    size_t p = 0;
    int    first = 1;
    while (p < g->length) {
        if (!first) sb_printf(sb, ",");
        int n = emit_one_json(sb, g->bytes + p, g->length - p,
                              g->machine);
        if (n <= 0) { if (!first) sb_printf(sb, "\"?\""); break; }
        p += (size_t)n;
        first = 0;
    }
    sb_printf(sb, "],\"bytes\":\"");
    for (size_t i = 0; i < g->length; i++) {
        sb_printf(sb, "%s%02x", i ? " " : "", g->bytes[i]);
    }
    sb_printf(sb, "\",\"insn_count\":%d", g->insn_count);
    sb_printf(sb, ",\"shstk_blocked\":%s",
              cet_shstk_blocked(g) ? "true" : "false");
    sb_printf(sb, ",\"starts_endbr\":%s}",
              cet_starts_endbr(g) ? "true" : "false");
}

void format_gadget_json(FILE *f, const gadget_t *g)
{
    char scratch[2048];
    strbuf_t sb = { scratch, sizeof scratch, 0, 0 };
    render_json(&sb, g);
    fputs(scratch, f);
    fputc('\n', f);
}

int format_gadget_json_render(const gadget_t *g, char *buf, size_t buflen)
{
    strbuf_t sb = { buf, buflen, 0, 0 };
    render_json(&sb, g);
    if (sb.overflowed) return -1;
    return (int)sb.len;
}
