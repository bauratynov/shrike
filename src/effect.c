/*
 * effect.c — compute gadget_effect_t per architecture.
 *
 * Kept narrow on purpose. Each arch gets a small linear walker
 * that recognises the shapes the chain synthesizer actually
 * relies on:
 *   - x86-64: pop <reg> ; ...; ret           (reg -> writes_mask)
 *             syscall / int3
 *             ret <imm>                      (stack_consumed bump)
 *             jmp/call <reg> / indirect      (JOP / COP)
 *   - aarch64: ldp x_lo, x_hi, [sp], #imm ; ret
 *              svc / brk / br/blr
 *   - RV64:   ld reg, imm(sp) ; ...; ret
 *             c.ldsp reg, imm(sp) ; ...; ret
 *             ecall / ebreak
 *             addi sp, sp, imm               (stack_consumed)
 *
 * Anything we don't recognise leaves that field zero — the
 * synthesizer treats a gadget with terminator GADGET_TERM_NONE
 * as "don't use me."
 */

#include <shrike/effect.h>
#include <shrike/format.h>
#include <shrike/elf64.h>
#include <shrike/arm64.h>
#include <shrike/riscv.h>

#include <stdint.h>
#include <string.h>

/* ------------------ x86-64 ------------------ */

static int compute_x86(const gadget_t *g, gadget_effect_t *out)
{
    size_t p = 0;
    uint32_t writes = 0;
    uint32_t stack = 0;
    gadget_term_t term = GADGET_TERM_NONE;

    while (p < g->length) {
        uint8_t b = g->bytes[p];
        /* single-byte push N (we don't emit gadgets starting with
         * push in practice, but tolerate them for robustness). */
        if (b >= 0x58 && b <= 0x5F) {
            writes |= 1u << (b - 0x58);
            stack += 8;
            p += 1;
        } else if (b == 0x41 && p + 1 < g->length &&
                   g->bytes[p + 1] >= 0x58 && g->bytes[p + 1] <= 0x5F) {
            writes |= 1u << (8 + (g->bytes[p + 1] - 0x58));
            stack += 8;
            p += 2;
        } else if (b == 0xC3) {
            term = GADGET_TERM_RET;
            stack += 8;
            p += 1;
            break;
        } else if (b == 0xC2 && p + 2 < g->length) {
            /* ret imm16 */
            term = GADGET_TERM_RET;
            stack += 8 + (uint32_t)g->bytes[p + 1] +
                    ((uint32_t)g->bytes[p + 2] << 8);
            p += 3;
            break;
        } else if (b == 0x0F && p + 1 < g->length &&
                   g->bytes[p + 1] == 0x05) {
            term = GADGET_TERM_SYSCALL;
            out->has_syscall = 1;
            p += 2;
            break;
        } else if (b == 0xCC) {
            term = GADGET_TERM_INT;
            p += 1;
            break;
        } else if (b == 0xFF && p + 1 < g->length) {
            /* FF /2 (call rN), FF /3 (far call), FF /4 (jmp rN),
             * FF /5 (far jmp) — classify by the ModR/M reg field. */
            uint8_t modrm = g->bytes[p + 1];
            uint8_t rr = (modrm >> 3) & 0x7;
            if (rr == 2 || rr == 3) term = GADGET_TERM_CALL_REG;
            else if (rr == 4 || rr == 5) term = GADGET_TERM_JMP_REG;
            /* length depends on ModR/M/SIB/disp — we don't care
             * past the terminator, since the effect record only
             * describes what got done before the branch. */
            p = g->length;
            break;
        } else {
            /* Unknown prefix: abandon — conservative default is
             * "we don't know what effect this gadget has." */
            out->terminator   = GADGET_TERM_NONE;
            out->writes_mask  = 0;
            out->stack_consumed = 0;
            return 0;
        }
    }

    out->writes_mask    = writes;
    out->reads_mask     = 0;
    out->stack_consumed = stack;
    out->terminator     = term;
    return 0;
}

/* ------------------ AArch64 ------------------ */

static int compute_a64(const gadget_t *g, gadget_effect_t *out)
{
    /* Only the pure `ldp Xa, Xb, [sp], #imm ; ... ; ret` shape
     * that regidx already recognises — but we compute a proper
     * writes_mask + stack_consumed instead of just crediting
     * destinations one by one. */
    size_t p = 0;
    uint32_t writes = 0;
    uint32_t stack = 0;
    gadget_term_t term = GADGET_TERM_NONE;

    while (p + 4 <= g->length) {
        uint32_t insn = arm64_read_insn(g->bytes + p);

        /* ldp <Xt1>, <Xt2>, [sp], #imm  post-index form
         *   1010 1000 11 | imm7 | Rt2 | Rn=11111(sp) | Rt1  */
        if ((insn & 0xffc003e0u) == 0xa8c003e0u) {
            uint32_t rt1 = insn & 0x1f;
            uint32_t rt2 = (insn >> 10) & 0x1f;
            int imm7 = (int)((insn >> 15) & 0x7f);
            if (imm7 & 0x40) imm7 -= 0x80;   /* sign extend */
            writes |= 1u << rt1;
            writes |= 1u << rt2;
            stack  += (uint32_t)(imm7 * 8);
            p += 4;
            continue;
        }
        /* ret (xn) — generally ret x30 */
        if (arm64_is_terminator(insn)) {
            term = GADGET_TERM_RET;
            if ((insn & 0xFFE0001Fu) == 0xD4000001u) {
                term = GADGET_TERM_SYSCALL;
                out->has_syscall = 1;
            } else if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) {
                term = GADGET_TERM_JMP_REG;
            } else if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) {
                term = GADGET_TERM_CALL_REG;
            }
            p += 4;
            break;
        }

        /* Unknown instruction in the chain → bail conservatively. */
        out->terminator = GADGET_TERM_NONE;
        return 0;
    }

    out->writes_mask    = writes;
    out->stack_consumed = stack;
    out->terminator     = term;
    return 0;
}

/* ------------------ RV64 ------------------ */

static int compute_rv(const gadget_t *g, gadget_effect_t *out)
{
    size_t p = 0;
    uint32_t writes = 0;
    int32_t sp_delta = 0;
    gadget_term_t term = GADGET_TERM_NONE;

    while (p + 2 <= g->length) {
        size_t il = riscv_insn_len(g->bytes + p, g->length - p);
        if (il == 0) break;

        if (il == 4) {
            uint32_t w = (uint32_t)g->bytes[p] |
                         ((uint32_t)g->bytes[p + 1] << 8) |
                         ((uint32_t)g->bytes[p + 2] << 16) |
                         ((uint32_t)g->bytes[p + 3] << 24);
            uint32_t opcode = w & 0x7f;
            uint32_t funct3 = (w >> 12) & 0x7;
            uint32_t rs1    = (w >> 15) & 0x1f;
            uint32_t rd     = (w >> 7)  & 0x1f;

            /* ld rd, imm(sp) */
            if (opcode == 0x03 && funct3 == 0x3 && rs1 == 2) {
                if (rd != 0) writes |= 1u << rd;
                p += il;
                continue;
            }
            /* addi sp, sp, imm  -- sign-extend imm12 */
            if (opcode == 0x13 && funct3 == 0 && rd == 2 && rs1 == 2) {
                int32_t imm = (int32_t)(w >> 20);
                if (imm & 0x800) imm -= 0x1000;
                sp_delta += imm;
                p += il;
                continue;
            }
            if (riscv_is_ret(g->bytes + p, il)) {
                term = GADGET_TERM_RET;
                p += il;
                break;
            }
            riscv_term_t rt = riscv_classify_terminator(g->bytes + p, il);
            if (rt == RV_TERM_ECALL) {
                term = GADGET_TERM_SYSCALL;
                out->has_syscall = 1;
                p += il; break;
            }
            if (rt == RV_TERM_EBREAK) { term = GADGET_TERM_INT; p += il; break; }
            if (rt == RV_TERM_JALR)   { term = GADGET_TERM_CALL_REG; p += il; break; }
            if (rt != RV_TERM_NONE)   { term = GADGET_TERM_RET; p += il; break; }

            /* Unknown non-terminator instruction → bail. */
            out->terminator = GADGET_TERM_NONE;
            return 0;
        } else {
            uint16_t h = (uint16_t)(g->bytes[p] | (g->bytes[p + 1] << 8));
            /* c.ldsp rd, imm(sp): funct3=011, op=10 */
            if ((h & 0xe003) == 0x6002) {
                uint32_t rd = (h >> 7) & 0x1f;
                if (rd != 0) writes |= 1u << rd;
                p += 2; continue;
            }
            if (riscv_is_ret(g->bytes + p, 2)) {
                term = GADGET_TERM_RET; p += 2; break;
            }
            riscv_term_t rt = riscv_classify_terminator(g->bytes + p, 2);
            if (rt == RV_TERM_C_JR)   { term = GADGET_TERM_JMP_REG; p += 2; break; }
            if (rt == RV_TERM_C_JALR) { term = GADGET_TERM_CALL_REG; p += 2; break; }

            out->terminator = GADGET_TERM_NONE;
            return 0;
        }
    }

    /* stack_consumed reports bytes actually consumed — for
     * `addi sp, sp, +N ; ret` that's N (plus nothing for ret,
     * since RISC-V ret doesn't pop anything). For `addi sp, sp,
     * -N` we treat that as a pivot signal rather than a negative
     * consumption (which doesn't make sense as an unsigned). */
    if (sp_delta > 0) out->stack_consumed = (uint32_t)sp_delta;
    else if (sp_delta < 0) out->is_pivot = 1;

    out->writes_mask = writes;
    out->terminator  = term;
    return 0;
}

int
gadget_effect_compute(const gadget_t *g, gadget_effect_t *out)
{
    memset(out, 0, sizeof *out);
    if (!g || g->length == 0) return 0;

    if (g->machine == EM_AARCH64) return compute_a64(g, out);
    if (g->machine == EM_RISCV)   return compute_rv(g, out);
    return compute_x86(g, out);
}
