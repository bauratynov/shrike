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
#include <shrike/insn_effect.h>
#include <shrike/format.h>
#include <shrike/elf64.h>
#include <shrike/arm64.h>
#include <shrike/riscv.h>
#include <shrike/xdec.h>

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

        /* v5.4.0: PAC classification. AUT* inside a gadget
         * body means the chain needs a valid sign oracle or
         * dies to FPAC. PAC* inside = sign oracle primitive. */
        arm64_pac_t pac = arm64_pac_kind(insn);
        if (pac != ARM64_PAC_NONE) {
            if (pac >= ARM64_PAC_AUTIA && pac <= ARM64_PAC_AUTDB) {
                out->has_pac_auth = 1;
            } else {
                out->has_pac_sign = 1;
            }
            p += 4;
            continue;
        }

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
        /* ret (xn) — generally ret x30. RETAA/RETAB also implicit
         * PAC auth on the return address; flag it too. */
        if (arm64_is_terminator(insn)) {
            /* RETAA = 0xD65F0BFF, RETAB = 0xD65F0FFF — the
             * Ab-authenticated variants perform an AUTIA/AUTIB
             * implicitly on x30. Mark them. */
            if ((insn & 0xFFFFFBFFu) == 0xD65F0BFFu) {
                out->has_pac_auth = 1;
            }
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

/* v2.1.2: dispatcher classifier. We walk the gadget once,
 * track the last indirect-branch terminator plus the x86
 * ModR/M target register (or the aarch64 Xn / RV64 rs1), and
 * check whether an earlier insn wrote that register. Tight
 * scope — full Bletsch dispatcher detection (loop-carried
 * memory cursor) is in V3's semantic-depth sprints. */
int
gadget_is_dispatcher(const gadget_t *g, gadget_term_t which)
{
    if (!g || g->length == 0) return 0;

    size_t pos = 0;
    uint32_t writes_so_far = 0;
    int target = -1;      /* reg used by the branch, or -1 if unknown */

    while (pos < g->length) {
        insn_effect_t ie;
        int n = insn_effect_decode(g->bytes + pos, g->length - pos,
                                   g->machine, &ie);
        /* Unknown instruction — step past it using a length-only
         * decoder so the dispatcher-shape walker can still span
         * gadgets whose middle contains mov/lea/add shapes we
         * haven't yet taught insn_effect_decode about. */
        if (n <= 0) {
            int step = 0;
            if (g->machine == EM_X86_64) {
                xdec_info_t xi;
                if (xdec_full(g->bytes + pos, g->length - pos, &xi) < 0 ||
                    xi.length <= 0) break;
                step = xi.length;
                /* A memory-source MOV (0x8B) or LEA (0x8D) writes
                 * the destination reg — conservatively mark it
                 * so the dispatcher shape registers even though
                 * insn_effect_decode doesn't yet enumerate every
                 * MOV form. REX.R extends the reg field. */
                if ((xi.opcode == 0x8B || xi.opcode == 0x8D) &&
                    xi.has_modrm) {
                    int rex_r = (xi.rex >> 2) & 1;
                    int reg = ((xi.modrm >> 3) & 7) | (rex_r << 3);
                    writes_so_far |= 1u << reg;
                }
            } else if (g->machine == EM_AARCH64) {
                step = 4;
            } else if (g->machine == EM_RISCV) {
                step = (int)riscv_insn_len(g->bytes + pos,
                                           g->length - pos);
                if (step <= 0) break;
            } else {
                break;
            }
            pos += (size_t)step;
            continue;
        }

        if (ie.terminator == which) {
            /* Work out which register the branch consumed.
             * For x86, FF /4 and FF /5 carry rm in the ModR/M;
             * we need to peek at the decoded bytes. */
            if (g->machine == EM_X86_64) {
                if (pos + 1 < g->length && g->bytes[pos] == 0xFF) {
                    uint8_t modrm = g->bytes[pos + 1];
                    target = modrm & 7;
                    /* REX.B on preceding byte extends it. */
                    if (pos > 0 && (g->bytes[pos - 1] & 0xF0) == 0x40 &&
                        (g->bytes[pos - 1] & 0x01)) {
                        target |= 8;
                    }
                }
            } else if (g->machine == EM_AARCH64) {
                if (pos + 4 <= g->length) {
                    uint32_t insn = arm64_read_insn(g->bytes + pos);
                    target = (int)((insn >> 5) & 0x1f);
                }
            } else if (g->machine == EM_RISCV) {
                /* Two cases:
                 *   32-bit JALR — rs1 at bits 19..15
                 *   16-bit c.jr/c.jalr — rs1 at bits 11..7
                 * ie.length tells us which encoding we're on. */
                if (ie.length == 4 && pos + 4 <= g->length) {
                    uint32_t w = (uint32_t)g->bytes[pos] |
                                 ((uint32_t)g->bytes[pos + 1] << 8) |
                                 ((uint32_t)g->bytes[pos + 2] << 16) |
                                 ((uint32_t)g->bytes[pos + 3] << 24);
                    target = (int)((w >> 15) & 0x1f);
                } else if (pos + 2 <= g->length) {
                    uint16_t h = (uint16_t)(g->bytes[pos] |
                                            (g->bytes[pos + 1] << 8));
                    target = (int)((h >> 7) & 0x1f);
                }
            }
            break;
        }

        writes_so_far |= ie.writes_mask;
        pos += (size_t)n;
    }

    if (target < 0 || target >= 32) return 0;
    return (writes_so_far >> target) & 1;
}

/* v2.1.4: minimum-viable DOP detector.
 * Scan for MOV [reg], reg (opcode 0x89, mod != 3) where the
 * base register was previously written from memory (MOV reg,
 * [...] earlier in the same gadget). Gadget must end in RET
 * — a control-flow break would take us out of the DOP
 * scheduler loop. Scope: x86 only; aarch64/RV64 DOP shapes
 * come later. */
int
gadget_is_dop_write(const gadget_t *g)
{
    if (!g || g->machine != EM_X86_64 || g->length == 0) return 0;

    size_t pos = 0;
    uint32_t loaded_from_mem = 0;
    int ends_ret = 0;

    while (pos < g->length) {
        xdec_info_t xi;
        if (xdec_full(g->bytes + pos, g->length - pos, &xi) < 0) break;
        int step = xi.length;
        if (step <= 0) break;

        /* MOV reg, [r/m]  — 0x8B, mod != 3 → destination loaded
         * from memory, flag the dst register. */
        if (xi.opcode == 0x8B && xi.has_modrm && (xi.modrm >> 6) != 3) {
            int rex_r = (xi.rex >> 2) & 1;
            int reg = ((xi.modrm >> 3) & 7) | (rex_r << 3);
            loaded_from_mem |= 1u << reg;
        }
        /* MOV [r/m], reg — 0x89, mod != 3 → store to memory
         * whose base register came from an earlier mem load.
         * That's the DOP arbitrary-write primitive. */
        if (xi.opcode == 0x89 && xi.has_modrm && (xi.modrm >> 6) != 3) {
            int rex_b = (xi.rex >> 0) & 1;
            uint8_t mod = (xi.modrm >> 6) & 3;
            uint8_t rm = xi.modrm & 7;
            int base = -1;
            if (xi.sib_present) {
                /* base field 5 + mod 0 = disp32-only; reject. */
                uint8_t bs = xi.sib & 7;
                if (!(bs == 5 && mod == 0)) base = bs | (rex_b << 3);
            } else if (!(mod == 0 && rm == 5)) {
                base = rm | (rex_b << 3);
            }
            if (base >= 0 && ((loaded_from_mem >> base) & 1)) {
                /* We have the write. Make sure the gadget ends
                 * in a plain RET, not a branch out of the DOP
                 * scheduler. */
                size_t p = pos + (size_t)step;
                while (p < g->length) {
                    xdec_info_t ti;
                    if (xdec_full(g->bytes + p, g->length - p, &ti) < 0)
                        break;
                    if (ti.opcode == 0xC3) { ends_ret = 1; break; }
                    if (ti.opcode == 0xCB) { ends_ret = 1; break; }
                    if (ti.length <= 0) break;
                    p += (size_t)ti.length;
                }
                return ends_ret ? 1 : 0;
            }
        }
        pos += (size_t)step;
    }
    return 0;
}

/* v2.1.1: compositional walk. Calls insn_effect_decode once per
 * instruction and merges the per-insn record into the gadget
 * total:
 *   - reads:  set the first time any instruction reads a reg,
 *             but *only before* that reg has been written by
 *             an earlier instruction in the same gadget (so the
 *             first write hides future reads from the total).
 *   - writes: union of all write masks.
 *   - stack_consumed: sum of per-insn stack_delta (clamped at
 *             0 — negative deltas flag a pivot instead).
 *   - terminator: taken from the last insn that has one set.
 *   - has_syscall: terminator == GADGET_TERM_SYSCALL.
 */
int
gadget_effect_compose(const gadget_t *g, gadget_effect_t *out)
{
    memset(out, 0, sizeof *out);
    if (!g || g->length == 0) return 0;

    size_t pos = 0;
    int count = 0;
    int32_t stack = 0;

    while (pos < g->length) {
        insn_effect_t ie;
        int n = insn_effect_decode(g->bytes + pos, g->length - pos,
                                   g->machine, &ie);
        if (n <= 0) return -1;
        if ((ie.flags & INSN_EFFECT_KNOWN) == 0) return -1;

        /* Reads before first write hide behind later writes. */
        uint32_t new_reads = ie.reads_mask & ~out->writes_mask;
        out->reads_mask  |= new_reads;
        out->writes_mask |= ie.writes_mask;
        stack            += ie.stack_delta;

        if (ie.terminator != GADGET_TERM_NONE) {
            out->terminator = ie.terminator;
            if (ie.terminator == GADGET_TERM_SYSCALL) {
                out->has_syscall = 1;
            }
        }

        pos += (size_t)n;
        count++;
        /* Stop at the first terminator — chain synthesizer
         * only cares about effect up to control-flow exit. */
        if (ie.terminator != GADGET_TERM_NONE) break;
    }

    if (stack > 0) out->stack_consumed = (uint32_t)stack;
    else if (stack < 0) out->is_pivot  = 1;

    return count;
}
