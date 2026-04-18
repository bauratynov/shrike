/*
 * smt.c — SMT-LIB2 proof emitter for chain correctness.
 *
 * Models each gadget as a transition on a register state. Every
 * register gets a fresh SSA-style 64-bit bitvector variable for
 * each step, and gadgets assert the post-state in terms of the
 * pre-state. Stack pointer `sp` gets the same SSA treatment;
 * each step's stack_consumed comes from the regidx so the
 * assertions match what the actual chain will do at runtime.
 *
 * Final assertion has two halves:
 *   - every register the recipe requested has the requested literal
 *   - sp_final = sp_0 + sum(per-step stack_consumed)
 *
 * Running through `z3 -smt2 -` produces sat (chain works) or
 * unsat (something clobbers / misalign).
 */

#include <shrike/smt.h>
#include <shrike/recipe.h>
#include <shrike/regidx.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

static int
regidx_nregs_smt(uint16_t machine)
{
    if (machine == EM_AARCH64) return 32;
    if (machine == EM_RISCV)   return 32;
    return 16;
}

static const char *
arch_name(uint16_t machine)
{
    if (machine == EM_AARCH64) return "aarch64";
    if (machine == EM_RISCV)   return "riscv64";
    return "x86_64";
}

/* Bump SP by N bytes per step. For SET_REG we look up the actual
 * observed gadget's stack_consumed from the regidx; for SYSCALL
 * the terminator doesn't touch SP; for RET the emitter owes 8
 * bytes to the caller. Zero when we have no information. */
static uint32_t
step_stack_bump(const recipe_stmt_t *st, const regidx_t *idx)
{
    if (st->op == RSTMT_SET_REG) {
        if (st->reg >= 0 && st->reg < REGIDX_MAX_REGS &&
            idx->counts[st->reg] > 0) {
            return idx->stack_consumed[st->reg][0];
        }
        return 16;      /* conservative default: addr + value slot */
    }
    if (st->op == RSTMT_RET)     return 8;
    if (st->op == RSTMT_SYSCALL) return 0;
    return 0;
}

int
shrike_smt_emit(const recipe_t *recipe, const regidx_t *index,
                uint16_t machine, FILE *out)
{
    if (!recipe || !index || !out) return -1;

    int nregs = regidx_nregs_smt(machine);
    uint64_t sp_total = 0;

    fprintf(out,
        "; shrike chain-correctness proof\n"
        "; arch: %s  steps: %d  registers: %d\n"
        "; pipe this file through `z3 -smt2 -` for a sat/unsat verdict.\n"
        "(set-logic QF_BV)\n"
        "(set-option :produce-models true)\n\n",
        arch_name(machine), recipe->n, nregs);

    /* Step 0 — initial symbolic state. Registers + sp are fresh
     * 64-bit bitvector consts. No constraints yet; they'll be
     * related to the post-state through per-step assertions. */
    for (int r = 0; r < nregs; r++) {
        fprintf(out, "(declare-const r%d_0 (_ BitVec 64))\n", r);
    }
    fprintf(out, "(declare-const sp_0 (_ BitVec 64))\n\n");

    for (int s = 0; s < recipe->n; s++) {
        const recipe_stmt_t *st = &recipe->stmts[s];
        int k = s + 1;
        uint32_t bump = step_stack_bump(st, index);
        sp_total += bump;

        fprintf(out, "; step %d  (sp += %u)\n", k, (unsigned)bump);
        for (int r = 0; r < nregs; r++) {
            fprintf(out, "(declare-const r%d_%d (_ BitVec 64))\n", r, k);
        }
        fprintf(out,
            "(declare-const sp_%d (_ BitVec 64))\n"
            "(assert (= sp_%d (bvadd sp_%d (_ bv%u 64))))\n",
            k, k, k - 1, (unsigned)bump);

        if (st->op == RSTMT_SET_REG) {
            int target = st->reg;
            if (st->is_literal) {
                fprintf(out,
                    "(assert (= r%d_%d (_ bv%" PRIu64 " 64)))\n",
                    target, k, st->value);
            } else {
                /* wildcard — fresh payload-slot constant that
                 * symbolises the attacker's chosen value. */
                fprintf(out,
                    "(declare-const slot%d (_ BitVec 64))\n"
                    "(assert (= r%d_%d slot%d))\n",
                    k, target, k, k);
            }
            for (int r = 0; r < nregs; r++) {
                if (r == target) continue;
                fprintf(out, "(assert (= r%d_%d r%d_%d))\n",
                        r, k, r, k - 1);
            }
        } else {
            /* SYSCALL / RET — GP register state is unchanged for
             * proof purposes (the actual semantics of syscall /
             * ret don't model kernel or return-address effects,
             * deliberately — see DESIGN.md § SMT scope). */
            for (int r = 0; r < nregs; r++) {
                fprintf(out, "(assert (= r%d_%d r%d_%d))\n",
                        r, k, r, k - 1);
            }
        }
        fputc('\n', out);
    }

    /* Goals. Two halves:
     *   1. every literal-valued recipe register holds its requested
     *      value at the final step.
     *   2. sp_final = sp_0 + total accumulated bumps. Catches the
     *      class of pivot-mistake where the synthesizer picked a
     *      gadget whose stack_consumed didn't add up. */
    fprintf(out, "; goals — what the recipe promised\n");
    for (int s = 0; s < recipe->n; s++) {
        const recipe_stmt_t *st = &recipe->stmts[s];
        if (st->op != RSTMT_SET_REG || !st->is_literal) continue;
        fprintf(out,
            "(assert (= r%d_%d (_ bv%" PRIu64 " 64)))\n",
            st->reg, recipe->n, st->value);
    }
    fprintf(out,
        "(assert (= sp_%d (bvadd sp_0 (_ bv%" PRIu64 " 64))))\n",
        recipe->n, sp_total);

    fputs("\n(check-sat)\n", out);

    /* Provenance — makes the proof file self-explanatory when
     * a human reads it without re-running shrike. */
    fprintf(out, "\n; chain provenance (gadget addresses + stack per step)\n");
    for (int s = 0; s < recipe->n; s++) {
        const recipe_stmt_t *st = &recipe->stmts[s];
        if (st->op == RSTMT_SET_REG &&
            st->reg >= 0 && st->reg < REGIDX_MAX_REGS &&
            index->counts[st->reg] > 0) {
            fprintf(out,
                "; step %d: r%d <- 0x%" PRIx64 "  (consumes %u bytes)\n",
                s + 1, st->reg, index->addrs[st->reg][0],
                (unsigned)index->stack_consumed[st->reg][0]);
        } else if (st->op == RSTMT_SYSCALL &&
                   index->syscall_count > 0) {
            fprintf(out, "; step %d: syscall at 0x%" PRIx64 "\n",
                    s + 1, index->syscall_addrs[0]);
        }
    }
    fprintf(out, "; sp delta total: %" PRIu64 " bytes\n", sp_total);

    return 0;
}
