/*
 * smt.c — SMT-LIB2 proof emitter for chain correctness.
 *
 * Models the resolved chain as a sequence of state transitions
 * on per-register 64-bit bitvectors + a stack pointer. Every
 * step corresponds to one GADGET the resolver would pick, which
 * is not always one recipe statement: a multi-pop gadget
 * (`pop rdi ; pop rsi ; pop rdx ; ret`) satisfies three SET_REG
 * statements in one step, consuming stack once (not thrice).
 *
 * Final assertion has two halves:
 *   - every literal-valued recipe register holds its requested
 *     value at the final state
 *   - sp_final = sp_0 + sum(per-gadget stack_consumed)
 *
 * Piped through `z3 -smt2 -`:
 *   sat   = chain is correct
 *   unsat = the resolver picked a gadget that clobbers or
 *           miscounts; (get-model) shows the contradiction.
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

/* Declare r0..r(nregs-1) + sp at step k. */
static void
declare_step(FILE *out, int nregs, int k)
{
    for (int r = 0; r < nregs; r++) {
        fprintf(out, "(declare-const r%d_%d (_ BitVec 64))\n", r, k);
    }
    fprintf(out, "(declare-const sp_%d (_ BitVec 64))\n", k);
}

/* Assert that every register OUTSIDE `written_mask` is unchanged
 * between step k-1 and k. */
static void
copy_unwritten(FILE *out, int nregs, int k, uint32_t written_mask)
{
    for (int r = 0; r < nregs; r++) {
        if ((written_mask >> r) & 1) continue;
        fprintf(out, "(assert (= r%d_%d r%d_%d))\n",
                r, k, r, k - 1);
    }
}

/* Emit the per-step sp transition: sp_k = sp_{k-1} + bump. */
static void
assert_sp_bump(FILE *out, int k, uint32_t bump)
{
    fprintf(out,
        "(assert (= sp_%d (bvadd sp_%d (_ bv%u 64))))\n",
        k, k - 1, (unsigned)bump);
}

int
shrike_smt_emit(const recipe_t *recipe, const regidx_t *index,
                uint16_t machine, FILE *out)
{
    if (!recipe || !index || !out) return -1;
    if (recipe->n == 0) {
        fprintf(out, "; empty recipe — trivially sat\n(check-sat)\n");
        return 0;
    }

    int nregs = regidx_nregs_smt(machine);
    uint64_t sp_total = 0;

    fprintf(out,
        "; shrike chain-correctness proof\n"
        "; arch: %s  recipe statements: %d  registers: %d\n"
        "; pipe through `z3 -smt2 -` for a sat/unsat verdict.\n"
        "(set-logic QF_BV)\n"
        "(set-option :produce-models true)\n\n",
        arch_name(machine), recipe->n, nregs);

    /* Step 0: fresh symbolic initial state. */
    declare_step(out, nregs, 0);
    fputc('\n', out);

    int k = 0;          /* step counter (runs ahead of statement i) */

    for (int i = 0; i < recipe->n; ) {
        const recipe_stmt_t *st = &recipe->stmts[i];

        /* Before processing a SET_REG run, check if the resolver
         * would pick a multi-pop gadget. If so, emit ONE step
         * spanning the run; otherwise one step per statement. */
        if (st->op == RSTMT_SET_REG) {
            int run = 0;
            uint32_t needed = 0;
            for (int j = i;
                 j < recipe->n && recipe->stmts[j].op == RSTMT_SET_REG;
                 j++)
            {
                int reg = recipe->stmts[j].reg;
                if (reg < 0 || reg >= REGIDX_MAX_REGS) break;
                needed |= 1u << reg;
                run++;
            }
            const regidx_multi_t *mp = NULL;
            if (run >= 2) {
                mp = regidx_find_multi(index, needed, /*committed=*/0, 1);
                if (!mp) mp = regidx_find_multi(index, needed, 0, 0);
            }
            if (mp) {
                k++;
                uint32_t bump = mp->stack_consumed;
                sp_total += bump;
                fprintf(out,
                    "; step %d  — multi-pop gadget 0x%" PRIx64
                    " covers %d recipe regs  (sp += %u)\n",
                    k, mp->addr, run, (unsigned)bump);
                declare_step(out, nregs, k);
                assert_sp_bump(out, k, bump);

                /* Each popped register either gets a recipe literal
                 * or — for the subset-cover padding regs — a
                 * symbolic slot. Writes_mask covers both. */
                for (int pi = 0; pi < mp->pop_count; pi++) {
                    int reg = mp->pop_order[pi];
                    int matched = -1;
                    for (int k2 = 0; k2 < run; k2++) {
                        if (recipe->stmts[i + k2].reg == reg) {
                            matched = i + k2;
                            break;
                        }
                    }
                    if (matched >= 0 && recipe->stmts[matched].is_literal) {
                        fprintf(out,
                            "(assert (= r%d_%d (_ bv%" PRIu64 " 64)))\n",
                            reg, k, recipe->stmts[matched].value);
                    } else {
                        fprintf(out,
                            "(declare-const slot%d_r%d (_ BitVec 64))\n"
                            "(assert (= r%d_%d slot%d_r%d))\n",
                            k, reg, reg, k, k, reg);
                    }
                }
                copy_unwritten(out, nregs, k, mp->writes_mask);
                fputc('\n', out);
                i += run;
                continue;
            }
            /* Fall through: no multi-pop gadget, emit one step per
             * statement in the run, like v5.1 did. */
        }

        /* Single-statement step (SET_REG single-pop, SYSCALL, RET). */
        k++;
        uint32_t bump = 16;          /* default */
        if (st->op == RSTMT_SET_REG &&
            st->reg >= 0 && st->reg < REGIDX_MAX_REGS &&
            index->counts[st->reg] > 0) {
            bump = index->stack_consumed[st->reg][0];
        } else if (st->op == RSTMT_RET) {
            bump = 8;
        } else if (st->op == RSTMT_SYSCALL) {
            bump = 0;
        }
        sp_total += bump;

        fprintf(out, "; step %d  — %s  (sp += %u)\n",
                k,
                st->op == RSTMT_SET_REG ? "single-pop" :
                st->op == RSTMT_SYSCALL ? "syscall"    : "ret",
                (unsigned)bump);
        declare_step(out, nregs, k);
        assert_sp_bump(out, k, bump);

        if (st->op == RSTMT_SET_REG) {
            int target = st->reg;
            if (st->is_literal) {
                fprintf(out,
                    "(assert (= r%d_%d (_ bv%" PRIu64 " 64)))\n",
                    target, k, st->value);
            } else {
                fprintf(out,
                    "(declare-const slot%d_r%d (_ BitVec 64))\n"
                    "(assert (= r%d_%d slot%d_r%d))\n",
                    k, target, target, k, k, target);
            }
            copy_unwritten(out, nregs, k, 1u << target);
        } else {
            copy_unwritten(out, nregs, k, 0);
        }
        fputc('\n', out);
        i++;
    }

    /* Goals. */
    fprintf(out, "; goals — what the recipe promised\n");
    for (int i = 0; i < recipe->n; i++) {
        const recipe_stmt_t *st = &recipe->stmts[i];
        if (st->op != RSTMT_SET_REG || !st->is_literal) continue;
        fprintf(out,
            "(assert (= r%d_%d (_ bv%" PRIu64 " 64)))\n",
            st->reg, k, st->value);
    }
    fprintf(out,
        "(assert (= sp_%d (bvadd sp_0 (_ bv%" PRIu64 " 64))))\n",
        k, sp_total);

    fputs("\n(check-sat)\n", out);

    /* Provenance. */
    fprintf(out, "\n; chain provenance (derived from the regidx)\n");
    for (int i = 0; i < recipe->n; i++) {
        const recipe_stmt_t *st = &recipe->stmts[i];
        if (st->op == RSTMT_SET_REG &&
            st->reg >= 0 && st->reg < REGIDX_MAX_REGS &&
            index->counts[st->reg] > 0) {
            fprintf(out,
                "; stmt %d: r%d <- 0x%" PRIx64 "  (gadget consumes %u bytes)\n",
                i + 1, st->reg, index->addrs[st->reg][0],
                (unsigned)index->stack_consumed[st->reg][0]);
        } else if (st->op == RSTMT_SYSCALL && index->syscall_count > 0) {
            fprintf(out, "; stmt %d: syscall at 0x%" PRIx64 "\n",
                    i + 1, index->syscall_addrs[0]);
        }
    }
    fprintf(out, "; total steps emitted: %d   sp delta: %" PRIu64 " bytes\n",
            k, sp_total);

    return 0;
}
