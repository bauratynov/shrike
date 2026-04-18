/*
 * smt.h — SMT-LIB2 proof emitter for chain correctness.
 *
 * Stability: @stable_since 5.1. The single entry point
 * shrike_smt_emit(recipe, index, machine, FILE *) is frozen
 * for the 5.x line. The SMT2 output shape itself (QF_BV
 * register-state semantics) may gain new assertions in patch
 * bumps — e.g. memory modelling in a future 5.x — but existing
 * assertions won't be removed.
 *
 * Given a recipe and its resolved gadget chain (as found by the
 * v1.5.x synthesizer), emit an SMT2 file that encodes:
 *
 *   - per-gadget effects, translated from gadget_effect_t into
 *     (assert (= x_post (bvadd x_pre 0x...)))-style assertions
 *   - the final requested register values from the recipe
 *   - a (check-sat) at the end
 *
 * Running the file through `z3 -smt2 proof.smt` produces `sat`
 * if and only if the chain actually achieves what the recipe
 * asked for. `unsat` means a gadget is clobbering a register,
 * or the synthesizer's picker hit a bug.
 *
 * Scope for v2.6.0: register-set semantics only. Stack and
 * memory modelling lands in v2.6.1. We don't ship Z3 — users
 * pipe the output through whichever SMT solver they already
 * have.
 */
#ifndef SHRIKE_SMT_H
#define SHRIKE_SMT_H

#include <shrike/regidx.h>
#include <shrike/recipe.h>

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Emit the SMT2 proof to `out`. Returns 0 on success, -1 + errno
 * on failure (which basically only happens if `out` does). */
int shrike_smt_emit(const recipe_t *recipe,
                    const regidx_t *index,
                    uint16_t        machine,
                    FILE           *out);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_SMT_H */
