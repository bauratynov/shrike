/*
 * recipe.h — mini DSL for ROP chain synthesis.
 *
 * Grammar (semicolon-separated statements):
 *
 *     stmt     := reg_stmt | 'syscall' | 'ret'
 *     reg_stmt := REG_NAME '=' VALUE
 *     VALUE    := '*' | INTEGER         ('*' = runtime-supplied)
 *
 * Example:
 *     rdi=*; rsi=*; rdx=*; rax=59; syscall
 *
 * Design decisions (v0.11, informed by research on pwntools):
 *   - Greedy per-register resolver: pick the first address from the
 *     regidx for each target register. No clobber analysis in v0.11
 *     (tracked for v0.14 stack-pivot work). A note in the output
 *     flags missing registers.
 *   - Output is a plain text chain: one line per gadget or payload
 *     slot, comments explain intent. v0.12 adds a pwntools-Python
 *     format using the same parser.
 */
#ifndef SHRIKE_RECIPE_H
#define SHRIKE_RECIPE_H

#include "regidx.h"

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RSTMT_SET_REG = 1,
    RSTMT_SYSCALL,
    RSTMT_RET
} recipe_op_t;

typedef struct {
    recipe_op_t op;
    int         reg;         /* valid for SET_REG; regidx index */
    int         is_literal;  /* 1 → use .value; 0 → placeholder  */
    uint64_t    value;
} recipe_stmt_t;

#define RECIPE_MAX_STMTS 32

typedef struct {
    recipe_stmt_t stmts[RECIPE_MAX_STMTS];
    int           n;
} recipe_t;

/* Parse the DSL. Returns 0 on success, -1 on malformed input. */
int recipe_parse(const char *src, recipe_t *out, uint16_t machine);

/* Resolve the recipe against a register-control index and print a
 * text chain. Returns the number of unresolved statements (0 means
 * every register / terminator was matched). */
int recipe_resolve(const recipe_t *r, const regidx_t *idx,
                   uint16_t machine, FILE *out);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_RECIPE_H */
