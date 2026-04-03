/*
 * pivots.h — stack pivot atlas.
 *
 * A "pivot" is any gadget that modifies rsp / sp. The atlas enumerates
 * them with the delta they apply, so a chain author can pick the
 * smallest pivot that reaches their controlled memory.
 *
 * Kinds:
 *   literal   — add rsp, 0x28  →  delta = +40
 *   register  — mov rsp, rbx   →  source = rbx
 *   rbp       — leave          →  symbolic (rsp = rbp)
 *   stack    — pop rsp         →  delta read from top-of-stack
 */
#ifndef SHRIKE_PIVOTS_H
#define SHRIKE_PIVOTS_H

#include "scan.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PIVOT_NONE     = 0,
    PIVOT_LITERAL  = 1,   /* add rsp, imm    or    add sp, imm          */
    PIVOT_REGISTER = 2,   /* mov rsp, rXX    or    mov sp, Xn            */
    PIVOT_RBP      = 3,   /* leave (symbolic, rsp = rbp)                 */
    PIVOT_STACK    = 4    /* pop rsp / pop sp (symbolic, delta on stack) */
} pivot_kind_t;

typedef struct {
    pivot_kind_t kind;
    int64_t      delta;       /* for PIVOT_LITERAL; 0 otherwise */
    int          source_reg;  /* regidx index for PIVOT_REGISTER; -1 else */
    int          trailing_ret;/* 1 if the gadget ends in a RET */
} pivot_info_t;

/* Analyse a gadget. Returns PIVOT_NONE if it is not a pivot. */
void pivot_analyze(const gadget_t *g, pivot_info_t *out);

/* Collector + printer used by the --pivots CLI mode. */
typedef struct pivot_atlas pivot_atlas_t;

pivot_atlas_t *pivot_atlas_new(void);
void           pivot_atlas_free(pivot_atlas_t *a);

/* Record one gadget (no-op if not a pivot). */
void pivot_atlas_observe(pivot_atlas_t *a, const gadget_t *g);

/* Emit sorted text / JSON output. */
void pivot_atlas_print     (const pivot_atlas_t *a, uint16_t machine, FILE *f);
void pivot_atlas_print_json(const pivot_atlas_t *a, uint16_t machine, FILE *f);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_PIVOTS_H */
