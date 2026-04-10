/*
 * sarif.h — SARIF 2.1.0 output for gadget findings.
 *
 * One rule per category (SHRIKE.POP / MOV / ARITH / STACK_PIVOT /
 * SYSCALL / INDIRECT / RET_ONLY / OTHER). Each gadget becomes one
 * result with level="note" and a physicalLocation containing the
 * binary path and the absolute virtual address.
 *
 * Designed to round-trip cleanly through GitHub Code Scanning.
 * The --sarif-cap flag limits result count to stay under GitHub's
 * 10 MB / 25 000-result per-file limits.
 */
#ifndef SHRIKE_SARIF_H
#define SHRIKE_SARIF_H

#include "scan.h"
#include "category.h"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sarif_emitter sarif_emitter_t;

sarif_emitter_t *sarif_new(FILE *out, size_t cap);
void             sarif_free(sarif_emitter_t *e);

/* Begin/end the top-level document. Must be called once each. */
void sarif_begin(sarif_emitter_t *e);
void sarif_end  (sarif_emitter_t *e);

/* Emit one result for a gadget found in `src_path`. */
void sarif_emit(sarif_emitter_t *e,
                const gadget_t  *g,
                gadget_category_t cat,
                const char      *src_path);

/* How many results were dropped due to --sarif-cap. */
size_t sarif_dropped(const sarif_emitter_t *e);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_SARIF_H */
