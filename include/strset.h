/*
 * strset.h — tiny open-addressed hash set of owned strings.
 *
 * Used by --unique in main.c to dedupe gadgets by their rendered
 * mnemonic text. FNV-1a hashing, linear probing, capacity doubles
 * when load factor exceeds 0.75. Strings are duplicated on insert
 * so callers can reuse their scratch buffers.
 */
#ifndef SHRIKE_STRSET_H
#define SHRIKE_STRSET_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char   **slots;   /* NULL = empty */
    size_t   cap;     /* power of two, >= 16 */
    size_t   used;    /* populated slots */
} strset_t;

void strset_init(strset_t *s);
void strset_free(strset_t *s);

/* Returns 1 if newly inserted, 0 if already present, -1 on OOM. */
int  strset_add(strset_t *s, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_STRSET_H */
