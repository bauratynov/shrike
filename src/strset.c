/*
 * strset.c — open-addressed hash set of strings.
 */

#include "strset.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint64_t fnv1a(const char *s)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (; *s; s++) {
        h ^= (uint8_t)*s;
        h *= 0x100000001b3ULL;
    }
    return h;
}

void strset_init(strset_t *s)
{
    s->slots = NULL;
    s->cap   = 0;
    s->used  = 0;
}

void strset_free(strset_t *s)
{
    if (!s->slots) return;
    for (size_t i = 0; i < s->cap; i++) free(s->slots[i]);
    free(s->slots);
    s->slots = NULL;
    s->cap   = 0;
    s->used  = 0;
}

static int grow(strset_t *s, size_t new_cap)
{
    char **new_slots = (char **)calloc(new_cap, sizeof(char *));
    if (!new_slots) return -1;

    size_t mask = new_cap - 1;
    if (s->slots) {
        for (size_t i = 0; i < s->cap; i++) {
            char *k = s->slots[i];
            if (!k) continue;
            size_t j = (size_t)fnv1a(k) & mask;
            while (new_slots[j]) j = (j + 1) & mask;
            new_slots[j] = k;
        }
        free(s->slots);
    }
    s->slots = new_slots;
    s->cap   = new_cap;
    return 0;
}

int strset_add(strset_t *s, const char *key)
{
    if (!s->slots) {
        if (grow(s, 16) < 0) return -1;
    }
    /* Load factor 0.75 → grow */
    if (s->used * 4 >= s->cap * 3) {
        if (grow(s, s->cap * 2) < 0) return -1;
    }

    size_t mask = s->cap - 1;
    size_t i    = (size_t)fnv1a(key) & mask;

    while (s->slots[i]) {
        if (strcmp(s->slots[i], key) == 0) return 0; /* already present */
        i = (i + 1) & mask;
    }

    char *dup = strdup(key);
    if (!dup) return -1;
    s->slots[i] = dup;
    s->used++;
    return 1;
}

int strset_contains(const strset_t *s, const char *key)
{
    if (!s->slots || s->cap == 0) return 0;
    size_t mask = s->cap - 1;
    size_t i    = (size_t)fnv1a(key) & mask;
    while (s->slots[i]) {
        if (strcmp(s->slots[i], key) == 0) return 1;
        i = (i + 1) & mask;
    }
    return 0;
}

void strset_foreach(const strset_t *s, strset_iter_fn fn, void *ctx)
{
    if (!s->slots) return;
    for (size_t i = 0; i < s->cap; i++) {
        if (s->slots[i]) fn(s->slots[i], ctx);
    }
}
