/*
 * category.h — coarse classification of a gadget's shape.
 *
 * The categorizer inspects the first and last instruction of a gadget
 * and buckets it so that downstream filtering — "show only the
 * pop-gadgets" — stays a single flag. Arch-aware.
 */
#ifndef SHRIKE_CATEGORY_H
#define SHRIKE_CATEGORY_H

#include "scan.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CAT_OTHER       = 0,
    CAT_RET_ONLY    = 1,   /* single ret / retaa etc.                 */
    CAT_POP         = 2,   /* first insn is pop reg / LDP [SP],#N     */
    CAT_MOV         = 3,   /* first insn is mov reg, reg              */
    CAT_ARITH       = 4,   /* first insn is add/sub/xor reg, reg      */
    CAT_STACK_PIVOT = 5,   /* first insn modifies rsp / sp            */
    CAT_SYSCALL     = 6,   /* terminator is syscall / svc / int       */
    CAT_INDIRECT    = 7,   /* terminator is indirect CALL / JMP / BR  */
    CAT_MAX
} gadget_category_t;

gadget_category_t gadget_categorize(const gadget_t *g);
const char       *gadget_category_name(gadget_category_t c);

/* Parse a comma-separated list of category names and mask them into
 * a bitset in `*out_mask`. Returns 0 on success, -1 on unknown name. */
int gadget_category_parse_mask(const char *csv, uint32_t *out_mask);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_CATEGORY_H */
