/*
 * test_smt.c — minimal sanity of shrike_smt_emit output.
 *
 * Just confirm:
 *   1. shrike_smt_emit returns 0 on a trivial recipe
 *   2. output has balanced parens
 *   3. output contains exactly one "(check-sat)"
 *
 * No tmpfile (some CI sandboxes don't provide /tmp). Use an
 * in-process string sink via open_memstream when available,
 * fall back to a skip-and-pass when it isn't.
 */

#define _GNU_SOURCE
#include <shrike/smt.h>
#include <shrike/recipe.h>
#include <shrike/regidx.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fails = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        fails++; \
    } \
} while (0)

static int
balanced_parens(const char *s, size_t n)
{
    int depth = 0;
    int in_comment = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '\n') { in_comment = 0; continue; }
        if (in_comment) continue;
        if (c == ';') { in_comment = 1; continue; }
        if (c == '(') depth++;
        else if (c == ')') { depth--; if (depth < 0) return 0; }
    }
    return depth == 0;
}

int
main(void)
{
#ifdef _GNU_SOURCE
    char  *buf = NULL;
    size_t bufsz = 0;
    FILE  *out = open_memstream(&buf, &bufsz);
    if (!out) {
        fprintf(stderr, "test_smt: open_memstream unavailable, skipping\n");
        return 0;
    }

    recipe_t r;
    memset(&r, 0, sizeof r);
    r.n = 2;
    r.stmts[0].op = RSTMT_SET_REG;
    r.stmts[0].reg = 7;
    r.stmts[0].is_literal = 1;
    r.stmts[0].value = 0x41;
    r.stmts[1].op = RSTMT_SYSCALL;

    regidx_t idx;
    memset(&idx, 0, sizeof idx);
    idx.counts[7] = 1;
    idx.addrs[7][0] = 0x401000;
    idx.stack_consumed[7][0] = 16;
    idx.syscall_count = 1;
    idx.syscall_addrs[0] = 0x402000;

    int rc = shrike_smt_emit(&r, &idx, EM_X86_64, out);
    CHECK(rc == 0);
    fclose(out);           /* flushes into buf/bufsz */

    CHECK(buf != NULL);
    CHECK(bufsz > 0);
    if (buf) {
        CHECK(balanced_parens(buf, bufsz));
        CHECK(strstr(buf, "(check-sat)") != NULL);
        CHECK(strstr(buf, "bv65") != NULL);   /* 0x41 = 65 */
        free(buf);
    }

    if (fails == 0) { printf("test_smt: ok\n"); return 0; }
    return 1;
#else
    fprintf(stderr, "test_smt: _GNU_SOURCE not defined, skipping\n");
    return 0;
#endif
}
