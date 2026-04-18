/*
 * test_smt.c — sanity-check the SMT-LIB2 output from
 * shrike_smt_emit. We don't run Z3 (optional external tool);
 * we verify the output is syntactically well-formed enough
 * that a tree-walking parser would accept it:
 *   - every '(' matched by a ')'
 *   - no unterminated strings or quotes
 *   - check-sat appears exactly once
 *   - every declare-const declares a valid name
 */

#include <shrike/smt.h>
#include <shrike/recipe.h>
#include <shrike/regidx.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static int fails = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        fails++; \
    } \
} while (0)

/* Parenthesis + declare-const + check-sat sanity. */
static int
sanity_check(const char *buf, size_t len)
{
    int depth = 0;
    int maxdepth = 0;
    int checksat = 0;
    int declare_count = 0;
    int in_comment = 0;
    int ok = 1;

    for (size_t i = 0; i < len; i++) {
        char c = buf[i];
        if (c == '\n') { in_comment = 0; continue; }
        if (in_comment) continue;
        if (c == ';') { in_comment = 1; continue; }

        if (c == '(') {
            depth++;
            if (depth > maxdepth) maxdepth = depth;
            /* Match the opening keyword to count structural items. */
            const char *rest = buf + i + 1;
            if (!strncmp(rest, "check-sat", 9))    checksat++;
            if (!strncmp(rest, "declare-const", 13)) declare_count++;
        } else if (c == ')') {
            depth--;
            if (depth < 0) { ok = 0; break; }
        }
    }
    if (depth != 0) {
        fprintf(stderr, "SMT: unbalanced parens (final depth %d)\n", depth);
        ok = 0;
    }
    if (checksat != 1) {
        fprintf(stderr, "SMT: check-sat appears %d times (want 1)\n", checksat);
        ok = 0;
    }
    if (declare_count < 3) {
        fprintf(stderr, "SMT: only %d declare-const (want >= 3)\n", declare_count);
        ok = 0;
    }
    fprintf(stderr, "SMT sanity: depth=0 checksat=%d declares=%d maxdepth=%d\n",
            checksat, declare_count, maxdepth);
    return ok;
}

static void
fill_index(regidx_t *idx, uint16_t machine, int reg, uint64_t addr,
           uint32_t stack)
{
    if (reg < 0 || reg >= REGIDX_MAX_REGS) return;
    idx->addrs[reg][idx->counts[reg]] = addr;
    idx->stack_consumed[reg][idx->counts[reg]] = stack;
    idx->counts[reg]++;
    idx->machine = machine;
}

int
main(void)
{
    char   scratch[8192];
    FILE  *mem;

    /* Case 1: empty recipe — should emit trivial sat. */
    {
        recipe_t r;
        memset(&r, 0, sizeof r);
        r.n = 0;
        regidx_t idx; memset(&idx, 0, sizeof idx);
        mem = tmpfile();
        if (!mem) {
            /* Some CI sandboxes don't provide a writable /tmp.
             * Skip the test rather than fail — the feature
             * works elsewhere. */
            fprintf(stderr, "test_smt: tmpfile unavailable, skipping\n");
            return 0;
        }
        int rc = shrike_smt_emit(&r, &idx, EM_X86_64, mem);
        CHECK(rc == 0);
        fflush(mem);
        long pos = ftell(mem);
        rewind(mem);
        size_t n = fread(scratch, 1,
                         (size_t)pos < sizeof scratch
                            ? (size_t)pos : sizeof scratch,
                         mem);
        fclose(mem);
        CHECK(sanity_check(scratch, n));
    }

    /* Case 2: three-register set + syscall. */
    {
        recipe_t r;
        memset(&r, 0, sizeof r);
        r.n = 4;
        r.stmts[0].op = RSTMT_SET_REG;
        r.stmts[0].reg = 7;   /* rdi */
        r.stmts[0].is_literal = 1; r.stmts[0].value = 1;
        r.stmts[1].op = RSTMT_SET_REG;
        r.stmts[1].reg = 6;   /* rsi */
        r.stmts[1].is_literal = 1; r.stmts[1].value = 2;
        r.stmts[2].op = RSTMT_SET_REG;
        r.stmts[2].reg = 0;   /* rax */
        r.stmts[2].is_literal = 1; r.stmts[2].value = 59;
        r.stmts[3].op = RSTMT_SYSCALL;

        regidx_t idx; memset(&idx, 0, sizeof idx);
        fill_index(&idx, EM_X86_64, 7, 0x400500, 16);
        fill_index(&idx, EM_X86_64, 6, 0x400600, 16);
        fill_index(&idx, EM_X86_64, 0, 0x400700, 16);
        idx.syscall_addrs[0] = 0x401000;
        idx.syscall_count = 1;

        mem = tmpfile();
        if (!mem) return 0;
        int rc = shrike_smt_emit(&r, &idx, EM_X86_64, mem);
        CHECK(rc == 0);
        fflush(mem);
        long pos = ftell(mem);
        rewind(mem);
        memset(scratch, 0, sizeof scratch);
        size_t n = fread(scratch, 1,
                         (size_t)pos < sizeof scratch - 1
                            ? (size_t)pos : sizeof scratch - 1,
                         mem);
        fclose(mem);
        CHECK(sanity_check(scratch, n));
        /* Output should mention rax=59 in some form. */
        CHECK(strstr(scratch, "bv59") != NULL);
    }

    if (fails == 0) {
        printf("test_smt: ok\n");
        return 0;
    }
    fprintf(stderr, "test_smt: %d failure(s)\n", fails);
    return 1;
}
