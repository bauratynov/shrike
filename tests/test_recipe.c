/*
 * test_recipe.c — recipe parser + resolver unit tests.
 */

#include "recipe.h"
#include "regidx.h"
#include "elf64.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int passes = 0, fails = 0;

#define CHECK(cond, label)                                                    \
    do {                                                                      \
        if (cond) { passes++; printf("  [ok]   %s\n", label); }               \
        else { fails++; printf("  [FAIL] %s\n", label); }                     \
    } while (0)

static void test_parse_execve_chain(void)
{
    printf("parse execve-style recipe\n");
    recipe_t r;
    int rc = recipe_parse(" rdi=* ; rsi=* ; rdx=* ; rax=59 ; syscall ",
                          &r, EM_X86_64);
    CHECK(rc == 0, "parse success");
    CHECK(r.n == 5, "5 statements");

    CHECK(r.stmts[0].op == RSTMT_SET_REG, "0 = set reg");
    CHECK(r.stmts[0].reg == 7 /* rdi */, "0 = rdi");
    CHECK(r.stmts[0].is_literal == 0, "0 = placeholder");

    CHECK(r.stmts[3].op == RSTMT_SET_REG, "3 = set reg");
    CHECK(r.stmts[3].reg == 0 /* rax */, "3 = rax");
    CHECK(r.stmts[3].is_literal == 1, "3 = literal");
    CHECK(r.stmts[3].value == 59, "3 = rax=59");

    CHECK(r.stmts[4].op == RSTMT_SYSCALL, "4 = syscall");
}

static void test_parse_aarch64(void)
{
    printf("\nparse aarch64 recipe\n");
    recipe_t r;
    int rc = recipe_parse("x0=*; x1=0x42; svc", &r, EM_AARCH64);
    /* 'svc' is not a DSL keyword — only 'syscall'. Parser should fail. */
    CHECK(rc == -1, "svc is not a keyword (expected fail)");

    rc = recipe_parse("x0=*; x1=0x42; syscall", &r, EM_AARCH64);
    CHECK(rc == 0, "parse with syscall keyword");
    CHECK(r.n == 3, "3 statements");
    CHECK(r.stmts[0].reg == 0 /* x0 */, "x0 = reg 0");
    CHECK(r.stmts[1].value == 0x42, "x1 = 0x42");
}

static void test_parse_malformed(void)
{
    printf("\nmalformed inputs rejected\n");
    recipe_t r;
    CHECK(recipe_parse("no_such_reg=*", &r, EM_X86_64) == -1,
          "unknown register name");
    CHECK(recipe_parse("rdi", &r, EM_X86_64) == -1,
          "missing = and value");
    CHECK(recipe_parse("rdi=garbage", &r, EM_X86_64) == -1,
          "non-integer non-* value");
}

static void test_resolve_finds_gadgets(void)
{
    printf("\nresolver picks first address per reg\n");
    regidx_t idx;
    regidx_init(&idx, EM_X86_64);

    /* Manually populate: pop rdi @ 0x401000, pop rax @ 0x401100, syscall @ 0x401200 */
    idx.addrs[7 /* rdi */][0] = 0x401000; idx.counts[7] = 1;
    idx.addrs[0 /* rax */][0] = 0x401100; idx.counts[0] = 1;
    idx.syscall_addrs[0]      = 0x401200; idx.syscall_count = 1;

    recipe_t r;
    recipe_parse("rdi=*; rax=59; syscall", &r, EM_X86_64);

    FILE *f = tmpfile();
    int missing = recipe_resolve(&r, &idx, EM_X86_64, NULL,
                                 RECIPE_FMT_TEXT, f);
    CHECK(missing == 0, "all 3 resolved");

    /* Read the output */
    rewind(f);
    char buf[2048]; size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f);

    CHECK(strstr(buf, "0x0000000000401000") != NULL, "rdi gadget addr in output");
    CHECK(strstr(buf, "0x0000000000401100") != NULL, "rax gadget addr in output");
    CHECK(strstr(buf, "0x0000000000401200") != NULL, "syscall addr in output");
    CHECK(strstr(buf, "rax = 0x3b") != NULL, "rax literal 59 formatted as 0x3b");
}

static void test_resolve_missing(void)
{
    printf("\nresolver reports missing gadgets\n");
    regidx_t idx;
    regidx_init(&idx, EM_X86_64);
    /* Only rdi is available */
    idx.addrs[7][0] = 0x401000; idx.counts[7] = 1;

    recipe_t r;
    recipe_parse("rdi=*; rsi=*; syscall", &r, EM_X86_64);

    FILE *f = tmpfile();
    int missing = recipe_resolve(&r, &idx, EM_X86_64, NULL,
                                 RECIPE_FMT_TEXT, f);
    CHECK(missing == 2, "rsi + syscall reported missing");
    fclose(f);
}

static void test_pwntools_format(void)
{
    printf("\npwntools format emits ROP.raw() + cyclic placeholders\n");
    regidx_t idx;
    regidx_init(&idx, EM_X86_64);
    idx.addrs[7][0] = 0x401000; idx.counts[7] = 1;
    idx.addrs[0][0] = 0x401100; idx.counts[0] = 1;
    idx.syscall_addrs[0] = 0x401200; idx.syscall_count = 1;

    recipe_t r;
    recipe_parse("rdi=*; rax=59; syscall", &r, EM_X86_64);

    FILE *f = tmpfile();
    int missing = recipe_resolve(&r, &idx, EM_X86_64, "/bin/ls",
                                 RECIPE_FMT_PWNTOOLS, f);
    CHECK(missing == 0, "all resolved");

    rewind(f);
    char buf[4096]; size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f);

    CHECK(strstr(buf, "from pwn import *") != NULL,
          "emits pwn import");
    CHECK(strstr(buf, "context.arch = 'amd64'") != NULL,
          "context.arch set");
    CHECK(strstr(buf, "ELF('/bin/ls')") != NULL, "ELF path emitted");
    CHECK(strstr(buf, "rop = ROP(elf)") != NULL, "ROP object created");
    CHECK(strstr(buf, "rop.raw(0x401000)") != NULL,
          "rdi gadget via rop.raw");
    CHECK(strstr(buf, "cyclic(8, n=8)") != NULL,
          "cyclic placeholder for *");
    CHECK(strstr(buf, "rop.raw(0x3b)") != NULL,
          "literal rax=59 emitted");
}

int main(void)
{
    test_parse_execve_chain();
    test_parse_aarch64();
    test_parse_malformed();
    test_resolve_finds_gadgets();
    test_resolve_missing();
    test_pwntools_format();
    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
