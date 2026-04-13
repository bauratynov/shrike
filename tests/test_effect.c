/*
 * test_effect.c — unit tests for gadget_effect_compute.
 *
 * Synthesize a handful of gadgets across x86-64, aarch64, and
 * RV64, then check the effect record agrees with what the
 * assembler output says. Nothing fancy — concrete byte patterns,
 * concrete expectations.
 */

#include <shrike/effect.h>
#include <shrike/format.h>
#include <shrike/elf64.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int fails = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        fails++; \
    } \
} while (0)

/* Registers for x86_64:
 *   rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7,
 *   r8=8, r9=9, r10=10, r11=11, r12=12, r13=13, r14=14, r15=15.
 */

static void test_x86_pop_ret(void)
{
    /* pop rdi ; ret  => bytes: 5f c3 */
    uint8_t bytes[] = { 0x5f, 0xc3 };
    gadget_t g = {0};
    g.bytes = bytes; g.length = sizeof bytes; g.machine = EM_X86_64;

    gadget_effect_t e;
    CHECK(gadget_effect_compute(&g, &e) == 0);
    CHECK(e.terminator == GADGET_TERM_RET);
    CHECK(e.writes_mask == (1u << 7));   /* rdi = slot 7 */
    CHECK(e.stack_consumed == 16);       /* 8 pop + 8 ret */
    CHECK(e.has_syscall == 0);
}

static void test_x86_multi_pop_ret(void)
{
    /* pop rdi ; pop rsi ; pop rdx ; ret  => 5f 5e 5a c3 */
    uint8_t bytes[] = { 0x5f, 0x5e, 0x5a, 0xc3 };
    gadget_t g = {0};
    g.bytes = bytes; g.length = sizeof bytes; g.machine = EM_X86_64;

    gadget_effect_t e;
    CHECK(gadget_effect_compute(&g, &e) == 0);
    CHECK(e.terminator == GADGET_TERM_RET);
    /* rdi=7, rsi=6, rdx=2 */
    uint32_t expect = (1u << 7) | (1u << 6) | (1u << 2);
    CHECK(e.writes_mask == expect);
    CHECK(e.stack_consumed == 32);        /* 3*8 + 8 */
}

static void test_x86_syscall(void)
{
    uint8_t bytes[] = { 0x0f, 0x05 };
    gadget_t g = {0};
    g.bytes = bytes; g.length = sizeof bytes; g.machine = EM_X86_64;

    gadget_effect_t e;
    CHECK(gadget_effect_compute(&g, &e) == 0);
    CHECK(e.terminator == GADGET_TERM_SYSCALL);
    CHECK(e.has_syscall == 1);
    CHECK(e.writes_mask == 0);
}

static void test_x86_pop_r12_ret(void)
{
    /* pop r12 ; ret  => 41 5c c3 */
    uint8_t bytes[] = { 0x41, 0x5c, 0xc3 };
    gadget_t g = {0};
    g.bytes = bytes; g.length = sizeof bytes; g.machine = EM_X86_64;

    gadget_effect_t e;
    CHECK(gadget_effect_compute(&g, &e) == 0);
    CHECK(e.writes_mask == (1u << 12));  /* r12 */
    CHECK(e.stack_consumed == 16);
}

static void test_rv_ret(void)
{
    /* ret = jalr x0, x1, 0  => 67 80 00 00 */
    uint8_t bytes[] = { 0x67, 0x80, 0x00, 0x00 };
    gadget_t g = {0};
    g.bytes = bytes; g.length = sizeof bytes; g.machine = EM_RISCV;

    gadget_effect_t e;
    CHECK(gadget_effect_compute(&g, &e) == 0);
    CHECK(e.terminator == GADGET_TERM_RET);
    CHECK(e.writes_mask == 0);
}

static void test_rv_ecall(void)
{
    uint8_t bytes[] = { 0x73, 0x00, 0x00, 0x00 };
    gadget_t g = {0};
    g.bytes = bytes; g.length = sizeof bytes; g.machine = EM_RISCV;

    gadget_effect_t e;
    CHECK(gadget_effect_compute(&g, &e) == 0);
    CHECK(e.terminator == GADGET_TERM_SYSCALL);
    CHECK(e.has_syscall == 1);
}

int
main(void)
{
    test_x86_pop_ret();
    test_x86_multi_pop_ret();
    test_x86_syscall();
    test_x86_pop_r12_ret();
    test_rv_ret();
    test_rv_ecall();

    if (fails == 0) {
        printf("test_effect: ok\n");
        return 0;
    }
    fprintf(stderr, "test_effect: %d failure(s)\n", fails);
    return 1;
}
