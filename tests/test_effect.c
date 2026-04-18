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

/* v2.1.1 — composed walker must match gadget_effect_compute for
 * the shapes both of them recognise. */
static void test_compose_matches(void)
{
    struct {
        const uint8_t *bytes;
        size_t len;
        uint16_t machine;
        const char *label;
    } cases[] = {
        { (const uint8_t *)"\x5f\xc3",           2, EM_X86_64, "pop rdi; ret" },
        { (const uint8_t *)"\x5f\x5e\x5a\xc3",   4, EM_X86_64, "3x pop; ret" },
        { (const uint8_t *)"\x0f\x05",           2, EM_X86_64, "syscall" },
        { (const uint8_t *)"\x41\x5c\xc3",       3, EM_X86_64, "pop r12; ret" },
        { (const uint8_t *)"\x67\x80\x00\x00",   4, EM_RISCV,  "rv ret" },
        { (const uint8_t *)"\x73\x00\x00\x00",   4, EM_RISCV,  "rv ecall" },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        gadget_t g = {0};
        g.bytes = cases[i].bytes;
        g.length = cases[i].len;
        g.machine = cases[i].machine;

        gadget_effect_t a, b;
        CHECK(gadget_effect_compute(&g, &a) == 0);
        int n = gadget_effect_compose(&g, &b);
        CHECK(n >= 1);
        CHECK(a.writes_mask == b.writes_mask);
        CHECK(a.terminator == b.terminator);
        CHECK(a.stack_consumed == b.stack_consumed);
        CHECK(a.has_syscall == b.has_syscall);
    }
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
    test_compose_matches();

    /* v2.1.2: dispatcher-shape detection.
     * mov rax, [rdx] ; jmp rax   (canonical JOP dispatcher)
     *   48 8B 02           mov rax, [rdx]
     *   FF E0              jmp rax
     * Full byte sequence: 48 8B 02 FF E0 */
    {
        uint8_t disp[] = { 0x48, 0x8B, 0x02, 0xFF, 0xE0 };
        gadget_t g = {0};
        g.bytes = disp; g.length = sizeof disp; g.machine = EM_X86_64;
        CHECK(gadget_is_dispatcher(&g, GADGET_TERM_JMP_REG) == 1);
        CHECK(gadget_is_dispatcher(&g, GADGET_TERM_CALL_REG) == 0);
    }
    /* Negative: plain jmp rax without a preceding write — not a
     * dispatcher, just an arbitrary indirect branch we happened
     * to catch. */
    {
        uint8_t stray[] = { 0xFF, 0xE0 };
        gadget_t g = {0};
        g.bytes = stray; g.length = sizeof stray; g.machine = EM_X86_64;
        CHECK(gadget_is_dispatcher(&g, GADGET_TERM_JMP_REG) == 0);
    }

    /* v2.1.3: COP dispatcher — same walker, different terminator.
     *   mov rax, [rdx] ; call rax
     *   48 8B 02  FF D0 */
    {
        uint8_t cop[] = { 0x48, 0x8B, 0x02, 0xFF, 0xD0 };
        gadget_t g = {0};
        g.bytes = cop; g.length = sizeof cop; g.machine = EM_X86_64;
        CHECK(gadget_is_dispatcher(&g, GADGET_TERM_CALL_REG) == 1);
        CHECK(gadget_is_dispatcher(&g, GADGET_TERM_JMP_REG) == 0);
    }

    /* v2.1.4: DOP write primitive.
     *   mov rax, [rdi]   48 8B 07      — load target addr from memory
     *   mov [rax], rsi   48 89 30      — store attacker data via it
     *   ret              C3            — back to the DOP scheduler
     * Combined: 48 8B 07 48 89 30 C3 */
    {
        uint8_t dop[] = { 0x48, 0x8B, 0x07, 0x48, 0x89, 0x30, 0xC3 };
        gadget_t g = {0};
        g.bytes = dop; g.length = sizeof dop; g.machine = EM_X86_64;
        CHECK(gadget_is_dop_write(&g) == 1);
    }
    /* Negative: write is present but base register wasn't loaded
     * from memory earlier — not a DOP primitive, just a store. */
    {
        uint8_t not_dop[] = { 0x48, 0x89, 0x30, 0xC3 };
        gadget_t g = {0};
        g.bytes = not_dop; g.length = sizeof not_dop; g.machine = EM_X86_64;
        CHECK(gadget_is_dop_write(&g) == 0);
    }

    if (fails == 0) {
        printf("test_effect: ok\n");
        return 0;
    }
    fprintf(stderr, "test_effect: %d failure(s)\n", fails);
    return 1;
}
