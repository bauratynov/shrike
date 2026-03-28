/*
 * test_category.c — gadget classification unit tests.
 */

#include "category.h"
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

static gadget_t make(const uint8_t *b, size_t n, int insns, uint16_t mach)
{
    gadget_t g;
    memset(&g, 0, sizeof g);
    g.bytes = b;
    g.length = n;
    g.insn_count = insns;
    g.machine = mach;
    return g;
}

static void test_x86(void)
{
    printf("x86 classification\n");

    /* ret only */
    static const uint8_t ret[] = { 0xC3 };
    gadget_t g = make(ret, 1, 1, EM_X86_64);
    CHECK(gadget_categorize(&g) == CAT_RET_ONLY, "RET -> ret_only");

    /* pop rdi ; ret */
    static const uint8_t pop[] = { 0x5F, 0xC3 };
    g = make(pop, 2, 2, EM_X86_64);
    CHECK(gadget_categorize(&g) == CAT_POP, "pop rdi ; ret -> pop");

    /* pop r12 (REX.B + 5C) ; ret */
    static const uint8_t pop_r12[] = { 0x41, 0x5C, 0xC3 };
    g = make(pop_r12, 3, 2, EM_X86_64);
    CHECK(gadget_categorize(&g) == CAT_POP, "pop r12 ; ret -> pop");

    /* mov rax, rbx ; ret (48 89 D8 C3) */
    static const uint8_t mov[] = { 0x48, 0x89, 0xD8, 0xC3 };
    g = make(mov, 4, 2, EM_X86_64);
    CHECK(gadget_categorize(&g) == CAT_MOV, "mov rax, rbx -> mov");

    /* xor eax, eax ; ret */
    static const uint8_t xor[] = { 0x31, 0xC0, 0xC3 };
    g = make(xor, 3, 2, EM_X86_64);
    CHECK(gadget_categorize(&g) == CAT_ARITH, "xor eax, eax -> arith");

    /* add rsp, 0x8 ; ret (48 83 C4 08 C3) */
    static const uint8_t piv[] = { 0x48, 0x83, 0xC4, 0x08, 0xC3 };
    g = make(piv, 5, 2, EM_X86_64);
    CHECK(gadget_categorize(&g) == CAT_STACK_PIVOT,
          "add rsp, 8 -> stack_pivot");

    /* syscall */
    static const uint8_t syscall[] = { 0x0F, 0x05 };
    g = make(syscall, 2, 1, EM_X86_64);
    CHECK(gadget_categorize(&g) == CAT_SYSCALL, "syscall -> syscall");

    /* jmp rax (FF E0) */
    static const uint8_t jmp[] = { 0xFF, 0xE0 };
    g = make(jmp, 2, 1, EM_X86_64);
    CHECK(gadget_categorize(&g) == CAT_INDIRECT, "jmp rax -> indirect");
}

static void test_arm64(void)
{
    printf("\naarch64 classification\n");

    /* RET */
    static const uint8_t ret[] = { 0xC0, 0x03, 0x5F, 0xD6 };
    gadget_t g = make(ret, 4, 1, EM_AARCH64);
    CHECK(gadget_categorize(&g) == CAT_RET_ONLY, "RET -> ret_only");

    /* MOV X0, X1 ; RET (AA0103E0 + D65F03C0) LE */
    static const uint8_t mov[] = {
        0xE0, 0x03, 0x01, 0xAA, 0xC0, 0x03, 0x5F, 0xD6
    };
    g = make(mov, 8, 2, EM_AARCH64);
    CHECK(gadget_categorize(&g) == CAT_MOV, "MOV X0, X1 -> mov");

    /* LDP X29, X30, [SP], #16 ; RET
     * 0xA8C17BFD (LDP post-idx, Rn=SP) + RET. */
    static const uint8_t ldp[] = {
        0xFD, 0x7B, 0xC1, 0xA8, 0xC0, 0x03, 0x5F, 0xD6
    };
    g = make(ldp, 8, 2, EM_AARCH64);
    CHECK(gadget_categorize(&g) == CAT_POP, "LDP [SP]... -> pop");

    /* ADD SP, SP, #0x20 ; RET — 0x910083FF + RET */
    static const uint8_t pivot[] = {
        0xFF, 0x83, 0x00, 0x91, 0xC0, 0x03, 0x5F, 0xD6
    };
    g = make(pivot, 8, 2, EM_AARCH64);
    CHECK(gadget_categorize(&g) == CAT_STACK_PIVOT, "ADD SP -> stack_pivot");

    /* SVC #0 (D4000001) */
    static const uint8_t svc[] = { 0x01, 0x00, 0x00, 0xD4 };
    g = make(svc, 4, 1, EM_AARCH64);
    CHECK(gadget_categorize(&g) == CAT_SYSCALL, "SVC -> syscall");

    /* BR X0 (D61F0000) */
    static const uint8_t br[] = { 0x00, 0x00, 0x1F, 0xD6 };
    g = make(br, 4, 1, EM_AARCH64);
    CHECK(gadget_categorize(&g) == CAT_INDIRECT, "BR X0 -> indirect");
}

static void test_mask_parse(void)
{
    printf("\nmask parser\n");
    uint32_t m;
    CHECK(gadget_category_parse_mask("pop", &m) == 0, "parse 'pop'");
    CHECK(m == (1u << CAT_POP), "pop mask = bit 2");

    CHECK(gadget_category_parse_mask("pop,mov,syscall", &m) == 0,
          "parse csv");
    uint32_t want = (1u << CAT_POP) | (1u << CAT_MOV) | (1u << CAT_SYSCALL);
    CHECK(m == want, "csv mask = union");

    CHECK(gadget_category_parse_mask("nope", &m) == -1, "unknown -> err");
}

int main(void)
{
    test_x86();
    test_arm64();
    test_mask_parse();
    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
