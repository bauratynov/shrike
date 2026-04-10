/*
 * test_regidx.c — register-control index unit tests.
 */

#include <shrike/regidx.h>
#include <shrike/elf64.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int passes = 0, fails = 0;

#define CHECK(cond, label)                                                    \
    do {                                                                      \
        if (cond) { passes++; printf("  [ok]   %s\n", label); }               \
        else { fails++; printf("  [FAIL] %s\n", label); }                     \
    } while (0)

static gadget_t make(const uint8_t *b, size_t n, int insns, uint16_t mach,
                     uint64_t va)
{
    gadget_t g;
    memset(&g, 0, sizeof g);
    g.bytes = b;
    g.length = n;
    g.insn_count = insns;
    g.machine = mach;
    g.vaddr = va;
    return g;
}

static void test_x86_single_pop(void)
{
    printf("x86 single pop + ret\n");
    regidx_t ri; regidx_init(&ri, EM_X86_64);

    /* pop rdi (0x5F) ; ret */
    static const uint8_t g1[] = { 0x5F, 0xC3 };
    gadget_t gg = make(g1, 2, 2, EM_X86_64, 0x401000);
    regidx_observe(&ri, &gg);

    /* pop rsi (0x5E) ; ret */
    static const uint8_t g2[] = { 0x5E, 0xC3 };
    gg = make(g2, 2, 2, EM_X86_64, 0x401100);
    regidx_observe(&ri, &gg);

    /* rdi = 7, rsi = 6 */
    CHECK(ri.counts[7] == 1, "rdi count");
    CHECK(ri.addrs[7][0] == 0x401000, "rdi address");
    CHECK(ri.counts[6] == 1, "rsi count");
    CHECK(ri.addrs[6][0] == 0x401100, "rsi address");
}

static void test_x86_multi_pop(void)
{
    printf("\nx86 multi-pop (pop rbp ; pop r12 ; ret)\n");
    regidx_t ri; regidx_init(&ri, EM_X86_64);

    /* 5D = pop rbp (5), 41 5C = pop r12 (12), C3 = ret */
    static const uint8_t g[] = { 0x5D, 0x41, 0x5C, 0xC3 };
    gadget_t gg = make(g, 4, 3, EM_X86_64, 0x401200);
    regidx_observe(&ri, &gg);

    CHECK(ri.counts[5]  == 1, "rbp credited");
    CHECK(ri.counts[12] == 1, "r12 credited");
    CHECK(ri.addrs[5][0] == 0x401200, "rbp address");
    CHECK(ri.addrs[12][0] == 0x401200, "r12 address");
}

static void test_x86_non_pop_shape_ignored(void)
{
    printf("\nx86 non-pop gadget is ignored\n");
    regidx_t ri; regidx_init(&ri, EM_X86_64);

    /* xor rax, rax ; ret (48 31 C0 C3) */
    static const uint8_t g[] = { 0x48, 0x31, 0xC0, 0xC3 };
    gadget_t gg = make(g, 4, 2, EM_X86_64, 0x401300);
    regidx_observe(&ri, &gg);

    for (int r = 0; r < 16; r++) CHECK(ri.counts[r] == 0, "no reg credited");
}

static void test_syscall_indexed(void)
{
    printf("\nsyscall-only gadget\n");
    regidx_t ri; regidx_init(&ri, EM_X86_64);

    static const uint8_t g[] = { 0x0F, 0x05 };
    gadget_t gg = make(g, 2, 1, EM_X86_64, 0x401400);
    regidx_observe(&ri, &gg);

    CHECK(ri.syscall_count == 1, "syscall recorded");
    CHECK(ri.syscall_addrs[0] == 0x401400, "syscall address");
}

static void test_aarch64_ldp_pair(void)
{
    printf("\naarch64 LDP [SP], #16 ; RET\n");
    regidx_t ri; regidx_init(&ri, EM_AARCH64);

    /* LDP X29, X30, [SP], #16: 0xA8C17BFD LE bytes FD 7B C1 A8
     *   sf=1 opc=10 101 0 00 100 imm7=0000001 (16/8=2? actually imm7 has
     *   scaling). Encoding: bits 31-30=10 (sf=1, opc=10 LDP), 28-23=101000,
     *   L=1, imm7 at 21-15, Rt2 at 14-10, Rn at 9-5, Rt at 4-0.
     * LDP X29, X30 with Rn=SP(31):
     *   Rt = 29 (0x1D), Rt2 = 30 (0x1E), Rn=31 (0x1F),
     *   wback | post-idx bits, imm7 = 0x2 (8*2=16), opc=10 (64-bit).
     *   Full = 0xA8C17BFD. */
    static const uint8_t g[] = {
        0xFD, 0x7B, 0xC1, 0xA8,   /* LDP x29, x30, [sp], #16 */
        0xC0, 0x03, 0x5F, 0xD6    /* RET */
    };
    gadget_t gg = make(g, 8, 2, EM_AARCH64, 0x500000);
    regidx_observe(&ri, &gg);

    CHECK(ri.counts[29] == 1, "x29 credited");
    CHECK(ri.counts[30] == 1, "x30 credited");
    CHECK(ri.addrs[29][0] == 0x500000, "x29 address");
}

static void test_dedup(void)
{
    printf("\nsame address observed twice is deduped\n");
    regidx_t ri; regidx_init(&ri, EM_X86_64);

    static const uint8_t g[] = { 0x5F, 0xC3 };
    gadget_t gg = make(g, 2, 2, EM_X86_64, 0x401500);
    regidx_observe(&ri, &gg);
    regidx_observe(&ri, &gg);   /* second observation of same addr */
    regidx_observe(&ri, &gg);

    CHECK(ri.counts[7] == 1, "dedup kept 1 entry");
}

int main(void)
{
    test_x86_single_pop();
    test_x86_multi_pop();
    test_x86_non_pop_shape_ignored();
    test_syscall_indexed();
    test_aarch64_ldp_pair();
    test_dedup();
    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
