/*
 * test_arm64.c — ARM AArch64 classifier + renderer tests.
 *
 * Instruction encodings here are hand-assembled from ARM ARM to stay
 * independent of a specific toolchain.
 */

#include "arm64.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int passes = 0, fails = 0;

#define CHECK(cond, label)                                                    \
    do {                                                                      \
        if (cond) { passes++; printf("  [ok]   %s\n", label); }               \
        else { fails++;  printf("  [FAIL] %s\n", label); }                    \
    } while (0)

static void test_terminators(void)
{
    printf("arm64 terminator classifier\n");
    /* RET (default Rn = X30): 0xD65F03C0 */
    CHECK(arm64_is_terminator(0xD65F03C0u), "RET (X30)");
    /* RET X0: 0xD65F0000 */
    CHECK(arm64_is_terminator(0xD65F0000u), "RET (X0)");
    /* RETAA: 0xD65F0BFF */
    CHECK(arm64_is_terminator(0xD65F0BFFu), "RETAA");
    /* RETAB: 0xD65F0FFF */
    CHECK(arm64_is_terminator(0xD65F0FFFu), "RETAB");
    /* BR X0: 0xD61F0000 */
    CHECK(arm64_is_terminator(0xD61F0000u), "BR X0");
    /* BLR X10: 0xD63F0140 */
    CHECK(arm64_is_terminator(0xD63F0140u), "BLR X10");
    /* SVC #0: 0xD4000001 */
    CHECK(arm64_is_terminator(0xD4000001u), "SVC #0");
    /* NOP (hint): not a terminator */
    CHECK(!arm64_is_terminator(0xD503201Fu), "NOP rejected");
    /* MOV X0, X1 — not a terminator */
    CHECK(!arm64_is_terminator(0xAA0103E0u), "MOV X0, X1 rejected");
}

static void test_bti(void)
{
    printf("\narm64 BTI landing pad\n");
    CHECK(arm64_is_bti(0xD503241Fu), "BTI");
    CHECK(arm64_is_bti(0xD503245Fu), "BTI c");
    CHECK(arm64_is_bti(0xD503249Fu), "BTI j");
    CHECK(arm64_is_bti(0xD50324DFu), "BTI jc");
    CHECK(!arm64_is_bti(0xD503201Fu), "NOP is not BTI");
    CHECK(!arm64_is_bti(0xD65F03C0u), "RET is not BTI");
}

static void test_render(void)
{
    printf("\narm64 render\n");
    char buf[64];

    arm64_render_insn(buf, sizeof buf, 0xD65F03C0u);
    CHECK(strcmp(buf, "ret") == 0, "ret (implicit X30)");

    arm64_render_insn(buf, sizeof buf, 0xD65F0000u);
    CHECK(strcmp(buf, "ret x0") == 0, "ret x0");

    arm64_render_insn(buf, sizeof buf, 0xD65F0BFFu);
    CHECK(strcmp(buf, "retaa") == 0, "retaa");

    arm64_render_insn(buf, sizeof buf, 0xD65F0FFFu);
    CHECK(strcmp(buf, "retab") == 0, "retab");

    arm64_render_insn(buf, sizeof buf, 0xD61F0140u);
    CHECK(strcmp(buf, "br x10") == 0, "br x10");

    arm64_render_insn(buf, sizeof buf, 0xD503201Fu);
    CHECK(strcmp(buf, "nop") == 0, "nop");

    arm64_render_insn(buf, sizeof buf, 0xD4000001u);
    CHECK(strcmp(buf, "svc #0x0") == 0, "svc #0");

    arm64_render_insn(buf, sizeof buf, 0xD503245Fu);
    CHECK(strcmp(buf, "bti c") == 0, "bti c");

    /* MOV X0, X1 should render */
    arm64_render_insn(buf, sizeof buf, 0xAA0103E0u);
    CHECK(strcmp(buf, "mov x0, x1") == 0, "mov x0, x1");

    /* Unknown encoding falls back to .word */
    arm64_render_insn(buf, sizeof buf, 0x12345678u);
    CHECK(strstr(buf, ".word") != NULL, "unknown → .word fallback");
}

static void test_read_insn(void)
{
    printf("\narm64 little-endian read\n");
    static const uint8_t buf[4] = { 0xC0, 0x03, 0x5F, 0xD6 }; /* RET */
    CHECK(arm64_read_insn(buf) == 0xD65F03C0u, "RET bytes → u32");
}

int main(void)
{
    test_terminators();
    test_bti();
    test_render();
    test_read_insn();
    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
