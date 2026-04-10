/*
 * test_cet.c — CET classifier unit tests.
 */

#include <shrike/cet.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int passes = 0, fails = 0;

#define CHECK(cond, label)                                                    \
    do {                                                                      \
        if (cond) { passes++; printf("  [ok]   %s\n", label); }               \
        else { fails++;  printf("  [FAIL] %s\n", label); }                    \
    } while (0)

static gadget_t make(const uint8_t *bytes, size_t length)
{
    gadget_t g;
    memset(&g, 0, sizeof g);
    g.bytes  = bytes;
    g.length = length;
    return g;
}

static void test_shstk_blocked(void)
{
    printf("cet_shstk_blocked\n");
    /* RET (C3) — last byte */
    static const uint8_t b_ret[] = { 0x5F, 0xC3 };
    gadget_t g1 = make(b_ret, sizeof b_ret);
    CHECK(cet_shstk_blocked(&g1) == 1, "RET terminator flagged");

    /* RETF (CB) */
    static const uint8_t b_retf[] = { 0x90, 0xCB };
    gadget_t g2 = make(b_retf, sizeof b_retf);
    CHECK(cet_shstk_blocked(&g2) == 1, "RETF flagged");

    /* RET imm16 (C2 XX XX) — byte at len-3 is 0xC2 */
    static const uint8_t b_ret_imm[] = { 0xC2, 0x08, 0x00 };
    gadget_t g3 = make(b_ret_imm, sizeof b_ret_imm);
    CHECK(cet_shstk_blocked(&g3) == 1, "RET imm16 flagged");

    /* SYSCALL (0F 05) — not shstk-blocked */
    static const uint8_t b_sys[] = { 0x0F, 0x05 };
    gadget_t g4 = make(b_sys, sizeof b_sys);
    CHECK(cet_shstk_blocked(&g4) == 0, "SYSCALL not flagged");

    /* JMP indirect (FF E0) — not shstk-blocked */
    static const uint8_t b_ind[] = { 0xFF, 0xE0 };
    gadget_t g5 = make(b_ind, sizeof b_ind);
    CHECK(cet_shstk_blocked(&g5) == 0, "indirect JMP not flagged");

    /* Empty — not flagged */
    gadget_t g6 = make(NULL, 0);
    CHECK(cet_shstk_blocked(&g6) == 0, "empty gadget not flagged");
}

static void test_starts_endbr(void)
{
    printf("\ncet_starts_endbr\n");

    /* ENDBR64 (F3 0F 1E FA) + ret */
    static const uint8_t b1[] = { 0xF3, 0x0F, 0x1E, 0xFA, 0xC3 };
    gadget_t g1 = make(b1, sizeof b1);
    CHECK(cet_starts_endbr(&g1) == 1, "ENDBR64 at start flagged");

    /* ENDBR32 (F3 0F 1E FB) */
    static const uint8_t b2[] = { 0xF3, 0x0F, 0x1E, 0xFB, 0xC3 };
    gadget_t g2 = make(b2, sizeof b2);
    CHECK(cet_starts_endbr(&g2) == 1, "ENDBR32 flagged");

    /* Not ENDBR — pop rdi ; ret */
    static const uint8_t b3[] = { 0x5F, 0xC3 };
    gadget_t g3 = make(b3, sizeof b3);
    CHECK(cet_starts_endbr(&g3) == 0, "non-ENDBR start not flagged");

    /* Too short */
    static const uint8_t b4[] = { 0xF3, 0x0F };
    gadget_t g4 = make(b4, sizeof b4);
    CHECK(cet_starts_endbr(&g4) == 0, "truncated ENDBR prefix not flagged");
}

int main(void)
{
    test_shstk_blocked();
    test_starts_endbr();
    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
