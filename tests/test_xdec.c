/*
 * test_xdec.c — x86-64 length-decoder unit tests.
 *
 * Each case is a short byte sequence with a known expected length.
 * Coverage focuses on the instruction classes that appear in ROP
 * gadgets: pushes, pops, moves, arithmetic, returns, syscalls,
 * Jcc, CALL/JMP relative and indirect, with and without REX, with
 * and without operand-size override.
 */

#include <shrike/xdec.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int passes = 0;
static int fails  = 0;

static void check(const char *label, const uint8_t *bytes, size_t len,
                  int expect)
{
    int got = -1;
    int rc = xdec_length(bytes, len, &got);
    int ok = (expect < 0)
             ? (rc < 0)
             : (rc == 0 && got == expect);
    if (ok) {
        passes++;
        printf("  [ok]   %-30s len=%d\n", label, got);
    } else {
        fails++;
        printf("  [FAIL] %-30s expected=%d  got=%d (rc=%d)\n",
               label, expect, got, rc);
    }
}

#define CASE(label, expect, ...)                       \
    do {                                               \
        static const uint8_t _b[] = { __VA_ARGS__ };   \
        check(label, _b, sizeof _b, expect);           \
    } while (0)

int main(void)
{
    printf("simple 1-byte opcodes\n");
    CASE("NOP",          1, 0x90);
    CASE("RET",          1, 0xC3);
    CASE("RETF",         1, 0xCB);
    CASE("LEAVE",        1, 0xC9);
    CASE("HLT",          1, 0xF4);
    CASE("INT3",         1, 0xCC);
    CASE("PUSH RAX",     1, 0x50);
    CASE("PUSH RDI",     1, 0x57);
    CASE("POP RDI",      1, 0x5F);

    printf("\nreturns with immediate\n");
    CASE("RET imm16",    3, 0xC2, 0x08, 0x00);
    CASE("RETF imm16",   3, 0xCA, 0x08, 0x00);

    printf("\ninterrupts, syscall\n");
    CASE("INT 0x80",     2, 0xCD, 0x80);
    CASE("SYSCALL",      2, 0x0F, 0x05);
    CASE("SYSRET",       2, 0x0F, 0x07);

    printf("\nJcc / short jumps\n");
    CASE("JMP rel8",     2, 0xEB, 0x10);
    CASE("JMP rel32",    5, 0xE9, 0x00, 0x01, 0x02, 0x03);
    CASE("JE rel8",      2, 0x74, 0x05);
    CASE("JZ rel32",     6, 0x0F, 0x84, 0x00, 0x01, 0x02, 0x03);
    CASE("CALL rel32",   5, 0xE8, 0x00, 0x01, 0x02, 0x03);

    printf("\nindirect CALL / JMP via FF\n");
    CASE("CALL *RAX",    2, 0xFF, 0xD0);   /* mod=11, reg=2, rm=0 */
    CASE("JMP *RAX",     2, 0xFF, 0xE0);   /* mod=11, reg=4, rm=0 */
    CASE("CALL [RAX]",   2, 0xFF, 0x10);   /* mod=00, reg=2, rm=0 */
    CASE("JMP [RIP+d32]",6, 0xFF, 0x25, 0, 0, 0, 0);

    printf("\nMOV immediate forms\n");
    CASE("MOV AL, imm8",    2, 0xB0, 0x42);
    CASE("MOV EAX, imm32",  5, 0xB8, 0x78, 0x56, 0x34, 0x12);
    CASE("MOV RAX, imm64", 10, 0x48, 0xB8, 0x88, 0x77, 0x66, 0x55,
                                0x44, 0x33, 0x22, 0x11);
    CASE("MOV AX, imm16 (op66)",
                            4, 0x66, 0xB8, 0x34, 0x12);

    printf("\narithmetic & logic\n");
    CASE("ADD AL, imm8",  2, 0x04, 0x05);
    CASE("ADD EAX, imm32",5, 0x05, 0x78, 0x56, 0x34, 0x12);
    CASE("XOR EAX, EAX",  2, 0x31, 0xC0);
    CASE("XOR RAX, RAX",  3, 0x48, 0x31, 0xC0);
    CASE("ADD r/m, imm8", 3, 0x83, 0xC0, 0x08);             /* add eax, 8 */
    CASE("ADD r/m, imm32",6, 0x81, 0xC0, 0x78, 0x56, 0x34, 0x12);

    printf("\nMOV reg/mem\n");
    CASE("MOV r, r/m",    2, 0x89, 0xD8);                   /* mov eax, ebx */
    CASE("MOV r, r/m REX",3, 0x48, 0x89, 0xD8);             /* mov rax, rbx */
    CASE("MOV r,[r+i8]",  3, 0x8B, 0x43, 0x08);             /* mov eax, [rbx+8] */
    CASE("MOV r,[r+i32]", 6, 0x8B, 0x83, 0x00, 0x10, 0, 0); /* mov eax, [rbx+0x1000] */
    CASE("MOV [RSP+8]",   4, 0x8B, 0x44, 0x24, 0x08);       /* mov eax, [rsp+8], SIB */

    printf("\nLEA\n");
    CASE("LEA r, [r+i8]", 4, 0x48, 0x8D, 0x7E, 0x08);  /* lea rdi, [rsi+8] */

    printf("\ngroup 3 (TEST) peeking\n");
    CASE("NOT r/m (F7 /2)",  2, 0xF7, 0xD0);           /* not eax */
    CASE("TEST r/m, imm32",  6, 0xF7, 0xC0, 0x78, 0x56, 0x34, 0x12);
    CASE("TEST r/m8, imm8",  3, 0xF6, 0xC0, 0x55);

    printf("\ntruncation must fail\n");
    CASE("truncated REX",   -1, 0x48);
    CASE("truncated MOV64", -1, 0x48, 0xB8, 0x00, 0x00);
    CASE("truncated Jcc32", -1, 0x0F, 0x84, 0x00);

    /* empty input: call xdec_length directly with size 0 */
    {
        int got = 999;
        int rc = xdec_length(NULL, 0, &got);
        if (rc < 0) { passes++; printf("  [ok]   empty input rejected\n"); }
        else { fails++; printf("  [FAIL] empty input: rc=%d got=%d\n", rc, got); }
    }

    printf("\ninvalid in 64-bit\n");
    CASE("PUSH ES (06)",    -1, 0x06);
    CASE("PUSH CS (0E)",    -1, 0x0E);
    CASE("DAA (27)",        -1, 0x27);
    CASE("AAM (D4)",        -1, 0xD4, 0x0A);
    CASE("LES (C4 inv)",    -1, 0xC4, 0x00, 0x00);  /* VEX prefix */

    printf("\nstacked prefixes\n");
    CASE("REP MOVSB",       2, 0xF3, 0xA4);
    CASE("CS: MOV",         3, 0x2E, 0x89, 0xD8);

    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
