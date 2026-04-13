/*
 * test_riscv.c — RV64GC length + terminator classifier.
 *
 * Hand-encoded instruction bytes for the opcodes we care about.
 * The encoding references are from the RISC-V Unprivileged ISA
 * Spec v20240411 §§ 2.5 (JALR) and 3 (C extension), plus the
 * Privileged ISA Spec §3.3 (MRET/SRET).
 */

#include <shrike/riscv.h>

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

int
main(void)
{
    /* ret == jalr x0, x1, 0
     *   opcode=1100111 (0x67), funct3=000, rd=00000, rs1=00001,
     *   imm12=0  => 0x00008067 little-endian: 67 80 00 00 */
    uint8_t ret_insn[4] = { 0x67, 0x80, 0x00, 0x00 };
    CHECK(riscv_insn_len(ret_insn, 4) == 4);
    CHECK(riscv_classify_terminator(ret_insn, 4) == RV_TERM_JALR);
    CHECK(riscv_is_ret(ret_insn, 4) == 1);

    /* ecall: 0x00000073 */
    uint8_t ecall[4] = { 0x73, 0x00, 0x00, 0x00 };
    CHECK(riscv_insn_len(ecall, 4) == 4);
    CHECK(riscv_classify_terminator(ecall, 4) == RV_TERM_ECALL);

    /* ebreak: 0x00100073 */
    uint8_t ebreak[4] = { 0x73, 0x00, 0x10, 0x00 };
    CHECK(riscv_classify_terminator(ebreak, 4) == RV_TERM_EBREAK);

    /* mret: 0x30200073 */
    uint8_t mret[4] = { 0x73, 0x00, 0x20, 0x30 };
    CHECK(riscv_classify_terminator(mret, 4) == RV_TERM_MRET);

    /* sret: 0x10200073 */
    uint8_t sret[4] = { 0x73, 0x00, 0x20, 0x10 };
    CHECK(riscv_classify_terminator(sret, 4) == RV_TERM_SRET);

    /* c.jr x1:
     *   funct4=1000, rd/rs1=00001, rs2=00000, op=10
     *   => 16-bit value 1000 00001 00000 10  = 0b1000_0000_1000_0010
     *   = 0x8082, little-endian: 82 80 */
    uint8_t c_jr[2] = { 0x82, 0x80 };
    CHECK(riscv_insn_len(c_jr, 2) == 2);
    CHECK(riscv_classify_terminator(c_jr, 2) == RV_TERM_C_JR);
    CHECK(riscv_is_ret(c_jr, 2) == 1);

    /* c.jalr x5:
     *   funct4=1001, rd/rs1=00101, rs2=00000, op=10
     *   => 1001 00101 00000 10 = 0b1001_0010_1000_0010 = 0x9282 */
    uint8_t c_jalr[2] = { 0x82, 0x92 };
    CHECK(riscv_classify_terminator(c_jalr, 2) == RV_TERM_C_JALR);
    CHECK(riscv_is_ret(c_jalr, 2) == 0);   /* rs1 != 1 → not ret */

    /* addi x1, x0, 5 (RV32/64I): imm=5 in upper 12, rs1=0, funct3=0,
     *   rd=1, opcode=0010011 (0x13).
     *   => 0x00500093, LE: 93 00 50 00 — NOT a terminator. */
    uint8_t nop_like[4] = { 0x93, 0x00, 0x50, 0x00 };
    CHECK(riscv_insn_len(nop_like, 4) == 4);
    CHECK(riscv_classify_terminator(nop_like, 4) == RV_TERM_NONE);

    /* c.addi4spn x8, 16: compressed op with low bits 0b00 → 2 bytes. */
    uint8_t c_compressed[2] = { 0x20, 0x08 };
    CHECK(riscv_insn_len(c_compressed, 2) == 2);
    CHECK(riscv_classify_terminator(c_compressed, 2) == RV_TERM_NONE);

    /* Truncated buffer: reject lengths. */
    CHECK(riscv_insn_len(ret_insn, 1) == 0);
    CHECK(riscv_insn_len(ret_insn, 3) == 0);  /* base-32 needs 4 */

    if (fails == 0) {
        printf("test_riscv: ok\n");
        return 0;
    }
    fprintf(stderr, "test_riscv: %d failure(s)\n", fails);
    return 1;
}
