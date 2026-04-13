/*
 * riscv.c — RV64GC decoder primitives.
 *
 * Kept narrow on purpose. v1.4.0 covers:
 *   - instruction length (2 vs 4 bytes) from the low two bits of
 *     the first halfword
 *   - terminator classification for the opcodes a ROP/JOP
 *     composer can actually terminate chains on
 *
 * Full operand rendering comes later — same decoupling shrike
 * used during the x86-64 and aarch64 ramp.
 */

#include <shrike/riscv.h>

#include <stdint.h>
#include <stddef.h>

/* Low two bits of the first halfword determine the length. RISC-V
 * reserves 48-bit and 64-bit encodings (lowest bits 0b011111 or
 * 0b0111111) for future extensions — nothing ships them today. */
size_t
riscv_insn_len(const uint8_t *bytes, size_t remaining)
{
    if (remaining < 2) return 0;
    uint16_t lo = (uint16_t)(bytes[0] | (bytes[1] << 8));
    if ((lo & 0x3) != 0x3) return 2;         /* RVC */
    if (remaining < 4) return 0;
    if ((lo & 0x1c) != 0x1c) return 4;        /* base 32-bit */
    /* 48-bit+ forms reserved, reject for v1.4. */
    return 0;
}

static uint32_t
rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t
rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

riscv_term_t
riscv_classify_terminator(const uint8_t *bytes, size_t len)
{
    if (len == 4) {
        uint32_t w = rd32(bytes);
        uint32_t opcode = w & 0x7f;
        uint32_t funct3 = (w >> 12) & 0x7;

        /* jalr: opcode 1100111, funct3 000 */
        if (opcode == 0x67 && funct3 == 0) return RV_TERM_JALR;

        /* system opcode 1110011. Discriminate by imm[11:0] ("csr/
         * function select") when rd and rs1 are both zero and
         * funct3 is zero. */
        if (opcode == 0x73 && funct3 == 0) {
            uint32_t rd  = (w >> 7)  & 0x1f;
            uint32_t rs1 = (w >> 15) & 0x1f;
            uint32_t imm = (w >> 20) & 0xfff;
            if (rd == 0 && rs1 == 0) {
                if (imm == 0x000) return RV_TERM_ECALL;
                if (imm == 0x001) return RV_TERM_EBREAK;
                if (imm == 0x302) return RV_TERM_MRET;
                if (imm == 0x102) return RV_TERM_SRET;
            }
        }
    } else if (len == 2) {
        uint16_t h = rd16(bytes);
        /* C.JR   : funct4 1000, rs1 != 0, rs2 == 0, op == 10
         * C.JALR : funct4 1001, rs1 != 0, rs2 == 0, op == 10 */
        if ((h & 0x3) == 0x2) {
            uint32_t rs1 = (h >> 7) & 0x1f;
            uint32_t rs2 = (h >> 2) & 0x1f;
            uint32_t funct4 = (h >> 12) & 0xf;
            if (rs1 != 0 && rs2 == 0) {
                if (funct4 == 0x8) return RV_TERM_C_JR;
                if (funct4 == 0x9) return RV_TERM_C_JALR;
            }
        }
    }
    return RV_TERM_NONE;
}

int
riscv_is_ret(const uint8_t *bytes, size_t len)
{
    if (len == 4) {
        uint32_t w = rd32(bytes);
        /* jalr x0, x1, 0  => rd=0, rs1=1, imm=0, opcode=0x67, funct3=0 */
        if ((w & 0x7f) == 0x67 && ((w >> 12) & 0x7) == 0 &&
            ((w >> 7)  & 0x1f) == 0 && ((w >> 15) & 0x1f) == 1 &&
            ((w >> 20) & 0xfff) == 0) {
            return 1;
        }
    } else if (len == 2) {
        uint16_t h = rd16(bytes);
        /* c.jr x1 : funct4=1000, rs1=1, rs2=0, op=10 */
        if ((h & 0x3) == 0x2 &&
            ((h >> 12) & 0xf) == 0x8 &&
            ((h >> 7)  & 0x1f) == 1 &&
            ((h >> 2)  & 0x1f) == 0) {
            return 1;
        }
    }
    return 0;
}
