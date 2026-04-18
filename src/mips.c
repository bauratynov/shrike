/*
 * mips.c — minimal MIPS32/MIPS64 decoder for gadget scanning.
 */

#include <shrike/mips.h>

#include <stdint.h>
#include <stdio.h>

uint32_t
mips_read_insn(const uint8_t *buf, int little_endian)
{
    if (little_endian) {
        return (uint32_t)buf[0]
             | ((uint32_t)buf[1] << 8)
             | ((uint32_t)buf[2] << 16)
             | ((uint32_t)buf[3] << 24);
    }
    return ((uint32_t)buf[0] << 24)
         | ((uint32_t)buf[1] << 16)
         | ((uint32_t)buf[2] <<  8)
         |  (uint32_t)buf[3];
}

static int
is_jr(uint32_t insn)
{
    /* SPECIAL opcode 000000, function 001000. rs field at 21..25
     * is the source register. rd and rt must be zero for JR.
     *   000000 rs 00000 00000 xxxxx 001000
     * Mask 0xFC1FFFFF lets the rs vary; pattern 0x00000008.
     * For JR $ra specifically, rs = 31 (0x1F), giving 0x03E00008. */
    return (insn & 0xFC1FFFFFu) == 0x00000008u;
}

static int
is_jalr(uint32_t insn)
{
    /* SPECIAL function 001001, any rs + rd. */
    return (insn & 0xFC00003Fu) == 0x00000009u;
}

int
mips_is_terminator(uint32_t insn)
{
    if (is_jr(insn))              return 1;
    if (is_jalr(insn))             return 1;
    if (insn == 0x0000000Cu)       return 1;  /* syscall */
    if (insn == 0x42000018u)       return 1;  /* eret */
    return 0;
}

int
mips_is_syscall(uint32_t insn)
{
    return insn == 0x0000000Cu;
}

int
mips_render_insn(char *buf, size_t buflen, uint32_t insn)
{
    if (is_jr(insn)) {
        uint32_t rs = (insn >> 21) & 0x1F;
        if (rs == 31) return snprintf(buf, buflen, "jr $ra");
        return snprintf(buf, buflen, "jr $%u", rs);
    }
    if (is_jalr(insn)) {
        uint32_t rs = (insn >> 21) & 0x1F;
        return snprintf(buf, buflen, "jalr $%u", rs);
    }
    if (insn == 0x0000000Cu) return snprintf(buf, buflen, "syscall");
    if (insn == 0x42000018u) return snprintf(buf, buflen, "eret");
    if (insn == 0x00000000u) return snprintf(buf, buflen, "nop");
    return snprintf(buf, buflen, ".word 0x%08x", insn);
}
