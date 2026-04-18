/*
 * ppc64.c — minimal PowerPC 64 decoder for gadget scanning.
 */

#include <shrike/ppc64.h>

#include <stdint.h>
#include <stdio.h>

uint32_t
ppc64_read_insn(const uint8_t *buf)
{
    /* Little-endian (ppc64le). Big-endian ppc64 would flip this. */
    return (uint32_t)buf[0]
         | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16)
         | ((uint32_t)buf[3] << 24);
}

int
ppc64_is_terminator(uint32_t insn)
{
    /* BLR   0x4E800020 */
    if (insn == 0x4E800020u) return 1;
    /* BCTR  0x4E800420 */
    if (insn == 0x4E800420u) return 1;
    /* SC    0x44000002 */
    if (insn == 0x44000002u) return 1;
    return 0;
}

int
ppc64_is_syscall(uint32_t insn)
{
    return insn == 0x44000002u;
}

int
ppc64_render_insn(char *buf, size_t buflen, uint32_t insn)
{
    if (insn == 0x4E800020u) return snprintf(buf, buflen, "blr");
    if (insn == 0x4E800420u) return snprintf(buf, buflen, "bctr");
    if (insn == 0x44000002u) return snprintf(buf, buflen, "sc");
    if (insn == 0x60000000u) return snprintf(buf, buflen, "nop");
    return snprintf(buf, buflen, ".long 0x%08x", insn);
}
