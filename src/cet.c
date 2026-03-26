/*
 * cet.c — CET classification helpers.
 *
 * Pure byte inspection — no instruction decode needed for these
 * specific checks, since RET opcodes and ENDBR64's byte signature
 * are unambiguous.
 */

#include "cet.h"

#include <stdint.h>

int cet_shstk_blocked(const gadget_t *g)
{
    if (!g || g->length == 0) return 0;

    /* Last instruction is:
     *   RET  (C3)     — last byte = 0xC3
     *   RETF (CB)     — last byte = 0xCB
     *   RET imm16 (C2 XX XX)  — 3-from-end = 0xC2
     *   RETF imm16 (CA XX XX) — 3-from-end = 0xCA
     *
     * These are the only terminator patterns the shadow stack mitigates;
     * SYSCALL / SYSRET / INT / indirect CALL/JMP do not touch the
     * return stack the same way. */
    uint8_t last = g->bytes[g->length - 1];
    if (last == 0xC3 || last == 0xCB) return 1;

    if (g->length >= 3) {
        uint8_t b = g->bytes[g->length - 3];
        if (b == 0xC2 || b == 0xCA) return 1;
    }
    return 0;
}

int cet_starts_endbr(const gadget_t *g)
{
    if (!g || g->length < 4) return 0;
    return g->bytes[0] == 0xF3 &&
           g->bytes[1] == 0x0F &&
           g->bytes[2] == 0x1E &&
           (g->bytes[3] == 0xFA || g->bytes[3] == 0xFB);
}
