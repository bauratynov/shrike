/*
 * cet.c — CET / BTI classification helpers.
 *
 * Arch-aware: on x86-64 checks RET family + ENDBR64/ENDBR32; on
 * AArch64 checks RET/RETAA/RETAB + BTI landing pads. The JSON
 * field names stay `shstk_blocked` / `starts_endbr` for continuity
 * with v0.4.0 — on ARM64 "starts_endbr" semantically means "starts
 * with a BTI landing pad", which is the analogous construct.
 */

#include "cet.h"
#include "elf64.h"
#include "arm64.h"

#include <stdint.h>

int cet_shstk_blocked(const gadget_t *g)
{
    if (!g || g->length == 0) return 0;

    if (g->machine == EM_AARCH64) {
        if (g->length < 4) return 0;
        uint32_t last = arm64_read_insn(g->bytes + g->length - 4);
        /* RET Xn */
        if ((last & 0xFFFFFC00u) == 0xD65F0000u) return 1;
        /* RETAA / RETAB */
        if ((last & 0xFFFFFBFFu) == 0xD65F0BFFu) return 1;
        return 0;
    }

    /* x86-64:
     *   RET  (C3) last byte = 0xC3
     *   RETF (CB) last byte = 0xCB
     *   RET imm16 (C2 XX XX)  — 3-from-end = 0xC2
     *   RETF imm16 (CA XX XX) — 3-from-end = 0xCA */
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
    if (!g) return 0;

    if (g->machine == EM_AARCH64) {
        if (g->length < 4) return 0;
        return arm64_is_bti(arm64_read_insn(g->bytes));
    }

    if (g->length < 4) return 0;
    return g->bytes[0] == 0xF3 &&
           g->bytes[1] == 0x0F &&
           g->bytes[2] == 0x1E &&
           (g->bytes[3] == 0xFA || g->bytes[3] == 0xFB);
}
