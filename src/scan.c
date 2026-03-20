/*
 * scan.c — backward gadget scanner.
 *
 * For every potential terminator byte in the segment, try every
 * candidate start up to `max_backscan` bytes earlier and decode a
 * chain through the length decoder. A valid gadget is a chain whose
 * instructions decode cleanly and whose *last* instruction is a
 * terminator ending precisely at the expected boundary.
 *
 * The scan is O(segment_size · max_backscan · max_insn) in decode
 * calls; on a typical 100 KB .text this finishes well under 100 ms.
 */

#include "scan.h"
#include "xdec.h"

#include <string.h>

void scan_config_default(scan_config_t *cfg)
{
    cfg->max_insn        = 5;
    cfg->max_backscan    = 48;
    cfg->include_syscall = 1;
    cfg->include_int     = 1;
    cfg->include_ff      = 1;
}

/* Is this decoded instruction a gadget terminator? */
static int is_terminator(const xdec_info_t *info,
                         const scan_config_t *cfg)
{
    if (info->map == 1) {
        switch (info->opcode) {
        case 0xC2:  /* RET imm16         */
        case 0xC3:  /* RET               */
        case 0xCA:  /* RETF imm16        */
        case 0xCB:  /* RETF              */
            return 1;
        case 0xCC:  /* INT3              */
        case 0xCD:  /* INT imm8          */
            return cfg->include_int ? 1 : 0;
        case 0xFF: {
            uint8_t reg = (uint8_t)((info->modrm >> 3) & 7);
            /* /2 CALL r/m, /3 CALL far, /4 JMP r/m, /5 JMP far */
            if (reg >= 2 && reg <= 5) return cfg->include_ff ? 1 : 0;
            return 0;
        }
        default: return 0;
        }
    } else if (info->map == 2) {
        /* SYSCALL (0F 05) and SYSRET (0F 07) */
        if (info->opcode == 0x05 || info->opcode == 0x07)
            return cfg->include_syscall ? 1 : 0;
    }
    return 0;
}

/* Quick screen: is `seg->bytes[t]` a byte that could plausibly start
 * a terminator instruction? Saves work in the outer loop. */
static int could_start_terminator(const elf64_segment_t *seg, size_t t,
                                  const scan_config_t *cfg)
{
    if (t >= seg->size) return 0;
    uint8_t b = seg->bytes[t];
    switch (b) {
    case 0xC3: case 0xC2: case 0xCA: case 0xCB:
    case 0xCC:
        return 1;
    case 0xCD: /* INT imm8 */
        return cfg->include_int;
    case 0x0F:
        if (!cfg->include_syscall) return 0;
        if (t + 1 >= seg->size) return 0;
        {
            uint8_t b2 = seg->bytes[t + 1];
            return (b2 == 0x05 || b2 == 0x07);
        }
    case 0xFF:
        if (!cfg->include_ff) return 0;
        if (t + 1 >= seg->size) return 0;
        {
            uint8_t mrm = seg->bytes[t + 1];
            uint8_t reg = (uint8_t)((mrm >> 3) & 7);
            return (reg >= 2 && reg <= 5);
        }
    default:
        return 0;
    }
}

size_t scan_segment(const elf64_segment_t *seg,
                    const scan_config_t   *cfg,
                    gadget_cb_t            cb,
                    void                  *ctx)
{
    scan_config_t defaults;
    if (!cfg) { scan_config_default(&defaults); cfg = &defaults; }

    if (!seg || !seg->bytes || seg->size == 0 || !cb) return 0;

    size_t emitted = 0;

    for (size_t t = 0; t < seg->size; t++) {
        if (!could_start_terminator(seg, t, cfg)) continue;

        /* We also need to know the terminator's own length so the
         * chain-end comparison is exact. Decode the terminator first
         * as a sanity check; if it doesn't decode, skip. */
        xdec_info_t term_info;
        if (xdec_full(seg->bytes + t, seg->size - t, &term_info) < 0) {
            continue;
        }
        if (!is_terminator(&term_info, cfg)) continue;

        size_t term_end = t + (size_t)term_info.length;
        size_t backscan = (t > (size_t)cfg->max_backscan)
                          ? (size_t)cfg->max_backscan
                          : t;

        /* Try each candidate start from offset 0 (terminator only) up
         * to offset = backscan bytes earlier. */
        for (size_t offset = 0; offset <= backscan; offset++) {
            size_t s = t - offset;
            size_t p = s;
            int    insns = 0;
            int    ok = 0;

            while (p <= t && insns < cfg->max_insn) {
                xdec_info_t info;
                if (xdec_full(seg->bytes + p,
                              seg->size - p, &info) < 0) {
                    break;
                }
                insns++;
                if (p == t) {
                    /* Reached the terminator position cleanly. */
                    ok = 1;
                    break;
                }
                if (p + (size_t)info.length > t) break; /* overshot */
                p += (size_t)info.length;
            }

            if (ok) {
                gadget_t g;
                g.vaddr      = seg->vaddr + s;
                g.offset     = s;
                g.length     = term_end - s;
                g.insn_count = insns;
                g.bytes      = seg->bytes + s;
                cb(seg, &g, ctx);
                emitted++;
            }
        }
    }

    return emitted;
}
