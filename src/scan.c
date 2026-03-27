/*
 * scan.c — backward gadget scanner.
 *
 * Dispatches on the ELF machine type:
 *   EM_X86_64  — variable-length instructions, full backward-scan with
 *                the length decoder (original shrike pipeline).
 *   EM_AARCH64 — fixed 4-byte instructions; the scan collapses to:
 *                for each 4-byte aligned word that is a terminator,
 *                emit gadgets of length 1..max_insn ending at it.
 *
 * The scan is O(segment_size · max_backscan · max_insn) in decode
 * calls on x86-64, and O(segment_size / 4 · max_insn) on AArch64.
 * On a typical 100 KB .text this finishes well under 100 ms in
 * either mode.
 */

#include "scan.h"
#include "xdec.h"
#include "arm64.h"
#include "elf64.h"

#include <string.h>

void scan_config_default(scan_config_t *cfg)
{
    cfg->max_insn        = 5;
    cfg->max_backscan    = 48;
    cfg->include_syscall = 1;
    cfg->include_int     = 1;
    cfg->include_ff      = 1;
}

/* ============================================================
 * x86-64 scanner
 * ============================================================ */

static int x86_is_terminator(const xdec_info_t *info,
                             const scan_config_t *cfg)
{
    if (info->map == 1) {
        switch (info->opcode) {
        case 0xC2: case 0xC3: case 0xCA: case 0xCB:
            return 1;
        case 0xCC: case 0xCD:
            return cfg->include_int ? 1 : 0;
        case 0xFF: {
            uint8_t reg = (uint8_t)((info->modrm >> 3) & 7);
            if (reg >= 2 && reg <= 5) return cfg->include_ff ? 1 : 0;
            return 0;
        }
        default: return 0;
        }
    } else if (info->map == 2) {
        if (info->opcode == 0x05 || info->opcode == 0x07)
            return cfg->include_syscall ? 1 : 0;
    }
    return 0;
}

static int x86_could_start_terminator(const elf64_segment_t *seg, size_t t,
                                      const scan_config_t *cfg)
{
    if (t >= seg->size) return 0;
    uint8_t b = seg->bytes[t];
    switch (b) {
    case 0xC3: case 0xC2: case 0xCA: case 0xCB: case 0xCC:
        return 1;
    case 0xCD:
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

static size_t scan_x86(const elf64_segment_t *seg,
                       const scan_config_t   *cfg,
                       gadget_cb_t            cb,
                       void                  *ctx)
{
    size_t emitted = 0;

    for (size_t t = 0; t < seg->size; t++) {
        if (!x86_could_start_terminator(seg, t, cfg)) continue;

        xdec_info_t term_info;
        if (xdec_full(seg->bytes + t, seg->size - t, &term_info) < 0)
            continue;
        if (!x86_is_terminator(&term_info, cfg)) continue;

        size_t term_end = t + (size_t)term_info.length;
        size_t backscan = (t > (size_t)cfg->max_backscan)
                          ? (size_t)cfg->max_backscan : t;

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
                if (p == t) { ok = 1; break; }
                if (p + (size_t)info.length > t) break;
                p += (size_t)info.length;
            }

            if (ok) {
                gadget_t g;
                g.vaddr      = seg->vaddr + s;
                g.offset     = s;
                g.length     = term_end - s;
                g.insn_count = insns;
                g.bytes      = seg->bytes + s;
                g.machine    = seg->machine;
                cb(seg, &g, ctx);
                emitted++;
            }
        }
    }
    return emitted;
}

/* ============================================================
 * AArch64 scanner
 * ============================================================
 * Fixed 4-byte instructions. The segment is walked in 4-byte steps;
 * whenever we hit a terminator we emit gadgets of length 1..max_insn
 * ending at the terminator (i.e. starting 0, 4, 8, ... bytes before).
 */

static int a64_terminator_enabled(uint32_t insn, const scan_config_t *cfg)
{
    if (!arm64_is_terminator(insn)) return 0;
    /* SVC — covered by include_syscall */
    if ((insn & 0xFFE0001Fu) == 0xD4000001u) return cfg->include_syscall;
    /* BR / BLR — covered by include_ff (indirect branch) */
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) return cfg->include_ff;
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) return cfg->include_ff;
    /* RET / RETAA / RETAB — always on */
    return 1;
}

static size_t scan_aarch64(const elf64_segment_t *seg,
                           const scan_config_t   *cfg,
                           gadget_cb_t            cb,
                           void                  *ctx)
{
    /* Align the start of the scan up to 4 bytes — PT_LOAD vaddr is
     * 4-byte aligned on aarch64, but the file offset may not be. */
    size_t start = (4 - (seg->vaddr & 3)) & 3;
    size_t emitted = 0;

    for (size_t t = start; t + 4 <= seg->size; t += 4) {
        uint32_t insn = arm64_read_insn(seg->bytes + t);
        if (!a64_terminator_enabled(insn, cfg)) continue;

        size_t term_end  = t + 4;
        int    max_insn  = cfg->max_insn;
        int    max_words = (int)(t / 4);
        if (max_insn > max_words + 1) max_insn = max_words + 1;

        for (int k = 1; k <= max_insn; k++) {
            size_t s = t - (size_t)(k - 1) * 4;
            gadget_t g;
            g.vaddr      = seg->vaddr + s;
            g.offset     = s;
            g.length     = term_end - s;
            g.insn_count = k;
            g.bytes      = seg->bytes + s;
            g.machine    = seg->machine;
            cb(seg, &g, ctx);
            emitted++;
        }
    }
    return emitted;
}

/* ============================================================
 * Dispatch
 * ============================================================ */

size_t scan_segment(const elf64_segment_t *seg,
                    const scan_config_t   *cfg,
                    gadget_cb_t            cb,
                    void                  *ctx)
{
    scan_config_t defaults;
    if (!cfg) { scan_config_default(&defaults); cfg = &defaults; }

    if (!seg || !seg->bytes || seg->size == 0 || !cb) return 0;

    if (seg->machine == EM_AARCH64) {
        return scan_aarch64(seg, cfg, cb, ctx);
    }
    /* Default / EM_X86_64 */
    return scan_x86(seg, cfg, cb, ctx);
}
