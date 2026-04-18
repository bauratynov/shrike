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

#include <shrike/scan.h>
#include <shrike/xdec.h>
#include <shrike/arm64.h>
#include <shrike/riscv.h>
#include <shrike/ppc64.h>
#include <shrike/mips.h>
#include <shrike/elf64.h>

/* SSE2 is available on every real x86-64 host; wrap its use so
 * non-x86 cross-builds keep working with the scalar path.
 *
 * AVX2 would give us 32-byte windows and roughly double the
 * prefilter throughput on top of SSE2, but SSE2 is part of
 * x86_64 baseline (Microsoft's ABI mandates it, gcc -m64
 * enables it by default) while AVX2 is a runtime-detect story.
 * Keep it SSE2-only until we have a benchmark that shows AVX2
 * actually moving the needle on real libc sizes — memory
 * bandwidth dominates on large inputs and extra lanes don't
 * help there. */
#if defined(__SSE2__)
# include <emmintrin.h>
# define SHRIKE_HAVE_SSE2 1
#else
# define SHRIKE_HAVE_SSE2 0
#endif

/* Environment override to force the scalar path — useful for
 * A/B benchmarking and for debugging prefilter vs detailed-
 * check divergence. Set SHRIKE_SCALAR=1 in the environment. */
#include <stdlib.h>
static int
x86_want_sse2(void)
{
#if SHRIKE_HAVE_SSE2
    static int cached = -1;
    if (cached < 0) {
        const char *env = getenv("SHRIKE_SCALAR");
        cached = (env && env[0] && env[0] != '0') ? 0 : 1;
    }
    return cached;
#else
    return 0;
#endif
}

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

/* SSE2 prefilter — scan 16 bytes at a time, produce a 16-bit
 * mask with 1-bits at positions where the byte is one of the
 * known terminator starters (0xC3, 0xC2, 0xCA..0xCD, 0x0F, 0xFF).
 * Caller still calls x86_could_start_terminator on each hit to
 * apply config-driven filters (include_syscall/int/ff). */
#if SHRIKE_HAVE_SSE2
static uint32_t
sse2_candidate_mask(const uint8_t *p)
{
    __m128i b   = _mm_loadu_si128((const __m128i *)p);
    __m128i c3  = _mm_cmpeq_epi8(b, _mm_set1_epi8((char)0xC3));
    __m128i c2  = _mm_cmpeq_epi8(b, _mm_set1_epi8((char)0xC2));
    __m128i ca  = _mm_cmpeq_epi8(b, _mm_set1_epi8((char)0xCA));
    __m128i cb  = _mm_cmpeq_epi8(b, _mm_set1_epi8((char)0xCB));
    __m128i cc  = _mm_cmpeq_epi8(b, _mm_set1_epi8((char)0xCC));
    __m128i cd  = _mm_cmpeq_epi8(b, _mm_set1_epi8((char)0xCD));
    __m128i zf  = _mm_cmpeq_epi8(b, _mm_set1_epi8((char)0x0F));
    __m128i ff  = _mm_cmpeq_epi8(b, _mm_set1_epi8((char)0xFF));
    __m128i any = _mm_or_si128(
                    _mm_or_si128(
                        _mm_or_si128(c3, c2),
                        _mm_or_si128(ca, cb)),
                    _mm_or_si128(
                        _mm_or_si128(cc, cd),
                        _mm_or_si128(zf, ff)));
    return (uint32_t)_mm_movemask_epi8(any);
}
#endif

static size_t scan_x86(const elf64_segment_t *seg,
                       const scan_config_t   *cfg,
                       gadget_cb_t            cb,
                       void                  *ctx)
{
    size_t emitted = 0;

#if SHRIKE_HAVE_SSE2
    /* Fast path: SSE2 prefilter. Walk in 16-byte windows; for
     * every candidate position call into the detailed checker.
     * Tail bytes (seg->size < 16 or remainder after last full
     * window) fall through to the scalar loop below. Honours
     * SHRIKE_SCALAR=1 for A/B testing. */
    size_t t = 0;
    if (x86_want_sse2() && seg->size >= 16) { size_t vec_end = seg->size - 16;
    for (; t <= vec_end; t += 16) {
        uint32_t mask = sse2_candidate_mask(seg->bytes + t);
        while (mask) {
            int bit = __builtin_ctz(mask);
            mask &= mask - 1;
            size_t pos = t + (size_t)bit;
            if (!x86_could_start_terminator(seg, pos, cfg)) continue;
            xdec_info_t term_info;
            if (xdec_full(seg->bytes + pos, seg->size - pos,
                          &term_info) < 0) continue;
            if (!x86_is_terminator(&term_info, cfg)) continue;

            size_t term_end = pos + (size_t)term_info.length;
            size_t backscan = (pos > (size_t)cfg->max_backscan)
                              ? (size_t)cfg->max_backscan : pos;
            for (size_t offset = 0; offset <= backscan; offset++) {
                size_t s = pos - offset;
                size_t p = s;
                int insns = 0, ok = 0;
                while (p <= pos && insns < cfg->max_insn) {
                    xdec_info_t info;
                    if (xdec_full(seg->bytes + p,
                                  seg->size - p, &info) < 0) break;
                    insns++;
                    if (p == pos) { ok = 1; break; }
                    if (p + (size_t)info.length > pos) break;
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
    }
    }    /* close if (seg->size >= 16) */
    /* Scalar tail for the last <16 bytes, or all bytes when
     * seg->size < 16 (rare but real — tiny PLT stubs). */
    for (; t < seg->size; t++) {
        if (!x86_could_start_terminator(seg, t, cfg)) continue;
#else
    for (size_t t = 0; t < seg->size; t++) {
        if (!x86_could_start_terminator(seg, t, cfg)) continue;
#endif

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
 * RISC-V RV64GC scanner
 * ============================================================
 * Variable-length (2 vs 4 bytes) like x86, but much more regular.
 * We walk terminator candidates at 2-byte stride, and for each
 * candidate try every valid backward start offset (also in 2-byte
 * steps). From a candidate start, forward-decode instructions
 * with riscv_insn_len until we either land exactly on the
 * terminator (emit) or overshoot / fail to decode (skip).
 */

static int
rv_terminator_enabled(riscv_term_t k, const scan_config_t *cfg)
{
    switch (k) {
    case RV_TERM_JALR:
    case RV_TERM_C_JR:       return 1;                  /* ret / jmp reg */
    case RV_TERM_C_JALR:     return cfg->include_ff;    /* jalr with link */
    case RV_TERM_ECALL:      return cfg->include_syscall;
    case RV_TERM_EBREAK:     return cfg->include_int;
    case RV_TERM_MRET:
    case RV_TERM_SRET:       return 1;                  /* privileged ret */
    default:                 return 0;
    }
}

static size_t scan_riscv(const elf64_segment_t *seg,
                         const scan_config_t   *cfg,
                         gadget_cb_t            cb,
                         void                  *ctx)
{
    size_t emitted = 0;

    /* Mirror scan_x86's shape: a single loop over byte-offset
     * starts. offset=0 covers the bare-terminator 1-insn gadget
     * without a second emit block. Stride is 2 because RV64 aligns
     * instructions on a 2-byte boundary (compressed extension). */
    for (size_t t = 0; t + 2 <= seg->size; t += 2) {
        size_t tl = riscv_insn_len(seg->bytes + t, seg->size - t);
        if (tl == 0) continue;
        riscv_term_t kind = riscv_classify_terminator(seg->bytes + t, tl);
        if (kind == RV_TERM_NONE) continue;
        if (!rv_terminator_enabled(kind, cfg)) continue;

        size_t term_end = t + tl;
        /* Max backscan in bytes: max_insn instructions of up to 4
         * bytes each. Clamp to how far we can actually walk. */
        size_t max_back = (size_t)cfg->max_insn * 4;
        if (t < max_back) max_back = t;

        for (size_t offset = 0; offset <= max_back; offset += 2) {
            size_t s = t - offset;
            size_t p = s;
            int    insns = 0;
            int    ok = 0;

            while (p < t && insns < cfg->max_insn - 1) {
                size_t il = riscv_insn_len(seg->bytes + p,
                                           seg->size - p);
                if (il == 0) break;
                if (p + il > t) break;
                p += il;
                insns++;
            }
            if (p == t) {
                /* Terminator is always the final insn of the gadget. */
                insns++;
                ok = 1;
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
 * PowerPC 64 scanner (v5.0.0)
 * ============================================================
 * Fixed 4-byte instructions like aarch64. Same walk, different
 * terminator table. ppc64le only for v5.0.
 */

static size_t scan_ppc64(const elf64_segment_t *seg,
                         const scan_config_t   *cfg,
                         gadget_cb_t            cb,
                         void                  *ctx)
{
    size_t start = (4 - (seg->vaddr & 3)) & 3;
    size_t emitted = 0;

    for (size_t t = start; t + 4 <= seg->size; t += 4) {
        uint32_t insn = ppc64_read_insn(seg->bytes + t);
        if (!ppc64_is_terminator(insn)) continue;
        if (ppc64_is_syscall(insn) && !cfg->include_syscall) continue;

        size_t term_end = t + 4;
        int max_insn  = cfg->max_insn;
        int max_words = (int)(t / 4);
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
 * MIPS32 / MIPS64 scanner (v5.0.0)
 * ============================================================
 * Fixed 4-byte instructions. Byte-order taken from machine code:
 * EM_MIPS_RS3_LE implies little-endian; EM_MIPS is big-endian
 * (the historical default; modern Linux MIPS64 is LE via
 * EM_MIPS_RS3_LE or e_ident[5] but we stick to the machine field
 * for clarity).
 *
 * Delay slot: ignored for v5.0. Gadgets end at the branch itself.
 * Chain consumers must pad one instruction for the delay slot on
 * their own. Full delay-slot-aware scanning is 5.x work.
 */

static size_t scan_mips(const elf64_segment_t *seg,
                        const scan_config_t   *cfg,
                        gadget_cb_t            cb,
                        void                  *ctx)
{
    int le = (seg->machine == EM_MIPS_RS3_LE);
    size_t start = (4 - (seg->vaddr & 3)) & 3;
    size_t emitted = 0;

    for (size_t t = start; t + 4 <= seg->size; t += 4) {
        uint32_t insn = mips_read_insn(seg->bytes + t, le);
        if (!mips_is_terminator(insn)) continue;
        if (mips_is_syscall(insn) && !cfg->include_syscall) continue;

        size_t term_end = t + 4;
        int max_insn  = cfg->max_insn;
        int max_words = (int)(t / 4);
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
    if (seg->machine == EM_RISCV) {
        return scan_riscv(seg, cfg, cb, ctx);
    }
    if (seg->machine == EM_PPC64) {
        return scan_ppc64(seg, cfg, cb, ctx);
    }
    if (seg->machine == EM_MIPS || seg->machine == EM_MIPS_RS3_LE) {
        return scan_mips(seg, cfg, cb, ctx);
    }
    /* Default / EM_X86_64 */
    return scan_x86(seg, cfg, cb, ctx);
}
