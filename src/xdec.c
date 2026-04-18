/*
 * xdec.c — x86-64 instruction length decoder.
 *
 * Structure of one decode pass:
 *   1. Consume legacy prefixes (at most 15, but typical code has 0-3).
 *   2. Consume REX prefix if present; remember REX.W for immediate sizing.
 *   3. Read opcode. Distinguish 1-byte, 2-byte (0x0F NN), 3-byte
 *      (0x0F 0x38 NN and 0x0F 0x3A NN) forms.
 *   4. Look up (has-modrm, immediate-size) for the opcode.
 *   5. If the opcode needs a ModR/M, parse it + optional SIB and
 *      displacement using the standard addressing-mode table.
 *   6. Add the immediate bytes.
 *   7. Sanity-check total length against the x86-64 15-byte cap.
 */

#include <shrike/xdec.h>

#include <string.h>

/* ------------------------------------------------------------------
 * Primary opcode table (index = opcode byte, AFTER prefixes + REX).
 * The table encodes which opcodes need a ModR/M and what their base
 * immediate size is. Operand-size dependence is resolved at decode
 * time against the 0x66 prefix and REX.W bit.
 * ------------------------------------------------------------------ */

/* Flags */
#define M   0x01    /* has ModR/M */
#define I1  0x02    /* imm = 1 byte */
#define I2  0x04    /* imm = 2 bytes fixed */
#define I4  0x08    /* imm = 4 bytes fixed */
#define IV  0x10    /* imm = 2 or 4 (operand-size dependent) */
#define IQ  0x20    /* imm = 2, 4, or 8 (MOV r64, imm64) */
#define IM  0x40    /* imm = 8 (moffs on x86-64) */
#define XV  0x80    /* invalid / unsupported in 64-bit mode */

static const uint8_t prim_map[256] = {
    /* 00 */ M,      M,      M,      M,      I1,     IV,     XV,     XV,
    /* 08 */ M,      M,      M,      M,      I1,     IV,     XV,     XV,
    /* 10 */ M,      M,      M,      M,      I1,     IV,     XV,     XV,
    /* 18 */ M,      M,      M,      M,      I1,     IV,     XV,     XV,
    /* 20 */ M,      M,      M,      M,      I1,     IV,     0,      XV,
    /* 28 */ M,      M,      M,      M,      I1,     IV,     0,      XV,
    /* 30 */ M,      M,      M,      M,      I1,     IV,     0,      XV,
    /* 38 */ M,      M,      M,      M,      I1,     IV,     0,      XV,
    /* 40 */ XV,     XV,     XV,     XV,     XV,     XV,     XV,     XV,
    /* 48 */ XV,     XV,     XV,     XV,     XV,     XV,     XV,     XV,
    /* 50 */ 0,      0,      0,      0,      0,      0,      0,      0,
    /* 58 */ 0,      0,      0,      0,      0,      0,      0,      0,
    /* 60 */ XV,     XV,     XV,     M,      0,      0,      0,      0,
    /* 68 */ IV,     M|IV,   I1,     M|I1,   0,      0,      0,      0,
    /* 70 */ I1,     I1,     I1,     I1,     I1,     I1,     I1,     I1,
    /* 78 */ I1,     I1,     I1,     I1,     I1,     I1,     I1,     I1,
    /* 80 */ M|I1,   M|IV,   XV,     M|I1,   M,      M,      M,      M,
    /* 88 */ M,      M,      M,      M,      M,      M,      M,      M,
    /* 90 */ 0,      0,      0,      0,      0,      0,      0,      0,
    /* 98 */ 0,      0,      XV,     0,      0,      0,      0,      0,
    /* A0 */ IM,     IM,     IM,     IM,     0,      0,      0,      0,
    /* A8 */ I1,     IV,     0,      0,      0,      0,      0,      0,
    /* B0 */ I1,     I1,     I1,     I1,     I1,     I1,     I1,     I1,
    /* B8 */ IQ,     IQ,     IQ,     IQ,     IQ,     IQ,     IQ,     IQ,
    /* C0 */ M|I1,   M|I1,   I2,     0,      XV,     XV,     M|I1,   M|IV,
    /* C8 */ 0,      0,      I2,     0,      0,      I1,     XV,     0,
    /* D0 */ M,      M,      M,      M,      XV,     XV,     XV,     0,
    /* D8 */ M,      M,      M,      M,      M,      M,      M,      M,
    /* E0 */ I1,     I1,     I1,     I1,     I1,     I1,     I1,     I1,
    /* E8 */ I4,     I4,     XV,     I1,     0,      0,      0,      0,
    /* F0 */ XV,     0,      XV,     XV,     0,      0,      M,      M,
    /* F8 */ 0,      0,      0,      0,      0,      0,      M,      M,
};

/* ------------------------------------------------------------------
 * 0x0F two-byte opcode classifier.
 * Returns 0 on success with *has_modrm / *imm set; returns -1 on
 * invalid opcode (so far only VEX/EVEX prefixes hit this).
 *
 * FIXME(2026-04-02): this classifier doesn't disambiguate the
 * 0x38 / 0x3A three-byte escape path. Most 3-byte opcodes happen
 * to follow the same (modrm=1, imm=0) default, so we get lucky.
 * When we add AVX2 VPCMPISTR etc. it'll bite. Keep the default
 * but watch for miscounts via the fuzz harness.
 * ------------------------------------------------------------------ */
static int classify_0f(uint8_t op, int op66, int rex_w,
                       int *has_modrm, int *imm)
{
    (void)op66; (void)rex_w;

    /* default: most 0F opcodes take a ModR/M, no immediate */
    *has_modrm = 1;
    *imm       = 0;

    switch (op) {
    /* SYSCALL, SYSRET, INVD, WBINVD, UD2, WRMSR, RDTSC, RDMSR, RDPMC,
     * SYSENTER, SYSEXIT, GETSEC, PUSH/POP FS/GS, CPUID, BSWAP reg,
     * RSM — all 2-byte, no modrm, no imm. */
    case 0x05: case 0x06: case 0x07: case 0x08: case 0x09: case 0x0B:
    case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: case 0x37:
    case 0xA0: case 0xA1: case 0xA2: case 0xA8: case 0xA9: case 0xAA:
    case 0xC8: case 0xC9: case 0xCA: case 0xCB:
    case 0xCC: case 0xCD: case 0xCE: case 0xCF:
        *has_modrm = 0;
        return 0;

    /* Jcc rel32 */
    case 0x80: case 0x81: case 0x82: case 0x83:
    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
        *has_modrm = 0;
        *imm = 4;
        return 0;

    /* opcodes with ModR/M + imm8 */
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0xA4: case 0xAC: case 0xBA:
    case 0xC2: case 0xC4: case 0xC5: case 0xC6:
        *imm = 1;
        return 0;

    default:
        /* Default: modrm, no imm. Covers SSE/MMX/AVX non-VEX,
         * CMOVcc, SETcc, MOVZX/MOVSX, BT/BTS/..., etc. */
        return 0;
    }
}

/* ------------------------------------------------------------------
 * Decode a single instruction.
 * Returns 0 on success with *info filled; -1 on truncation / invalid.
 * ------------------------------------------------------------------ */
int xdec_full(const uint8_t *buf, size_t max, xdec_info_t *info)
{
    memset(info, 0, sizeof(*info));
    if (max == 0) return -1;

    size_t p = 0;

    /* ---------- 1. legacy prefixes ---------- */
    while (p < max && info->npfx < (uint8_t)sizeof(info->prefixes)) {
        uint8_t b = buf[p];
        int is_pfx = 0;
        switch (b) {
        case 0xF0: case 0xF2: case 0xF3:
        case 0x2E: case 0x36: case 0x3E: case 0x26:
        case 0x64: case 0x65: case 0x67:
            is_pfx = 1; break;
        case 0x66:
            is_pfx = 1; info->op66 = 1; break;
        default:
            is_pfx = 0;
        }
        if (!is_pfx) break;
        info->prefixes[info->npfx++] = b;
        p++;
    }
    if (p >= max) return -1;

    /* ---------- 2. REX ---------- */
    if ((buf[p] & 0xF0) == 0x40) {
        info->rex   = buf[p];
        info->rex_w = (buf[p] >> 3) & 1u;
        p++;
        if (p >= max) return -1;
    }

    /* ---------- 3. VEX prefix (C4 / C5) ---------- */
    /* In 64-bit mode, C4 and C5 are VEX prefixes — the classic
     * LES / LDS encodings they collided with only exist in legacy
     * modes. We do length-only VEX handling here: skip the VEX
     * encoding bytes, then decode the following opcode via the
     * normal 0F map (for C5) or 0F 38 / 0F 3A map (for C4's
     * m-mmmm field). Operand-level semantics (which register
     * goes where, L=1 meaning 256-bit) are deferred to the
     * renderer — they don't affect length.
     *
     * C5 (2-byte VEX):
     *     C5  [R'.vvvv.L.pp]  opcode  modrm ...
     * C4 (3-byte VEX):
     *     C4  [R'.X'.B'.mmmmm]  [W.vvvv.L.pp]  opcode  modrm ... */
    /* The VEX pp field (byte1[1:0] on C5, byte2[1:0] on C4)
     * supplies the instruction's mandatory prefix:
     *   00 → none, 01 → op66, 10 → F3, 11 → F2.
     * classify_0f only distinguishes op66 from non-op66, so
     * that's all we need to map pp into. Any legacy op66
     * prefix we ate earlier is semantically discarded by VEX. */
    if (buf[p] == 0xC5 && p + 1 < max) {
        uint8_t b1 = buf[p + 1];
        uint8_t pp = b1 & 0x3;
        p += 2;                  /* consume C5 + byte1 */
        if (p >= max) return -1;
        uint8_t op = buf[p++];
        info->map    = 2;        /* C5 implies 0F map */
        info->opcode = op;
        int has_modrm = 1, imm_bytes = 0;
        int vex_op66 = (pp == 0x1);
        classify_0f(op, vex_op66, info->rex_w,
                    &has_modrm, &imm_bytes);
        info->has_modrm = (uint8_t)has_modrm;
        info->imm_bytes = (uint8_t)imm_bytes;
        /* VEX mandatory prefix overrides legacy op66 for the
         * purposes of imm-size classification. Reflect that in
         * info->op66 so callers (format.c renderer, xdec_length
         * consumers) see the effective prefix state, not stale
         * pre-VEX legacy state. */
        info->op66 = (uint8_t)vex_op66;
        goto do_modrm;
    }
    if (buf[p] == 0xC4 && p + 2 < max) {
        uint8_t b1 = buf[p + 1];
        uint8_t b2 = buf[p + 2];
        uint8_t mmmm = b1 & 0x1f;
        uint8_t pp   = b2 & 0x3;
        info->rex_w = (b2 >> 7) & 1u;   /* W bit lives in byte2 */
        p += 3;                  /* consume C4 + byte1 + byte2 */
        if (p >= max) return -1;
        uint8_t op = buf[p++];
        int has_modrm = 1, imm_bytes = 0;
        int vex_op66 = (pp == 0x1);
        info->op66 = (uint8_t)vex_op66;
        if (mmmm == 0x01) {                /* 0F map */
            info->map = 2;
            info->opcode = op;
            classify_0f(op, vex_op66, info->rex_w,
                        &has_modrm, &imm_bytes);
        } else if (mmmm == 0x02) {         /* 0F 38 map */
            info->map    = 3;
            info->opcode = op;
            imm_bytes    = 0;
        } else if (mmmm == 0x03) {         /* 0F 3A map */
            info->map    = 3;
            info->opcode = op;
            imm_bytes    = 1;
        } else {
            /* Reserved VEX map — reject so the scanner treats
             * the bytes as non-starters rather than walking into
             * them as if they were instructions. */
            return -1;
        }
        info->has_modrm = (uint8_t)has_modrm;
        info->imm_bytes = (uint8_t)imm_bytes;
        goto do_modrm;
    }

    /* ---------- 3. legacy / 0F opcode ---------- */
    uint8_t op = buf[p++];
    int has_modrm = 0;
    int imm_bytes = 0;

    if (op == 0x0F) {
        if (p >= max) return -1;
        op = buf[p++];

        if (op == 0x38) {
            /* 3-byte opcode, 0x38 map: treat generously */
            if (p >= max) return -1;
            op = buf[p++];
            info->map       = 3;
            info->opcode    = op;
            has_modrm = 1;
            imm_bytes = 0;
        } else if (op == 0x3A) {
            /* 3-byte, 0x3A map: typical forms have imm8 */
            if (p >= max) return -1;
            op = buf[p++];
            info->map       = 3;
            info->opcode    = op;
            has_modrm = 1;
            imm_bytes = 1;
        } else {
            info->map    = 2;
            info->opcode = op;
            if (classify_0f(op, info->op66, info->rex_w,
                            &has_modrm, &imm_bytes) < 0)
                return -1;
        }
    } else {
        info->map    = 1;
        info->opcode = op;

        uint8_t flags = prim_map[op];
        if (flags & XV) return -1;
        has_modrm = (flags & M) != 0;

        if      (flags & I1) imm_bytes = 1;
        else if (flags & I2) imm_bytes = 2;
        else if (flags & I4) imm_bytes = 4;
        else if (flags & IV) imm_bytes = info->op66 ? 2 : 4;
        else if (flags & IQ) imm_bytes = info->rex_w ? 8
                                          : (info->op66 ? 2 : 4);
        else if (flags & IM) imm_bytes = 8;
        else                 imm_bytes = 0;

        /* ENTER imm16, imm8 → 3 immediate bytes */
        if (op == 0xC8) imm_bytes = 3;
    }

    info->has_modrm = (uint8_t)has_modrm;

do_modrm:
    /* ---------- 4. ModR/M + SIB + displacement ---------- */
    {
    int disp = 0;
    int grp3_peek = (info->map == 1 &&
                     (info->opcode == 0xF6 || info->opcode == 0xF7));

    if (has_modrm) {
        if (p >= max) return -1;
        uint8_t mrm = buf[p++];
        info->modrm = mrm;
        uint8_t mod = mrm >> 6;
        uint8_t reg = (mrm >> 3) & 7;
        uint8_t rm  = mrm & 7;

        /* Grp3 (F6 / F7): if reg field is 0 or 1, opcode is TEST,
         * which carries an extra immediate of operand size. */
        if (grp3_peek && (reg == 0 || reg == 1)) {
            imm_bytes = (op == 0xF6) ? 1
                                     : (info->op66 ? 2 : 4);
        }
        (void)reg;

        if (mod != 3) {
            /* effective-address forms */
            if (rm == 4) {
                /* SIB present */
                if (p >= max) return -1;
                info->sib         = buf[p++];
                info->sib_present = 1;
                uint8_t base = info->sib & 7;
                if (mod == 0) {
                    disp = (base == 5) ? 4 : 0;
                } else if (mod == 1) {
                    disp = 1;
                } else {
                    disp = 4;
                }
            } else {
                if (mod == 0) {
                    disp = (rm == 5) ? 4 : 0;  /* RIP-relative */
                } else if (mod == 1) {
                    disp = 1;
                } else {
                    disp = 4;
                }
            }
        }
    }

    info->disp_bytes = (uint8_t)disp;
    if (p + (size_t)disp > max) return -1;
    p += (size_t)disp;

    info->imm_bytes = (uint8_t)imm_bytes;
    if (p + (size_t)imm_bytes > max) return -1;
    p += (size_t)imm_bytes;

    if (p > XDEC_MAX_LEN) return -1;

    info->length = (int)p;
    return 0;
    }   /* end of do_modrm scope */
}

int xdec_length(const uint8_t *buf, size_t max, int *out_len)
{
    xdec_info_t info;
    int rc = xdec_full(buf, max, &info);
    if (rc < 0) return -1;
    *out_len = info.length;
    return 0;
}
