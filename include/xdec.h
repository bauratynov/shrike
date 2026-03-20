/*
 * xdec.h — x86-64 instruction length decoder.
 *
 * Not a full disassembler — just enough to walk bytes and know how
 * many to advance per instruction. Sufficient for gadget enumeration
 * because the scanner's job is to find byte sequences that chain
 * consistently up to a known terminator byte; exact mnemonics matter
 * only for display, not for correctness.
 *
 * Supported surface:
 *   - legacy prefixes (0xF0/F2/F3, segment overrides, 0x66, 0x67)
 *   - REX prefix (0x40-0x4F), with REX.W affecting immediate size
 *   - 1-byte opcode map (primary)
 *   - 2-byte opcode map (0x0F NN)
 *   - 3-byte opcode maps (0x0F 0x38 NN and 0x0F 0x3A NN), treated
 *     generously: 38-map = modrm/no-imm, 3A-map = modrm/imm8
 *   - ModR/M + SIB + displacement
 *   - immediates including 64-bit MOV r64, imm64 and moffs operands
 *
 * Out of scope: VEX/EVEX-encoded instructions (mapped to INVALID),
 * multi-byte 3DNow opcodes past first imm8, AMX, instruction semantics.
 */
#ifndef SHRIKE_XDEC_H
#define SHRIKE_XDEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XDEC_MAX_LEN 15   /* x86-64 spec maximum */

/* Decode a single instruction's length.
 *   buf     — start of candidate instruction bytes
 *   max     — how many bytes are available at buf
 *   out_len — on success, receives the total instruction length
 *              (1..XDEC_MAX_LEN)
 *
 * Returns 0 on success, -1 on:
 *   - truncation (max too small)
 *   - invalid opcode (VEX/EVEX prefixes, illegal-in-64 opcodes)
 *   - instruction length > 15 bytes (spec violation)
 */
int xdec_length(const uint8_t *buf, size_t max, int *out_len);

/* Full decode. Returns length and fills info with coarse category
 * (was there a ModR/M? a prefix? the opcode byte itself?). Intended
 * for the mnemonic printer in format.c. */
typedef struct {
    int      length;      /* total bytes */
    uint8_t  prefixes[8]; /* legacy prefixes consumed */
    uint8_t  npfx;        /* number of legacy prefixes */
    uint8_t  rex;         /* REX byte (0 if none) */
    uint8_t  rex_w;       /* REX.W bit */
    uint8_t  op66;        /* 0x66 prefix seen */
    uint8_t  opcode;      /* final opcode byte */
    uint8_t  map;         /* 1, 2, or 3 */
    uint8_t  has_modrm;
    uint8_t  modrm;       /* if has_modrm */
    uint8_t  sib_present;
    uint8_t  sib;         /* if sib_present */
    uint8_t  disp_bytes;
    uint8_t  imm_bytes;
} xdec_info_t;

int xdec_full(const uint8_t *buf, size_t max, xdec_info_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_XDEC_H */
