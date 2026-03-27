/*
 * arm64.h — ARM AArch64 gadget primitives.
 *
 * AArch64 has a fixed 32-bit little-endian instruction encoding, so
 * "length decoding" is trivial: every instruction is 4 bytes. The
 * interesting part is terminator classification (RET / BR / BLR /
 * SVC / RETAA / RETAB), BTI landing-pad recognition, and a minimal
 * mnemonic printer.
 */
#ifndef SHRIKE_ARM64_H
#define SHRIKE_ARM64_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 1 if the 32-bit instruction is a gadget terminator.
 * Recognises:
 *   RET  (0xd65f03c0 / 0xd65f03..)  — includes RETAA / RETAB.
 *   BR   (0xd61f0000 / ...)
 *   BLR  (0xd63f0000 / ...)
 *   SVC  (0xd4000001 / ...)
 */
int arm64_is_terminator(uint32_t insn);

/* Is the instruction a BTI landing pad (any of c / j / jc variants)? */
int arm64_is_bti(uint32_t insn);

/* Read 4 bytes from buf as a little-endian u32. */
uint32_t arm64_read_insn(const uint8_t *buf);

/* Render a mnemonic for insn into buf. Returns chars written.
 * Unknown encodings produce ".word 0xXXXXXXXX" as a safe fallback. */
int arm64_render_insn(char *buf, size_t buflen, uint32_t insn);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_ARM64_H */
