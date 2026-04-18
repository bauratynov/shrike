/*
 * ppc64.h — PowerPC 64 fixed-width length decoder + terminator
 * classifier.
 *
 * Every PPC64 instruction is exactly 4 bytes. Scanning collapses
 * to the same stride-4 loop the aarch64 scanner uses. We
 * recognise:
 *   BLR   (branch-to-link-register) = 0x4E800020
 *   BCTR  (branch-to-count-register) = 0x4E800420
 *   SC    (system call) = 0x44000002
 *
 * Endian: modern Linux ppc64le encodes instructions in
 * little-endian word order. The shrike scanner reads 4 bytes
 * LE-first; if the input is big-endian (AIX / ppc64be) the
 * loader flips them. For v5.0 we accept ppc64le only — ppc64be
 * is a 5.x patch bump.
 */
#ifndef SHRIKE_PPC64_H
#define SHRIKE_PPC64_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EM_PPC64  21

uint32_t ppc64_read_insn(const uint8_t *buf);
int      ppc64_is_terminator(uint32_t insn);
int      ppc64_is_syscall(uint32_t insn);
int      ppc64_render_insn(char *buf, size_t buflen, uint32_t insn);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_PPC64_H */
