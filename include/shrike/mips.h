/*
 * mips.h — MIPS32/64 fixed-width length decoder + terminator
 * classifier.
 *
 * MIPS instructions are 4 bytes. The big wart is the
 * branch-delay slot: the instruction after a branch executes
 * before control transfers. For gadget scanning we *ignore*
 * the delay slot for now — emit gadgets ending at the branch
 * itself and leave it to chain consumers to deal with the
 * slot. Full delay-slot-aware scanning is tracked for a
 * later patch bump.
 *
 * Terminators:
 *   jr $ra   — branch to link-register (conventional return)
 *   jr $rN   — indirect branch
 *   jalr     — indirect call
 *   syscall  — 0x0000000C
 *   eret     — 0x42000018 (privileged return)
 */
#ifndef SHRIKE_MIPS_H
#define SHRIKE_MIPS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EM_MIPS           8
#define EM_MIPS_RS3_LE   10

uint32_t mips_read_insn(const uint8_t *buf, int little_endian);
int      mips_is_terminator(uint32_t insn);
int      mips_is_syscall(uint32_t insn);
int      mips_render_insn(char *buf, size_t buflen, uint32_t insn);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_MIPS_H */
