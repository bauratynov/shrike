/*
 * cet.h — Intel CET classification for a decoded gadget.
 *
 * Two boolean properties of interest when auditing a target that
 * runs under Control-flow Enforcement Technology:
 *
 *   - shstk_blocked : the gadget's terminator is a RET/RETF family
 *     instruction, which the shadow stack neutralises. A ROP chain
 *     that uses this gadget cannot survive on a process with SHSTK
 *     enabled.
 *
 *   - starts_endbr  : the gadget's first instruction is ENDBR64
 *     (or ENDBR32). Under IBT, indirect CALL/JMP must land on an
 *     ENDBR; such a gadget is a legitimate indirect-branch target.
 *     (Gadgets that do NOT start with ENDBR are unreachable by
 *     indirect branches in an IBT-enforced process.)
 *
 * The canonical "surviving CET" classifier therefore is:
 *     survivable = !shstk_blocked && (!needs_indirect_entry || starts_endbr)
 *
 * Since shrike works on static bytes and cannot know whether the
 * attacker intends to pivot into the gadget via an indirect branch,
 * the CLI exposes the two properties and lets the operator filter.
 */
#ifndef SHRIKE_CET_H
#define SHRIKE_CET_H

#include "scan.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Terminator is RET / RETF / RET imm16 / RETF imm16. */
int cet_shstk_blocked(const gadget_t *g);

/* Gadget's first instruction is ENDBR64 (F3 0F 1E FA) or ENDBR32 (...FB). */
int cet_starts_endbr(const gadget_t *g);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_CET_H */
