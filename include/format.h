/*
 * format.h — minimal x86-64 mnemonic printer for gadgets.
 */
#ifndef SHRIKE_FORMAT_H
#define SHRIKE_FORMAT_H

#include "scan.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Render a single gadget as one text line to `f`, with format:
 *   0x<vaddr>: <insn> ; <insn> ; ... ; <terminator>
 *
 * The printer recognises a small vocabulary of common opcodes used in
 * ROP gadgets and falls back to "db 0x<hex>, ..." for anything else.
 * That keeps the output readable for the 95% case without pretending
 * to be a full disassembler.
 */
void format_gadget(FILE *f, const gadget_t *g);

/* Same, but as a single semicolon-delimited instruction list without
 * the address prefix — used by the deduper / hash and by tests. */
void format_gadget_insns(FILE *f, const gadget_t *g);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_FORMAT_H */
