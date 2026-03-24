/*
 * format.h — gadget mnemonic printer.
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

/* Render a gadget as one text line to `f`, with format:
 *   0x<vaddr>: <insn> ; <insn> ; ... ; <terminator>
 * Unknown opcodes fall back to "db 0x..". */
void format_gadget(FILE *f, const gadget_t *g);

/* Render only the semicolon-separated instruction list (no address)
 * to `f`. Used by tests. */
void format_gadget_insns(FILE *f, const gadget_t *g);

/* Render the full "0x<addr>: ..." line into a caller-provided buffer.
 * Returns the number of characters written (excluding NUL), or -1
 * if the output would exceed buflen. Does not write a trailing '\n'. */
int  format_gadget_render(const gadget_t *g, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_FORMAT_H */
