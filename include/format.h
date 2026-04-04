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

/* Render one JSON object per gadget, one per line (JSON-Lines):
 *   {"addr":"0x...","insns":["mov ...","pop ...","ret"],"bytes":"5f c3"}
 * Trailing newline included. */
void format_gadget_json(FILE *f, const gadget_t *g);

/* Render the JSON object into a caller-provided buffer; used by --unique
 * and --filter so filtering works identically in text and JSON modes. */
int  format_gadget_json_render(const gadget_t *g, char *buf, size_t buflen);

/* Canonical dedup key. Applies:
 *   - ret 0x0 / retn 0 / retf  →  ret
 *   - xor REG, REG             →  ZERO(REG)
 * Used only as a dedup key in --canonical mode; the output stays the
 * rendered form. Returns chars written or -1 on overflow. */
int  format_gadget_canonical_render(const gadget_t *g,
                                    char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_FORMAT_H */
