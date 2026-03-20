/*
 * scan.h — gadget scanner.
 *
 * Walks an executable segment looking for gadget terminators (RET,
 * SYSCALL, INT, indirect CALL/JMP), then for each terminator walks
 * backward byte-by-byte, decoding instruction chains through the
 * length decoder and emitting every chain that lands exactly on the
 * terminator.
 *
 * Emission is via a callback, which keeps memory ownership out of
 * scan.c: the caller chooses whether to print, accumulate, hash, etc.
 */
#ifndef SHRIKE_SCAN_H
#define SHRIKE_SCAN_H

#include "elf64.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t       vaddr;       /* virtual address of the first byte */
    size_t         offset;      /* byte offset within the segment */
    size_t         length;      /* total bytes incl. the terminator */
    int            insn_count;  /* number of instructions */
    const uint8_t *bytes;       /* convenience: segment bytes + offset */
} gadget_t;

typedef void (*gadget_cb_t)(const elf64_segment_t *seg,
                            const gadget_t        *g,
                            void                  *ctx);

typedef struct {
    int  max_insn;        /* max instructions per gadget  (default 5)   */
    int  max_backscan;    /* max bytes back from terminator (default 48) */
    int  include_syscall; /* emit 0F 05 (SYSCALL) gadgets   (default 1)  */
    int  include_int;     /* emit INT imm8 gadgets          (default 1)  */
    int  include_ff;      /* emit indirect CALL/JMP         (default 1)  */
} scan_config_t;

void scan_config_default(scan_config_t *cfg);

/* Run the scanner over one executable segment.
 * Returns the number of gadgets emitted. */
size_t scan_segment(const elf64_segment_t *seg,
                    const scan_config_t   *cfg,
                    gadget_cb_t            cb,
                    void                  *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_SCAN_H */
