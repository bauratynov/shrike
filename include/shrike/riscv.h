/*
 * riscv.h — RV64GC length decoder + terminator classifier.
 *
 * RISC-V is variable-length-lite: every instruction is either 2
 * bytes (the C / RVC compressed extension) or 4 bytes (the base
 * ISA). The encoding rule is trivially cheap — if the low two
 * bits of the first halfword are 2'b11, the instruction is 4
 * bytes; otherwise it's 2. There are longer forms (6/8/16 bytes)
 * reserved for future extensions; none are emitted by GCC 14 /
 * Clang 20 in practice, so v1.4 declines them.
 *
 * Terminator kinds we recognise:
 *   RV_TERM_JALR   — 32-bit jalr; ret is jalr x0, x1, 0
 *   RV_TERM_C_JR   — 16-bit c.jr rs1 (rs1 != 0)
 *   RV_TERM_C_JALR — 16-bit c.jalr rs1 (rs1 != 0)
 *   RV_TERM_ECALL  — 32-bit system call
 *   RV_TERM_EBREAK — 32-bit breakpoint
 *   RV_TERM_MRET   — machine-mode return (privileged)
 *   RV_TERM_SRET   — supervisor-mode return (privileged)
 *
 * Everything else is NONE. Scanner walks back from a terminator
 * and enumerates gadgets the usual way.
 */
#ifndef SHRIKE_RISCV_H
#define SHRIKE_RISCV_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RV_TERM_NONE = 0,
    RV_TERM_JALR,
    RV_TERM_C_JR,
    RV_TERM_C_JALR,
    RV_TERM_ECALL,
    RV_TERM_EBREAK,
    RV_TERM_MRET,
    RV_TERM_SRET
} riscv_term_t;

/* Return the decoded length of the instruction starting at `bytes`
 * (2 or 4), or 0 if the buffer is too short. Does not validate the
 * opcode — just the length encoding. */
size_t       riscv_insn_len(const uint8_t *bytes, size_t remaining);

/* Classify the instruction at `bytes` (with `len` being what
 * riscv_insn_len returned). RV_TERM_NONE for anything we don't
 * explicitly recognise. */
riscv_term_t riscv_classify_terminator(const uint8_t *bytes, size_t len);

/* True if this is a "ret" — jalr x0, x1, 0 or c.jr x1. Used by
 * the scanner to distinguish RET-survivable gadgets from the
 * broader jalr/c.jr family. */
int          riscv_is_ret(const uint8_t *bytes, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_RISCV_H */
