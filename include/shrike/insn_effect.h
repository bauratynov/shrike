/*
 * insn_effect.h — per-instruction typed effect record.
 *
 * `gadget_effect_t` (v1.5.0) summarises the whole gadget. For
 * symbolic execution, chain-correctness proofs, and any analysis
 * that needs "what does *this one instruction* read / write",
 * we need finer granularity.
 *
 * `insn_effect_t` is a small fixed-size struct that names:
 *   - which registers this instruction reads
 *   - which it writes
 *   - how the stack pointer moves (positive = pop, negative = push)
 *   - whether memory is touched (flags only — the V3 symbolic
 *     backend fills in ranges)
 *   - whether this is a terminator (and of which kind)
 *
 * Register numbering matches regidx / gadget_effect.
 */
#ifndef SHRIKE_INSN_EFFECT_H
#define SHRIKE_INSN_EFFECT_H

#include <shrike/effect.h>   /* for gadget_term_t */
#include <shrike/elf64.h>

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define INSN_EFFECT_MEM_READ   0x01u
#define INSN_EFFECT_MEM_WRITE  0x02u
#define INSN_EFFECT_KNOWN      0x04u  /* decoder recognised this insn */

typedef struct {
    uint32_t      reads_mask;
    uint32_t      writes_mask;

    /* Net effect on the stack pointer. Positive means the SP
     * moves up (stack shrinks, values are consumed — POP/RET).
     * Negative means the SP moves down (stack grows — PUSH,
     * CALL-ish forms). Zero means no SP effect. */
    int32_t       stack_delta;

    /* Bitmask of INSN_EFFECT_* flags. */
    uint8_t       flags;

    /* GADGET_TERM_NONE if this isn't a terminator; otherwise
     * which kind. Set whenever the instruction ends control
     * flow (ret, syscall, indirect jmp/call, etc.). */
    gadget_term_t terminator;

    /* Decoded length in bytes. Useful when the caller wants to
     * step forward through the gadget instruction by instruction
     * using this record alone (no second call to xdec / riscv
     * length). */
    uint8_t       length;
} insn_effect_t;

/* Decode a single instruction at `bytes` and populate `out`. The
 * `machine` field comes from the containing gadget (EM_X86_64,
 * EM_AARCH64, EM_RISCV).
 *
 * Returns the instruction's length on success, 0 if the buffer
 * is too short, -1 if the shape isn't one we know. On -1, `out`
 * is still zeroed so callers can mem-compare safely. */
int insn_effect_decode(const uint8_t *bytes, size_t remaining,
                       uint16_t machine, insn_effect_t *out);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_INSN_EFFECT_H */
