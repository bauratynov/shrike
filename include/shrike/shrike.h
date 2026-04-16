/*
 * shrike.h — the 2.x stable C API.
 *
 * This header is the v2 ABI contract. Functions and types
 * declared here do not change between v2.0.0 and v2.x — see
 * STABILITY.md. The 1.x-era headers (`elf64.h`, `pe.h`,
 * `macho.h`, `scan.h`, `regidx.h`) remain available but are
 * considered internal and retain their SHRIKE_DEPRECATED
 * annotations; consumers should prefer this header.
 *
 * Design follows capstone's opaque-handle pattern:
 *
 *     shrike_ctx_t *ctx;
 *     if (shrike_open("/bin/ls", &ctx) != 0) { ... }
 *
 *     shrike_iter_t *it = shrike_iter_begin(ctx);
 *     const shrike_gadget_t *g;
 *     while ((g = shrike_iter_next(it)) != NULL) {
 *         printf("0x%" PRIx64 "  %s\n",
 *                shrike_gadget_address(g),
 *                shrike_gadget_disasm(g));
 *     }
 *     shrike_iter_end(it);
 *     shrike_close(ctx);
 *
 * Every field on every struct is accessed via a getter — struct
 * layouts can evolve across 2.x patch bumps without breaking
 * ABI. The underlying v1.x loader machinery is unchanged; this
 * header is a thin opaque wrapper over it.
 */
#ifndef SHRIKE_H
#define SHRIKE_H

#include <shrike/version.h>
#include <shrike/elf64.h>   /* for elf64_t — used as private state */
#include <shrike/scan.h>    /* for gadget_t — wrapped opaquely     */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handle types. The struct definitions live in shrike.c
 * and are not part of the ABI. */
typedef struct shrike_ctx  shrike_ctx_t;
typedef struct shrike_iter shrike_iter_t;

/* A gadget record is also opaque — accessed only through
 * getters below. The pointer returned by shrike_iter_next()
 * is owned by the iterator and valid until the next call
 * to shrike_iter_next() or shrike_iter_end(). */
typedef struct shrike_gadget shrike_gadget_t;

/* --- Options. --- */

typedef enum {
    /* Max instructions per gadget (int, default 5). */
    SHRIKE_OPT_MAX_INSN       = 1,

    /* Max backscan window in bytes (int, default 48, x86 only). */
    SHRIKE_OPT_MAX_BACKSCAN   = 2,

    /* Skip syscall terminators (int 0/1, default 0 = keep). */
    SHRIKE_OPT_NO_SYSCALL     = 10,

    /* Skip int3 terminators (int 0/1, default 0 = keep). */
    SHRIKE_OPT_NO_INT         = 11,

    /* Skip indirect call/jmp (int 0/1, default 0 = keep). */
    SHRIKE_OPT_NO_INDIRECT    = 12,

    /* Preferred arch slice for Mach-O fat binaries — pass
     * "x86_64" / "arm64" via shrike_set_option_str. */
    SHRIKE_OPT_MACHO_ARCH     = 20
} shrike_option_t;

/* --- Lifecycle. --- */

/* mmap + parse a file and populate the context. Returns 0 on
 * success, non-zero errno on failure. Caller must pair with
 * shrike_close. */
int  shrike_open(const char *path, shrike_ctx_t **out);

/* Parse an already-resident buffer. Caller guarantees `buf`
 * outlives the context. */
int  shrike_open_mem(const uint8_t *buf, size_t size,
                     shrike_ctx_t **out);

void shrike_close(shrike_ctx_t *ctx);

/* --- Options. --- */

int  shrike_set_option_int(shrike_ctx_t *ctx,
                           shrike_option_t opt, int value);
int  shrike_set_option_str(shrike_ctx_t *ctx,
                           shrike_option_t opt, const char *value);

/* --- Iteration. --- */

shrike_iter_t *shrike_iter_begin(shrike_ctx_t *ctx);

/* Returns NULL when iteration is complete. */
const shrike_gadget_t *shrike_iter_next(shrike_iter_t *it);

void shrike_iter_end(shrike_iter_t *it);

/* --- Gadget accessors. --- */

uint64_t       shrike_gadget_address(const shrike_gadget_t *g);
const uint8_t *shrike_gadget_bytes(const shrike_gadget_t *g);
size_t         shrike_gadget_size(const shrike_gadget_t *g);
const char    *shrike_gadget_disasm(const shrike_gadget_t *g);
int            shrike_gadget_instruction_count(const shrike_gadget_t *g);

/* Category enum — matches the 1.x taxonomy. 2.x may add new
 * values but never renumbers existing ones. */
typedef enum {
    SHRIKE_CAT_OTHER      = 0,
    SHRIKE_CAT_RET_ONLY   = 1,
    SHRIKE_CAT_POP        = 2,
    SHRIKE_CAT_MOV        = 3,
    SHRIKE_CAT_ARITH      = 4,
    SHRIKE_CAT_STACK_PIVOT= 5,
    SHRIKE_CAT_SYSCALL    = 6,
    SHRIKE_CAT_INDIRECT   = 7
} shrike_category_t;

shrike_category_t shrike_gadget_category(const shrike_gadget_t *g);

/* Architecture the gadget lives in. */
typedef enum {
    SHRIKE_ARCH_X86_64  = 1,
    SHRIKE_ARCH_AARCH64 = 2,
    SHRIKE_ARCH_RISCV64 = 3
} shrike_arch_t;

shrike_arch_t shrike_gadget_arch(const shrike_gadget_t *g);

/* --- Errors. --- */

/* Returns the last errno-style error recorded on this context.
 * Zero when no error has been seen since the last successful
 * call. Thread-local storage is NOT used — callers should
 * serialise access to the same context from multiple threads. */
int         shrike_errno(const shrike_ctx_t *ctx);
const char *shrike_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_H */
