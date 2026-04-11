/*
 * pe.h — minimal PE/COFF loader for executable-section enumeration.
 *
 * Shrike's scanner wants "a pointer to bytes plus the VA they'd live
 * at", which is the same regardless of container format. Rather than
 * thread a generic segment type through every caller, pe_load fills
 * an elf64_t in place with `ehdr`/`phdr` left NULL and `phnum` at
 * zero — the loops in main.c that touch those are already guarded
 * by `phnum` so they skip cleanly for PE inputs.
 *
 * Scope for v1.2.0: DOS stub → NT headers → section table → scannable
 * bytes for every IMAGE_SCN_MEM_EXECUTE section. Debug Directory,
 * Delay-Load, CLI headers, packer metadata are all out of scope and
 * will get annotations in later patch bumps.
 */
#ifndef SHRIKE_PE_H
#define SHRIKE_PE_H

#include <shrike/elf64.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Microsoft PE machine codes (IMAGE_FILE_MACHINE_*). */
#define IMAGE_FILE_MACHINE_I386  0x014c
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_ARM64 0xaa64

/* Executable-section gate: this is the flag the Windows loader uses
 * to decide whether a page should be mapped PROT_EXEC. We rely on
 * it alone and do not also test IMAGE_SCN_CNT_CODE, because obfuscators
 * and thunk generators routinely leave CNT_CODE off on pages they
 * still expect to execute from. */
#define IMAGE_SCN_MEM_EXECUTE 0x20000000u
#define IMAGE_SCN_CNT_CODE    0x00000020u

/* mmap + parse + fill e->segs[] with every executable section.
 * Returns 0 on success, -1 + errno on failure. On success the
 * caller must elf64_close(e) as with the ELF path. */
int  pe_load(const char *path, elf64_t *e);

/* Parse an already-resident buffer. Caller guarantees `buf` outlives
 * the elf64_t. Used by unit tests. */
int  pe_load_buffer(const uint8_t *buf, size_t size, elf64_t *e);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_PE_H */
