/*
 * macho.h — minimal Mach-O 64-bit loader.
 *
 * Scope for v1.3.0: thin binaries only (MH_MAGIC_64 = 0xfeedfacf,
 * little-endian). Fat/universal dispatch lands in v1.3.1.
 *
 * We parse just enough to enumerate executable Mach-O segments
 * (LC_SEGMENT_64 load commands whose initprot includes
 * VM_PROT_EXECUTE) and extract the `__TEXT,__text` section bytes.
 * No symbol table, no dyld info, no code-signing directory —
 * shrike scans bytes.
 *
 * Like pe_load, macho_load populates an elf64_t in place with
 * phdr/phnum left NULL/0. The scanner, recipe composer, SARIF
 * emitter et al. read out the segment array unchanged.
 */
#ifndef SHRIKE_MACHO_H
#define SHRIKE_MACHO_H

#include <shrike/elf64.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Magic numbers. We only accept MH_MAGIC_64 (native little-endian
 * 64-bit). MH_CIGAM_64 (big-endian-to-little-endian swap) is
 * declined until someone brings a real Apple-silicon-on-BE
 * use case. */
#define MH_MAGIC_64        0xfeedfacfu
#define MH_MAGIC_32        0xfeedfaceu     /* detected-but-rejected */
#define FAT_MAGIC          0xcafebabeu     /* detected-but-rejected */
#define FAT_CIGAM          0xbebafecau

/* CPU types we care about. Values from <mach/machine.h>. */
#define CPU_ARCH_ABI64     0x01000000
#define CPU_TYPE_X86_64    (7 | CPU_ARCH_ABI64)   /* 0x01000007 */
#define CPU_TYPE_ARM64     (12 | CPU_ARCH_ABI64)  /* 0x0100000c */

/* cpusubtype mask + arm64e (PAC-enabled) discriminator. */
#define CPU_SUBTYPE_MASK       0xff000000u
#define CPU_SUBTYPE_ARM64E     2

/* Filetype values — MH_EXECUTE = regular binary, MH_DYLIB =
 * dynamic library, MH_BUNDLE = plugin, all have executable
 * __TEXT segments we want. */
#define MH_EXECUTE         2
#define MH_DYLIB           6
#define MH_BUNDLE          8

/* Load commands. LC_SEGMENT_64 carries segments; everything else
 * we ignore. */
#define LC_REQ_DYLD        0x80000000u
#define LC_SEGMENT_64      0x19u

/* VM protection bits on segment initprot. */
#define VM_PROT_READ       0x1
#define VM_PROT_WRITE      0x2
#define VM_PROT_EXECUTE    0x4

/* mmap + parse + fill e->segs[] with every executable segment.
 * Returns 0 on success, -1 + errno on failure. On success the
 * caller must elf64_close(e). */
int  macho_load(const char *path, elf64_t *e);

/* Parse an already-resident buffer. Caller guarantees `buf`
 * outlives the elf64_t. Used by unit tests. */
int  macho_load_buffer(const uint8_t *buf, size_t size, elf64_t *e);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_MACHO_H */
