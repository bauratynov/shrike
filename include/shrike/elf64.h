/*
 * elf64.h — minimal ELF64 loader for executable-segment enumeration.
 *
 * We only care about the parts of the format shrike needs to find
 * gadget candidates: the program headers that describe executable
 * loadable segments. Everything else (dynamic, symtab, RELRO, etc.)
 * is ignored.
 */
#ifndef SHRIKE_ELF64_H
#define SHRIKE_ELF64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define EI_NIDENT    16
#define ELFMAG0      0x7f
#define ELFMAG1      'E'
#define ELFMAG2      'L'
#define ELFMAG3      'F'
#define ELFCLASS64   2
#define ELFDATA2LSB  1
#define EM_X86_64    62
#define EM_AARCH64   183
#define EM_RISCV     243

#define ET_EXEC 2
#define ET_DYN  3

#define PT_LOAD         1
#define PT_NOTE         4
#define PT_GNU_PROPERTY 0x6474e553

#define PF_X 1u
#define PF_W 2u
#define PF_R 4u

typedef struct {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

/* One executable, loadable region in the mapped file. */
typedef struct {
    const uint8_t *bytes;    /* pointer inside the mmap */
    size_t         size;     /* file bytes */
    uint64_t       vaddr;    /* virtual address in the process image */
    uint32_t       flags;    /* PF_* */
    uint16_t       machine;  /* EM_* of the containing ELF */
} elf64_segment_t;

#define SHRIKE_MAX_SEGMENTS 32

typedef struct {
    const uint8_t   *map;
    size_t           size;
    int              owns;           /* we must munmap on close */

    const Elf64_Ehdr *ehdr;
    const Elf64_Phdr *phdr;
    size_t            phnum;

    elf64_segment_t   segs[SHRIKE_MAX_SEGMENTS];
    size_t            nseg;          /* executable PT_LOAD segments */

    uint64_t          entry;         /* e_entry, for reporting */
    int               is_dyn;        /* ET_DYN vs ET_EXEC */
    uint16_t          machine;       /* EM_X86_64 or EM_AARCH64 */

    /* v1.2.0 / v1.2.1: source-format discriminator + PE metadata.
     * ELF inputs leave `format = 0` and `pe_dll_chars = 0`; PE
     * inputs set `format = 1` and populate pe_dll_chars from
     * IMAGE_OPTIONAL_HEADER.DllCharacteristics so the hardening
     * audit (`--cet-posture` et al.) can report CF Guard / DEP /
     * ASLR / HIGH_ENTROPY_VA without a second parse pass. */
    int               format;
    uint16_t          pe_dll_chars;
} elf64_t;

/* mmap + parse + fill the segs[] array with executable PT_LOAD entries.
 * Returns 0 on success, -1 + errno on failure.
 *
 * v1.9.1: this function is part of the 1.x C surface that goes
 * internal in 2.0 — the v2 opaque-handle API (shrike_open /
 * shrike_iter_*) replaces the manual loader-plus-scan loop.
 * See docs/migration-1-to-2.md. */
#include <shrike/version.h>
SHRIKE_DEPRECATED("retired in 2.0 — use shrike_open(). "
                  "See docs/migration-1-to-2.md.")
int  elf64_load(const char *path, elf64_t *out);

/* Parse an already-resident buffer. The caller guarantees buf outlives
 * the elf64_t. Useful for unit tests. */
SHRIKE_DEPRECATED("retired in 2.0 — use shrike_open_mem().")
int  elf64_load_buffer(const uint8_t *buf, size_t size, elf64_t *out);

SHRIKE_DEPRECATED("retired in 2.0 — use shrike_close().")
void elf64_close(elf64_t *e);

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_ELF64_H */
