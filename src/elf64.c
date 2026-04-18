/*
 * elf64.c — ELF64 loader, bounds-checked.
 *
 * Only gathers executable PT_LOAD segments. Everything else (sections,
 * dynamic, symtab) is deliberately ignored: shrike scans bytes, not
 * symbols.
 */

#include <shrike/elf64.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if !defined(_WIN32)
  #include <unistd.h>
  #include <sys/mman.h>
#endif

static int in_bounds(const elf64_t *e, uint64_t off, uint64_t len)
{
    return off <= e->size && len <= e->size && off + len <= e->size;
}

static int parse(elf64_t *e)
{
    if (e->size < sizeof(Elf64_Ehdr)) { errno = EINVAL; return -1; }
    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)e->map;

    if (eh->e_ident[0] != ELFMAG0 || eh->e_ident[1] != ELFMAG1 ||
        eh->e_ident[2] != ELFMAG2 || eh->e_ident[3] != ELFMAG3) {
        /* v0.22.0: give a specific hint for common non-ELF containers */
        if (e->size >= 2 && e->map[0] == 'M' && e->map[1] == 'Z') {
            /* PE/COFF (DOS stub: 'MZ') */
            errno = ENOTSUP; return -2;
        }
        if (e->size >= 4 &&
            ((e->map[0] == 0xCF && e->map[1] == 0xFA &&
              e->map[2] == 0xED && e->map[3] == 0xFE) ||
             (e->map[0] == 0xCA && e->map[1] == 0xFE &&
              e->map[2] == 0xBA && e->map[3] == 0xBE))) {
            /* Mach-O 64 LE or universal 'fat' magic */
            errno = ENOTSUP; return -3;
        }
        errno = EINVAL; return -1;
    }
    if (eh->e_ident[4] != ELFCLASS64 || eh->e_ident[5] != ELFDATA2LSB) {
        errno = ENOTSUP; return -1;
    }
    /* v1.4.1 + v5.0.0: accept x86-64, aarch64, RISC-V, PPC64,
     * MIPS. Byte-order for MIPS is taken from e_ident[5] so both
     * big-endian and little-endian flavours work. */
    if (eh->e_machine != EM_X86_64 &&
        eh->e_machine != EM_AARCH64 &&
        eh->e_machine != EM_RISCV &&
        eh->e_machine != EM_PPC64 &&
        eh->e_machine != EM_MIPS &&
        eh->e_machine != EM_MIPS_RS3_LE) {
        errno = ENOTSUP; return -1;
    }
    if (eh->e_phentsize != sizeof(Elf64_Phdr)) { errno = EINVAL; return -1; }

    e->ehdr    = eh;
    e->entry   = eh->e_entry;
    e->is_dyn  = (eh->e_type == ET_DYN);
    e->machine = eh->e_machine;

    if (!eh->e_phnum) return 0;

    uint64_t phsz = (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr);
    if (!in_bounds(e, eh->e_phoff, phsz)) { errno = EINVAL; return -1; }

    e->phdr  = (const Elf64_Phdr *)(e->map + eh->e_phoff);
    e->phnum = eh->e_phnum;

    for (size_t i = 0; i < e->phnum && e->nseg < SHRIKE_MAX_SEGMENTS; i++) {
        const Elf64_Phdr *p = &e->phdr[i];
        if (p->p_type != PT_LOAD) continue;
        if (!(p->p_flags & PF_X))  continue;
        if (!in_bounds(e, p->p_offset, p->p_filesz)) continue;

        elf64_segment_t *s = &e->segs[e->nseg++];
        s->bytes   = e->map + p->p_offset;
        s->size    = (size_t)p->p_filesz;
        s->vaddr   = p->p_vaddr;
        s->flags   = p->p_flags;
        s->machine = e->machine;
    }
    return 0;
}

int elf64_load_buffer(const uint8_t *buf, size_t size, elf64_t *out)
{
    memset(out, 0, sizeof(*out));
    out->map           = buf;
    out->size          = size;
    out->map_base      = buf;
    out->map_base_size = size;
    out->owns          = 0;
    return parse(out);
}

#if !defined(_WIN32)
int elf64_load(const char *path, elf64_t *out)
{
    memset(out, 0, sizeof(*out));

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return -1; }
    if (st.st_size <= 0)    { close(fd); errno = EINVAL; return -1; }

    void *map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -1;

    out->map           = (const uint8_t *)map;
    out->size          = (size_t)st.st_size;
    out->map_base      = out->map;
    out->map_base_size = out->size;
    out->owns          = 1;

    int rc = parse(out);
    if (rc < 0) {
        int saved = errno;
        munmap((void *)out->map_base, out->map_base_size);
        memset(out, 0, sizeof(*out));
        errno = saved;
        return rc == -2 ? -2 : rc == -3 ? -3 : rc == -4 ? -4 : -1;
    }
    return 0;
}
#else
int elf64_load(const char *path, elf64_t *out)
{
    (void)path; (void)out;
    errno = ENOSYS; return -1;
}
#endif

void elf64_close(elf64_t *e)
{
    if (!e) return;
#if !defined(_WIN32)
    /* Always munmap from map_base, not map — the Mach-O fat
     * dispatcher re-points map at a slice inside the outer
     * mapping, so munmap(map, size) would target the wrong
     * region. map_base was set once at load time. */
    if (e->owns && e->map_base) {
        munmap((void *)e->map_base, e->map_base_size);
    }
#endif
    memset(e, 0, sizeof(*e));
}
