/*
 * macho.c — Mach-O 64-bit loader, bounds-checked.
 *
 * Walks the mach_header_64 then the ncmds load commands and
 * picks out LC_SEGMENT_64 entries whose initprot includes
 * VM_PROT_EXECUTE. Each such segment becomes an
 * `elf64_segment_t` the existing scanner can consume.
 *
 * Like elf64.c and pe.c this is a sequential-advance parser
 * with a size-check before every deref. A malformed input
 * cannot read past the mapped buffer, by construction.
 *
 * Explicitly out of scope for v1.3.0:
 *   - fat / universal binaries (v1.3.1)
 *   - 32-bit Mach-O (V3 roadmap Stage VIII)
 *   - byte-swapped (big-endian) magic
 *   - encrypted __text via LC_ENCRYPTION_INFO_64
 *   - chained fixups / LINKEDIT
 *   - code-signing directory
 */

#include <shrike/macho.h>
#include <shrike/elf64.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if !defined(_WIN32)
  #include <unistd.h>
  #include <sys/mman.h>
#endif

#define MH64_HDR_SIZE  32
#define LC_HDR_SIZE    8
#define SEG64_CMD_SIZE 72
#define LC_SIZE_MIN    8
#define LC_SIZE_MAX    0x00100000u   /* 1 MiB: saner than cmdsize == 0 */

/* Offsets inside mach_header_64 (after the 4-byte magic). */
#define MH_CPUTYPE_OFF      4
#define MH_CPUSUBTYPE_OFF   8
#define MH_FILETYPE_OFF     12
#define MH_NCMDS_OFF        16
#define MH_SIZEOFCMDS_OFF   20
#define MH_FLAGS_OFF        24
/* mach_header_64 trails a 4-byte reserved field → 32 bytes total. */

/* Offsets inside an LC_SEGMENT_64 command (after cmd/cmdsize). */
#define SEG_SEGNAME_OFF     8         /* 16 bytes */
#define SEG_VMADDR_OFF      24
#define SEG_VMSIZE_OFF      32
#define SEG_FILEOFF_OFF     40
#define SEG_FILESIZE_OFF    48
#define SEG_MAXPROT_OFF     56        /* vm_prot_t (int32) */
#define SEG_INITPROT_OFF    60
#define SEG_NSECTS_OFF      64
/* flags (uint32) at offset 68; sections follow at offset 72. */

static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd_u64(const uint8_t *p)
{
    return (uint64_t)rd_u32(p) | ((uint64_t)rd_u32(p + 4) << 32);
}

static int in_bounds(const elf64_t *e, uint64_t off, uint64_t len)
{
    return off <= e->size && len <= e->size && off + len <= e->size;
}

static int parse(elf64_t *e)
{
    if (e->size < MH64_HDR_SIZE) { errno = EINVAL; return -1; }

    uint32_t magic = rd_u32(e->map);
    if (magic == MH_MAGIC_32) {
        /* 32-bit Mach-O: detected, unsupported. */
        errno = ENOTSUP; return -1;
    }
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        /* Universal binary: main.c returns its own helpful message;
         * macho_load just refuses. v1.3.1 will pick a slice here. */
        errno = ENOTSUP; return -1;
    }
    if (magic != MH_MAGIC_64) { errno = EINVAL; return -1; }

    uint32_t cputype    = rd_u32(e->map + MH_CPUTYPE_OFF);
    uint32_t filetype   = rd_u32(e->map + MH_FILETYPE_OFF);
    uint32_t ncmds      = rd_u32(e->map + MH_NCMDS_OFF);
    uint32_t sizeofcmds = rd_u32(e->map + MH_SIZEOFCMDS_OFF);

    switch (cputype) {
    case CPU_TYPE_X86_64: e->machine = EM_X86_64;  break;
    case CPU_TYPE_ARM64:  e->machine = EM_AARCH64; break;
    default:              errno = ENOTSUP; return -1;
    }

    /* Executable + dylib + bundle are all fair game for gadget
     * scanning. Everything else (object files, kext, core dumps,
     * DSYM) is declined. */
    switch (filetype) {
    case MH_EXECUTE: e->is_dyn = 0; break;
    case MH_DYLIB:   e->is_dyn = 1; break;
    case MH_BUNDLE:  e->is_dyn = 1; break;
    default:         errno = ENOTSUP; return -1;
    }
    e->format = 2;    /* 0 = ELF, 1 = PE, 2 = Mach-O */

    if (ncmds == 0 || ncmds > 4096)    { errno = EINVAL; return -1; }
    if (!in_bounds(e, MH64_HDR_SIZE, sizeofcmds)) { errno = EINVAL; return -1; }

    uint64_t cur = MH64_HDR_SIZE;
    uint64_t end = cur + sizeofcmds;

    e->nseg  = 0;
    e->entry = 0;

    for (uint32_t i = 0; i < ncmds; i++) {
        if (cur + LC_HDR_SIZE > end) { errno = EINVAL; return -1; }
        uint32_t lc_cmd  = rd_u32(e->map + cur);
        uint32_t lc_size = rd_u32(e->map + cur + 4);
        if (lc_size < LC_SIZE_MIN || lc_size > LC_SIZE_MAX) {
            errno = EINVAL; return -1;
        }
        if (cur + lc_size > end) { errno = EINVAL; return -1; }

        if ((lc_cmd & ~LC_REQ_DYLD) == LC_SEGMENT_64 &&
            lc_size >= SEG64_CMD_SIZE)
        {
            const uint8_t *lc = e->map + cur;

            uint64_t vmaddr   = rd_u64(lc + SEG_VMADDR_OFF);
            uint64_t vmsize   = rd_u64(lc + SEG_VMSIZE_OFF);
            uint64_t fileoff  = rd_u64(lc + SEG_FILEOFF_OFF);
            uint64_t filesize = rd_u64(lc + SEG_FILESIZE_OFF);
            uint32_t initprot = rd_u32(lc + SEG_INITPROT_OFF);

            if ((initprot & VM_PROT_EXECUTE) == 0) goto next_lc;
            if (filesize == 0)                     goto next_lc;
            if (!in_bounds(e, fileoff, filesize))  goto next_lc;
            if (e->nseg >= SHRIKE_MAX_SEGMENTS)    break;

            /* Clamp scan size to filesize; vm tail beyond the
             * file is zero-filled at load, no gadgets there. */
            uint64_t scan = filesize;
            if (vmsize && vmsize < scan) scan = vmsize;

            elf64_segment_t *s = &e->segs[e->nseg++];
            s->bytes   = e->map + fileoff;
            s->size    = (size_t)scan;
            s->vaddr   = vmaddr;
            s->flags   = 0;
            if (initprot & VM_PROT_READ)    s->flags |= PF_R;
            if (initprot & VM_PROT_WRITE)   s->flags |= PF_W;
            if (initprot & VM_PROT_EXECUTE) s->flags |= PF_X;
            s->machine = e->machine;
        }

next_lc:
        cur += lc_size;
    }

    if (e->nseg == 0) { errno = ENOEXEC; return -1; }
    return 0;
}

int
macho_load_buffer(const uint8_t *buf, size_t size, elf64_t *e)
{
    memset(e, 0, sizeof *e);
    e->map  = buf;
    e->size = size;
    e->owns = 0;
    return parse(e);
}

int
macho_load(const char *path, elf64_t *e)
{
#if defined(_WIN32)
    (void)path; (void)e;
    errno = ENOTSUP;
    return -1;
#else
    memset(e, 0, sizeof *e);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) { int se = errno; close(fd); errno = se; return -1; }
    if (st.st_size <= 0 || (uint64_t)st.st_size > (uint64_t)SIZE_MAX) {
        close(fd); errno = EFBIG; return -1;
    }

    size_t size = (size_t)st.st_size;
    void *map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) return -1;

    e->map  = (const uint8_t *)map;
    e->size = size;
    e->owns = 1;

    int rc = parse(e);
    if (rc < 0) {
        int se = errno;
        elf64_close(e);
        errno = se;
        return rc;
    }
    return 0;
#endif
}
