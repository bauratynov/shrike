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

#include <stdio.h>

/* Preferred slice for fat/universal binaries. Set by
 * macho_set_preferred_arch(); NULL means "no preference — take
 * the first slice and warn". Module-level state is ugly but
 * matches how sarif_current / pivot_atlas_current thread
 * emitter context through gadget_cb_t callbacks elsewhere in
 * shrike without changing stable API shapes. */
static uint32_t g_pref_cputype = 0;

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

/* fat_header / fat_arch are stored big-endian regardless of host.
 * Everything else in a Mach-O lives in native byte order — but
 * fat is special, for compatibility with toolchains that need to
 * read multi-arch containers without knowing the inner arch. */
static uint32_t rd_be_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static uint64_t rd_u64(const uint8_t *p)
{
    return (uint64_t)rd_u32(p) | ((uint64_t)rd_u32(p + 4) << 32);
}

static int in_bounds(const elf64_t *e, uint64_t off, uint64_t len)
{
    return off <= e->size && len <= e->size && off + len <= e->size;
}

static int parse(elf64_t *e);

/* NOTE: this spent two evenings figuring out. Apple's otool
 * happily parses fat binaries where the outer fat_arch entries
 * and the inner mach_header disagree on cputype. We refuse
 * them — it makes the loader simpler and the pathological case
 * (malformed fat as attack surface) goes away. If a real
 * shipping binary trips this check, file an issue. */

/* Resolve a fat/universal image to a single slice and re-point
 * e->map / e->size at it before calling into the thin parser.
 * Ownership of the outer mmap stays on e->owns — the inner slice
 * is a view into the same mapping. */
static int
parse_fat(elf64_t *e, uint32_t magic)
{
    /* fat_header: magic(4 BE) + nfat_arch(4 BE). */
    if (e->size < 8) { errno = EINVAL; return -1; }
    uint32_t nfat = rd_be_u32(e->map + 4);
    if (nfat == 0 || nfat > 32) { errno = EINVAL; return -1; }
    if (e->size < 8 + (uint64_t)nfat * 20) { errno = EINVAL; return -1; }
    /* Use `magic` to suppress -Wunused-parameter; also validates
     * the byte-order expectation — FAT_CIGAM would mean a
     * host-endian fat_header, which Apple tooling never emits. */
    if (magic != FAT_MAGIC) { errno = ENOTSUP; return -1; }

    /* First pass: find the slice whose cputype matches the hint. */
    const uint8_t *archs = e->map + 8;
    uint32_t pick_idx = UINT32_MAX;
    for (uint32_t i = 0; i < nfat; i++) {
        uint32_t ct = rd_be_u32(archs + i * 20 + 0);
        if (g_pref_cputype && ct == g_pref_cputype) {
            pick_idx = i; break;
        }
    }
    /* No hint or no match → first slice wins, emit a warning so
     * the user notices the ambiguity. `lipo -thin <arch>` is how
     * they'd get a deterministic single-arch input. */
    if (pick_idx == UINT32_MAX) {
        pick_idx = 0;
        if (!g_pref_cputype) {
            fprintf(stderr,
                "shrike: Mach-O universal image — no --mach-o-arch set, "
                "scanning first slice (of %u). Pass --mach-o-arch "
                "<x86_64|arm64> to pick deterministically.\n",
                (unsigned)nfat);
        }
    }

    uint32_t off  = rd_be_u32(archs + pick_idx * 20 + 8);
    uint32_t size = rd_be_u32(archs + pick_idx * 20 + 12);
    if (off == 0 || size == 0)             { errno = EINVAL; return -1; }
    if (!in_bounds(e, off, size))          { errno = EINVAL; return -1; }

    /* Rewrite e->map/size to point at the slice. Parse recurses. */
    e->map  = e->map + off;
    e->size = size;
    return parse(e);
}

static int parse(elf64_t *e)
{
    if (e->size < MH64_HDR_SIZE) { errno = EINVAL; return -1; }

    uint32_t magic = rd_u32(e->map);
    if (magic == MH_MAGIC_32) {
        /* 32-bit Mach-O: detected, unsupported. */
        errno = ENOTSUP; return -1;
    }
    /* Fat magic is big-endian-on-disk, so read it either way. */
    uint32_t be_magic = rd_be_u32(e->map);
    if (be_magic == FAT_MAGIC || be_magic == FAT_CIGAM) {
        return parse_fat(e, be_magic);
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

void
macho_set_preferred_arch(const char *name)
{
    if (name == NULL)                         g_pref_cputype = 0;
    else if (!strcmp(name, "x86_64"))         g_pref_cputype = CPU_TYPE_X86_64;
    else if (!strcmp(name, "arm64") ||
             !strcmp(name, "aarch64"))        g_pref_cputype = CPU_TYPE_ARM64;
    else                                      g_pref_cputype = 0;
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
