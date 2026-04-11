/*
 * pe.c — PE/COFF loader, bounds-checked.
 *
 * Parses just enough of the PE format to enumerate executable
 * sections: DOS header → NT headers (PE\0\0) → optional header
 * (to pick up ImageBase and PE32-vs-PE32+) → section table.
 * Everything else — directories, debug info, CLI/.NET, resources,
 * imports — is deliberately ignored because shrike scans bytes,
 * not symbols.
 *
 * Validation is layered: every pointer advance is guarded against
 * the mapped file size before the deref. A malformed input cannot
 * read past the end of the buffer, by construction. Integer fields
 * that come out of the file are cross-checked against sane bounds
 * (NumberOfSections < 96, SizeOfOptionalHeader within spec) — the
 * Windows loader itself rejects weirder values.
 */

#include <shrike/pe.h>
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

/* Offsets + sizes lifted from the Microsoft PE/COFF spec so that
 * this file reads like a parser, not a translation of Windows.h. */
#define PE_DOS_MAGIC_OFF     0x00
#define PE_DOS_LFANEW_OFF    0x3c
#define PE_DOS_HDR_SIZE      0x40

#define PE_NT_SIG_SIZE       4
#define PE_FILE_HDR_SIZE     20
#define PE_SECT_HDR_SIZE     40

/* IMAGE_FILE_HEADER fields relative to the start of the File Header. */
#define PE_FH_MACHINE_OFF    0
#define PE_FH_NUMSECT_OFF    2
#define PE_FH_OPTSZ_OFF      16
#define PE_FH_CHAR_OFF       18

/* IMAGE_OPTIONAL_HEADER Magic values. */
#define PE_OPT_MAGIC_PE32    0x010b
#define PE_OPT_MAGIC_PE32P   0x020b

/* Offsets into IMAGE_OPTIONAL_HEADER. ImageBase moves between PE32
 * (uint32 at 28) and PE32+ (uint64 at 24) — the rest are identical
 * across both forms for what we read. */
#define PE_OPT_MAGIC_OFF         0
#define PE_OPT_ADDR_ENTRY_OFF    16
#define PE_OPT_IMAGEBASE32_OFF   28
#define PE_OPT_IMAGEBASE64_OFF   24
#define PE_OPT_DLLCHAR_PE32_OFF  70
#define PE_OPT_DLLCHAR_PE32P_OFF 70

/* IMAGE_SECTION_HEADER field offsets relative to the 40-byte record. */
#define PE_SH_NAME_OFF        0
#define PE_SH_VSIZE_OFF       8
#define PE_SH_VADDR_OFF       12
#define PE_SH_RAWSZ_OFF       16
#define PE_SH_RAWPTR_OFF      20
#define PE_SH_CHAR_OFF        36

static uint16_t rd_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
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
    /* DOS header: MZ magic + e_lfanew at fixed offset. */
    if (e->size < PE_DOS_HDR_SIZE)           { errno = EINVAL; return -1; }
    if (e->map[0] != 'M' || e->map[1] != 'Z'){ errno = EINVAL; return -1; }

    uint32_t e_lfanew = rd_u32(e->map + PE_DOS_LFANEW_OFF);
    if (e_lfanew < PE_DOS_HDR_SIZE)          { errno = EINVAL; return -1; }

    /* NT headers: PE\0\0 + FileHeader + OptionalHeader. */
    uint64_t nt_off = e_lfanew;
    if (!in_bounds(e, nt_off, PE_NT_SIG_SIZE + PE_FILE_HDR_SIZE)) {
        errno = EINVAL; return -1;
    }
    const uint8_t *nt = e->map + nt_off;
    if (nt[0] != 'P' || nt[1] != 'E' || nt[2] != 0 || nt[3] != 0) {
        errno = EINVAL; return -1;
    }

    const uint8_t *fh = nt + PE_NT_SIG_SIZE;
    uint16_t machine  = rd_u16(fh + PE_FH_MACHINE_OFF);
    uint16_t nsect    = rd_u16(fh + PE_FH_NUMSECT_OFF);
    uint16_t opt_sz   = rd_u16(fh + PE_FH_OPTSZ_OFF);

    if (nsect == 0 || nsect > 96)           { errno = EINVAL; return -1; }
    if (opt_sz < 2)                          { errno = EINVAL; return -1; }

    /* Map PE machine codes to the ELF EM_* values the rest of shrike
     * speaks. PE i386 falls through as "unsupported" for now — the
     * decoder is 64-bit only. */
    switch (machine) {
    case IMAGE_FILE_MACHINE_AMD64: e->machine = EM_X86_64;  break;
    case IMAGE_FILE_MACHINE_ARM64: e->machine = EM_AARCH64; break;
    default:                       errno = ENOTSUP; return -1;
    }

    uint64_t opt_off = nt_off + PE_NT_SIG_SIZE + PE_FILE_HDR_SIZE;
    if (!in_bounds(e, opt_off, opt_sz))     { errno = EINVAL; return -1; }

    const uint8_t *opt = e->map + opt_off;
    uint16_t opt_magic = rd_u16(opt + PE_OPT_MAGIC_OFF);

    uint64_t image_base;
    if (opt_magic == PE_OPT_MAGIC_PE32) {
        if (opt_sz < PE_OPT_IMAGEBASE32_OFF + 4) { errno = EINVAL; return -1; }
        image_base = rd_u32(opt + PE_OPT_IMAGEBASE32_OFF);
    } else if (opt_magic == PE_OPT_MAGIC_PE32P) {
        if (opt_sz < PE_OPT_IMAGEBASE64_OFF + 8) { errno = EINVAL; return -1; }
        image_base = rd_u64(opt + PE_OPT_IMAGEBASE64_OFF);
    } else {
        errno = EINVAL; return -1;
    }

    uint32_t addr_entry = 0;
    if (opt_sz >= PE_OPT_ADDR_ENTRY_OFF + 4) {
        addr_entry = rd_u32(opt + PE_OPT_ADDR_ENTRY_OFF);
    }
    e->entry = addr_entry ? (image_base + addr_entry) : 0;

    /* DllCharacteristics lives at the same OptionalHeader offset in
     * both PE32 and PE32+. Good-enough check for "image expects ASLR
     * at load time," which we surface as ET_DYN-equivalent. */
    if (opt_sz >= PE_OPT_DLLCHAR_PE32P_OFF + 2) {
        uint16_t dllchar = rd_u16(opt + PE_OPT_DLLCHAR_PE32P_OFF);
        e->is_dyn        = (dllchar & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) ? 1 : 0;
        e->pe_dll_chars  = dllchar;
    }

    /* Mark the image as PE-sourced so the hardening audit knows to
     * read pe_dll_chars instead of walking PT_GNU_PROPERTY. */
    e->format = 1;

    /* Section table immediately follows the OptionalHeader. */
    uint64_t sect_off = opt_off + opt_sz;
    uint64_t sect_tbl = (uint64_t)nsect * PE_SECT_HDR_SIZE;
    if (!in_bounds(e, sect_off, sect_tbl))  { errno = EINVAL; return -1; }

    e->nseg = 0;
    for (uint16_t i = 0; i < nsect; i++) {
        if (e->nseg >= SHRIKE_MAX_SEGMENTS) break;

        const uint8_t *sh = e->map + sect_off + (uint64_t)i * PE_SECT_HDR_SIZE;

        uint32_t vsize     = rd_u32(sh + PE_SH_VSIZE_OFF);
        uint32_t vaddr_rva = rd_u32(sh + PE_SH_VADDR_OFF);
        uint32_t raw_size  = rd_u32(sh + PE_SH_RAWSZ_OFF);
        uint32_t raw_ptr   = rd_u32(sh + PE_SH_RAWPTR_OFF);
        uint32_t chars     = rd_u32(sh + PE_SH_CHAR_OFF);

        if (!(chars & IMAGE_SCN_MEM_EXECUTE)) continue;
        if (raw_size == 0 || raw_ptr == 0)    continue;
        if (!in_bounds(e, raw_ptr, raw_size)) continue;

        /* The Windows loader zero-fills the tail when VirtualSize
         * exceeds SizeOfRawData. Gadget-wise those bytes are noise,
         * so we scan only the on-disk range. */
        uint32_t scan = raw_size;
        if (vsize && vsize < scan) scan = vsize;

        elf64_segment_t *s = &e->segs[e->nseg++];
        s->bytes   = e->map + raw_ptr;
        s->size    = scan;
        s->vaddr   = image_base + vaddr_rva;
        /* Re-use ELF PF_* flags so downstream consumers don't care
         * which format the segment came from. PE pages are RX by
         * default when MEM_EXECUTE is set; the writable/readable
         * bits fold in for completeness. */
        s->flags   = PF_X | PF_R;
        if (chars & 0x80000000u) s->flags |= PF_W;   /* IMAGE_SCN_MEM_WRITE */
        s->machine = e->machine;
    }

    if (e->nseg == 0) { errno = ENOEXEC; return -1; }
    return 0;
}

int
pe_load_buffer(const uint8_t *buf, size_t size, elf64_t *e)
{
    memset(e, 0, sizeof *e);
    e->map  = buf;
    e->size = size;
    e->owns = 0;
    return parse(e);
}

int
pe_load(const char *path, elf64_t *e)
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
