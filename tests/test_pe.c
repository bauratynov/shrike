/*
 * test_pe.c — synthesize a minimal PE64 image in memory and verify
 * pe_load walks it without reading past the buffer.
 *
 * The point isn't to exhaustively test PE semantics — that's a
 * research project of its own — but to pin the happy path so
 * regressions in the bounded-advance logic surface immediately.
 */

#include <shrike/pe.h>
#include <shrike/elf64.h>

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>

static int fails = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        fails++; \
    } \
} while (0)

static void
put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void
put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void
put_u64(uint8_t *p, uint64_t v)
{
    put_u32(p, (uint32_t)v);
    put_u32(p + 4, (uint32_t)(v >> 32));
}

int
main(void)
{
    /* Layout (spec-accurate offsets — no padding between opt header
     * and section table):
     *   0x000  DOS header (64 bytes; e_lfanew = 0x80)
     *   0x080  NT signature "PE\0\0"       (4 bytes)
     *   0x084  IMAGE_FILE_HEADER           (20 bytes)
     *   0x098  IMAGE_OPTIONAL_HEADER64     (112 bytes)
     *   0x108  IMAGE_SECTION_HEADER[0] — .text (executable)
     *   0x130  IMAGE_SECTION_HEADER[1] — .data (non-executable)
     *   0x400  .text contents (16 bytes of RET-family bytes)
     *   0x600  .data contents (padding)
     */
    uint8_t img[0x800];
    memset(img, 0, sizeof img);

    /* DOS */
    img[0] = 'M'; img[1] = 'Z';
    put_u32(img + 0x3c, 0x80);

    /* NT signature */
    memcpy(img + 0x80, "PE\0\0", 4);

    /* IMAGE_FILE_HEADER: machine=AMD64, nsect=2, opt_sz=112 */
    uint8_t *fh = img + 0x84;
    put_u16(fh + 0,  0x8664);  /* Machine = IMAGE_FILE_MACHINE_AMD64 */
    put_u16(fh + 2,  2);        /* NumberOfSections */
    put_u16(fh + 16, 112);      /* SizeOfOptionalHeader */

    /* IMAGE_OPTIONAL_HEADER64: magic=0x20b, image_base=0x140000000,
     * AddressOfEntryPoint=0x1000, DllCharacteristics with ASLR bit. */
    uint8_t *opt = img + 0x98;
    put_u16(opt + 0,  0x020b);
    put_u32(opt + 16, 0x1000);
    put_u64(opt + 24, 0x140000000ull);
    put_u16(opt + 70, 0x0040);  /* IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE */

    /* Section table starts immediately after the optional header at
     * 0x98 + 112 = 0x108. The parser computes this offset exactly. */
    uint8_t *s0 = img + 0x108;
    memcpy(s0, ".text", 5);
    put_u32(s0 + 8,  0x10);           /* VirtualSize */
    put_u32(s0 + 12, 0x1000);         /* VirtualAddress (RVA) */
    put_u32(s0 + 16, 0x10);           /* SizeOfRawData */
    put_u32(s0 + 20, 0x400);          /* PointerToRawData */
    put_u32(s0 + 36, 0x60000020u);    /* MEM_EXECUTE | MEM_READ | CNT_CODE */

    /* Section 1: .data (not executable, must be skipped) */
    uint8_t *s1 = img + 0x130;
    memcpy(s1, ".data", 5);
    put_u32(s1 + 8,  0x10);
    put_u32(s1 + 12, 0x2000);
    put_u32(s1 + 16, 0x10);
    put_u32(s1 + 20, 0x600);
    put_u32(s1 + 36, 0xc0000040u);    /* MEM_READ | MEM_WRITE | CNT_INIT_DATA */

    /* .text payload: harmless ret bytes so a scanner wouldn't choke. */
    memset(img + 0x400, 0xc3, 0x10);

    elf64_t e;
    int rc = pe_load_buffer(img, sizeof img, &e);
    CHECK(rc == 0);
    CHECK(e.nseg == 1);
    CHECK(e.machine == EM_X86_64);
    CHECK(e.is_dyn == 1);
    CHECK(e.format == 1);
    CHECK(e.pe_dll_chars == IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
    CHECK(e.entry == 0x140000000ull + 0x1000);

    if (e.nseg == 1) {
        const elf64_segment_t *s = &e.segs[0];
        CHECK(s->vaddr == 0x140000000ull + 0x1000);
        CHECK(s->size == 0x10);
        CHECK(s->bytes == img + 0x400);
        CHECK((s->flags & PF_X) != 0);
        CHECK(s->machine == EM_X86_64);
    }

    /* A truncated buffer must fail closed — no deref past end. */
    elf64_t e2;
    CHECK(pe_load_buffer(img, 0x40, &e2) < 0);

    /* Bad DOS magic must fail. */
    uint8_t img2[0x80];
    memcpy(img2, img, sizeof img2);
    img2[0] = 'X';
    CHECK(pe_load_buffer(img2, sizeof img2, &e2) < 0);

    if (fails == 0) {
        printf("test_pe: ok (nseg=%zu va=0x%" PRIx64 ")\n",
               e.nseg, e.segs[0].vaddr);
        return 0;
    }
    fprintf(stderr, "test_pe: %d failure(s)\n", fails);
    return 1;
}
