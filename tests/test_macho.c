/*
 * test_macho.c — synthesize a minimal Mach-O 64-bit image in
 * memory and verify macho_load walks it bounded-safely.
 *
 * Same structure as test_pe: assemble bytes, call the loader,
 * assert the happy path, then hit a couple of malformed inputs
 * to confirm fail-closed behaviour.
 */

#include <shrike/macho.h>
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
    /* Layout:
     *   0x000 mach_header_64 (32 bytes)
     *   0x020 LC_SEGMENT_64 __PAGEZERO (72 bytes, no sections)
     *   0x068 LC_SEGMENT_64 __TEXT     (72 bytes, no sections)
     *   0x0b0 LC_SEGMENT_64 __DATA     (72 bytes, no sections)
     *   0x400 __TEXT contents (16 bytes of RET for x86-64)
     *   0x600 __DATA contents (padding)
     */
    uint8_t img[0x800];
    memset(img, 0, sizeof img);

    /* mach_header_64: MH_MAGIC_64 + x86_64 + MH_EXECUTE + 3 lc */
    put_u32(img + 0,  0xfeedfacfu);        /* magic */
    put_u32(img + 4,  0x01000007u);        /* cputype = x86_64 */
    put_u32(img + 8,  3);                  /* cpusubtype */
    put_u32(img + 12, 2);                  /* filetype = MH_EXECUTE */
    put_u32(img + 16, 3);                  /* ncmds */
    put_u32(img + 20, 72 * 3);             /* sizeofcmds */
    put_u32(img + 24, 0x00200085u);        /* flags (irrelevant) */

    /* LC_SEGMENT_64 __PAGEZERO at 0x20 — unmapped, initprot=0 */
    uint8_t *lc0 = img + 0x20;
    put_u32(lc0 + 0,  0x19);
    put_u32(lc0 + 4,  72);
    memcpy(lc0 + 8, "__PAGEZERO", 10);
    put_u64(lc0 + 24, 0x0);
    put_u64(lc0 + 32, 0x100000000ull);
    put_u32(lc0 + 60, 0);                  /* initprot — no exec */

    /* LC_SEGMENT_64 __TEXT — initprot = R|X, maps [0x100000000,+0x200) */
    uint8_t *lc1 = img + 0x20 + 72;
    put_u32(lc1 + 0,  0x19);
    put_u32(lc1 + 4,  72);
    memcpy(lc1 + 8, "__TEXT", 6);
    put_u64(lc1 + 24, 0x100000000ull);     /* vmaddr */
    put_u64(lc1 + 32, 0x200);              /* vmsize */
    put_u64(lc1 + 40, 0x400);              /* fileoff */
    put_u64(lc1 + 48, 0x10);               /* filesize */
    put_u32(lc1 + 60, VM_PROT_READ | VM_PROT_EXECUTE);

    /* LC_SEGMENT_64 __DATA — initprot = R|W, NOT executable */
    uint8_t *lc2 = img + 0x20 + 72 * 2;
    put_u32(lc2 + 0,  0x19);
    put_u32(lc2 + 4,  72);
    memcpy(lc2 + 8, "__DATA", 6);
    put_u64(lc2 + 24, 0x100000200ull);
    put_u64(lc2 + 32, 0x200);
    put_u64(lc2 + 40, 0x600);
    put_u64(lc2 + 48, 0x10);
    put_u32(lc2 + 60, VM_PROT_READ | VM_PROT_WRITE);

    /* __TEXT payload */
    memset(img + 0x400, 0xc3, 0x10);

    elf64_t e;
    int rc = macho_load_buffer(img, sizeof img, &e);
    CHECK(rc == 0);
    CHECK(e.nseg == 1);
    CHECK(e.machine == EM_X86_64);
    CHECK(e.format == 2);
    CHECK(e.is_dyn == 0);    /* MH_EXECUTE */

    size_t captured_nseg = e.nseg;
    uint64_t captured_va = (e.nseg == 1) ? e.segs[0].vaddr : 0;

    if (e.nseg == 1) {
        const elf64_segment_t *s = &e.segs[0];
        CHECK(s->vaddr == 0x100000000ull);
        CHECK(s->size == 0x10);
        CHECK(s->bytes == img + 0x400);
        CHECK((s->flags & PF_X) != 0);
    }

    /* Fat/universal magic must be refused (no v1.3.1 yet). */
    uint8_t fat[8];
    put_u32(fat + 0, 0xcafebabeu);
    put_u32(fat + 4, 0);
    CHECK(macho_load_buffer(fat, sizeof fat, &e) < 0);

    /* 32-bit Mach-O must be refused. */
    uint8_t m32[32];
    memset(m32, 0, sizeof m32);
    put_u32(m32, 0xfeedfaceu);
    CHECK(macho_load_buffer(m32, sizeof m32, &e) < 0);

    /* Bad magic must be refused. */
    uint8_t bad[32];
    memset(bad, 0, sizeof bad);
    CHECK(macho_load_buffer(bad, sizeof bad, &e) < 0);

    if (fails == 0) {
        printf("test_macho: ok (nseg=%zu va=0x%" PRIx64 ")\n",
               captured_nseg, captured_va);
        return 0;
    }
    fprintf(stderr, "test_macho: %d failure(s)\n", fails);
    return 1;
}
