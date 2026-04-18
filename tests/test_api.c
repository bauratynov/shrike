/*
 * test_api.c — smoke test for the 2.0 opaque-handle API.
 *
 * Doesn't need a file on disk: builds a tiny ELF64 in memory
 * (actually reuses the synthesized PE buffer from test_pe for a
 * quick "does shrike_open_mem dispatch to pe_load" check) and
 * walks the resulting gadgets via the public API only —
 * shrike_ctx_t / shrike_gadget_t are opaque, never dereferenced.
 */

#include <shrike/shrike.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

static int fails = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        fails++; \
    } \
} while (0)

static void
put_u16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void
put_u32(uint8_t *p, uint32_t v)
{
    p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8);
    p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24);
}
static void
put_u64(uint8_t *p, uint64_t v)
{
    put_u32(p, (uint32_t)v);
    put_u32(p + 4, (uint32_t)(v >> 32));
}

/* Same minimal PE64 image as test_pe.c — reused here to drive
 * shrike_open_mem through its pe_load dispatch. */
static uint8_t image[0x800];

static void
build_pe64(void)
{
    memset(image, 0, sizeof image);
    image[0]='M'; image[1]='Z';
    put_u32(image + 0x3c, 0x80);
    memcpy(image + 0x80, "PE\0\0", 4);
    uint8_t *fh = image + 0x84;
    put_u16(fh + 0, 0x8664);
    put_u16(fh + 2, 1);
    put_u16(fh + 16, 112);
    uint8_t *opt = image + 0x98;
    put_u16(opt + 0, 0x020b);
    put_u32(opt + 16, 0x1000);
    put_u64(opt + 24, 0x140000000ull);
    uint8_t *sh = image + 0x108;
    memcpy(sh, ".text", 5);
    put_u32(sh + 8, 0x10);
    put_u32(sh + 12, 0x1000);
    put_u32(sh + 16, 0x10);
    put_u32(sh + 20, 0x400);
    put_u32(sh + 36, 0x60000020u);
    memset(image + 0x400, 0xc3, 0x10);   /* 16 RET bytes */
}

int
main(void)
{
    build_pe64();

    shrike_ctx_t *ctx = NULL;
    int rc = shrike_open_mem(image, sizeof image, &ctx);
    CHECK(rc == 0);
    CHECK(ctx != NULL);

    if (!ctx) { fprintf(stderr, "test_api: ctx alloc failed\n"); return 1; }

    /* Option plumbing: max_insn = 1 → each terminator by itself. */
    CHECK(shrike_set_option_int(ctx, SHRIKE_OPT_MAX_INSN, 1) == 0);

    shrike_iter_t *it = shrike_iter_begin(ctx);
    CHECK(it != NULL);

    int seen = 0;
    int saw_ret = 0;
    const shrike_gadget_t *g;
    while ((g = shrike_iter_next(it)) != NULL) {
        seen++;
        CHECK(shrike_gadget_arch(g) == SHRIKE_ARCH_X86_64);
        CHECK(shrike_gadget_size(g) >= 1);
        CHECK(shrike_gadget_address(g) >= 0x140001000ull);
        CHECK(shrike_gadget_address(g) <  0x140002000ull);
        CHECK(shrike_gadget_bytes(g) != NULL);
        /* Disassembly for a single 0xC3 byte is "ret" — at least
         * verify it's a non-empty string. */
        const char *d = shrike_gadget_disasm(g);
        CHECK(d != NULL && d[0] != '\0');
        /* Category must be one of the enum values, and for a
         * single-byte ret we expect RET_ONLY. */
        shrike_category_t cat = shrike_gadget_category(g);
        CHECK(cat >= SHRIKE_CAT_OTHER && cat <= SHRIKE_CAT_INDIRECT);
        if (cat == SHRIKE_CAT_RET_ONLY) saw_ret = 1;
        /* Instruction count plausibility: single-byte ret is 1
         * instruction. Multi-byte backscan gadgets may be more. */
        CHECK(shrike_gadget_instruction_count(g) >= 1);
    }
    CHECK(saw_ret);   /* at least one gadget classified as ret_only */
    /* 16 bytes of C3 → at least 16 "ret" terminator positions;
     * potentially more since each position can emit multiple
     * gadget prefixes up to max_insn. With max_insn=1 (set
     * above), each terminator contributes exactly one gadget —
     * but downstream scanner policy can still vary, so only
     * assert the lower bound. */
    CHECK(seen >= 16);

    shrike_iter_end(it);
    shrike_close(ctx);

    /* shrike_open on a bogus path must fail cleanly. */
    shrike_ctx_t *bogus;
    CHECK(shrike_open("/nonexistent/path/to/no/binary", &bogus) != 0);

    /* v5.2.0: errno + strerror accessors. shrike_errno on a
     * NULL ctx must return EINVAL (or equivalent), not crash.
     * shrike_strerror must return non-NULL for any integer. */
    CHECK(shrike_errno(NULL) != 0);
    CHECK(shrike_strerror(0) != NULL);
    CHECK(shrike_strerror(EINVAL) != NULL);

    /* v5.2.0: fat munmap fix sanity. Build a minimal fat image,
     * load via shrike_open_mem (which dispatches through the
     * fat parser), close it. Before the fix, elf64_close's
     * munmap was a no-op on caller-owned buffers — so the test
     * passing here doesn't directly prove the mmap-case fix
     * works, but it does prove parse_fat no longer corrupts
     * map_base/map_base_size on the way through. */
    uint8_t fat[0x1000];
    memset(fat, 0, sizeof fat);
    /* FAT_MAGIC big-endian */
    fat[0]=0xca; fat[1]=0xfe; fat[2]=0xba; fat[3]=0xbe;
    fat[7] = 1;
    /* fat_arch[0]: cputype=X86_64, offset=0x400, size=0x800 */
    fat[8]=0x01; fat[11]=0x07;
    fat[17] = 0; fat[18] = 0x04; fat[19] = 0;   /* offset 0x400 */
    fat[21] = 0; fat[22] = 0x08; fat[23] = 0;   /* size 0x800 */
    /* reuse the thin image bytes from above for the slice payload */
    memcpy(fat + 0x400, image, sizeof image);
    shrike_ctx_t *fctx;
    int frc = shrike_open_mem(fat, sizeof fat, &fctx);
    CHECK(frc == 0);
    if (fctx) shrike_close(fctx);    /* must NOT crash */

    if (fails == 0) {
        printf("test_api: ok (seen=%d gadgets)\n", seen);
        return 0;
    }
    fprintf(stderr, "test_api: %d failure(s)\n", fails);
    return 1;
}
