/*
 * test_scan.c — gadget-scanner unit tests.
 *
 * Each case builds a byte buffer representing a tiny code region and
 * asserts the set of gadgets that scan_segment finds. A scratch
 * callback records the emitted gadgets for inspection.
 */

#include <shrike/scan.h>
#include <shrike/format.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int passes = 0;
static int fails  = 0;

#define CHECK(cond, label)                                                    \
    do {                                                                      \
        if (cond) { passes++; printf("  [ok]   %s\n", label); }               \
        else { fails++; printf("  [FAIL] %s\n", label); }                     \
    } while (0)

typedef struct {
    gadget_t items[128];
    size_t   n;
} capture_t;

static void capture_cb(const elf64_segment_t *seg,
                       const gadget_t *g, void *ctx)
{
    (void)seg;
    capture_t *c = (capture_t *)ctx;
    if (c->n < sizeof(c->items) / sizeof(c->items[0])) {
        c->items[c->n++] = *g;
    }
}

static void run(const uint8_t *bytes, size_t size, uint64_t vaddr,
                capture_t *cap)
{
    elf64_segment_t seg = {
        .bytes = bytes,
        .size  = size,
        .vaddr = vaddr,
        .flags = 5   /* r-x */
    };
    cap->n = 0;
    scan_segment(&seg, NULL, capture_cb, cap);
}

/* Find a gadget whose vaddr equals `v`. */
static int has_vaddr(const capture_t *cap, uint64_t v)
{
    for (size_t i = 0; i < cap->n; i++)
        if (cap->items[i].vaddr == v) return 1;
    return 0;
}

static void test_single_ret(void)
{
    printf("single ret at offset 0\n");
    static const uint8_t b[] = { 0xC3 };
    capture_t cap;
    run(b, sizeof b, 0x400000, &cap);
    CHECK(cap.n >= 1, "at least one gadget");
    CHECK(has_vaddr(&cap, 0x400000), "ret-only gadget at 0x400000");
}

static void test_pop_rdi_ret(void)
{
    printf("pop rdi ; ret\n");
    /* 5F = pop rdi, C3 = ret */
    static const uint8_t b[] = { 0x5F, 0xC3 };
    capture_t cap;
    run(b, sizeof b, 0x400000, &cap);
    CHECK(has_vaddr(&cap, 0x400000), "full chain at 0x400000");
    CHECK(has_vaddr(&cap, 0x400001), "ret-only sub-gadget at 0x400001");
}

static void test_two_rets_produce_two_gadgets(void)
{
    printf("xor rax,rax ; ret ; nop ; ret\n");
    /* 48 31 C0 = xor rax, rax (3 bytes)
     * C3        = ret
     * 90        = nop
     * C3        = ret */
    static const uint8_t b[] = { 0x48, 0x31, 0xC0, 0xC3, 0x90, 0xC3 };
    capture_t cap;
    run(b, sizeof b, 0x400000, &cap);
    CHECK(has_vaddr(&cap, 0x400000), "xor rax,rax ; ret at 0x400000");
    CHECK(has_vaddr(&cap, 0x400003), "ret-only at 0x400003");
    CHECK(has_vaddr(&cap, 0x400004), "nop ; ret at 0x400004");
    CHECK(has_vaddr(&cap, 0x400005), "ret-only at 0x400005");
}

static void test_syscall_gadget(void)
{
    printf("syscall\n");
    static const uint8_t b[] = { 0x0F, 0x05 };
    capture_t cap;
    run(b, sizeof b, 0x400000, &cap);
    CHECK(has_vaddr(&cap, 0x400000), "syscall-only gadget");
}

static void test_indirect_jump(void)
{
    printf("jmp rax\n");
    /* FF E0 = jmp rax */
    static const uint8_t b[] = { 0xFF, 0xE0 };
    capture_t cap;
    run(b, sizeof b, 0x400000, &cap);
    CHECK(has_vaddr(&cap, 0x400000), "jmp rax gadget");
}

static void test_empty_segment(void)
{
    printf("empty segment\n");
    capture_t cap;
    run(NULL, 0, 0x400000, &cap);
    CHECK(cap.n == 0, "no gadgets emitted");
}

static void test_no_terminator(void)
{
    printf("segment without any terminator\n");
    static const uint8_t b[] = { 0x90, 0x90, 0x90, 0x90 };  /* nops only */
    capture_t cap;
    run(b, sizeof b, 0x400000, &cap);
    CHECK(cap.n == 0, "no gadgets in nop-only region");
}

static void test_long_chain(void)
{
    printf("pop rdi ; pop rsi ; pop rdx ; ret\n");
    /* 5F 5E 5A C3 — pop rdi, pop rsi, pop rdx, ret */
    static const uint8_t b[] = { 0x5F, 0x5E, 0x5A, 0xC3 };
    capture_t cap;
    run(b, sizeof b, 0x400000, &cap);
    CHECK(has_vaddr(&cap, 0x400000), "4-instruction gadget");
    CHECK(cap.n >= 4, "also shorter sub-gadgets");
}

int main(void)
{
    test_single_ret();
    test_pop_rdi_ret();
    test_two_rets_produce_two_gadgets();
    test_syscall_gadget();
    test_indirect_jump();
    test_empty_segment();
    test_no_terminator();
    test_long_chain();

    printf("\n%d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
