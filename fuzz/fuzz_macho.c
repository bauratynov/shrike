/*
 * fuzz_macho.c — libFuzzer + AFL++ harness for macho_load_buffer.
 *
 * Covers both the thin-binary parser and the fat-universal
 * dispatcher. The fat path has the bigger attack surface —
 * it recurses into parse() after rewriting e->map/e->size, so
 * any unsoundness in the bounded-advance logic shows up as
 * an out-of-buffer read or integer overflow.
 */

#include <shrike/macho.h>
#include <shrike/elf64.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __AFL_COMPILER
# include <unistd.h>
#endif

static void
one_shot(const uint8_t *data, size_t size)
{
    if (size < 32) return;

    /* Randomise the preferred arch hint via a byte from the
     * input, to exercise both the "hint matches first slice"
     * and "no match, fall through" paths of parse_fat. */
    if (size > 4) {
        switch (data[0] & 0x3) {
        case 0: macho_set_preferred_arch("x86_64"); break;
        case 1: macho_set_preferred_arch("arm64");  break;
        case 2: macho_set_preferred_arch("aarch64"); break;
        default: macho_set_preferred_arch(NULL);    break;
        }
    }

    elf64_t e;
    if (macho_load_buffer(data, size, &e) == 0) {
        for (size_t i = 0; i < e.nseg; i++) {
            const elf64_segment_t *s = &e.segs[i];
            if (s->size == 0) continue;
            volatile uint8_t first = s->bytes[0];
            volatile uint8_t last  = s->bytes[s->size - 1];
            (void)first; (void)last;
        }
    }
}

#if defined(__clang__) && !defined(__AFL_COMPILER)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    one_shot(data, size);
    return 0;
}
#endif

#ifdef __AFL_COMPILER
int main(void)
{
    uint8_t buf[1 << 20];
    __AFL_INIT();
    while (__AFL_LOOP(1000)) {
        ssize_t n = read(0, buf, sizeof buf);
        if (n > 0) one_shot(buf, (size_t)n);
    }
    return 0;
}
#else
#include <stdio.h>
int main(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END);
        long n = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (n > 0 && n < (1L << 24)) {
            uint8_t *buf = malloc((size_t)n);
            if (buf && fread(buf, 1, (size_t)n, f) == (size_t)n) {
                one_shot(buf, (size_t)n);
            }
            free(buf);
        }
        fclose(f);
    }
    return 0;
}
#endif
