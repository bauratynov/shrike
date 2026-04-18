/*
 * fuzz_pe.c — libFuzzer + AFL++ harness for pe_load_buffer.
 *
 * PE parsing is attack surface: shrike takes a file path from
 * argv and memory-maps it. A malformed PE has to fail closed,
 * never read past the mapping, never segfault on integer
 * overflows in sect_off / debug_dir RVA chases.
 *
 * Compile:
 *   make -C fuzz libfuzzer           → clang + -fsanitize=fuzzer,address
 *   make -C fuzz afl                 → afl-clang-fast + AFL_PERSISTENT
 *
 * Run:
 *   ./fuzz/fuzz_pe_lf corpus/
 *   afl-fuzz -i fuzz/seeds -o fuzz/findings ./fuzz/fuzz_pe
 */

#include <shrike/pe.h>
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
    /* Reject tiny inputs early — not because they'd crash the
     * parser (it handles short buffers), but because < 64 bytes
     * can't contain a valid DOS header and wastes fuzzer cycles. */
    if (size < 64) return;

    elf64_t e;
    if (pe_load_buffer(data, size, &e) == 0) {
        /* Exercise the segs[] array that pe_load populates.
         * We don't care about the gadget output — we care that
         * the struct is internally consistent. */
        for (size_t i = 0; i < e.nseg; i++) {
            const elf64_segment_t *s = &e.segs[i];
            if (s->size == 0) continue;
            /* force a read of the first and last byte of each
             * segment to fault on an out-of-bounds slice the
             * bounds check missed. */
            volatile uint8_t first = s->bytes[0];
            volatile uint8_t last  = s->bytes[s->size - 1];
            (void)first;
            (void)last;
        }
        /* PE pdb_path must be null-terminated. */
        volatile size_t plen = strlen(e.pe_pdb_path);
        (void)plen;
    }
    /* No elf64_close — buffer is caller-owned, nothing to unmap. */
}

/* Entry-point selection:
 *   SHRIKE_FUZZ_LIBFUZZER — linked with libFuzzer (provides main);
 *                           we only define LLVMFuzzerTestOneInput.
 *   SHRIKE_FUZZ_AFL       — AFL++ persistent-mode loop main.
 *   else                  — standalone: read one file per argv.
 *
 * The fuzz/Makefile sets SHRIKE_FUZZ_LIBFUZZER for the libfuzzer
 * target and SHRIKE_FUZZ_AFL for the afl target. Previously we
 * keyed off __clang__, which defined LLVMFuzzerTestOneInput plus
 * our own main() on every clang build — libFuzzer's own main
 * then collided with ours at link time. */

#if defined(SHRIKE_FUZZ_LIBFUZZER)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    one_shot(data, size);
    return 0;
}
#elif defined(SHRIKE_FUZZ_AFL)
int main(void)
{
    uint8_t buf[1 << 20];    /* 1 MiB cap — bigger PEs are unrealistic as fuzz inputs */
    __AFL_INIT();
    while (__AFL_LOOP(1000)) {
        ssize_t n = read(0, buf, sizeof buf);
        if (n > 0) one_shot(buf, (size_t)n);
    }
    return 0;
}
#else
/* Stand-alone fallback — reads one file per argv entry. */
# include <stdio.h>
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
