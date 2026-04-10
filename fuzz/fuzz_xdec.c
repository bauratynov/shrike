/*
 * fuzz_xdec.c — AFL++ / libFuzzer harness for the x86-64 length
 * decoder. Feeds raw input bytes and asserts that xdec either
 * returns a length in [1, 15] or rejects cleanly.
 */

#include <shrike/xdec.h>

#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 15) return 0;
    int len = 0;
    int rc = xdec_length(data, size, &len);
    if (rc == 0) {
        /* Must be in spec. */
        if (len < 1 || len > 15) __builtin_trap();
    }
    return 0;
}

/* AFL++ persistent mode main — reuses LLVMFuzzerTestOneInput. */
#ifdef AFL_PERSISTENT
#include <unistd.h>
__AFL_FUZZ_INIT();
int main(void)
{
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        int n = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, (size_t)n);
    }
    return 0;
}
#endif
