/*
 * test_version.c — smoke test for <shrike/version.h>.
 *
 * Verifies: macro presence, runtime getters agree with macros,
 * packing scheme monotonic, version string format.
 */

#include <shrike/version.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static int fails = 0;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); \
        fails++; \
    } \
} while (0)

int
main(void)
{
    /* Compile-time macros must be visible here. */
    CHECK(SHRIKE_VERSION_MAJOR >= 1);
    CHECK(SHRIKE_VERSION_MINOR >= 1);
    CHECK(SHRIKE_VERSION_PATCH >= 0);

    /* Packed form equals runtime getter. */
    CHECK(shrike_version_number() == (uint32_t)SHRIKE_VERSION);

    /* Packing is monotonic: later versions compare greater. */
    CHECK(SHRIKE_MK_VERSION(1, 1, 0) < SHRIKE_MK_VERSION(1, 2, 0));
    CHECK(SHRIKE_MK_VERSION(1, 9, 9) < SHRIKE_MK_VERSION(2, 0, 0));
    CHECK(SHRIKE_MK_VERSION(0, 33, 0) < SHRIKE_MK_VERSION(1, 0, 0));

    /* Compile-time comparison works. */
#if SHRIKE_VERSION >= SHRIKE_MK_VERSION(1, 1, 0)
    /* expected path */
#else
    CHECK(!"SHRIKE_VERSION comparison broken");
#endif

    /* String form is non-empty, matches MAJOR.MINOR.PATCH shape. */
    const char *s = shrike_version_string();
    CHECK(s != NULL);
    CHECK(strlen(s) >= 5);

    /* Every character is a digit or a dot. */
    for (const char *p = s; *p; p++) {
        CHECK((*p >= '0' && *p <= '9') || *p == '.');
    }

    /* Exactly two dots. */
    int dots = 0;
    for (const char *p = s; *p; p++) if (*p == '.') dots++;
    CHECK(dots == 2);

    if (fails == 0) {
        printf("test_version: ok (version=%s number=%u)\n",
               s, (unsigned)shrike_version_number());
        return 0;
    }
    fprintf(stderr, "test_version: %d failure(s)\n", fails);
    return 1;
}
