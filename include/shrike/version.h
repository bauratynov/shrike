/*
 * shrike/version.h — compile-time + runtime version info.
 *
 * The three component macros are the source of truth; everything
 * else (the packed integer, the string) is derived via the
 * preprocessor so there's no template/codegen step.
 *
 * Packing is decimal (major * 10_000_000 + minor * 10_000 + patch
 * * 10) like liblzma. Hex packing (libssh2 style) caps each
 * component at 255, and decimal packing compares correctly as
 * plain integers.
 *
 * Typical use:
 *
 *     #include <shrike/version.h>
 *
 *     #if SHRIKE_VERSION >= SHRIKE_MK_VERSION(1, 2, 0)
 *         // use a 1.2+ API
 *     #endif
 *
 *     printf("linked against shrike %s\n",
 *            shrike_version_string());
 */

#ifndef SHRIKE_VERSION_H
#define SHRIKE_VERSION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHRIKE_VERSION_MAJOR 4
#define SHRIKE_VERSION_MINOR 0
#define SHRIKE_VERSION_PATCH 0

/* Compose a packed decimal version for compile-time comparisons. */
#define SHRIKE_MK_VERSION(major, minor, patch) \
    ((major) * 10000000 + (minor) * 10000 + (patch) * 10)

#define SHRIKE_VERSION \
    SHRIKE_MK_VERSION(SHRIKE_VERSION_MAJOR, \
                      SHRIKE_VERSION_MINOR, \
                      SHRIKE_VERSION_PATCH)

/* Two-stage stringification is required so the argument itself
 * expands before it's turned into a string literal. */
#define SHRIKE_VERSION_STRINGIFY_(x) #x
#define SHRIKE_VERSION_STRINGIFY(x)  SHRIKE_VERSION_STRINGIFY_(x)

#define SHRIKE_VERSION_STRING \
    SHRIKE_VERSION_STRINGIFY(SHRIKE_VERSION_MAJOR) "." \
    SHRIKE_VERSION_STRINGIFY(SHRIKE_VERSION_MINOR) "." \
    SHRIKE_VERSION_STRINGIFY(SHRIKE_VERSION_PATCH)

/* Runtime getters — useful when a binary was compiled against
 * header version X but loads shared library version Y. These
 * always report the *library's* version, not the header's. */
const char *shrike_version_string(void);
uint32_t    shrike_version_number(void);

/* v1.9.1: attribute macro used by 1.x public headers to mark
 * symbols that are being retired in 2.0. Downstream code
 * compiled against 1.9.x gets compiler warnings with a message
 * pointing at docs/migration-1-to-2.md. Defining
 * SHRIKE_IGNORE_DEPRECATIONS before including any shrike
 * header suppresses the attribute — useful for vendored
 * legacy code that hasn't been ported yet. */
#if defined(SHRIKE_IGNORE_DEPRECATIONS)
#  define SHRIKE_DEPRECATED(msg)
#elif defined(__GNUC__) || defined(__clang__)
#  define SHRIKE_DEPRECATED(msg) __attribute__((deprecated(msg)))
#elif defined(_MSC_VER)
#  define SHRIKE_DEPRECATED(msg) __declspec(deprecated(msg))
#else
#  define SHRIKE_DEPRECATED(msg)
#endif

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_VERSION_H */
