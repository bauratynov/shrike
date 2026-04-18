/*
 * warning.h — internal header for library-side advisory
 * messages. Exposed to src/*.c; NOT part of the public API.
 *
 * Public surface is shrike_set_warning_callback + friends in
 * <shrike/shrike.h>. This header declares the dispatch
 * function used by internal call sites.
 */
#ifndef SHRIKE_INTERNAL_WARNING_H
#define SHRIKE_INTERNAL_WARNING_H

#ifdef __cplusplus
extern "C" {
#endif

void shrike_warn(const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

#ifdef __cplusplus
}
#endif

#endif /* SHRIKE_INTERNAL_WARNING_H */
