/*
 * version.c — runtime version getters.
 *
 * These read the same macros the header defines, but the *linked*
 * library's copy, not the caller's. That's the whole point of
 * providing runtime getters alongside the compile-time macros:
 * users who load libshrike.so via dlopen, or who ship a binary
 * against libshrike headers from a different release, can ask
 * the actual library what version it is.
 */

#include <shrike/version.h>

const char *
shrike_version_string(void)
{
    return SHRIKE_VERSION_STRING;
}

uint32_t
shrike_version_number(void)
{
    return (uint32_t)SHRIKE_VERSION;
}
