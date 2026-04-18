/*
 * warning.c — advisory-message callback plumbing.
 *
 * v5.2.0: library code that used to do fprintf(stderr, ...)
 * now routes through shrike_warn() which dispatches to a
 * user-installable callback. Default callback writes to
 * stderr; CLI users keep the old behaviour, library consumers
 * can silence or redirect.
 */

#include <shrike/shrike.h>

#include <stdio.h>
#include <stdarg.h>

static shrike_warning_cb g_warn_cb = NULL;
static void             *g_warn_user = NULL;

static void
default_stderr_sink(const char *msg, void *user)
{
    (void)user;
    if (msg) fputs(msg, stderr);
}

void
shrike_set_warning_callback(shrike_warning_cb cb, void *user)
{
    g_warn_cb   = cb;
    g_warn_user = user;
}

void
shrike_warning_silent(const char *msg, void *user)
{
    (void)msg; (void)user;
}

/* Internal dispatch. Format a message and hand it to the
 * installed callback, or to default_stderr_sink. Called from
 * macho.c, pe.c, and anywhere else library code wants to
 * surface a non-fatal diagnostic. */
void
shrike_warn(const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);

    if (g_warn_cb) {
        g_warn_cb(buf, g_warn_user);
    } else {
        default_stderr_sink(buf, NULL);
    }
}
