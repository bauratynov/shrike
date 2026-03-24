/*
 * main.c — shrike CLI driver.
 *
 *   shrike [options] <elf64>
 *
 * By default scans every executable PT_LOAD segment of the input and
 * prints one gadget per line. Configuration flags tune the
 * scanner's aggressiveness (max instructions per gadget, how far
 * back from each terminator to scan, and which terminator families
 * to include).
 */

#include "elf64.h"
#include "scan.h"
#include "format.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t total;
    FILE  *out;
} print_ctx_t;

static void print_cb(const elf64_segment_t *seg,
                     const gadget_t *g, void *ctx)
{
    (void)seg;
    print_ctx_t *pc = (print_ctx_t *)ctx;
    pc->total++;
    if (pc->out) format_gadget(pc->out, g);
}

static void usage(const char *prog)
{
    fprintf(stderr,
"shrike — x86-64 ROP gadget finder\n"
"\n"
"Usage:\n"
"  %s [options] <elf64>\n"
"\n"
"Options:\n"
"      --max-insn N       max instructions per gadget       [5]\n"
"      --back N           max bytes to scan back per term.  [48]\n"
"      --no-syscall       skip syscall / sysret terminators\n"
"      --no-int           skip int / int3 terminators\n"
"      --no-ind           skip indirect CALL/JMP (FF /2..5)\n"
"      --quiet            only print the summary\n"
"  -h, --help             this message\n"
"\n"
"Exit codes: 0 ok, 1 runtime error, 2 bad invocation.\n",
    prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 2; }

    scan_config_t cfg;
    scan_config_default(&cfg);
    int quiet = 0;
    const char *path = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]); return 0;
        } else if (!strcmp(a, "--max-insn") && i + 1 < argc) {
            cfg.max_insn = atoi(argv[++i]);
        } else if (!strcmp(a, "--back") && i + 1 < argc) {
            cfg.max_backscan = atoi(argv[++i]);
        } else if (!strcmp(a, "--no-syscall")) {
            cfg.include_syscall = 0;
        } else if (!strcmp(a, "--no-int")) {
            cfg.include_int = 0;
        } else if (!strcmp(a, "--no-ind")) {
            cfg.include_ff = 0;
        } else if (!strcmp(a, "--quiet")) {
            quiet = 1;
        } else if (a[0] == '-') {
            fprintf(stderr, "shrike: unknown flag %s\n", a);
            usage(argv[0]);
            return 2;
        } else {
            if (path) {
                fprintf(stderr, "shrike: only one input supported\n");
                return 2;
            }
            path = a;
        }
    }

    if (!path) { usage(argv[0]); return 2; }

    elf64_t e;
    if (elf64_load(path, &e) < 0) {
        fprintf(stderr, "shrike: %s: %s\n", path, strerror(errno));
        return 1;
    }

    /* In quiet mode pc.out is NULL, so print_cb still counts but
     * emits nothing — the only thing on stdout is the summary line. */
    print_ctx_t pc = { 0, quiet ? NULL : stdout };

    if (!quiet) {
        fprintf(stdout, "# file: %s\n", path);
        fprintf(stdout, "# type: %s  entry: 0x%" PRIx64
                        "  segments: %zu\n",
                e.is_dyn ? "ET_DYN" : "ET_EXEC",
                e.entry, e.nseg);
    }

    for (size_t i = 0; i < e.nseg; i++) {
        const elf64_segment_t *s = &e.segs[i];
        if (!quiet) {
            fprintf(stdout, "# segment[%zu]: vaddr=0x%016" PRIx64
                            "  bytes=%zu\n", i, s->vaddr, s->size);
        }
        scan_segment(s, &cfg, print_cb, &pc);
    }

    fprintf(stderr, "shrike: %zu gadgets emitted\n", pc.total);

    elf64_close(&e);
    return 0;
}
