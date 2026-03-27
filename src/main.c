/*
 * main.c — shrike CLI driver (v0.3.0).
 *
 *   shrike [options] <elf64>
 *
 * New in v0.3.0:
 *   --json             emit one JSON object per gadget (JSON-Lines)
 *   --regex PATTERN    POSIX regex filter over the mnemonic line
 *                      (composes with --filter substring match)
 */

#include "elf64.h"
#include "scan.h"
#include "format.h"
#include "strset.h"

#include <errno.h>
#include <inttypes.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t        total;
    size_t        limit;         /* 0 = no limit */
    const char   *filter;        /* NULL = no substring filter */
    regex_t       re;            /* populated when regex_set = 1 */
    int           regex_set;
    int           unique;
    int           json;
    int           stop_signal;
    strset_t      seen;
    FILE         *out;           /* NULL = suppress emission */
} print_ctx_t;

static void emit_cb(const elf64_segment_t *seg,
                    const gadget_t *g, void *ctx)
{
    (void)seg;
    print_ctx_t *pc = (print_ctx_t *)ctx;
    if (pc->stop_signal) return;

    /* Always render the text form first — it is the canonical key
     * for filter / regex / dedup checks. JSON output uses the same
     * filter decision as text output by construction. */
    char text_line[1024];
    int  n = format_gadget_render(g, text_line, sizeof text_line);
    if (n < 0) return;

    if (pc->filter && !strstr(text_line, pc->filter)) return;

    if (pc->regex_set) {
        if (regexec(&pc->re, text_line, 0, NULL, 0) != 0) return;
    }

    if (pc->unique) {
        int rc = strset_add(&pc->seen, text_line);
        if (rc <= 0) return;
    }

    pc->total++;
    if (pc->out) {
        if (pc->json) format_gadget_json(pc->out, g);
        else          fprintf(pc->out, "%s\n", text_line);
    }

    if (pc->limit && pc->total >= pc->limit) pc->stop_signal = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
"shrike — x86-64 ROP gadget finder\n"
"\n"
"Usage:\n"
"  %s [options] <elf64>\n"
"\n"
"Scan configuration:\n"
"      --max-insn N       max instructions per gadget       [5]\n"
"      --back N           max bytes to scan back per term.  [48]\n"
"      --no-syscall       skip syscall / sysret terminators\n"
"      --no-int           skip int / int3 terminators\n"
"      --no-ind           skip indirect CALL/JMP (FF /2..5)\n"
"\n"
"Output filtering:\n"
"      --filter PATTERN   substring match against the mnemonic line\n"
"      --regex PATTERN    POSIX regex against the mnemonic line (v0.3.0)\n"
"      --unique           de-duplicate identical mnemonic chains\n"
"      --limit N          stop after N emitted gadgets\n"
"      --quiet            only print the summary, skip gadget output\n"
"\n"
"Output formatting:\n"
"      --json             emit one JSON object per gadget (v0.3.0)\n"
"\n"
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

    int         quiet  = 0;
    int         unique = 0;
    int         json   = 0;
    size_t      limit  = 0;
    const char *filter = NULL;
    const char *regex  = NULL;
    const char *path   = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(argv[0]); return 0;
        } else if (!strcmp(a, "--max-insn") && i + 1 < argc) {
            cfg.max_insn = atoi(argv[++i]);
        } else if (!strcmp(a, "--back") && i + 1 < argc) {
            cfg.max_backscan = atoi(argv[++i]);
        } else if (!strcmp(a, "--no-syscall")) { cfg.include_syscall = 0;
        } else if (!strcmp(a, "--no-int"))     { cfg.include_int     = 0;
        } else if (!strcmp(a, "--no-ind"))     { cfg.include_ff      = 0;
        } else if (!strcmp(a, "--quiet"))      { quiet  = 1;
        } else if (!strcmp(a, "--unique"))     { unique = 1;
        } else if (!strcmp(a, "--json"))       { json   = 1;
        } else if (!strcmp(a, "--filter") && i + 1 < argc) {
            filter = argv[++i];
        } else if (!strcmp(a, "--regex") && i + 1 < argc) {
            regex = argv[++i];
        } else if (!strcmp(a, "--limit") && i + 1 < argc) {
            limit = (size_t)strtoull(argv[++i], NULL, 10);
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

    print_ctx_t pc;
    memset(&pc, 0, sizeof pc);
    pc.out    = quiet ? NULL : stdout;
    pc.limit  = limit;
    pc.filter = filter;
    pc.unique = unique;
    pc.json   = json;
    strset_init(&pc.seen);

    if (regex) {
        int rc = regcomp(&pc.re, regex, REG_EXTENDED | REG_NOSUB);
        if (rc != 0) {
            char errbuf[256];
            regerror(rc, &pc.re, errbuf, sizeof errbuf);
            fprintf(stderr, "shrike: bad --regex: %s\n", errbuf);
            elf64_close(&e);
            return 2;
        }
        pc.regex_set = 1;
    }

    if (!quiet && !json) {
        fprintf(stdout, "# file: %s\n", path);
        fprintf(stdout, "# type: %s  entry: 0x%" PRIx64
                        "  segments: %zu\n",
                e.is_dyn ? "ET_DYN" : "ET_EXEC",
                e.entry, e.nseg);
    }

    for (size_t i = 0; i < e.nseg; i++) {
        const elf64_segment_t *s = &e.segs[i];
        if (!quiet && !json) {
            fprintf(stdout, "# segment[%zu]: vaddr=0x%016" PRIx64
                            "  bytes=%zu\n", i, s->vaddr, s->size);
        }
        scan_segment(s, &cfg, emit_cb, &pc);
        if (pc.stop_signal) break;
    }

    {
        const char *arch = (e.machine == EM_AARCH64) ? "aarch64" : "x86_64";
        fprintf(stderr,
                "shrike: [%s] %zu emitted  "
                "(SHSTK-blocked: %zu, ENDBR/BTI-start: %zu)%s\n",
                arch, pc.total,
                pc.shstk_blocked_count, pc.endbr_count,
                pc.stop_signal ? " (limit reached)" : "");
    }

    if (pc.regex_set) regfree(&pc.re);
    strset_free(&pc.seen);
    elf64_close(&e);
    return 0;
}
