/*
 * main.c — shrike CLI driver.
 *
 *   shrike [options] <elf64>
 *
 * Dispatches on ELF machine type: x86-64 or aarch64.
 */

#include "elf64.h"
#include "scan.h"
#include "format.h"
#include "strset.h"
#include "cet.h"
#include "category.h"
#include "regidx.h"
#include "recipe.h"
#include "sarif.h"
#include "pivots.h"

/* v0.13.0: file-scope pointer so emit_cb can reach the SARIF
 * emitter without changing the gadget_cb signature. */
sarif_emitter_t *shrike_sarif_emitter_current;

/* v0.14.0: same pattern for the pivot atlas. */
pivot_atlas_t   *shrike_pivot_atlas_current;

#include <errno.h>
#include <inttypes.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    size_t        total;
    size_t        shstk_blocked_count;
    size_t        endbr_count;
    size_t        cat_counts[CAT_MAX];
    size_t        bad_bytes_filtered;
    size_t        limit;
    const char   *filter;
    regex_t       re;
    int           regex_set;
    int           unique;
    int           json;
    int           cet_tag;
    int           want_shstk_survivable;
    int           want_endbr;
    uint32_t      cat_mask;
    int           cat_tag;
    int           bad_byte_active;
    uint8_t       bad_byte_set[256];
    int           stop_signal;
    strset_t      seen;
    FILE         *out;
    /* v0.8.0 — multi-binary: current source path, optional tag */
    const char   *src;
    int           src_tag;
    /* v0.10.0 — register-control indexer (updated per gadget) */
    regidx_t     *ri;
    /* v0.15.0 — canonical dedup */
    int           canonical;
} print_ctx_t;

/* Parse "0x00,0x0a,20" into the bad-byte set. */
static int parse_bad_bytes(const char *csv, uint8_t set[256])
{
    memset(set, 0, 256);
    const char *p = csv;
    while (*p) {
        const char *q = p;
        while (*q && *q != ',') q++;
        char buf[8];
        size_t len = (size_t)(q - p);
        if (len == 0 || len >= sizeof buf) return -1;
        memcpy(buf, p, len);
        buf[len] = '\0';
        char *end = NULL;
        unsigned long v = strtoul(buf, &end, 0);
        if (!end || *end || v > 255) return -1;
        set[v] = 1;
        p = *q ? q + 1 : q;
    }
    return 0;
}

static void emit_cb(const elf64_segment_t *seg,
                    const gadget_t *g, void *ctx)
{
    (void)seg;
    print_ctx_t *pc = (print_ctx_t *)ctx;
    if (pc->stop_signal) return;

    int shstk = cet_shstk_blocked(g);
    int endbr = cet_starts_endbr(g);
    gadget_category_t cat = gadget_categorize(g);

    if (pc->want_shstk_survivable && shstk) return;
    if (pc->want_endbr            && !endbr) return;
    if (pc->cat_mask && !(pc->cat_mask & (1u << cat))) return;

    if (pc->bad_byte_active) {
        uint64_t v = g->vaddr;
        for (int i = 0; i < 8; i++) {
            if (pc->bad_byte_set[v & 0xFF]) {
                pc->bad_bytes_filtered++;
                return;
            }
            v >>= 8;
        }
    }

    char text_line[1024];
    int  n = format_gadget_render(g, text_line, sizeof text_line);
    if (n < 0) return;

    if (pc->filter && !strstr(text_line, pc->filter)) return;
    if (pc->regex_set && regexec(&pc->re, text_line, 0, NULL, 0) != 0)
        return;

    if (pc->unique) {
        char key[1024];
        const char *dkey = text_line;
        if (pc->canonical &&
            format_gadget_canonical_render(g, key, sizeof key) >= 0) {
            dkey = key;
        }
        int rc = strset_add(&pc->seen, dkey);
        if (rc <= 0) return;
    }

    pc->total++;
    if (shstk) pc->shstk_blocked_count++;
    if (endbr) pc->endbr_count++;
    pc->cat_counts[cat]++;
    if (pc->ri) regidx_observe(pc->ri, g);

    /* v0.13.0 SARIF routing. */
    extern sarif_emitter_t *shrike_sarif_emitter_current;
    if (shrike_sarif_emitter_current) {
        sarif_emit(shrike_sarif_emitter_current, g, cat, pc->src);
    }

    /* v0.14.0 pivot atlas routing. */
    extern pivot_atlas_t *shrike_pivot_atlas_current;
    if (shrike_pivot_atlas_current) {
        pivot_atlas_observe(shrike_pivot_atlas_current, g);
    }

    if (pc->out) {
        if (pc->json) {
            /* Inject category + src as post-fix fields by stripping
             * the trailing '}' from the renderer output. */
            char jbuf[2048];
            int  jn = format_gadget_json_render(g, jbuf, sizeof jbuf);
            if (jn > 0 && jbuf[jn - 1] == '}') {
                jbuf[jn - 1] = '\0';
                fprintf(pc->out, "%s,\"category\":\"%s\"",
                        jbuf, gadget_category_name(cat));
                if (pc->src)
                    fprintf(pc->out, ",\"src\":\"%s\"", pc->src);
                fputs("}\n", pc->out);
            } else {
                format_gadget_json(pc->out, g);
            }
        } else if (pc->cet_tag || pc->cat_tag || pc->src_tag) {
            fputs(text_line, pc->out);
            if (pc->src_tag && pc->src) fprintf(pc->out, " [%s]", pc->src);
            if (pc->cet_tag && shstk)   fputs(" [SHSTK-BLOCKED]", pc->out);
            if (pc->cet_tag && endbr)   fputs(" [ENDBR/BTI]", pc->out);
            if (pc->cat_tag)
                fprintf(pc->out, " [%s]", gadget_category_name(cat));
            fputc('\n', pc->out);
        } else {
            fputs(text_line, pc->out);
            fputc('\n', pc->out);
        }
    }

    if (pc->limit && pc->total >= pc->limit) pc->stop_signal = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
"shrike — x86-64 / AArch64 ROP gadget finder\n"
"\n"
"Usage:\n"
"  %s [options] <elf64>\n"
"\n"
"Scan configuration:\n"
"      --max-insn N        max instructions per gadget       [5]\n"
"      --back N            max bytes to scan back per term.  [48, x86 only]\n"
"      --no-syscall        skip syscall / sysret / svc terminators\n"
"      --no-int            skip int / int3 terminators (x86 only)\n"
"      --no-ind            skip indirect CALL/JMP / BR / BLR\n"
"\n"
"Output filtering:\n"
"      --filter PATTERN    substring match against mnemonic line\n"
"      --regex PATTERN     POSIX regex against mnemonic line\n"
"      --unique            de-duplicate identical mnemonic chains\n"
"      --limit N           stop after N emitted gadgets\n"
"      --quiet             only print the summary\n"
"\n"
"CET / BTI classification:\n"
"      --shstk-survivable  emit only non-RET terminators\n"
"      --endbr             emit only gadgets starting at ENDBR (x86) /\n"
"                          BTI (aarch64)\n"
"      --cet-tag           append [SHSTK-BLOCKED]/[ENDBR/BTI] inline\n"
"\n"
"Category classification (v0.6.0):\n"
"      --category CSV      keep only gadgets whose category is in CSV\n"
"                          values: other, ret_only, pop, mov, arith,\n"
"                                   stack_pivot, syscall, indirect\n"
"      --cat-tag           append [<category>] inline in text mode\n"
"\n"
"Exploit-dev constraints (v0.7.0):\n"
"      --bad-bytes CSV     reject gadgets whose vaddr contains any\n"
"                          of these bytes (e.g. '0x00,0x0a,0x20')\n"
"\n"
"Multi-binary audit (v0.8.0):\n"
"      pass any number of ELF paths; --unique dedup applies\n"
"      across all of them, so gadget chains shared between libs\n"
"      collapse to one line.\n"
"      --src-tag           append [<file>] to each text line\n"
"      JSON output always carries a 'src' field.\n"
"\n"
"Register-control index (v0.10.0):\n"
"      --reg-index         after the scan, print a table of\n"
"                          'which register can I pop into, at what\n"
"                          addresses?' Indexes multi-pop chains too\n"
"                          (pop rbp ; pop r12 ; ret credits both).\n"
"      --reg-index-python  emit the index as a pwntools-compatible\n"
"                          Python dict literal instead.\n"
"      --reg-index-json    emit the index as JSON.\n"
"\n"
"Chain composer (v0.11.0):\n"
"      --recipe SRC        DSL: semicolon-separated statements.\n"
"                          REG=* sets a register from a payload slot\n"
"                          REG=N sets it to literal N\n"
"                          'syscall' inserts a syscall terminator\n"
"                          Example:\n"
"                              --recipe 'rdi=*; rsi=*; rax=59; syscall'\n"
"      --format FMT        recipe output format: text (default) |\n"
"                          pwntools (self-sufficient Python skeleton\n"
"                          using pwn.ROP().raw() + cyclic placeholders)\n"
"      -p                  short alias for --format pwntools\n"
"\n"
"Binary diff (v0.9.0):\n"
"      --diff              requires exactly two inputs:\n"
"                          'shrike --diff old.so new.so'.\n"
"                          Emits '+ mnemo' for gadgets present\n"
"                          in NEW but not in OLD, and '- mnemo'\n"
"                          for gadgets present in OLD but not\n"
"                          in NEW. Matching is by mnemonic text\n"
"                          (address-independent, ASLR-safe).\n"
"\n"
"Semantic dedup (v0.15.0):\n"
"      --canonical         implies --unique. Collapses semantically\n"
"                          equivalent gadgets into one line:\n"
"                             ret 0x0 / retf  →  ret\n"
"                             xor REG, REG    →  ZERO(REG)\n"
"                          Reduces output by 30-50%% on real binaries.\n"
"\n"
"Output formatting:\n"
"      --json              JSON-Lines output; carries arch, shstk_blocked,\n"
"                          starts_endbr, category for every gadget\n"
"\n"
"  -h, --help              this message\n"
"\n"
"Exit codes: 0 ok, 1 runtime error, 2 bad invocation.\n",
    prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 2; }

    scan_config_t cfg;
    scan_config_default(&cfg);

    int         quiet   = 0;
    int         unique  = 0;
    int         json    = 0;
    int         cet_tag = 0;
    int         cat_tag = 0;
    int         want_shstk = 0;
    int         want_endbr = 0;
    uint32_t    cat_mask = 0;
    int         bad_active = 0;
    uint8_t     bad_set[256];
    int         src_tag = 0;
    int         diff_mode = 0;        /* v0.9.0 */
    int         reg_index = 0;        /* v0.10.0 */
    const char *recipe_src = NULL;    /* v0.11.0 */
    int         recipe_fmt = 0;       /* v0.12.0 */
    int         sarif_mode = 0;       /* v0.13.0 */
    size_t      sarif_cap  = 1000;    /* v0.13.0 */
    int         pivots_mode = 0;      /* v0.14.0: 1=text, 2=json */
    int         canonical   = 0;      /* v0.15.0 */
    size_t      limit  = 0;
    const char *filter = NULL;
    const char *regex  = NULL;

    /* v0.8.0: accept multiple paths. Collected after flags. */
    const char *paths[64];
    size_t      n_paths = 0;

    memset(bad_set, 0, sizeof bad_set);

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
        } else if (!strcmp(a, "--cet-tag"))    { cet_tag = 1;
        } else if (!strcmp(a, "--cat-tag"))    { cat_tag = 1;
        } else if (!strcmp(a, "--shstk-survivable")) { want_shstk = 1;
        } else if (!strcmp(a, "--endbr"))      { want_endbr = 1;
        } else if (!strcmp(a, "--filter") && i + 1 < argc) {
            filter = argv[++i];
        } else if (!strcmp(a, "--regex") && i + 1 < argc) {
            regex = argv[++i];
        } else if (!strcmp(a, "--category") && i + 1 < argc) {
            if (gadget_category_parse_mask(argv[++i], &cat_mask) < 0) {
                fprintf(stderr, "shrike: bad --category value\n");
                return 2;
            }
        } else if (!strcmp(a, "--bad-bytes") && i + 1 < argc) {
            if (parse_bad_bytes(argv[++i], bad_set) < 0) {
                fprintf(stderr, "shrike: bad --bad-bytes value\n");
                return 2;
            }
            bad_active = 1;
        } else if (!strcmp(a, "--src-tag"))    { src_tag = 1;
        } else if (!strcmp(a, "--diff"))       { diff_mode = 1;
        } else if (!strcmp(a, "--reg-index"))        { reg_index = 1;
        } else if (!strcmp(a, "--reg-index-python")) { reg_index = 2;
        } else if (!strcmp(a, "--reg-index-json"))   { reg_index = 3;
        } else if (!strcmp(a, "--recipe") && i + 1 < argc) {
            recipe_src = argv[++i];
        } else if (!strcmp(a, "--sarif"))                    { sarif_mode = 1;
        } else if (!strcmp(a, "--sarif-cap") && i + 1 < argc) {
            sarif_cap = (size_t)strtoull(argv[++i], NULL, 10);
        } else if (!strcmp(a, "--pivots"))                   { pivots_mode = 1;
        } else if (!strcmp(a, "--pivots-json"))              { pivots_mode = 2;
        } else if (!strcmp(a, "--canonical"))                { canonical = 1;
            unique = 1;
        } else if ((!strcmp(a, "--format") || !strcmp(a, "-p"))
                   && i + 1 < argc) {
            const char *v = argv[++i];
            if      (!strcmp(v, "pwntools") || !strcmp(v, "py")) recipe_fmt = 1;
            else if (!strcmp(v, "text"))                         recipe_fmt = 0;
            else {
                fprintf(stderr, "shrike: bad --format (expected text|pwntools)\n");
                return 2;
            }
        } else if (!strcmp(a, "--limit") && i + 1 < argc) {
            limit = (size_t)strtoull(argv[++i], NULL, 10);
        } else if (a[0] == '-') {
            fprintf(stderr, "shrike: unknown flag %s\n", a);
            usage(argv[0]);
            return 2;
        } else {
            if (n_paths >= sizeof(paths) / sizeof(paths[0])) {
                fprintf(stderr, "shrike: too many inputs (max 64)\n");
                return 2;
            }
            paths[n_paths++] = a;
        }
    }

    if (n_paths == 0) { usage(argv[0]); return 2; }

    if (diff_mode && n_paths != 2) {
        fprintf(stderr, "shrike: --diff requires exactly two inputs\n");
        return 2;
    }

    /* ======== diff mode (v0.9.0) ========
     * Scan each input, collect mnemonic lines into a strset, then
     * print the symmetric difference with +/- prefixes. Matching is
     * by rendered mnemonic line so it is ASLR-safe.              */
    if (diff_mode) {
        strset_t set_old, set_new;
        strset_init(&set_old);
        strset_init(&set_new);

        /* Config the collector sees via file-scope statics below. */
        extern void diff_collect_set_target(strset_t *s);
        extern void diff_collect_cb(const elf64_segment_t *seg,
                                    const gadget_t *g, void *ctx);

        for (size_t pi = 0; pi < 2; pi++) {
            elf64_t e;
            if (elf64_load(paths[pi], &e) < 0) {
                fprintf(stderr, "shrike: %s: %s\n",
                        paths[pi], strerror(errno));
                strset_free(&set_old);
                strset_free(&set_new);
                return 1;
            }
            diff_collect_set_target(pi == 0 ? &set_old : &set_new);
            for (size_t i = 0; i < e.nseg; i++) {
                scan_segment(&e.segs[i], &cfg, diff_collect_cb, NULL);
            }
            elf64_close(&e);
        }

        /* emit + for entries in NEW not in OLD, - for OLD not in NEW */
        struct diff_emit_env {
            const strset_t *other;
            FILE           *out;
            char            prefix;
            size_t          count;
        };

        extern void diff_emit_cb(const char *key, void *ctx);

        /* NB: the diff_emit_env_t type is defined at file scope below;
         * referencing it here via a matching local struct is portable
         * because it has identical layout. */
        struct {
            const strset_t *other;
            FILE           *out;
            char            prefix;
            size_t          count;
        } added   = { &set_old, stdout, '+', 0 };
        struct {
            const strset_t *other;
            FILE           *out;
            char            prefix;
            size_t          count;
        } removed = { &set_new, stdout, '-', 0 };

        strset_foreach(&set_new, diff_emit_cb, &added);
        strset_foreach(&set_old, diff_emit_cb, &removed);

        size_t common = set_old.used > removed.count
                      ? set_old.used - removed.count : 0;

        fprintf(stderr, "shrike --diff: +%zu  -%zu  common=%zu\n",
                added.count, removed.count, common);

        strset_free(&set_old);
        strset_free(&set_new);
        return 0;
    }

    print_ctx_t pc;
    memset(&pc, 0, sizeof pc);
    pc.out                   = quiet ? NULL : stdout;
    pc.limit                 = limit;
    pc.filter                = filter;
    pc.unique                = unique;
    pc.canonical             = canonical;
    pc.json                  = json;
    pc.cet_tag               = cet_tag;
    pc.cat_tag               = cat_tag;
    pc.src_tag               = src_tag;
    pc.cat_mask              = cat_mask;
    pc.want_shstk_survivable = want_shstk;
    pc.want_endbr            = want_endbr;
    pc.bad_byte_active       = bad_active;
    if (bad_active) memcpy(pc.bad_byte_set, bad_set, sizeof bad_set);
    strset_init(&pc.seen);

    /* v0.10.0 / v0.11.0: enable the register indexer when either a
     * --reg-index-* flag is set OR a --recipe is being resolved. In
     * both cases, per-gadget emission is suppressed so stdout stays
     * clean for the index / chain consumer. */
    regidx_t ri;
    if (reg_index || recipe_src) {
        pc.ri  = &ri;
        pc.out = NULL;
    }

    /* v0.13.0 SARIF mode */
    sarif_emitter_t *sarif = NULL;
    if (sarif_mode) {
        sarif = sarif_new(stdout, sarif_cap);
        if (!sarif) { fprintf(stderr, "shrike: sarif alloc\n"); return 1; }
        sarif_begin(sarif);
        shrike_sarif_emitter_current = sarif;
        pc.out  = NULL;
        pc.json = 0;
    }

    /* v0.14.0 pivots mode */
    pivot_atlas_t *pivots = NULL;
    uint16_t pivots_machine = 0;
    if (pivots_mode) {
        pivots = pivot_atlas_new();
        if (!pivots) { fprintf(stderr, "shrike: pivots alloc\n"); return 1; }
        shrike_pivot_atlas_current = pivots;
        pc.out  = NULL;
        pc.json = 0;
    }

    if (regex) {
        int rc = regcomp(&pc.re, regex, REG_EXTENDED | REG_NOSUB);
        if (rc != 0) {
            char errbuf[256];
            regerror(rc, &pc.re, errbuf, sizeof errbuf);
            fprintf(stderr, "shrike: bad --regex: %s\n", errbuf);
            return 2;
        }
        pc.regex_set = 1;
    }

    int had_error = 0;
    int ri_initialised = 0;
    uint16_t first_arch = 0;

    for (size_t pi = 0; pi < n_paths && !pc.stop_signal; pi++) {
        const char *path = paths[pi];
        elf64_t e;
        if (elf64_load(path, &e) < 0) {
            fprintf(stderr, "shrike: %s: %s\n", path, strerror(errno));
            had_error = 1;
            continue;
        }
        pc.src = path;
        const char *arch = (e.machine == EM_AARCH64) ? "aarch64" : "x86_64";

        if ((reg_index || recipe_src) && !ri_initialised) {
            regidx_init(&ri, e.machine);
            first_arch = e.machine;
            ri_initialised = 1;
        }
        if (pivots_mode && pivots_machine == 0) pivots_machine = e.machine;

        if (!quiet && !json) {
            fprintf(stdout, "# file: %s\n", path);
            fprintf(stdout, "# type: %s  arch: %s  entry: 0x%" PRIx64
                            "  segments: %zu\n",
                    e.is_dyn ? "ET_DYN" : "ET_EXEC",
                    arch, e.entry, e.nseg);
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

        elf64_close(&e);
    }

    fprintf(stderr,
            "shrike: %zu inputs  %zu emitted  "
            "(SHSTK-blocked: %zu, ENDBR/BTI-start: %zu)%s\n",
            n_paths, pc.total,
            pc.shstk_blocked_count, pc.endbr_count,
            pc.stop_signal ? " (limit reached)" : "");

    if (pc.bad_byte_active && pc.bad_bytes_filtered > 0) {
        fprintf(stderr, "shrike: %zu rejected by --bad-bytes\n",
                pc.bad_bytes_filtered);
    }

    /* Category histogram on stderr when non-trivial output was produced. */
    if (pc.total > 0) {
        fprintf(stderr, "shrike: categories:");
        for (int i = 0; i < CAT_MAX; i++) {
            if (pc.cat_counts[i] > 0)
                fprintf(stderr, " %s=%zu",
                        gadget_category_name((gadget_category_t)i),
                        pc.cat_counts[i]);
        }
        fputc('\n', stderr);
    }

    /* v0.10.0 register-index emission — after all scanning is done. */
    if (reg_index && ri_initialised) {
        switch (reg_index) {
        case 2: regidx_print_python(&ri, stdout); break;
        case 3: regidx_print_json  (&ri, stdout); break;
        default: regidx_print       (&ri, stdout); break;
        }
    }

    /* v0.13.0 close SARIF. */
    if (sarif) {
        shrike_sarif_emitter_current = NULL;
        sarif_end(sarif);
        sarif_free(sarif);
    }

    /* v0.14.0 emit pivot atlas. */
    if (pivots) {
        shrike_pivot_atlas_current = NULL;
        if (pivots_mode == 2) pivot_atlas_print_json(pivots, pivots_machine, stdout);
        else                  pivot_atlas_print     (pivots, pivots_machine, stdout);
        pivot_atlas_free(pivots);
    }

    /* v0.11.0 + v0.12.0 recipe resolution. */
    if (recipe_src && ri_initialised) {
        recipe_t rec;
        if (recipe_parse(recipe_src, &rec, first_arch) < 0) {
            fprintf(stderr, "shrike: bad --recipe syntax\n");
            had_error = 1;
        } else {
            recipe_format_t fmt = recipe_fmt == 1
                                ? RECIPE_FMT_PWNTOOLS
                                : RECIPE_FMT_TEXT;
            int missing = recipe_resolve(&rec, &ri, first_arch,
                                         paths[0], fmt, stdout);
            if (missing > 0) had_error = 1;
        }
    }

    if (pc.regex_set) regfree(&pc.re);
    strset_free(&pc.seen);
    return had_error ? 1 : 0;
}

/* -------------------------------------------------------------------------
 * diff-mode helpers (v0.9.0).
 *
 * The collector writes mnemonic strings into a file-scope "current
 * target" strset. Between scans, main() calls diff_collect_set_target()
 * to switch which set receives new entries. The emitter iterates a set
 * and prints entries absent from a reference set.
 * ------------------------------------------------------------------------- */

static strset_t *g_diff_target;

void diff_collect_set_target(strset_t *s)
{
    g_diff_target = s;
}

void diff_collect_cb(const elf64_segment_t *seg,
                     const gadget_t *g, void *ctx)
{
    (void)seg; (void)ctx;
    if (!g_diff_target) return;
    char line[1024];
    int  n = format_gadget_render(g, line, sizeof line);
    if (n < 0) return;
    /* Strip the address prefix so matches are ASLR-safe: keep
     * everything after the ": ". */
    const char *colon = strstr(line, ": ");
    const char *key   = colon ? colon + 2 : line;
    strset_add(g_diff_target, key);
}

struct diff_emit_env_t {
    const strset_t *other;
    FILE           *out;
    char            prefix;
    size_t          count;
};

void diff_emit_cb(const char *key, void *ctx)
{
    struct diff_emit_env_t *env = (struct diff_emit_env_t *)ctx;
    if (strset_contains(env->other, key)) return;  /* in both → not a diff */
    fprintf(env->out, "%c %s\n", env->prefix, key);
    env->count++;
}
