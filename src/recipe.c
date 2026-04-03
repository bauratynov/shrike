/*
 * recipe.c — DSL parser + greedy chain resolver.
 */

#include "recipe.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */

static const char *skip_ws(const char *p)
{
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

static size_t trim_len(const char *p, size_t len)
{
    while (len > 0 && isspace((unsigned char)p[len - 1])) len--;
    return len;
}

/* Parse one statement from [p, q). Appends to `out` on success. */
static int parse_stmt(const char *p, const char *q,
                      recipe_t *out, uint16_t machine)
{
    p = skip_ws(p);
    size_t len = trim_len(p, (size_t)(q - p));
    if (len == 0) return 0;       /* empty → ignore (trailing ;)     */

    if (out->n >= RECIPE_MAX_STMTS) return -1;

    /* keyword statements */
    if (len == 7 && strncmp(p, "syscall", 7) == 0) {
        out->stmts[out->n++].op = RSTMT_SYSCALL;
        return 0;
    }
    if (len == 3 && strncmp(p, "ret", 3) == 0) {
        out->stmts[out->n++].op = RSTMT_RET;
        return 0;
    }

    /* reg_stmt := NAME '=' VALUE */
    const char *eq = NULL;
    for (const char *r = p; r < p + len; r++) {
        if (*r == '=') { eq = r; break; }
    }
    if (!eq) return -1;

    /* register name: [p, eq), trimmed */
    size_t nl = trim_len(p, (size_t)(eq - p));
    if (nl == 0 || nl >= 16) return -1;
    char name[16];
    memcpy(name, p, nl);
    name[nl] = '\0';

    int reg = regidx_reg_lookup(machine, name);
    if (reg < 0) return -1;

    /* value: after '=' */
    const char *vs = skip_ws(eq + 1);
    const char *vend = p + len;

    recipe_stmt_t *s = &out->stmts[out->n++];
    s->op  = RSTMT_SET_REG;
    s->reg = reg;

    if (vs < vend && *vs == '*') {
        s->is_literal = 0;
        s->value      = 0;
    } else {
        char *end = NULL;
        s->value      = strtoull(vs, &end, 0);
        s->is_literal = 1;
        if (!end || end == vs) return -1;
    }
    return 0;
}

int recipe_parse(const char *src, recipe_t *out, uint16_t machine)
{
    memset(out, 0, sizeof(*out));
    if (!src) return -1;

    const char *p = src;
    while (*p) {
        const char *q = p;
        while (*q && *q != ';') q++;
        if (parse_stmt(p, q, out, machine) < 0) return -1;
        p = (*q == ';') ? q + 1 : q;
    }
    return 0;
}

/* ------------------------------------------------------------------ */

static int resolve_text(const recipe_t *r, const regidx_t *idx,
                        uint16_t machine, FILE *f)
{
    int missing = 0;
    const char *arch = (machine == EM_AARCH64) ? "aarch64" : "x86_64";

    fprintf(f, "# shrike chain from recipe  (arch: %s)\n", arch);
    fprintf(f, "# format: addr  note                         (one slot per line)\n");

    for (int i = 0; i < r->n; i++) {
        const recipe_stmt_t *s = &r->stmts[i];

        if (s->op == RSTMT_SET_REG) {
            const char *rn = regidx_reg_name(machine, s->reg);
            if (!rn) { missing++; continue; }

            if (s->reg >= REGIDX_MAX_REGS || idx->counts[s->reg] == 0) {
                fprintf(f, "# MISSING: no pop-gadget for %s\n", rn);
                missing++;
                continue;
            }

            uint64_t g_addr = idx->addrs[s->reg][0];
            fprintf(f, "0x%016" PRIx64 "  # pop %s ; ret\n", g_addr, rn);
            if (s->is_literal) {
                fprintf(f, "0x%016" PRIx64 "  # %s = 0x%" PRIx64 "\n",
                        s->value, rn, s->value);
            } else {
                fprintf(f, "<value>            # %s (fill at exploit time)\n", rn);
            }
        } else if (s->op == RSTMT_SYSCALL) {
            if (idx->syscall_count == 0) {
                fprintf(f, "# MISSING: no syscall gadget\n");
                missing++;
            } else {
                fprintf(f, "0x%016" PRIx64 "  # %s\n",
                        idx->syscall_addrs[0],
                        machine == EM_AARCH64 ? "svc" : "syscall");
            }
        } else if (s->op == RSTMT_RET) {
            fprintf(f, "# (explicit ret — caller places an address here)\n");
        }
    }

    if (missing) {
        fprintf(f,
"# %d missing — the chain above is INCOMPLETE. Scan more binaries\n"
"# (shrike accepts N inputs — add libc.so, etc.) to fill the gaps.\n",
                missing);
    }
    return missing;
}

static int resolve_pwntools(const recipe_t *r, const regidx_t *idx,
                            uint16_t machine, const char *elf_path,
                            FILE *f)
{
    int missing = 0;
    const char *ctx_arch =
        (machine == EM_AARCH64) ? "aarch64" : "amd64";

    fprintf(f,
        "#!/usr/bin/env python3\n"
        "# Synthesised by shrike --format pwntools\n"
        "# Auto-generated exploit skeleton — audit before running.\n"
        "from pwn import *\n\n"
        "context.arch = '%s'\n", ctx_arch);
    if (elf_path) {
        fprintf(f, "context.binary = elf = ELF('%s')\n", elf_path);
    }
    fprintf(f, "rop = ROP(elf)\n\n");

    int slot_idx = 0;
    for (int i = 0; i < r->n; i++) {
        const recipe_stmt_t *s = &r->stmts[i];

        if (s->op == RSTMT_SET_REG) {
            const char *rn = regidx_reg_name(machine, s->reg);
            if (!rn) { missing++; continue; }
            if (s->reg >= REGIDX_MAX_REGS || idx->counts[s->reg] == 0) {
                fprintf(f, "# MISSING: no pop-gadget for %s\n", rn);
                missing++;
                continue;
            }
            uint64_t g = idx->addrs[s->reg][0];
            fprintf(f, "rop.raw(0x%" PRIx64 ")           # pop %s ; ret\n",
                    g, rn);
            if (s->is_literal) {
                fprintf(f, "rop.raw(0x%" PRIx64 ")           # %s = 0x%" PRIx64 "\n",
                        s->value, rn, s->value);
            } else {
                /* cyclic De Bruijn slot — helps identify the exact
                 * offset that ends up in the register at crash time. */
                fprintf(f, "rop.raw(cyclic(8, n=8))  # TODO <%s> slot %d\n",
                        rn, slot_idx++);
            }
        } else if (s->op == RSTMT_SYSCALL) {
            if (idx->syscall_count == 0) {
                fprintf(f, "# MISSING: no syscall gadget\n");
                missing++;
            } else {
                fprintf(f, "rop.raw(0x%" PRIx64 ")           # %s\n",
                        idx->syscall_addrs[0],
                        machine == EM_AARCH64 ? "svc" : "syscall");
            }
        } else if (s->op == RSTMT_RET) {
            fprintf(f, "# TODO: caller-provided return address\n");
        }
    }

    fprintf(f,
        "\n"
        "payload = rop.chain()\n"
        "# offset = ???   # TODO: distance from buffer start to saved RIP\n"
        "# io = process(elf.path)\n"
        "# io.sendline(flat({offset: payload}))\n"
        "# io.interactive()\n");

    if (missing) {
        fprintf(f,
            "# %d gadgets missing — scan additional binaries (e.g. libc)\n",
            missing);
    }
    return missing;
}

int recipe_resolve(const recipe_t *r,
                   const regidx_t *idx,
                   uint16_t        machine,
                   const char     *elf_path,
                   recipe_format_t fmt,
                   FILE           *f)
{
    if (fmt == RECIPE_FMT_PWNTOOLS) {
        return resolve_pwntools(r, idx, machine, elf_path, f);
    }
    return resolve_text(r, idx, machine, f);
}
