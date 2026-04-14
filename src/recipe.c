/*
 * recipe.c — DSL parser + greedy chain resolver.
 */

#include <shrike/recipe.h>

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

    /* keyword statements — arch-canonical spellings all alias to
     * RSTMT_SYSCALL so a single recipe can move between x86_64
     * `syscall`, aarch64 `svc`, and riscv64 `ecall`. The picker
     * emits the right terminator at rendering time. */
    if ((len == 7 && strncmp(p, "syscall", 7) == 0) ||
        (len == 3 && strncmp(p, "svc", 3) == 0) ||
        (len == 5 && strncmp(p, "ecall", 5) == 0)) {
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
    const char *arch = (machine == EM_AARCH64) ? "aarch64"
                     : (machine == EM_RISCV)   ? "riscv64"
                     :                           "x86_64";

    fprintf(f, "# shrike chain from recipe  (arch: %s)\n", arch);
    fprintf(f, "# format: addr  note                         (one slot per line)\n");

    for (int i = 0; i < r->n; i++) {
        const recipe_stmt_t *s = &r->stmts[i];

        /* v1.5.2: before falling back to a single-pop gadget,
         * check whether a contiguous run of SET_REG statements
         * can be satisfied by one multi-pop gadget. Exact-match
         * only — a gadget that pops (rdi, rsi, rdx) is chosen
         * only if the recipe asks for exactly those three. */
        if (s->op == RSTMT_SET_REG) {
            int run = 0;
            uint32_t needed = 0;
            for (int k = i; k < r->n && r->stmts[k].op == RSTMT_SET_REG; k++) {
                if (r->stmts[k].reg < 0 ||
                    r->stmts[k].reg >= REGIDX_MAX_REGS) break;
                needed |= 1u << r->stmts[k].reg;
                run++;
            }
            if (run >= 2) {
                const regidx_multi_t *mp =
                    regidx_find_multi_exact(idx, needed);
                if (mp) {
                    fprintf(f,
                        "0x%016" PRIx64 "  # multi-pop gadget  (stack: %u bytes)\n",
                        mp->addr, (unsigned)mp->stack_consumed);
                    for (int k = i; k < i + run; k++) {
                        const recipe_stmt_t *sk = &r->stmts[k];
                        const char *rn =
                            regidx_reg_name(machine, sk->reg);
                        if (sk->is_literal) {
                            fprintf(f,
                                "0x%016" PRIx64 "  # %s = 0x%" PRIx64 "\n",
                                sk->value, rn, sk->value);
                        } else {
                            fprintf(f,
                                "<value>            # %s (fill at exploit time)\n",
                                rn);
                        }
                    }
                    i += run - 1;   /* for-loop adds the last 1 */
                    continue;
                }
            }
        }

        if (s->op == RSTMT_SET_REG) {
            const char *rn = regidx_reg_name(machine, s->reg);
            if (!rn) { missing++; continue; }

            if (s->reg >= REGIDX_MAX_REGS || idx->counts[s->reg] == 0) {
                fprintf(f, "# MISSING: no pop-gadget for %s\n", rn);
                missing++;
                continue;
            }

            uint64_t g_addr = idx->addrs[s->reg][0];
            uint32_t stack  = idx->stack_consumed[s->reg][0];
            fprintf(f, "0x%016" PRIx64 "  # pop %s ; ret  (stack: %u bytes)\n",
                    g_addr, rn, (unsigned)stack);
            if (s->is_literal) {
                fprintf(f, "0x%016" PRIx64 "  # %s = 0x%" PRIx64 "\n",
                        s->value, rn, s->value);
            } else {
                fprintf(f, "<value>            # %s (fill at exploit time)\n", rn);
            }
            /* v1.5.1: multi-pop gadgets (e.g. `pop rdi ; pop rsi ;
             * ret`, stack=24) consume more than the default
             * 16 bytes. Pad the extra slots with 0xdeadbeef so the
             * emitter keeps alignment with the gadget's actual
             * footprint. 16 = 1 addr slot + 1 value slot; anything
             * beyond is padding. */
            if (stack > 16) {
                uint32_t extra = (stack - 16) / 8;
                for (uint32_t k = 0; k < extra; k++) {
                    fprintf(f,
                        "0x00000000deadbeef  # padding (multi-pop spillover)\n");
                }
            }
        } else if (s->op == RSTMT_SYSCALL) {
            if (idx->syscall_count == 0) {
                fprintf(f, "# MISSING: no syscall gadget\n");
                missing++;
            } else {
                const char *mnemo = "syscall";
                if (machine == EM_AARCH64)    mnemo = "svc";
                else if (machine == EM_RISCV) mnemo = "ecall";
                fprintf(f, "0x%016" PRIx64 "  # %s\n",
                        idx->syscall_addrs[0], mnemo);
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
    /* pwntools context.arch names: 'amd64', 'aarch64', 'riscv64'. */
    const char *ctx_arch = "amd64";
    if (machine == EM_AARCH64)    ctx_arch = "aarch64";
    else if (machine == EM_RISCV) ctx_arch = "riscv64";

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
