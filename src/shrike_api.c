/*
 * shrike_api.c — implementation of the 2.x stable C API.
 *
 * Thin wrapper over the 1.x loader + scanner. Holds an
 * elf64_t internally (remembering that pe_load and macho_load
 * also populate an elf64_t), plus a pre-collected vector of
 * gadgets produced at open time.
 *
 * Design choice: eager scan at open(). A context is cheap to
 * create and iterating its gadgets is a straight walk of an
 * array. Lazy streaming would save memory but complicates the
 * opaque-gadget lifetime contract.
 */

#define SHRIKE_IGNORE_DEPRECATIONS   /* we call the 1.x loaders */

#include <shrike/shrike.h>
#include <shrike/elf64.h>
#include <shrike/pe.h>
#include <shrike/macho.h>
#include <shrike/scan.h>
#include <shrike/format.h>
#include <shrike/category.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------- opaque shapes -------------------- */

struct shrike_gadget {
    uint64_t          address;
    const uint8_t    *bytes;
    size_t            size;
    int               insn_count;
    char              disasm[256];
    shrike_category_t category;
    shrike_arch_t     arch;
};

struct shrike_ctx {
    elf64_t            img;
    int                errno_saved;
    scan_config_t      cfg;
    /* Vector of materialised gadgets — grown as we scan. */
    struct shrike_gadget *gadgets;
    size_t              ngadgets;
    size_t              cap;
    int                scanned;
};

struct shrike_iter {
    shrike_ctx_t *ctx;
    size_t        cursor;
    /* Hot-path gadget record returned by shrike_iter_next —
     * stays stable until the next call. */
    struct shrike_gadget current;
};

/* -------------------- helpers -------------------- */

static shrike_arch_t
arch_from_em(uint16_t machine)
{
    if (machine == EM_AARCH64) return SHRIKE_ARCH_AARCH64;
    if (machine == EM_RISCV)   return SHRIKE_ARCH_RISCV64;
    return SHRIKE_ARCH_X86_64;
}

static shrike_category_t
cat_from_gadget(gadget_category_t c)
{
    switch (c) {
    case CAT_RET_ONLY:    return SHRIKE_CAT_RET_ONLY;
    case CAT_POP:         return SHRIKE_CAT_POP;
    case CAT_MOV:         return SHRIKE_CAT_MOV;
    case CAT_ARITH:       return SHRIKE_CAT_ARITH;
    case CAT_STACK_PIVOT: return SHRIKE_CAT_STACK_PIVOT;
    case CAT_SYSCALL:     return SHRIKE_CAT_SYSCALL;
    case CAT_INDIRECT:    return SHRIKE_CAT_INDIRECT;
    default:              return SHRIKE_CAT_OTHER;
    }
}

static void
capture_cb(const elf64_segment_t *seg, const gadget_t *g, void *ctx_v)
{
    (void)seg;
    shrike_ctx_t *ctx = (shrike_ctx_t *)ctx_v;
    if (ctx->ngadgets == ctx->cap) {
        size_t newcap = ctx->cap ? ctx->cap * 2 : 128;
        struct shrike_gadget *nxt = realloc(ctx->gadgets,
                                            newcap * sizeof *nxt);
        if (!nxt) { ctx->errno_saved = ENOMEM; return; }
        ctx->gadgets = nxt;
        ctx->cap     = newcap;
    }
    struct shrike_gadget *s = &ctx->gadgets[ctx->ngadgets++];
    s->address    = g->vaddr;
    s->bytes      = g->bytes;
    s->size       = g->length;
    s->insn_count = g->insn_count;
    s->arch       = arch_from_em(g->machine);
    s->category   = cat_from_gadget(gadget_categorize(g));
    format_gadget_render(g, s->disasm, sizeof s->disasm);
}

static int
load_dispatch(const char *path, const uint8_t *buf, size_t size,
              elf64_t *out)
{
    int rc;
    if (path) {
        rc = elf64_load(path, out);
        if (rc == 0) return 0;
        if (rc == -2) return pe_load(path, out);
        if (rc == -3) return macho_load(path, out);
        return rc;
    }
    rc = elf64_load_buffer(buf, size, out);
    if (rc == 0) return 0;
    if (rc == -2) return pe_load_buffer(buf, size, out);
    if (rc == -3) return macho_load_buffer(buf, size, out);
    return rc;
}

/* -------------------- public API -------------------- */

int
shrike_open(const char *path, shrike_ctx_t **out)
{
    if (!path || !out) return EINVAL;
    shrike_ctx_t *ctx = calloc(1, sizeof *ctx);
    if (!ctx) return ENOMEM;
    scan_config_default(&ctx->cfg);
    if (load_dispatch(path, NULL, 0, &ctx->img) < 0) {
        ctx->errno_saved = errno;
        shrike_close(ctx);
        return errno ? errno : EIO;
    }
    *out = ctx;
    return 0;
}

int
shrike_open_mem(const uint8_t *buf, size_t size, shrike_ctx_t **out)
{
    if (!buf || size == 0 || !out) return EINVAL;
    shrike_ctx_t *ctx = calloc(1, sizeof *ctx);
    if (!ctx) return ENOMEM;
    scan_config_default(&ctx->cfg);
    if (load_dispatch(NULL, buf, size, &ctx->img) < 0) {
        ctx->errno_saved = errno;
        shrike_close(ctx);
        return errno ? errno : EIO;
    }
    *out = ctx;
    return 0;
}

void
shrike_close(shrike_ctx_t *ctx)
{
    if (!ctx) return;
    elf64_close(&ctx->img);
    free(ctx->gadgets);
    free(ctx);
}

int
shrike_set_option_int(shrike_ctx_t *ctx, shrike_option_t opt, int value)
{
    if (!ctx) return EINVAL;
    switch (opt) {
    case SHRIKE_OPT_MAX_INSN:     ctx->cfg.max_insn = value; return 0;
    case SHRIKE_OPT_MAX_BACKSCAN: ctx->cfg.max_backscan = value; return 0;
    case SHRIKE_OPT_NO_SYSCALL:   ctx->cfg.include_syscall = !value; return 0;
    case SHRIKE_OPT_NO_INT:       ctx->cfg.include_int = !value; return 0;
    case SHRIKE_OPT_NO_INDIRECT:  ctx->cfg.include_ff = !value; return 0;
    default:                      return EINVAL;
    }
}

int
shrike_set_option_str(shrike_ctx_t *ctx, shrike_option_t opt,
                      const char *value)
{
    (void)ctx;
    if (opt == SHRIKE_OPT_MACHO_ARCH) {
        macho_set_preferred_arch(value);
        return 0;
    }
    return EINVAL;
}

shrike_iter_t *
shrike_iter_begin(shrike_ctx_t *ctx)
{
    if (!ctx) return NULL;
    if (!ctx->scanned) {
        for (size_t i = 0; i < ctx->img.nseg; i++) {
            scan_segment(&ctx->img.segs[i], &ctx->cfg,
                         capture_cb, ctx);
        }
        ctx->scanned = 1;
    }
    shrike_iter_t *it = calloc(1, sizeof *it);
    if (!it) { ctx->errno_saved = ENOMEM; return NULL; }
    it->ctx = ctx;
    return it;
}

const shrike_gadget_t *
shrike_iter_next(shrike_iter_t *it)
{
    if (!it) return NULL;
    if (it->cursor >= it->ctx->ngadgets) return NULL;
    it->current = it->ctx->gadgets[it->cursor++];
    return &it->current;
}

void
shrike_iter_end(shrike_iter_t *it)
{
    free(it);
}

/* -------- gadget getters (never read struct fields directly) -------- */

uint64_t
shrike_gadget_address(const shrike_gadget_t *g)
{
    return g ? g->address : 0;
}

const uint8_t *
shrike_gadget_bytes(const shrike_gadget_t *g)
{
    return g ? g->bytes : NULL;
}

size_t
shrike_gadget_size(const shrike_gadget_t *g)
{
    return g ? g->size : 0;
}

int
shrike_gadget_instruction_count(const shrike_gadget_t *g)
{
    return g ? g->insn_count : 0;
}

const char *
shrike_gadget_disasm(const shrike_gadget_t *g)
{
    return g ? g->disasm : "";
}

shrike_category_t
shrike_gadget_category(const shrike_gadget_t *g)
{
    return g ? g->category : SHRIKE_CAT_OTHER;
}

shrike_arch_t
shrike_gadget_arch(const shrike_gadget_t *g)
{
    return g ? g->arch : SHRIKE_ARCH_X86_64;
}

int
shrike_errno(const shrike_ctx_t *ctx)
{
    return ctx ? ctx->errno_saved : EINVAL;
}

const char *
shrike_strerror(int err)
{
    return strerror(err);
}
