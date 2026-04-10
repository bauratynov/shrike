/*
 * pivots.c — stack pivot analyser + atlas.
 */

#include <shrike/pivots.h>
#include <shrike/arm64.h>
#include <shrike/elf64.h>
#include <shrike/regidx.h>
#include <shrike/format.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *x86_regs[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

/* ------------------------------------------------------------------ *
 * Per-gadget analyser
 * ------------------------------------------------------------------ */

static int analyze_x86(const gadget_t *g, pivot_info_t *out)
{
    if (g->length < 2) return 0;

    /* leave (0xC9) or leave ; ret (0xC9 0xC3) — symbolic rbp pivot */
    if (g->length == 1 && g->bytes[0] == 0xC9) {
        out->kind = PIVOT_RBP;
        out->trailing_ret = 0;
        return 1;
    }
    if (g->length >= 2 && g->bytes[0] == 0xC9 && g->bytes[1] == 0xC3) {
        out->kind = PIVOT_RBP;
        out->trailing_ret = 1;
        return 1;
    }

    /* add/sub rsp, imm8 — REX.W 48, opcode 83, modrm C4 / EC */
    if (g->length >= 4 && g->bytes[0] == 0x48 && g->bytes[1] == 0x83) {
        uint8_t mrm = g->bytes[2];
        uint8_t reg = (mrm >> 3) & 7;
        uint8_t rm  = mrm & 7;
        if (rm == 4 && (reg == 0 || reg == 5)) {  /* /0 ADD /5 SUB */
            int8_t imm = (int8_t)g->bytes[3];
            out->kind  = PIVOT_LITERAL;
            out->delta = (reg == 5) ? -(int64_t)imm : (int64_t)imm;
            out->trailing_ret =
                (g->length >= 5 && g->bytes[g->length - 1] == 0xC3);
            return 1;
        }
    }

    /* add/sub rsp, imm32 — 48 81 modrm imm32 */
    if (g->length >= 7 && g->bytes[0] == 0x48 && g->bytes[1] == 0x81) {
        uint8_t mrm = g->bytes[2];
        uint8_t reg = (mrm >> 3) & 7;
        uint8_t rm  = mrm & 7;
        if (rm == 4 && (reg == 0 || reg == 5)) {
            int32_t imm = (int32_t)(
                  (uint32_t)g->bytes[3]
                | ((uint32_t)g->bytes[4] <<  8)
                | ((uint32_t)g->bytes[5] << 16)
                | ((uint32_t)g->bytes[6] << 24));
            out->kind  = PIVOT_LITERAL;
            out->delta = (reg == 5) ? -(int64_t)imm : (int64_t)imm;
            out->trailing_ret =
                (g->length >= 8 && g->bytes[g->length - 1] == 0xC3);
            return 1;
        }
    }

    /* mov rsp, rXX — 48 89 modrm  with modrm.rm = 4 (rsp), mod = 11 */
    if (g->length >= 3 && g->bytes[0] == 0x48 && g->bytes[1] == 0x89) {
        uint8_t mrm = g->bytes[2];
        if ((mrm & 0xC7) == 0xC4) {   /* mod=11, rm=4 (rsp) */
            int src = (mrm >> 3) & 7;
            out->kind       = PIVOT_REGISTER;
            out->source_reg = src;
            out->trailing_ret =
                (g->length >= 4 && g->bytes[g->length - 1] == 0xC3);
            return 1;
        }
    }

    /* xchg rsp, rXX — 87 modrm with rm=4 or reg=4 */
    if (g->length >= 2 && g->bytes[0] == 0x87) {
        uint8_t mrm = g->bytes[1];
        uint8_t reg = (mrm >> 3) & 7;
        uint8_t rm  = mrm & 7;
        if ((mrm >> 6) == 3 && (reg == 4 || rm == 4)) {
            out->kind       = PIVOT_REGISTER;
            out->source_reg = (reg == 4) ? rm : reg;
            out->trailing_ret =
                (g->length >= 3 && g->bytes[g->length - 1] == 0xC3);
            return 1;
        }
    }

    /* pop rsp — 0x5C */
    if (g->length >= 1 && g->bytes[0] == 0x5C) {
        out->kind = PIVOT_STACK;
        out->trailing_ret =
            (g->length >= 2 && g->bytes[g->length - 1] == 0xC3);
        return 1;
    }

    return 0;
}

static int analyze_a64(const gadget_t *g, pivot_info_t *out)
{
    if (g->length < 4) return 0;
    uint32_t first = arm64_read_insn(g->bytes);

    /* ADD SP, SP, #imm (12-bit imm, no shift): 100100010 + imm12 + 11111 + 11111
     * Encoding: 1001_0001_00 imm12 Rn=11111 Rd=11111
     * Mask fixed bits: 0xFF_C0_03_FF, pattern 0x91_00_03_FF. */
    if ((first & 0xFFC003FFu) == 0x910003FFu) {
        int32_t imm = (int32_t)((first >> 10) & 0xFFF);
        out->kind = PIVOT_LITERAL;
        out->delta = imm;
        goto check_trailing;
    }
    /* SUB SP, SP, #imm: 1101_0001_00 imm12 11111 11111 */
    if ((first & 0xFFC003FFu) == 0xD10003FFu) {
        int32_t imm = (int32_t)((first >> 10) & 0xFFF);
        out->kind = PIVOT_LITERAL;
        out->delta = -imm;
        goto check_trailing;
    }
    /* MOV SP, Xn — encoded as ADD SP, Xn, #0:
     * 1001_0001_00 0 000000000000 Rn Rd=11111 with Rn != 11111
     * Mask 0xFFC003E0 pattern 0x910003E0 *and* Rn field (bits 9..5) != 11111. */
    if ((first & 0xFFC003E0u) == 0x910003E0u) {
        int rn = (int)((first >> 5) & 0x1F);
        if (rn != 31) {
            out->kind       = PIVOT_REGISTER;
            out->source_reg = rn;
            goto check_trailing;
        }
    }

    return 0;

check_trailing:
    {
        /* Trailing RET = last 4 bytes match. */
        if (g->length >= 8) {
            uint32_t last = arm64_read_insn(g->bytes + g->length - 4);
            out->trailing_ret =
                (last & 0xFFFFFC00u) == 0xD65F0000u ||
                (last & 0xFFFFFBFFu) == 0xD65F0BFFu;
        }
        return 1;
    }
}

void pivot_analyze(const gadget_t *g, pivot_info_t *out)
{
    memset(out, 0, sizeof(*out));
    out->source_reg = -1;
    out->kind       = PIVOT_NONE;

    if (!g) return;
    if (g->machine == EM_AARCH64) (void)analyze_a64(g, out);
    else                          (void)analyze_x86(g, out);
}

/* ------------------------------------------------------------------ *
 * Atlas (dynamic collection)
 * ------------------------------------------------------------------ */

typedef struct {
    uint64_t     vaddr;
    pivot_info_t info;
    size_t       length;       /* for rendering */
    uint8_t      bytes[32];    /* snapshot so rendering after scan works */
    uint16_t     machine;
    int          insn_count;
} pivot_entry_t;

struct pivot_atlas {
    pivot_entry_t *entries;
    size_t         count;
    size_t         cap;
};

pivot_atlas_t *pivot_atlas_new(void)
{
    pivot_atlas_t *a = calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->cap = 64;
    a->entries = calloc(a->cap, sizeof(*a->entries));
    if (!a->entries) { free(a); return NULL; }
    return a;
}

void pivot_atlas_free(pivot_atlas_t *a)
{
    if (!a) return;
    free(a->entries);
    free(a);
}

void pivot_atlas_observe(pivot_atlas_t *a, const gadget_t *g)
{
    if (!a || !g) return;

    pivot_info_t info;
    pivot_analyze(g, &info);
    if (info.kind == PIVOT_NONE) return;

    if (a->count >= a->cap) {
        size_t ncap = a->cap * 2;
        void *nb = realloc(a->entries, ncap * sizeof(*a->entries));
        if (!nb) return;
        a->entries = nb;
        a->cap     = ncap;
    }

    pivot_entry_t *e = &a->entries[a->count++];
    memset(e, 0, sizeof(*e));
    e->vaddr      = g->vaddr;
    e->info       = info;
    e->length     = g->length < sizeof e->bytes ? g->length : sizeof e->bytes;
    memcpy(e->bytes, g->bytes, e->length);
    e->machine    = g->machine;
    e->insn_count = g->insn_count;
}

/* ------------------------------------------------------------------ *
 * Sorting & rendering
 * ------------------------------------------------------------------ */

/* Rank: literal first (sorted by |delta|), then register, then rbp,
 * then stack. Ties broken by address. */
static int rank_key(const pivot_entry_t *e)
{
    switch (e->info.kind) {
    case PIVOT_LITERAL:  return 0;
    case PIVOT_REGISTER: return 1;
    case PIVOT_RBP:      return 2;
    case PIVOT_STACK:    return 3;
    default:             return 4;
    }
}

static int cmp_entries(const void *a, const void *b)
{
    const pivot_entry_t *ea = a, *eb = b;
    int ra = rank_key(ea), rb = rank_key(eb);
    if (ra != rb) return ra - rb;
    if (ea->info.kind == PIVOT_LITERAL) {
        int64_t ad = ea->info.delta < 0 ? -ea->info.delta : ea->info.delta;
        int64_t bd = eb->info.delta < 0 ? -eb->info.delta : eb->info.delta;
        if (ad != bd) return (ad < bd) ? -1 : 1;
    }
    if (ea->vaddr < eb->vaddr) return -1;
    if (ea->vaddr > eb->vaddr) return  1;
    return 0;
}

static const char *reg_name(uint16_t machine, int r)
{
    if (machine == EM_AARCH64) {
        static const char *a64[32] = {
            "x0","x1","x2","x3","x4","x5","x6","x7",
            "x8","x9","x10","x11","x12","x13","x14","x15",
            "x16","x17","x18","x19","x20","x21","x22","x23",
            "x24","x25","x26","x27","x28","x29","x30","sp"
        };
        return (r >= 0 && r < 32) ? a64[r] : "?";
    }
    return (r >= 0 && r < 16) ? x86_regs[r] : "?";
}

static const char *kind_name(pivot_kind_t k)
{
    switch (k) {
    case PIVOT_LITERAL:  return "literal";
    case PIVOT_REGISTER: return "register";
    case PIVOT_RBP:      return "rbp";
    case PIVOT_STACK:    return "stack";
    default:             return "none";
    }
}

static void render_mnemo(const pivot_entry_t *e, char *buf, size_t buflen)
{
    gadget_t g;
    memset(&g, 0, sizeof g);
    g.bytes      = e->bytes;
    g.length     = e->length;
    g.insn_count = e->insn_count;
    g.machine    = e->machine;
    g.vaddr      = e->vaddr;
    (void)format_gadget_render(&g, buf, buflen);
    /* Strip the "0x...: " prefix — just show the mnemonic part. */
    char *colon = strstr(buf, ": ");
    if (colon) memmove(buf, colon + 2, strlen(colon + 2) + 1);
}

void pivot_atlas_print(const pivot_atlas_t *a, uint16_t machine, FILE *f)
{
    if (!a || a->count == 0) {
        fprintf(f, "# no stack pivots found\n");
        return;
    }

    pivot_entry_t *copy = calloc(a->count, sizeof(*copy));
    if (!copy) return;
    memcpy(copy, a->entries, a->count * sizeof(*copy));
    qsort(copy, a->count, sizeof(*copy), cmp_entries);

    fprintf(f, "# stack pivot atlas — %zu entries, sorted literal→symbolic\n",
            a->count);
    fprintf(f, "# addr               mnemonic                              kind     delta/source\n");
    for (size_t i = 0; i < a->count; i++) {
        const pivot_entry_t *e = &copy[i];
        char mn[128] = {0};
        render_mnemo(e, mn, sizeof mn);

        char detail[64] = {0};
        switch (e->info.kind) {
        case PIVOT_LITERAL:
            snprintf(detail, sizeof detail, "%+" PRId64 " bytes", e->info.delta);
            break;
        case PIVOT_REGISTER:
            snprintf(detail, sizeof detail, "src=%s",
                     reg_name(machine, e->info.source_reg));
            break;
        case PIVOT_RBP:   strcpy(detail, "rsp = rbp"); break;
        case PIVOT_STACK: strcpy(detail, "delta from stack"); break;
        default:          strcpy(detail, "?");
        }
        fprintf(f, "0x%016" PRIx64 "  %-40s %-8s %s\n",
                e->vaddr, mn, kind_name(e->info.kind), detail);
    }
    free(copy);
}

void pivot_atlas_print_json(const pivot_atlas_t *a, uint16_t machine, FILE *f)
{
    if (!a) { fputs("[]\n", f); return; }

    pivot_entry_t *copy = calloc(a->count, sizeof(*copy));
    if (!copy) { fputs("[]\n", f); return; }
    memcpy(copy, a->entries, a->count * sizeof(*copy));
    qsort(copy, a->count, sizeof(*copy), cmp_entries);

    fputs("[", f);
    for (size_t i = 0; i < a->count; i++) {
        const pivot_entry_t *e = &copy[i];
        char mn[128] = {0};
        render_mnemo(e, mn, sizeof mn);

        if (i) fputs(",", f);
        fprintf(f, "\n  {\"addr\":\"0x%016" PRIx64 "\",\"mnemonic\":\"%s\","
                   "\"kind\":\"%s\"",
                e->vaddr, mn, kind_name(e->info.kind));
        if (e->info.kind == PIVOT_LITERAL) {
            fprintf(f, ",\"delta\":%" PRId64, e->info.delta);
        }
        if (e->info.kind == PIVOT_REGISTER) {
            fprintf(f, ",\"source\":\"%s\"",
                    reg_name(machine, e->info.source_reg));
        }
        if (e->info.kind == PIVOT_RBP || e->info.kind == PIVOT_STACK) {
            fputs(",\"symbolic\":true", f);
        }
        fprintf(f, ",\"trailing_ret\":%s}",
                e->info.trailing_ret ? "true" : "false");
    }
    fputs("\n]\n", f);
    free(copy);
}
