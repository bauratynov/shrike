/*
 * category.c — gadget classification.
 *
 * Deliberately coarse: missing a classification returns CAT_OTHER
 * rather than a guess. Downstream filters know what to do with OTHER.
 */

#include <shrike/category.h>
#include <shrike/arm64.h>
#include <shrike/elf64.h>

#include <stdint.h>
#include <string.h>

static const char *names[CAT_MAX] = {
    "other", "ret_only", "pop", "mov", "arith",
    "stack_pivot", "syscall", "indirect"
};

const char *gadget_category_name(gadget_category_t c)
{
    return (c >= 0 && c < CAT_MAX) ? names[c] : "other";
}

int gadget_category_parse_mask(const char *csv, uint32_t *out_mask)
{
    uint32_t mask = 0;
    const char *p = csv;
    while (*p) {
        const char *q = p;
        while (*q && *q != ',') q++;
        size_t len = (size_t)(q - p);
        int matched = 0;
        for (int i = 0; i < CAT_MAX; i++) {
            if (strlen(names[i]) == len && strncmp(names[i], p, len) == 0) {
                mask |= (1u << i);
                matched = 1;
                break;
            }
        }
        if (!matched) return -1;
        p = *q ? q + 1 : q;
    }
    *out_mask = mask;
    return 0;
}

/* ---------- x86-64 ---------- */

static gadget_category_t cat_x86(const gadget_t *g)
{
    if (g->length < 1) return CAT_OTHER;

    /* Terminator inspection */
    uint8_t last = g->bytes[g->length - 1];

    /* SYSCALL (0F 05) / SYSRET (0F 07) */
    if (g->length >= 2 && g->bytes[g->length - 2] == 0x0F &&
        (last == 0x05 || last == 0x07)) {
        return CAT_SYSCALL;
    }
    /* INT imm8 (CD XX) or INT3 */
    if (last == 0xCC) return CAT_SYSCALL;
    if (g->length >= 2 && g->bytes[g->length - 2] == 0xCD) return CAT_SYSCALL;
    /* Indirect FF /2..5 */
    if (g->length >= 2 && g->bytes[g->length - 2] == 0xFF) {
        uint8_t mrm = last;
        uint8_t reg = (mrm >> 3) & 7;
        if (reg >= 2 && reg <= 5) return CAT_INDIRECT;
    }

    /* If we get here and terminator is not RET family, fall through */
    int ret_family =
        (last == 0xC3 || last == 0xCB) ||
        (g->length >= 3 && (g->bytes[g->length - 3] == 0xC2 ||
                            g->bytes[g->length - 3] == 0xCA));
    if (!ret_family) return CAT_OTHER;

    if (g->insn_count == 1) return CAT_RET_ONLY;

    /* First-instruction patterns */
    uint8_t b0 = g->bytes[0];

    /* Plain POP reg (r0-r7): 0x58..0x5F */
    if (b0 >= 0x58 && b0 <= 0x5F) return CAT_POP;
    /* POP r8-r15: REX.B = 0x41 + 0x58..0x5F */
    if (g->length >= 2 && b0 == 0x41 &&
        g->bytes[1] >= 0x58 && g->bytes[1] <= 0x5F) return CAT_POP;

    /* Stack pivot forms */
    /* add rsp, imm8 : 48 83 C4 XX */
    if (g->length >= 4 && b0 == 0x48 && g->bytes[1] == 0x83 &&
        g->bytes[2] == 0xC4) return CAT_STACK_PIVOT;
    /* mov rsp, rXX: 48 89 XX with modrm rm=4 and mod=11 */
    if (g->length >= 3 && b0 == 0x48 && g->bytes[1] == 0x89 &&
        (g->bytes[2] & 0xC7) == 0xC4) return CAT_STACK_PIVOT;
    /* xchg rsp, rXX (86/87 with modrm, rm=4 or reg=4) — rare, skip */

    /* 48 prefix + reg/reg opcode, mod=11 */
    if (g->length >= 3 && b0 == 0x48) {
        uint8_t op  = g->bytes[1];
        uint8_t mrm = g->bytes[2];
        if ((mrm >> 6) == 3) {
            if (op == 0x89 || op == 0x8B) return CAT_MOV;
            if (op == 0x31 || op == 0x33) return CAT_ARITH;
            if (op == 0x01 || op == 0x03) return CAT_ARITH;
            if (op == 0x29 || op == 0x2B) return CAT_ARITH;
        }
    }
    /* No REX */
    if (g->length >= 2) {
        uint8_t op  = b0;
        uint8_t mrm = g->bytes[1];
        if ((mrm >> 6) == 3) {
            if (op == 0x89 || op == 0x8B) return CAT_MOV;
            if (op == 0x31 || op == 0x33) return CAT_ARITH;
            if (op == 0x01 || op == 0x03) return CAT_ARITH;
            if (op == 0x29 || op == 0x2B) return CAT_ARITH;
        }
    }

    return CAT_OTHER;
}

/* ---------- aarch64 ---------- */

static gadget_category_t cat_arm64(const gadget_t *g)
{
    if (g->length < 4) return CAT_OTHER;
    uint32_t last = arm64_read_insn(g->bytes + g->length - 4);

    /* SVC */
    if ((last & 0xFFE0001Fu) == 0xD4000001u) return CAT_SYSCALL;
    /* BR / BLR */
    if ((last & 0xFFFFFC1Fu) == 0xD61F0000u) return CAT_INDIRECT;
    if ((last & 0xFFFFFC1Fu) == 0xD63F0000u) return CAT_INDIRECT;

    /* RET family */
    int ret =
        (last & 0xFFFFFC00u) == 0xD65F0000u ||
        (last & 0xFFFFFBFFu) == 0xD65F0BFFu;
    if (!ret) return CAT_OTHER;

    if (g->insn_count == 1) return CAT_RET_ONLY;

    uint32_t first = arm64_read_insn(g->bytes);

    /* MOV Xd, Xm = ORR Xd, XZR, Xm */
    if ((first & 0xFFE0FFE0u) == 0xAA0003E0u) return CAT_MOV;

    /* LDP post-index or pre-index with Rn = SP (reg 31) — POP idiom */
    if ((first & 0xFFC003E0u) == 0xA8C003E0u) return CAT_POP;  /* post-idx */
    if ((first & 0xFFC003E0u) == 0xA9C003E0u) return CAT_POP;  /* pre-idx  */

    /* ADD SP, SP, imm — stack pivot */
    if ((first & 0xFF0003FFu) == 0x910003FFu) return CAT_STACK_PIVOT;

    return CAT_OTHER;
}

gadget_category_t gadget_categorize(const gadget_t *g)
{
    if (!g || g->length == 0) return CAT_OTHER;
    if (g->machine == EM_AARCH64) return cat_arm64(g);
    return cat_x86(g);
}
