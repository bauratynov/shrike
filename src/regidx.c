/*
 * regidx.c — register-control index.
 *
 * Indexes "pop reg ; ret" shaped gadgets, crediting every register
 * in multi-pop chains. On AArch64, the dominant form is LDP Xt1,
 * Xt2, [SP], #N — it writes TWO registers per instruction so we
 * credit both. Single LDR [SP], #N and MOV reg-reg variants are
 * planned for v0.11+.
 */

#include "regidx.h"
#include "arm64.h"
#include "elf64.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char *x86_regs[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

static const char *a64_regs[32] = {
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28","x29","x30","sp"
};

const char *regidx_reg_name(uint16_t machine, int r)
{
    if (r < 0) return NULL;
    if (machine == EM_AARCH64) {
        if (r >= 32) return NULL;
        return a64_regs[r];
    }
    if (r >= 16) return NULL;
    return x86_regs[r];
}

void regidx_init(regidx_t *ri, uint16_t machine)
{
    memset(ri, 0, sizeof(*ri));
    ri->machine = machine;
}

static void add_addr(uint64_t *slots, uint16_t *count, uint64_t addr)
{
    if (*count >= REGIDX_MAX_PER) return;
    for (uint16_t i = 0; i < *count; i++) {
        if (slots[i] == addr) return;
    }
    slots[(*count)++] = addr;
}

static int is_x86_ret(uint8_t b) { return b == 0xC3; }

static void observe_x86(regidx_t *ri, const gadget_t *g)
{
    /* Walk instructions left-to-right: every POP reg credits its
     * target. Require the sequence to end with RET and to be made
     * up only of POPs + the terminating RET — otherwise we risk
     * misattribution (e.g. a pop inside a MOV-shaped gadget's
     * later effects). */
    size_t p = 0;
    int    regs[16];
    int    n_regs = 0;

    while (p < g->length) {
        uint8_t b = g->bytes[p];
        if (b >= 0x58 && b <= 0x5F) {
            if (n_regs < 16) regs[n_regs++] = b - 0x58;
            p += 1;
        } else if (b == 0x41 && p + 1 < g->length &&
                   g->bytes[p + 1] >= 0x58 && g->bytes[p + 1] <= 0x5F) {
            if (n_regs < 16) regs[n_regs++] = 8 + (g->bytes[p + 1] - 0x58);
            p += 2;
        } else {
            break;
        }
    }

    /* The remainder must be exactly a RET. */
    if (p >= g->length) return;
    if (p + 1 != g->length) return;
    if (!is_x86_ret(g->bytes[p])) return;

    /* Credit every popped register. */
    for (int i = 0; i < n_regs; i++) {
        int r = regs[i];
        if (r < 0 || r >= REGIDX_MAX_REGS) continue;
        add_addr(ri->addrs[r], &ri->counts[r], g->vaddr);
    }
}

static void observe_a64(regidx_t *ri, const gadget_t *g)
{
    /* Walk 4-byte instructions. Recognise:
     *   LDP Xt1, Xt2, [SP], #imm  (post-idx): 0xA8C003E0 / 0xFFC003E0
     *   LDP Xt1, Xt2, [SP], #imm  (pre-idx):  0xA9C003E0 / 0xFFC003E0
     *   LDR Xt,  [SP],  #imm      (post-idx): 0xF84003E0 / 0xFFE00FE0
     * and require the tail to be RET. */
    if (g->length < 4) return;

    size_t p = 0;
    int    any = 0;
    int    regs[32];
    int    n_regs = 0;

    while (p + 4 <= g->length) {
        uint32_t insn = arm64_read_insn(g->bytes + p);

        /* LDP post-idx / pre-idx with Rn=SP */
        int is_ldp = (insn & 0xFFC003E0u) == 0xA8C003E0u ||
                     (insn & 0xFFC003E0u) == 0xA9C003E0u;
        /* LDR (immediate, post-idx, 64-bit) with Rn=SP:
         *   1111 1000 010 imm9 01 Rn Rt   and Rn=31 -> (insn&0xFFE00FE0)=0xF84003E0 */
        int is_ldr_post = (insn & 0xFFE00FE0u) == 0xF84003E0u;

        if (is_ldp) {
            if (n_regs + 2 <= 32) {
                regs[n_regs++] = (int)(insn & 0x1Fu);        /* Rt1 */
                regs[n_regs++] = (int)((insn >> 10) & 0x1Fu); /* Rt2 */
            }
            any = 1;
            p += 4;
            continue;
        }
        if (is_ldr_post) {
            if (n_regs < 32) regs[n_regs++] = (int)(insn & 0x1Fu);
            any = 1;
            p += 4;
            continue;
        }
        break;
    }

    /* The remainder must be exactly one RET instruction. */
    if (!any) return;
    if (p + 4 != g->length) return;
    uint32_t last = arm64_read_insn(g->bytes + p);
    int is_ret =
        (last & 0xFFFFFC00u) == 0xD65F0000u ||
        (last & 0xFFFFFBFFu) == 0xD65F0BFFu;
    if (!is_ret) return;

    for (int i = 0; i < n_regs; i++) {
        int r = regs[i];
        if (r < 0 || r >= REGIDX_MAX_REGS) continue;
        add_addr(ri->addrs[r], &ri->counts[r], g->vaddr);
    }
}

static int is_syscall_only(const gadget_t *g)
{
    if (g->machine == EM_AARCH64) {
        if (g->length < 4) return 0;
        uint32_t insn = arm64_read_insn(g->bytes);
        /* Standalone SVC #0 (or any imm) */
        return g->length == 4 &&
               (insn & 0xFFE0001Fu) == 0xD4000001u;
    }
    return g->length == 2 && g->bytes[0] == 0x0F && g->bytes[1] == 0x05;
}

void regidx_observe(regidx_t *ri, const gadget_t *g)
{
    if (!ri || !g || g->length == 0) return;

    if (is_syscall_only(g)) {
        add_addr(ri->syscall_addrs, &ri->syscall_count, g->vaddr);
        return;
    }

    if (g->machine == EM_AARCH64) observe_a64(ri, g);
    else                          observe_x86(ri, g);
}

void regidx_print(const regidx_t *ri, FILE *f)
{
    int nregs = (ri->machine == EM_AARCH64) ? 32 : 16;

    fprintf(f, "register-control index (%s)\n",
            ri->machine == EM_AARCH64 ? "aarch64" : "x86_64");
    for (int r = 0; r < nregs; r++) {
        if (ri->counts[r] == 0) continue;
        fprintf(f, "  %-4s (%2u):",
                regidx_reg_name(ri->machine, r),
                (unsigned)ri->counts[r]);
        uint16_t cap = ri->counts[r] < 4 ? ri->counts[r] : 4;
        for (uint16_t i = 0; i < cap; i++) {
            fprintf(f, " 0x%" PRIx64, ri->addrs[r][i]);
        }
        if (ri->counts[r] > cap) fprintf(f, " ... (+%u)",
                                         ri->counts[r] - cap);
        fputc('\n', f);
    }

    if (ri->syscall_count > 0) {
        fprintf(f, "  %-4s (%2u):", "syscall", (unsigned)ri->syscall_count);
        uint16_t cap = ri->syscall_count < 4 ? ri->syscall_count : 4;
        for (uint16_t i = 0; i < cap; i++) {
            fprintf(f, " 0x%" PRIx64, ri->syscall_addrs[i]);
        }
        if (ri->syscall_count > cap)
            fprintf(f, " ... (+%u)", ri->syscall_count - cap);
        fputc('\n', f);
    }
}

void regidx_print_json(const regidx_t *ri, FILE *f)
{
    int nregs = (ri->machine == EM_AARCH64) ? 32 : 16;
    int first = 1;

    fprintf(f, "{\"arch\":\"%s\",\"registers\":{",
            ri->machine == EM_AARCH64 ? "aarch64" : "x86_64");
    for (int r = 0; r < nregs; r++) {
        if (ri->counts[r] == 0) continue;
        fprintf(f, "%s\"%s\":[", first ? "" : ",",
                regidx_reg_name(ri->machine, r));
        for (uint16_t i = 0; i < ri->counts[r]; i++) {
            fprintf(f, "%s\"0x%" PRIx64 "\"",
                    i ? "," : "", ri->addrs[r][i]);
        }
        fputc(']', f);
        first = 0;
    }
    fprintf(f, "},\"syscall\":[");
    for (uint16_t i = 0; i < ri->syscall_count; i++) {
        fprintf(f, "%s\"0x%" PRIx64 "\"",
                i ? "," : "", ri->syscall_addrs[i]);
    }
    fprintf(f, "]}\n");
}

void regidx_print_python(const regidx_t *ri, FILE *f)
{
    int nregs = (ri->machine == EM_AARCH64) ? 32 : 16;

    fprintf(f, "# shrike register-control index, pwntools-compatible\n");
    fprintf(f, "shrike_reg_index = {\n");
    fprintf(f, "    'arch': '%s',\n",
            ri->machine == EM_AARCH64 ? "aarch64" : "x86_64");
    fprintf(f, "    'registers': {\n");
    for (int r = 0; r < nregs; r++) {
        if (ri->counts[r] == 0) continue;
        fprintf(f, "        '%s': [", regidx_reg_name(ri->machine, r));
        for (uint16_t i = 0; i < ri->counts[r]; i++) {
            fprintf(f, "%s0x%" PRIx64,
                    i ? ", " : "", ri->addrs[r][i]);
        }
        fputs("],\n", f);
    }
    fprintf(f, "    },\n");
    fprintf(f, "    'syscall': [");
    for (uint16_t i = 0; i < ri->syscall_count; i++) {
        fprintf(f, "%s0x%" PRIx64,
                i ? ", " : "", ri->syscall_addrs[i]);
    }
    fprintf(f, "],\n");
    fprintf(f, "}\n");
}
