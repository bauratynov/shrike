/*
 * regidx.c — register-control index.
 *
 * Indexes "pop reg ; ret" shaped gadgets, crediting every register
 * in multi-pop chains. On AArch64, the dominant form is LDP Xt1,
 * Xt2, [SP], #N — it writes TWO registers per instruction so we
 * credit both. Single LDR [SP], #N and MOV reg-reg variants are
 * planned for v0.11+.
 */

#include <shrike/regidx.h>
#include <shrike/arm64.h>
#include <shrike/riscv.h>
#include <shrike/effect.h>
#include <shrike/cet.h>
#include <shrike/elf64.h>

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

/* RISC-V RV64 ABI register names. Indexed by raw register number
 * 0..31 — so x10 and a0 both map to slot 10, etc. We accept both
 * spellings in regidx_reg_lookup(). Only one canonical name is
 * reported back from regidx_reg_name(), and the ABI spelling
 * wins because recipes reading like `a0=*; a7=59; ecall` are
 * what users actually type. */
static const char *rv_regs[32] = {
    "zero","ra","sp","gp","tp","t0","t1","t2",
    "s0","s1","a0","a1","a2","a3","a4","a5",
    "a6","a7","s2","s3","s4","s5","s6","s7",
    "s8","s9","s10","s11","t3","t4","t5","t6"
};

/* Alternate raw spellings accepted by the lookup. Same index space
 * as rv_regs[]; a NULL entry means "no alternate name." */
static const char *rv_regs_alt[32] = {
    "x0","x1","x2","x3","x4","x5","x6","x7",
    "x8","x9","x10","x11","x12","x13","x14","x15",
    "x16","x17","x18","x19","x20","x21","x22","x23",
    "x24","x25","x26","x27","x28","x29","x30","x31"
};

const char *regidx_reg_name(uint16_t machine, int r)
{
    if (r < 0) return NULL;
    if (machine == EM_AARCH64) {
        if (r >= 32) return NULL;
        return a64_regs[r];
    }
    if (machine == EM_RISCV) {
        if (r >= 32) return NULL;
        return rv_regs[r];
    }
    if (r >= 16) return NULL;
    return x86_regs[r];
}

int regidx_reg_lookup(uint16_t machine, const char *name)
{
    if (machine == EM_RISCV) {
        for (int i = 0; i < 32; i++) {
            if (strcmp(rv_regs[i], name) == 0) return i;
            if (rv_regs_alt[i] && strcmp(rv_regs_alt[i], name) == 0) return i;
        }
        return -1;
    }
    int n = (machine == EM_AARCH64) ? 32 : 16;
    for (int i = 0; i < n; i++) {
        const char *nm = regidx_reg_name(machine, i);
        if (nm && strcmp(nm, name) == 0) return i;
    }
    return -1;
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

/* v1.5.1: credit a (reg, addr, stack_consumed) tuple. Stack info
 * lets the chain emitter pad payloads correctly for multi-pop
 * gadgets without a second parse pass.
 * v5.3.0: also record endbr_start so CET-aware chain selection
 * can prefer IBT-landing-pad gadgets when the target has CET on. */
static void
regidx_credit(regidx_t *ri, int r, uint64_t addr, uint32_t stack,
              int endbr)
{
    if (r < 0 || r >= REGIDX_MAX_REGS) return;
    if (ri->counts[r] >= REGIDX_MAX_PER) return;
    for (uint16_t i = 0; i < ri->counts[r]; i++) {
        if (ri->addrs[r][i] == addr) return;
    }
    uint16_t idx = ri->counts[r]++;
    ri->addrs[r][idx]          = addr;
    ri->stack_consumed[r][idx] = stack;
    ri->endbr_start[r][idx]    = endbr ? 1 : 0;
}

/* v1.5.2: record a multi-pop gadget (writes_mask popcount >= 2).
 * Duplicates (same mask + addr) are ignored.
 * v1.5.4: also carry the ordered pop list.
 * v5.3.0: endbr_start bit for CET-aware selection. */
static void
regidx_credit_multi(regidx_t *ri, uint32_t mask, uint64_t addr,
                    uint32_t stack, const int *order, int order_count,
                    int endbr)
{
    if (ri->multi_count >= REGIDX_MAX_MULTI) return;
    for (uint16_t i = 0; i < ri->multi_count; i++) {
        if (ri->multi[i].addr == addr && ri->multi[i].writes_mask == mask)
            return;
    }
    regidx_multi_t *m = &ri->multi[ri->multi_count++];
    m->writes_mask    = mask;
    m->stack_consumed = stack;
    m->addr           = addr;
    int n = order_count > REGIDX_MAX_POP_ORDER
          ? REGIDX_MAX_POP_ORDER : order_count;
    for (int i = 0; i < n; i++) m->pop_order[i] = (uint8_t)order[i];
    m->pop_count    = (uint8_t)n;
    m->endbr_start  = (uint8_t)(endbr ? 1 : 0);
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

    gadget_effect_t ef;
    gadget_effect_compute(g, &ef);
    int endbr = cet_starts_endbr(g);

    for (int i = 0; i < n_regs; i++) {
        regidx_credit(ri, regs[i], g->vaddr, ef.stack_consumed, endbr);
    }
    if (n_regs >= 2) {
        uint32_t mask = 0;
        for (int i = 0; i < n_regs; i++) mask |= 1u << regs[i];
        regidx_credit_multi(ri, mask, g->vaddr, ef.stack_consumed,
                            regs, n_regs, endbr);
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

    gadget_effect_t ef;
    gadget_effect_compute(g, &ef);
    int endbr = cet_starts_endbr(g);

    for (int i = 0; i < n_regs; i++) {
        regidx_credit(ri, regs[i], g->vaddr, ef.stack_consumed, endbr);
    }
    if (n_regs >= 2) {
        uint32_t mask = 0;
        for (int i = 0; i < n_regs; i++) mask |= 1u << regs[i];
        regidx_credit_multi(ri, mask, g->vaddr, ef.stack_consumed,
                            regs, n_regs, endbr);
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
    if (g->machine == EM_RISCV) {
        /* Standalone 4-byte ecall (0x00000073). */
        return g->length == 4 &&
               g->bytes[0] == 0x73 && g->bytes[1] == 0x00 &&
               g->bytes[2] == 0x00 && g->bytes[3] == 0x00;
    }
    return g->length == 2 && g->bytes[0] == 0x0F && g->bytes[1] == 0x05;
}

/* RISC-V prologue-sized `ld reg, imm(sp) ; ... ; ret` gadgets are
 * the epilogue shape generated by GCC/Clang on RV64. We walk
 * left-to-right and credit every `ld reg, imm(sp)` (and its
 * compressed c.ldsp counterpart) until we hit the terminator. */
static void observe_rv(regidx_t *ri, const gadget_t *g)
{
    size_t p = 0;
    int    regs[32];
    int    n_regs = 0;
    int    ends_in_ret = 0;

    while (p + 2 <= g->length) {
        size_t il = riscv_insn_len(g->bytes + p, g->length - p);
        if (il == 0) return;
        if (il == 4) {
            uint32_t w = (uint32_t)g->bytes[p] |
                         ((uint32_t)g->bytes[p + 1] << 8) |
                         ((uint32_t)g->bytes[p + 2] << 16) |
                         ((uint32_t)g->bytes[p + 3] << 24);
            uint32_t opcode = w & 0x7f;
            uint32_t funct3 = (w >> 12) & 0x7;
            uint32_t rs1    = (w >> 15) & 0x1f;
            uint32_t rd     = (w >> 7)  & 0x1f;

            if (opcode == 0x03 && funct3 == 0x3 && rs1 == 2) {
                /* ld rd, imm(sp) — canonical callee-save restore. */
                if (n_regs < 32 && rd != 0) regs[n_regs++] = (int)rd;
                p += il; continue;
            }
            /* addi sp, sp, imm — stack pointer adjust, also part
             * of the epilogue. Don't credit anything. */
            if (opcode == 0x13 && funct3 == 0 && rd == 2 && rs1 == 2) {
                p += il; continue;
            }
            if (riscv_is_ret(g->bytes + p, il)) {
                ends_in_ret = 1; break;
            }
            return;
        } else {
            uint16_t h = (uint16_t)(g->bytes[p] | (g->bytes[p + 1] << 8));
            /* c.ldsp rd, imm(sp): funct3 011, op 10, rd != 0 */
            if ((h & 0xe003) == 0x6002) {
                uint32_t rd = (h >> 7) & 0x1f;
                if (rd != 0 && n_regs < 32) regs[n_regs++] = (int)rd;
                p += 2; continue;
            }
            if (riscv_is_ret(g->bytes + p, 2)) {
                ends_in_ret = 1; break;
            }
            return;
        }
    }

    if (!ends_in_ret) return;

    gadget_effect_t ef;
    gadget_effect_compute(g, &ef);
    int endbr = cet_starts_endbr(g);

    for (int i = 0; i < n_regs; i++) {
        regidx_credit(ri, regs[i], g->vaddr, ef.stack_consumed, endbr);
    }
    if (n_regs >= 2) {
        uint32_t mask = 0;
        for (int i = 0; i < n_regs; i++) mask |= 1u << regs[i];
        regidx_credit_multi(ri, mask, g->vaddr, ef.stack_consumed,
                            regs, n_regs, endbr);
    }
}

/* popcount over a 32-bit writes_mask. Tiny and portable — no
 * need to reach for __builtin_popcount on a hot path we hit
 * once per observed gadget. */
static int
popcount32(uint32_t x)
{
    int n = 0;
    while (x) { x &= x - 1; n++; }
    return n;
}

void regidx_observe(regidx_t *ri, const gadget_t *g)
{
    if (!ri || !g || g->length == 0) return;

    if (is_syscall_only(g)) {
        /* Same dedup logic as add_addr but we also want to
         * remember whether this specific syscall gadget starts
         * at an ENDBR landing pad — CET-aware resolver needs
         * it the same way it needs the per-reg flag. */
        if (ri->syscall_count < REGIDX_MAX_PER) {
            int dup = 0;
            for (uint16_t i = 0; i < ri->syscall_count; i++) {
                if (ri->syscall_addrs[i] == g->vaddr) { dup = 1; break; }
            }
            if (!dup) {
                uint16_t idx = ri->syscall_count++;
                ri->syscall_addrs[idx]       = g->vaddr;
                ri->syscall_endbr_start[idx] = (uint8_t)cet_starts_endbr(g);
            }
        }
        return;
    }

    if (g->machine == EM_AARCH64)      observe_a64(ri, g);
    else if (g->machine == EM_RISCV)   observe_rv(ri, g);
    else                               observe_x86(ri, g);
}

const regidx_multi_t *
regidx_find_multi_exact(const regidx_t *ri, uint32_t needed)
{
    for (uint16_t i = 0; i < ri->multi_count; i++) {
        if (ri->multi[i].writes_mask == needed) return &ri->multi[i];
    }
    return NULL;
}

int
regidx_pick_index(const regidx_t *ri, int reg, int cet_aware)
{
    if (!ri || reg < 0 || reg >= REGIDX_MAX_REGS) return -1;
    if (ri->counts[reg] == 0) return -1;
    if (cet_aware) {
        for (uint16_t i = 0; i < ri->counts[reg]; i++) {
            if (ri->endbr_start[reg][i]) return (int)i;
        }
        /* No endbr-start gadget exists for this register. Fall
         * through to the first-observed as a last-ditch pick —
         * the resolver emits a chain-survives-cet warning at
         * report time when this happens. */
    }
    return 0;
}

int
regidx_pick_syscall_index(const regidx_t *ri, int cet_aware)
{
    if (!ri || ri->syscall_count == 0) return -1;
    if (cet_aware) {
        for (uint16_t i = 0; i < ri->syscall_count; i++) {
            if (ri->syscall_endbr_start[i]) return (int)i;
        }
    }
    return 0;
}

const regidx_multi_t *
regidx_find_multi(const regidx_t *ri, uint32_t needed,
                  uint32_t committed, int strict_cover)
{
    /* Prefer smaller writes_mask popcount — fewer padding slots,
     * tighter chain. Stable order so outputs are reproducible.
     * When CET IBT is required for the containing image, also
     * prefer endbr-start gadgets at the same popcount tier —
     * they survive IBT while the others die. */
    const regidx_multi_t *best = NULL;
    int best_pop = 0;
    int best_endbr = 0;
    int cet_aware = ri->cet_ibt_required;

    for (uint16_t i = 0; i < ri->multi_count; i++) {
        const regidx_multi_t *m = &ri->multi[i];
        if ((m->writes_mask & needed) != needed) continue;
        if ((m->writes_mask & committed) != 0) continue;
        if (strict_cover && m->writes_mask != needed) continue;
        int pop = popcount32(m->writes_mask);
        int endbr = m->endbr_start ? 1 : 0;
        if (!best) {
            best = m; best_pop = pop; best_endbr = endbr; continue;
        }
        /* Tiebreak order: smallest popcount wins; at equal
         * popcount, cet_aware + endbr=1 wins over endbr=0. */
        if (pop < best_pop) {
            best = m; best_pop = pop; best_endbr = endbr;
        } else if (pop == best_pop && cet_aware && endbr && !best_endbr) {
            best = m; best_endbr = 1;
        }
    }
    return best;
}

static int regidx_nregs(uint16_t machine)
{
    if (machine == EM_AARCH64) return 32;
    if (machine == EM_RISCV)   return 32;
    return 16;
}

static const char *regidx_arch_name(uint16_t machine)
{
    if (machine == EM_AARCH64) return "aarch64";
    if (machine == EM_RISCV)   return "riscv64";
    return "x86_64";
}

void regidx_print(const regidx_t *ri, FILE *f)
{
    int nregs = regidx_nregs(ri->machine);

    fprintf(f, "register-control index (%s)\n",
            regidx_arch_name(ri->machine));
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
                                         (unsigned)(ri->counts[r] - cap));
        fputc('\n', f);
    }

    if (ri->syscall_count > 0) {
        fprintf(f, "  %-4s (%2u):", "syscall", (unsigned)ri->syscall_count);
        uint16_t cap = ri->syscall_count < 4 ? ri->syscall_count : 4;
        for (uint16_t i = 0; i < cap; i++) {
            fprintf(f, " 0x%" PRIx64, ri->syscall_addrs[i]);
        }
        if (ri->syscall_count > cap)
            fprintf(f, " ... (+%u)",
                    (unsigned)(ri->syscall_count - cap));
        fputc('\n', f);
    }
}

void regidx_print_json(const regidx_t *ri, FILE *f)
{
    int nregs = regidx_nregs(ri->machine);
    int first = 1;

    fprintf(f, "{\"arch\":\"%s\",\"registers\":{",
            regidx_arch_name(ri->machine));
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
    int nregs = regidx_nregs(ri->machine);

    fprintf(f, "# shrike register-control index, pwntools-compatible\n");
    fprintf(f, "shrike_reg_index = {\n");
    fprintf(f, "    'arch': '%s',\n", regidx_arch_name(ri->machine));
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
