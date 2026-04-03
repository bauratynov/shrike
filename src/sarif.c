/*
 * sarif.c — SARIF 2.1.0 emitter. Streams one result per gadget.
 *
 * Minimalist: hand-written JSON with just the fields GitHub Code
 * Scanning inspects. Keeps the binary dependency-free.
 */

#include "sarif.h"
#include "format.h"
#include "elf64.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sarif_emitter {
    FILE   *out;
    size_t  cap;
    size_t  emitted;
    size_t  dropped;
    int     first_result;   /* 1 if next emit is the first in the array */
    int     began;
    int     ended;
};

sarif_emitter_t *sarif_new(FILE *out, size_t cap)
{
    sarif_emitter_t *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    e->out = out;
    e->cap = cap;
    e->first_result = 1;
    return e;
}

void sarif_free(sarif_emitter_t *e)
{
    if (!e) return;
    if (e->began && !e->ended) sarif_end(e);
    free(e);
}

size_t sarif_dropped(const sarif_emitter_t *e) { return e ? e->dropped : 0; }

static void json_escape_str(FILE *f, const char *s)
{
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n",  f); break;
        case '\r': fputs("\\r",  f); break;
        case '\t': fputs("\\t",  f); break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else          fputc(c, f);
        }
    }
}

/* Return the shrike.io ruleId for a category. */
static const char *rule_id_for(gadget_category_t c)
{
    switch (c) {
    case CAT_RET_ONLY:    return "SHRIKE.RET_ONLY";
    case CAT_POP:         return "SHRIKE.POP";
    case CAT_MOV:         return "SHRIKE.MOV";
    case CAT_ARITH:       return "SHRIKE.ARITH";
    case CAT_STACK_PIVOT: return "SHRIKE.STACK_PIVOT";
    case CAT_SYSCALL:     return "SHRIKE.SYSCALL";
    case CAT_INDIRECT:    return "SHRIKE.INDIRECT";
    default:              return "SHRIKE.OTHER";
    }
}

static const char *rule_description(gadget_category_t c)
{
    switch (c) {
    case CAT_RET_ONLY:    return "Single RET — minimal gadget terminator.";
    case CAT_POP:         return "POP reg ; RET — register-control primitive.";
    case CAT_MOV:         return "MOV reg, reg ; RET — register transfer primitive.";
    case CAT_ARITH:       return "Arithmetic reg, reg ; RET — ADD/SUB/XOR primitive.";
    case CAT_STACK_PIVOT: return "Stack pivot — modifies rsp / sp.";
    case CAT_SYSCALL:     return "Direct kernel syscall / software interrupt.";
    case CAT_INDIRECT:    return "Indirect CALL/JMP — JOP dispatch.";
    default:              return "Uncategorised gadget.";
    }
}

void sarif_begin(sarif_emitter_t *e)
{
    if (!e || e->began) return;
    e->began = 1;

    fprintf(e->out,
"{\n"
"  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n"
"  \"version\": \"2.1.0\",\n"
"  \"runs\": [\n"
"    {\n"
"      \"tool\": {\n"
"        \"driver\": {\n"
"          \"name\": \"shrike\",\n"
"          \"version\": \"0.13.0\",\n"
"          \"informationUri\": \"https://github.com/bauratynov/shrike\",\n"
"          \"rules\": [\n");

    gadget_category_t cats[] = {
        CAT_RET_ONLY, CAT_POP, CAT_MOV, CAT_ARITH,
        CAT_STACK_PIVOT, CAT_SYSCALL, CAT_INDIRECT, CAT_OTHER
    };
    int first = 1;
    for (size_t i = 0; i < sizeof(cats) / sizeof(cats[0]); i++) {
        if (!first) fputs(",\n", e->out);
        fprintf(e->out,
"            { \"id\": \"%s\", "
"\"shortDescription\": { \"text\": \"%s\" }, "
"\"defaultConfiguration\": { \"level\": \"note\" } }",
                rule_id_for(cats[i]), rule_description(cats[i]));
        first = 0;
    }

    fputs("\n          ]\n        }\n      },\n      \"results\": [\n",
          e->out);
}

void sarif_emit(sarif_emitter_t *e,
                const gadget_t  *g,
                gadget_category_t cat,
                const char      *src_path)
{
    if (!e || !e->began || e->ended) return;
    if (e->emitted >= e->cap) { e->dropped++; return; }

    if (!e->first_result) fputs(",\n", e->out);
    e->first_result = 0;

    /* Render mnemonic into a local buffer — used in message. */
    char mnemo[512];
    if (format_gadget_render(g, mnemo, sizeof mnemo) < 0) {
        strncpy(mnemo, "<gadget>", sizeof mnemo);
        mnemo[sizeof mnemo - 1] = '\0';
    }

    fprintf(e->out,
"        {\n"
"          \"ruleId\": \"%s\",\n"
"          \"level\": \"note\",\n"
"          \"message\": { \"text\": \"",
            rule_id_for(cat));
    json_escape_str(e->out, mnemo);
    fputs("\" },\n", e->out);

    fputs("          \"locations\": [ { \"physicalLocation\": {\n"
          "            \"artifactLocation\": { \"uri\": \"file://",
          e->out);
    json_escape_str(e->out, src_path ? src_path : "");
    fputs("\" },\n", e->out);

    fprintf(e->out,
"            \"address\": { \"absoluteAddress\": %" PRIu64 ", "
"\"offsetFromParent\": %zu }\n"
"          } } ],\n"
"          \"properties\": { \"bytes\": \"",
            g->vaddr, g->offset);
    for (size_t i = 0; i < g->length; i++) {
        fprintf(e->out, "%s%02x", i ? " " : "", g->bytes[i]);
    }
    fprintf(e->out,
"\", \"length\": %zu, \"insn_count\": %d, "
"\"arch\": \"%s\" },\n"
"          \"partialFingerprints\": { \"gadgetHash\": \"",
            g->length, g->insn_count,
            g->machine == EM_AARCH64 ? "aarch64" : "x86_64");
    /* FNV-1a over bytes to form a stable fingerprint. */
    {
        uint64_t h = 0xcbf29ce484222325ULL;
        for (size_t i = 0; i < g->length; i++) {
            h ^= g->bytes[i];
            h *= 0x100000001b3ULL;
        }
        fprintf(e->out, "%016" PRIx64 "\" }\n        }", h);
    }
    e->emitted++;
}

void sarif_end(sarif_emitter_t *e)
{
    if (!e || !e->began || e->ended) return;
    e->ended = 1;

    fputs("\n      ]", e->out);
    if (e->dropped > 0) {
        fprintf(e->out,
",\n      \"invocations\": [ { \"executionSuccessful\": true, "
"\"toolExecutionNotifications\": [ { \"level\": \"warning\", "
"\"message\": { \"text\": \"%zu gadgets dropped by --sarif-cap\" } } ] } ]",
                e->dropped);
    }
    fputs("\n    }\n  ]\n}\n", e->out);
}
