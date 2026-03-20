/*
 * main.c — shrike CLI driver (sprint 1 skeleton).
 *
 * Loads the ELF64, enumerates executable PT_LOAD segments, prints a
 * summary. Sprints 2-3 wire in the x86-64 length decoder and the
 * gadget scanner.
 */

#include "elf64.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *prog)
{
    fprintf(stderr,
"shrike — ROP gadget finder for x86-64 ELF64\n"
"\n"
"Usage:\n"
"  %s [options] <elf64>\n"
"\n"
"Options:\n"
"  -h, --help        show this message\n"
"\n"
"Sprint 1: prints executable PT_LOAD segments.\n"
"Sprints 2-3 add the length decoder and the gadget scanner.\n",
    prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(argv[0]); return 2; }
    if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        usage(argv[0]); return 0;
    }

    elf64_t e;
    if (elf64_load(argv[1], &e) < 0) {
        fprintf(stderr, "shrike: %s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    printf("file    : %s\n", argv[1]);
    printf("type    : %s\n", e.is_dyn ? "ET_DYN (PIE / shared)" : "ET_EXEC");
    printf("entry   : 0x%" PRIx64 "\n", e.entry);
    printf("segments: %zu executable\n", e.nseg);
    for (size_t i = 0; i < e.nseg; i++) {
        printf("  [%zu] vaddr=0x%016" PRIx64
               "  bytes=%zu  flags=%c%c%c\n",
               i, e.segs[i].vaddr, e.segs[i].size,
               (e.segs[i].flags & PF_R) ? 'r' : '-',
               (e.segs[i].flags & PF_W) ? 'w' : '-',
               (e.segs[i].flags & PF_X) ? 'x' : '-');
    }

    elf64_close(&e);
    return 0;
}
