# fuzz/Makefile — drivers for AFL++ and libFuzzer.
#
# Targets:
#   make libfuzzer    clang + -fsanitize=fuzzer,address,undefined
#   make afl          afl-clang-fast with PERSISTENT loop
#
# Usage (libFuzzer):
#   make libfuzzer
#   ./fuzz_xdec_lf corpus/ -max_total_time=60
#
# Usage (AFL++):
#   make afl
#   afl-fuzz -i seeds -o findings ./fuzz_xdec
#
# We build three harnesses, one per attack-surface component:
#   fuzz_xdec   — x86-64 length decoder (v0.1-era)
#   fuzz_pe     — PE/COFF loader (v2.2-era)
#   fuzz_macho  — Mach-O thin + fat loader (v1.3-era)

CC       ?= clang
INCLUDES := -I../include
CFLAGS   += -std=c99 -Wall -Wextra -O1 -g $(INCLUDES)

HARNESSES_LF := fuzz_xdec_lf fuzz_pe_lf fuzz_macho_lf
HARNESSES_AFL := fuzz_xdec fuzz_pe fuzz_macho

.PHONY: all libfuzzer afl clean

all: libfuzzer

libfuzzer: CFLAGS += -fsanitize=fuzzer,address,undefined
libfuzzer: $(HARNESSES_LF)

afl: CFLAGS += -DAFL_PERSISTENT
afl: $(HARNESSES_AFL)

# libFuzzer drivers. Each harness links only the specific
# src/*.c files it needs — keeps coverage focused.
fuzz_xdec_lf: fuzz_xdec.c ../src/xdec.c
	$(CC) $(CFLAGS) -o $@ $^

fuzz_pe_lf: fuzz_pe.c ../src/pe.c ../src/elf64.c
	$(CC) $(CFLAGS) -o $@ $^

fuzz_macho_lf: fuzz_macho.c ../src/macho.c ../src/elf64.c
	$(CC) $(CFLAGS) -o $@ $^

# AFL++ drivers. Same sources, afl-clang-fast instrumentation.
fuzz_xdec: fuzz_xdec.c ../src/xdec.c
	afl-clang-fast $(CFLAGS) -o $@ $^

fuzz_pe: fuzz_pe.c ../src/pe.c ../src/elf64.c
	afl-clang-fast $(CFLAGS) -o $@ $^

fuzz_macho: fuzz_macho.c ../src/macho.c ../src/elf64.c
	afl-clang-fast $(CFLAGS) -o $@ $^

clean:
	rm -f $(HARNESSES_LF) $(HARNESSES_AFL)
