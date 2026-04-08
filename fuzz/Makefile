# fuzz/Makefile — drivers for AFL++ and libFuzzer.
#
# Usage (AFL++):
#   make -C fuzz afl
#   afl-fuzz -i corpus -o findings ./fuzz/fuzz_xdec
#
# Usage (libFuzzer / clang):
#   make -C fuzz libfuzzer
#   ./fuzz/fuzz_xdec corpus/
#
# OSS-Fuzz integration is tracked for v1.0.

CC       ?= clang
INCLUDES := -I../include
CFLAGS   += -std=c99 -Wall -Wextra -O1 -g $(INCLUDES)

.PHONY: all libfuzzer afl clean

all: libfuzzer

libfuzzer: CFLAGS += -fsanitize=fuzzer,address,undefined
libfuzzer: fuzz_xdec_lf

afl: CFLAGS += -DAFL_PERSISTENT
afl: fuzz_xdec

fuzz_xdec_lf: fuzz_xdec.c ../src/xdec.c
	$(CC) $(CFLAGS) -o $@ $^

fuzz_xdec: fuzz_xdec.c ../src/xdec.c
	afl-clang-fast $(CFLAGS) -o $@ $^

clean:
	rm -f fuzz_xdec_lf fuzz_xdec
