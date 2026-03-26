CC       ?= cc
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wshadow -Wpedantic -Wstrict-prototypes -Wmissing-prototypes
OPT      ?= -O0 -g
CFLAGS   += $(CSTD) $(WARN) $(OPT) -I../include

TESTS := test_xdec test_scan test_cet

.PHONY: all run clean
all: $(TESTS)

test_xdec: test_xdec.c ../src/xdec.c
	$(CC) $(CFLAGS) -o $@ $^

test_scan: test_scan.c ../src/xdec.c ../src/scan.c ../src/format.c ../src/cet.c
	$(CC) $(CFLAGS) -o $@ $^

test_cet: test_cet.c ../src/cet.c
	$(CC) $(CFLAGS) -o $@ $^

run: $(TESTS)
	@set -e; for t in $(TESTS); do echo "==> $$t"; ./$$t; done

clean:
	rm -f $(TESTS)
