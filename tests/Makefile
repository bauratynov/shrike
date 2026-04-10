CC       ?= cc
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wshadow -Wpedantic -Wstrict-prototypes -Wmissing-prototypes
OPT      ?= -O0 -g
CFLAGS   += $(CSTD) $(WARN) $(OPT) -I../include

LIB := ../libshrike.a

TESTS := test_xdec test_scan test_cet test_arm64 test_category test_regidx test_recipe

.PHONY: all run clean

all: $(TESTS)

# Tests link against the freshly-built libshrike.a. Each test still
# supplies its own main() — the archive provides every other symbol.
$(LIB):
	$(MAKE) -C .. lib

test_xdec: test_xdec.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

test_scan: test_scan.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

test_cet: test_cet.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

test_arm64: test_arm64.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

test_category: test_category.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

test_regidx: test_regidx.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

test_recipe: test_recipe.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

run: $(TESTS)
	@set -e; for t in $(TESTS); do echo "==> $$t"; ./$$t; done

clean:
	rm -f $(TESTS)
