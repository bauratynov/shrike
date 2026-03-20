# shrike — minimal ROP gadget finder for x86-64 ELF64
# Targets:
#   make            build the shrike binary
#   make test       run unit + integration tests (sprint 2+)
#   make clean

CC       ?= cc
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wshadow -Wpedantic -Wstrict-prototypes -Wmissing-prototypes
OPT      ?= -O2
CFLAGS   += $(CSTD) $(WARN) $(OPT) -Iinclude -D_GNU_SOURCE
LDFLAGS  +=
LDLIBS   +=

# Sprint 1 only ships the ELF loader and a CLI stub. Sprint 2 adds xdec.c,
# sprint 3 adds scan.c and format.c; the Makefile grows with each.
SRC := src/elf64.c src/main.c
OBJ := $(SRC:.c=.o)
BIN := shrike

.PHONY: all test clean install

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(BIN)
	@[ -d tests ] && $(MAKE) -C tests run || echo "no tests yet"

clean:
	rm -f $(OBJ) $(BIN)
	@[ -d tests ] && $(MAKE) -C tests clean 2>/dev/null || true

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)/usr/local/bin/$(BIN)
