# shrike — ROP gadget scanner for ELF64 (x86-64 + AArch64)
# Targets:
#   make            build libshrike.a and the shrike CLI
#   make lib        build libshrike.a only
#   make test       run unit + integration tests
#   make clean
#   make install    install binary (DESTDIR respected)

CC       ?= cc
AR       ?= ar
RANLIB   ?= ranlib
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wshadow -Wpedantic -Wstrict-prototypes -Wmissing-prototypes
OPT      ?= -O2
CFLAGS   += $(CSTD) $(WARN) $(OPT) -Iinclude -D_GNU_SOURCE
LDFLAGS  +=
LDLIBS   +=

# Library sources: everything except the CLI entry point. This is the
# unit that v2's stable C API will wrap — keep main.c out.
LIB_SRC := \
    src/elf64.c src/xdec.c src/arm64.c src/scan.c src/format.c \
    src/strset.c src/cet.c src/category.c src/regidx.c src/recipe.c \
    src/sarif.c src/pivots.c src/version.c
LIB_OBJ := $(LIB_SRC:.c=.o)
LIB     := libshrike.a

CLI_SRC := src/main.c
CLI_OBJ := $(CLI_SRC:.c=.o)
BIN     := shrike

.PHONY: all lib test clean install

all: $(BIN)

lib: $(LIB)

$(LIB): $(LIB_OBJ)
	$(AR) rcs $@ $^
	$(RANLIB) $@ 2>/dev/null || true

$(BIN): $(CLI_OBJ) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(CLI_OBJ) $(LIB) $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(BIN) $(LIB)
	$(MAKE) -C tests run

clean:
	rm -f $(LIB_OBJ) $(CLI_OBJ) $(LIB) $(BIN)
	$(MAKE) -C tests clean

install: $(BIN)
	install -Dm755 $(BIN) $(DESTDIR)/usr/local/bin/$(BIN)
