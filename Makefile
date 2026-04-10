# shrike — ROP gadget scanner for ELF64 (x86-64 + AArch64)
# Targets:
#   make            build libshrike.a and the shrike CLI
#   make lib        build libshrike.a only
#   make pc         generate shrike.pc from the template
#   make test       run unit + integration tests
#   make install    install everything under $(PREFIX) (DESTDIR respected)
#   make uninstall  remove the installed files
#   make clean
#
# Install layout (PREFIX defaults to /usr/local):
#   $(PREFIX)/bin/shrike
#   $(PREFIX)/lib/libshrike.a
#   $(PREFIX)/lib/pkgconfig/shrike.pc
#   $(PREFIX)/include/shrike/*.h

CC       ?= cc
AR       ?= ar
RANLIB   ?= ranlib
INSTALL  ?= install
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wshadow -Wpedantic -Wstrict-prototypes -Wmissing-prototypes
OPT      ?= -O2
CFLAGS   += $(CSTD) $(WARN) $(OPT) -Iinclude -D_GNU_SOURCE
LDFLAGS  +=
LDLIBS   +=

# Install prefixes — override on command line, e.g.
#   make install PREFIX=/usr DESTDIR=$HOME/staging
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
LIBDIR     ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
PCDIR      ?= $(LIBDIR)/pkgconfig

# Derive the version string from the public header so there's a
# single source of truth. The shell runs once at parse time.
SHRIKE_VERSION := $(shell awk '\
    /^\#define SHRIKE_VERSION_MAJOR/ {maj=$$3} \
    /^\#define SHRIKE_VERSION_MINOR/ {min=$$3} \
    /^\#define SHRIKE_VERSION_PATCH/ {pat=$$3} \
    END {print maj"."min"."pat}' include/shrike/version.h)

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

PC      := shrike.pc
PC_IN   := packaging/shrike.pc.in
HEADERS := $(wildcard include/shrike/*.h)

.PHONY: all lib pc test clean install uninstall

all: $(BIN) $(PC)

lib: $(LIB)

pc: $(PC)

# Substitute @VERSION@ / @PREFIX@ / @LIBDIR@ / @INCLUDEDIR@ in the
# pkg-config template. The installed .pc knows the install prefix,
# not the build-tree layout, so downstream pkg-config --cflags
# --libs resolves correctly.
$(PC): $(PC_IN) include/shrike/version.h
	sed -e 's|@VERSION@|$(SHRIKE_VERSION)|g' \
	    -e 's|@PREFIX@|$(PREFIX)|g' \
	    -e 's|@LIBDIR@|$(LIBDIR)|g' \
	    -e 's|@INCLUDEDIR@|$(INCLUDEDIR)|g' \
	    $(PC_IN) > $@

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
	rm -f $(LIB_OBJ) $(CLI_OBJ) $(LIB) $(BIN) $(PC)
	$(MAKE) -C tests clean

# `install` forces a fresh shrike.pc so PREFIX/LIBDIR overrides on
# the command line take effect even if a stale .pc is on disk.
install: $(BIN) $(LIB)
	rm -f $(PC)
	$(MAKE) $(PC) PREFIX='$(PREFIX)' LIBDIR='$(LIBDIR)' INCLUDEDIR='$(INCLUDEDIR)'
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 644 $(LIB) $(DESTDIR)$(LIBDIR)/$(LIB)
	$(INSTALL) -d $(DESTDIR)$(PCDIR)
	$(INSTALL) -m 644 $(PC) $(DESTDIR)$(PCDIR)/$(PC)
	$(INSTALL) -d $(DESTDIR)$(INCLUDEDIR)/shrike
	$(INSTALL) -m 644 $(HEADERS) $(DESTDIR)$(INCLUDEDIR)/shrike/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(LIBDIR)/$(LIB)
	rm -f $(DESTDIR)$(PCDIR)/$(PC)
	rm -rf $(DESTDIR)$(INCLUDEDIR)/shrike
