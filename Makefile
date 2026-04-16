# shrike — ROP gadget scanner for ELF64 (x86-64 + AArch64)
# Targets:
#   make            build libshrike.a, libshrike.so.N.M.P, and CLI
#   make lib        build static + shared libraries only
#   make static     static library only
#   make shared     shared library only (PIC)
#   make pc         generate shrike.pc from the template
#   make test       run unit + integration tests
#   make install    install everything under $(PREFIX) (DESTDIR respected)
#   make uninstall  remove the installed files
#   make clean
#
# Install layout (PREFIX defaults to /usr/local):
#   $(PREFIX)/bin/shrike
#   $(PREFIX)/lib/libshrike.a
#   $(PREFIX)/lib/libshrike.so.$(SHRIKE_VERSION)   (real file)
#   $(PREFIX)/lib/libshrike.so.$(SOMAJOR)          (soname symlink)
#   $(PREFIX)/lib/libshrike.so                     (linker symlink)
#   $(PREFIX)/lib/pkgconfig/shrike.pc
#   $(PREFIX)/include/shrike/*.h
#
# The CLI remains linked against libshrike.a so the "one static
# binary you drop on any Linux host" story survives; library
# consumers get libshrike.so via pkg-config.

CC       ?= cc
AR       ?= ar
RANLIB   ?= ranlib
INSTALL  ?= install
CSTD     ?= -std=c99
WARN     ?= -Wall -Wextra -Wshadow -Wpedantic -Wstrict-prototypes -Wmissing-prototypes
OPT      ?= -O2
CFLAGS   += $(CSTD) $(WARN) $(OPT) -Iinclude -D_GNU_SOURCE \
            -DSHRIKE_IGNORE_DEPRECATIONS
LDFLAGS  +=
LDLIBS   +=

# PIC flags for shared-library objects — built into a parallel
# object tree so a single `make` produces both archive and .so
# without a second compile pass for the CLI.
PIC_FLAGS ?= -fPIC

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
    /^#define SHRIKE_VERSION_MAJOR/ {maj=$$3} \
    /^#define SHRIKE_VERSION_MINOR/ {min=$$3} \
    /^#define SHRIKE_VERSION_PATCH/ {pat=$$3} \
    END {print maj"."min"."pat}' include/shrike/version.h)

# Library sources: everything except the CLI entry point. This is the
# unit that v2's stable C API will wrap — keep main.c out.
LIB_SRC := \
    src/elf64.c src/pe.c src/macho.c \
    src/xdec.c src/arm64.c src/riscv.c src/scan.c src/format.c \
    src/strset.c src/cet.c src/category.c src/regidx.c src/recipe.c \
    src/sarif.c src/pivots.c src/effect.c src/insn_effect.c \
    src/version.c src/shrike_api.c
LIB_OBJ     := $(LIB_SRC:.c=.o)
LIB_PIC_OBJ := $(LIB_SRC:.c=.pic.o)
LIB         := libshrike.a

# soname scheme: libshrike.so.1 (bumped only on ABI break),
# points at libshrike.so.<SHRIKE_VERSION> (real file),
# and libshrike.so (unversioned, for the linker) points at the
# soname. This matches what liblzma / libsodium / libssh2 do.
SOMAJOR     := $(shell awk '/^#define SHRIKE_VERSION_MAJOR/ {print $$3}' include/shrike/version.h)
LIB_SO_REAL := libshrike.so.$(SHRIKE_VERSION)
LIB_SO_NAME := libshrike.so.$(SOMAJOR)
LIB_SO_LINK := libshrike.so

CLI_SRC := src/main.c
CLI_OBJ := $(CLI_SRC:.c=.o)
BIN     := shrike

PC      := shrike.pc
PC_IN   := packaging/shrike.pc.in
HEADERS := $(wildcard include/shrike/*.h)

.PHONY: all lib static shared pc test clean install uninstall

all: $(BIN) $(LIB_SO_REAL) $(PC)

lib: static shared

static: $(LIB)

shared: $(LIB_SO_REAL)

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

# Build the shared library with an explicit soname so dynamic
# linkers load the right major version at runtime even if the
# unversioned libshrike.so symlink points somewhere else. Create
# the two side-symlinks in the build tree so the local `shrike`
# binary (if rebuilt against the .so) and downstream smoke tests
# can resolve them.
$(LIB_SO_REAL): $(LIB_PIC_OBJ)
	$(CC) $(CFLAGS) -shared \
	    -Wl,-soname,$(LIB_SO_NAME) \
	    -o $@ $^ $(LDFLAGS) $(LDLIBS)
	ln -sf $(LIB_SO_REAL) $(LIB_SO_NAME)
	ln -sf $(LIB_SO_NAME) $(LIB_SO_LINK)

$(BIN): $(CLI_OBJ) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(CLI_OBJ) $(LIB) $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# PIC objects live beside the non-PIC ones with a .pic.o suffix.
# Two object trees is cheaper than rebuilding the CLI against PIC
# objects too.
%.pic.o: %.c
	$(CC) $(CFLAGS) $(PIC_FLAGS) -c -o $@ $<

test: $(BIN) $(LIB)
	$(MAKE) -C tests run

clean:
	rm -f $(LIB_OBJ) $(LIB_PIC_OBJ) $(CLI_OBJ) \
	      $(LIB) $(LIB_SO_REAL) $(LIB_SO_NAME) $(LIB_SO_LINK) \
	      $(BIN) $(PC)
	$(MAKE) -C tests clean

# `install` forces a fresh shrike.pc so PREFIX/LIBDIR overrides on
# the command line take effect even if a stale .pc is on disk.
install: $(BIN) $(LIB) $(LIB_SO_REAL)
	rm -f $(PC)
	$(MAKE) $(PC) PREFIX='$(PREFIX)' LIBDIR='$(LIBDIR)' INCLUDEDIR='$(INCLUDEDIR)'
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)
	$(INSTALL) -m 644 $(LIB) $(DESTDIR)$(LIBDIR)/$(LIB)
	$(INSTALL) -m 755 $(LIB_SO_REAL) $(DESTDIR)$(LIBDIR)/$(LIB_SO_REAL)
	ln -sf $(LIB_SO_REAL) $(DESTDIR)$(LIBDIR)/$(LIB_SO_NAME)
	ln -sf $(LIB_SO_NAME) $(DESTDIR)$(LIBDIR)/$(LIB_SO_LINK)
	$(INSTALL) -d $(DESTDIR)$(PCDIR)
	$(INSTALL) -m 644 $(PC) $(DESTDIR)$(PCDIR)/$(PC)
	$(INSTALL) -d $(DESTDIR)$(INCLUDEDIR)/shrike
	$(INSTALL) -m 644 $(HEADERS) $(DESTDIR)$(INCLUDEDIR)/shrike/

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(LIBDIR)/$(LIB)
	rm -f $(DESTDIR)$(LIBDIR)/$(LIB_SO_REAL)
	rm -f $(DESTDIR)$(LIBDIR)/$(LIB_SO_NAME)
	rm -f $(DESTDIR)$(LIBDIR)/$(LIB_SO_LINK)
	rm -f $(DESTDIR)$(PCDIR)/$(PC)
	rm -rf $(DESTDIR)$(INCLUDEDIR)/shrike
