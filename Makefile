# pgpid — the PGP ID tools
#
# © 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>
# Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Two generations live here. `pgpid`, in C over gpgme, is what bl-pgpid and
# bl-pgpkey became; `pgpid-gen` and `pgpid-qrscan`, in shell, are what came
# before it and still work. Building one does not need the other.

BIN      = pgpid
SRCDIR   = src
BUILDDIR = _build

# The version is the commit, as bl-pgpid and bl-pgpkey answer it. A release
# number nobody can place is worse than a hash somebody can check out; when a
# tag exists, git describe says so on its own.
#
# --match keeps it to upstream tags: the debian branch carries debian/0.0.7-1
# and the like, and a binary that answers "debian/0.0.7-1-39-g…" inside a
# package numbered 0.1.0 tells nobody anything. A packager passes VERSION in
# and none of this runs.
VERSION ?= $(shell git describe --match='[0-9]*' --dirty --broken --always 2>/dev/null)
ifeq ($(VERSION),)
VERSION := unknown
endif

SOURCES  = $(wildcard $(SRCDIR)/*.c)
OBJECTS  = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))

# gpgme ships a pkg-config file since 1.13; gpgme-config is the fallback for
# the older distributions this may still have to build on.
GPGME_CFLAGS := $(shell pkg-config --cflags gpgme 2>/dev/null || gpgme-config --cflags)
GPGME_LIBS   := $(shell pkg-config --libs   gpgme 2>/dev/null || gpgme-config --libs)

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -D_GNU_SOURCE $(GPGME_CFLAGS) -I$(BUILDDIR) \
           -DPGPID_LOCALEDIR='"$(LOCALEDIR)"'
LDLIBS  += $(GPGME_LIBS)

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
LOCALEDIR ?= $(DATADIR)/locale

# man/ and po/ spell it `prefix`, this file spells it `PREFIX`, and a variable
# set here does not reach a sub-make on its own. Passed explicitly, or
# `make PREFIX=/tmp/x install` quietly writes into /usr/local — which is what
# it did before anybody noticed.
SUBMAKE = $(MAKE) prefix='$(PREFIX)' DESTDIR='$(DESTDIR)'

# Tauri picks its sidecars up by target triple, so a bundle looks for
# _build/pgpid-<triple> and not _build/pgpid. The same binary is left under both
# names rather than built twice: one to run from here, one for a bundle.
TRIPLE := $(shell rustc -vV 2>/dev/null | sed -n 's/^host: //p')

.PHONY: all build check clean install uninstall sidecar man po

all: build

build: $(BUILDDIR)/$(BIN) man po

man:
	$(SUBMAKE) -C man

po:
	$(SUBMAKE) -C po

$(BUILDDIR)/$(BIN): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/pgpid.h $(BUILDDIR)/version.h | $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

# The version through a header rather than a -D, and rewritten only when it
# actually changes. Passed on the command line it never triggers a rebuild:
# the binary keeps saying which commit it was first built from, which is worse
# than saying nothing at all in a bug report.
.PHONY: $(BUILDDIR)/version.h.new
$(BUILDDIR)/version.h.new: | $(BUILDDIR)
	@printf '#define PGPID_VERSION "%s"\n' '$(VERSION)' > $@

$(BUILDDIR)/version.h: $(BUILDDIR)/version.h.new
	@cmp -s $@ $< 2>/dev/null || { cp $< $@ ; echo "  version $(VERSION)" ; }

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Runs against a keyring of its own, built on the spot: a test that needs the
# caller's own certificates is a test nobody else can run.
check: $(BUILDDIR)/$(BIN)
	./tests/run.sh ./$(BUILDDIR)/$(BIN)
	./tests/pgpi_var_to_json.sh
	$(SUBMAKE) -C man check
	$(SUBMAKE) -C po check

sidecar: $(BUILDDIR)/$(BIN)
	@test -n "$(TRIPLE)" || { \
		echo "$(BIN): no rustc to ask for the target triple" >&2 ; exit 1 ; }
	cp -f $(BUILDDIR)/$(BIN) $(BUILDDIR)/$(BIN)-$(TRIPLE)

install: build
	install -D -m 0755 $(BUILDDIR)/$(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	install -D -m 0755 bin/pgpid-gen     $(DESTDIR)$(BINDIR)/pgpid-gen
	install -D -m 0755 bin/pgpid-qrscan  $(DESTDIR)$(BINDIR)/pgpid-qrscan
	$(SUBMAKE) -C man install
	$(SUBMAKE) -C po install

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/$(BIN)
	$(RM) $(DESTDIR)$(BINDIR)/pgpid-gen $(DESTDIR)$(BINDIR)/pgpid-qrscan
	$(SUBMAKE) -C man uninstall
	$(SUBMAKE) -C po uninstall

clean:
	rm -rf $(BUILDDIR)
	$(SUBMAKE) -C man clean
	$(SUBMAKE) -C po clean
