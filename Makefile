# pgpid-mip
#
# Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
# Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only

BIN      = pgpid-mip
SRCDIR   = src
BUILDDIR = build

SOURCES  = $(wildcard $(SRCDIR)/*.c)
OBJECTS  = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))

# gpgme ships a pkg-config file since 1.13; gpgme-config is the fallback for
# the older distributions this may still have to build on.
GPGME_CFLAGS := $(shell pkg-config --cflags gpgme 2>/dev/null || gpgme-config --cflags)
GPGME_LIBS   := $(shell pkg-config --libs   gpgme 2>/dev/null || gpgme-config --libs)

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -D_GNU_SOURCE $(GPGME_CFLAGS)
LDLIBS  += $(GPGME_LIBS)

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

.PHONY: all clean install check

all: $(BUILDDIR)/$(BIN)

$(BUILDDIR)/$(BIN): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/pgpid.h | $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# Runs against a keyring of its own, built on the spot: a test that needs the
# caller's own certificates is a test nobody else can run.
check: all
	./tests/run.sh ./$(BUILDDIR)/$(BIN)

install: all
	install -D -m 0755 $(BUILDDIR)/$(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

clean:
	rm -rf $(BUILDDIR)
