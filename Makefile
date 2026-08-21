# pgpid-mip
#
# Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
# Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only

BIN      = pgpid-mip
SRCDIR   = src
BUILDDIR = build

# The version is the application's: this ships inside the foodjis package
# (djibian-onboarding), which installs it as /usr/bin/pgpid-mip, and a tool
# that travels inside a package has no version of its own to give. Read from
# package.json rather than written twice, because two numbers meant to be
# equal drift the day someone bumps one of them.
#
# mip is migration in progress. When bl-pgpid and bl-pgpkey have finished
# moving here, this leaves for a repository and a package of its own under
# the name pgpid — and on that day package.json is gone, the fallback below
# becomes the real number, and this comment is the note explaining why it was
# ever borrowed.
VERSION := $(shell sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' \
                       ../package.json 2>/dev/null | head -n 1)
ifeq ($(VERSION),)
VERSION := 0.0.0-standalone
endif

SOURCES  = $(wildcard $(SRCDIR)/*.c)
OBJECTS  = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SOURCES))

# gpgme ships a pkg-config file since 1.13; gpgme-config is the fallback for
# the older distributions this may still have to build on.
GPGME_CFLAGS := $(shell pkg-config --cflags gpgme 2>/dev/null || gpgme-config --cflags)
GPGME_LIBS   := $(shell pkg-config --libs   gpgme 2>/dev/null || gpgme-config --libs)

CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes \
           -D_GNU_SOURCE -DPGPID_MIP_VERSION='"$(VERSION)"' $(GPGME_CFLAGS)
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
