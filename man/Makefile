# © 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>
#
# SPDX-License-Identifier: LGPL-3.0-only

TARGETS           := $(basename $(wildcard *.md))

prefix            ?= /usr/local
datarootdir       ?= $(prefix)/share
mandir            ?= $(datarootdir)/man

GZIPPED_TARGETS   := $(addsuffix .gz, $(TARGETS))
MANDIR            := $(DESTDIR)$(mandir)
DEST_TARGETS      := $(foreach ITEM, $(TARGETS), \
                       $(MANDIR)/man$(subst .,,$(suffix $(ITEM)))/$(ITEM).gz)
DEST_TARGETS_DIRS := $(sort $(dir $(DEST_TARGETS)))

SHELL             := /bin/sh
INSTALL           := install
INSTALL_DATA      := $(INSTALL) --mode 644
TO_MAN            := pandoc --standalone --to=man
GIT_DATE          := LANG=C git log --max-count 1
GIT_DATE          += --format='%ad' --date='format:%d %B %Y' --

.POSIX:
.SUFFIXES:
.DELETE_ON_ERROR:

all: build

build: $(GZIPPED_TARGETS)

check: build

clean:
	$(RM) $(TARGETS) $(GZIPPED_TARGETS)

install: build | $(DEST_TARGETS_DIRS)
	-$(foreach ITEM, $(DEST_TARGETS), \
	   $(INSTALL_DATA) $(notdir $(ITEM)) $(dir $(ITEM)) &&) true

uninstall:
	$(RM) $(DEST_TARGETS)

.PHONY: all build clean install uninstall

%:: %.md Makefile
	$(TO_MAN) --metadata date:"$$($(GIT_DATE) $<)" < $< > $@

%.gz: %
	gzip < $< > $@

$(DEST_TARGETS_DIRS):
	-mkdir -p $@
