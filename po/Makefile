# pgpid — message catalogues
#
# Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
# Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only
#
# The template is not rebuilt by `make`: regenerating it moves every line
# number and rewrites the date, so a build would show the whole catalogue as
# changed for having been built. `make update-po` does it, on purpose, when
# the messages have actually moved.

DOMAIN            := pgpid
LINGUAS           := de en es fr it pl pt ru uk

prefix            ?= /usr/local
datarootdir       ?= $(prefix)/share
localedir         ?= $(datarootdir)/locale

POFILES           := $(addsuffix .po, $(LINGUAS))
MOFILES           := $(addsuffix .mo, $(LINGUAS))
DESTS             := $(foreach L, $(LINGUAS), \
                       $(DESTDIR)$(localedir)/$(L)/LC_MESSAGES/$(DOMAIN).mo)

SHELL             := /bin/sh
INSTALL           := install
INSTALL_DATA      := $(INSTALL) --mode 644

.SUFFIXES:
.DELETE_ON_ERROR:

all: build

build: $(MOFILES)

%.mo: %.po
	msgfmt --check --output-file=$@ $<

# What a translator wants to know before saying a language is done: nothing
# fuzzy, nothing untranslated.
check: build
	@for po in $(POFILES) ; do \
		printf '%-6s ' "$${po%.po}" ; \
		msgfmt --check --statistics --output-file=/dev/null $$po 2>&1 ; \
	done

# --no-wrap throughout: these msgids are column-aligned help blocks, and a
# line broken at 80 hides the alignment that check-width.py is there to guard.
update-po: $(DOMAIN).pot
	@for po in $(POFILES) ; do \
		msgmerge --quiet --no-wrap --previous --update --backup=none $$po $(DOMAIN).pot ; \
	done

$(DOMAIN).pot: $(wildcard ../src/*.c)
	xgettext --language=C --from-code=UTF-8 --no-wrap \
		--keyword=_ --keyword=N_ --add-comments=TRANSLATORS \
		--package-name=$(DOMAIN) --msgid-bugs-address=jjbrucker@foopgp.org \
		--copyright-holder="Jean-Jacques Brucker and Mnêmê" \
		--output=$@.new ../src/*.c
	@# Keep our header: xgettext writes its own every time.
	@sed -n '1,/^msgid ""$$/p' $@ | head -n -1 > $@.head 2>/dev/null || true
	@if [ -s $@.head ] ; then \
		sed -n '/^msgid ""$$/,$$p' $@.new | cat $@.head - > $@ ; \
	else cp $@.new $@ ; fi
	@$(RM) $@.new $@.head

install: build
	@for L in $(LINGUAS) ; do \
		$(INSTALL) --directory $(DESTDIR)$(localedir)/$$L/LC_MESSAGES ; \
		$(INSTALL_DATA) $$L.mo \
			$(DESTDIR)$(localedir)/$$L/LC_MESSAGES/$(DOMAIN).mo ; \
	done

uninstall:
	$(RM) $(DESTS)

clean:
	$(RM) $(MOFILES)

.PHONY: all build check clean install uninstall update-po
