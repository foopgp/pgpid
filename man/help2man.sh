#!/bin/bash

# Generate manual pages from the tools' own --help, in every language.
#
# © 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>
# Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Taken from bash-libs and carried further. What came from there: the NAME
# line read out of the tool itself rather than written twice, the .extra file
# so that hand-written sections survive a regeneration, and the fixes for the
# artefacts pandoc leaves behind.
#
# What is new here. The C tool has twenty-four actions, each with a --help of
# its own, and a page that lists only their names tells a reader nothing —
# so each action's help is included, verbatim, in a section of its own. And
# since those helps are now translated, the same run produces one page per
# language: the content comes from the catalogues, and the only thing that
# stays English is the section headings, which are keywords rather than prose.
#
# LANGUAGE rather than --locale for the language itself: only the locales
# somebody generated exist on a given machine, and asking for ru_RU.UTF-8 on a
# box that has not got it fails. LANGUAGE needs no locale to exist — but it is
# ignored outright when LC_MESSAGES resolves to C or POSIX, which is exactly
# what --locale C.UTF-8 does. So any non-C UTF-8 locale will do as a carrier,
# and LANGUAGE picks the catalogue.

set -eo pipefail

here=$(dirname "$(readlink --canonicalize "$0")")
cd "$here"

versionstring=$(git describe --match='[0-9]*' --tags 2>/dev/null \
	| sed --regexp-extended ' s:.*([0-9]+\.[0-9]+\.[0-9]+).*:\1: ') || versionstring=unknown
linguas=$(sed --silent 's/^LINGUAS *:*= *//p' ../po/Makefile)

usage="Usage: $0 [OPTIONS]... [TOOL]..."
helpmsg="
Internal tool for this git repository: generates the manual pages.

Options:
  -v, --target-version VER  set target version (default: $versionstring)
  -l, --languages 'a b'     which languages (default: $linguas)
  -y, --yes                 replace without asking
  -h, --help                show help and exit
"

assumeyes=""
for ((;$#;)) ; do
	case "$1" in
		-v|--target-version) shift ; versionstring="$1" ;;
		-l|--languages) shift ; linguas="$1" ;;
		-y|--yes) assumeyes=. ;;
		-h|--help) printf "%s\n%s\n" "$usage" "$helpmsg" ; exit ;;
		--) shift ; break ;;
		-*) printf "%s: Error: unrecognized option '%s'\n" "$0" "$1" >&2 ; exit 2 ;;
		*) break ;;
	esac
	shift
done

# The catalogues have to be where the binary was told to look, and it was told
# at compile time. So the tool is built and installed into a throwaway prefix,
# and the pages are generated from that copy rather than from the source tree.
# A locale that is not C, so that LANGUAGE is honoured. Which one does not
# matter: LANGUAGE overrides it for the catalogue lookup, and the encoding is
# UTF-8 either way.
carrier=$(locale -a 2>/dev/null | grep --extended-regexp '\.(utf8|UTF-8)$' \
	| grep --invert-match --extended-regexp '^(C|POSIX)' | head --lines=1)
if [[ -z "$carrier" ]] ; then
	echo "$0: no non-C UTF-8 locale on this machine — only English pages" >&2
	linguas=en
	carrier=C.UTF-8
fi

staging=$(mktemp --directory -t pgpid-man.XXXXXX)
trap 'rm -rf "$staging"' EXIT
echo "$0: building into $staging…" >&2
make --silent --directory=.. PREFIX="$staging" >/dev/null
make --silent --directory=.. PREFIX="$staging" install >/dev/null
mkdir -p "$staging/wrap"
PATH="$staging/wrap:$staging/bin:$PATH"

# The first paragraph of --help, joined into one line. bash-libs takes the
# first line alone, which works there because every description fits on one;
# pgpid's runs to two, and cutting it mid-sentence puts half a sentence into
# whatis and apropos.
namedesc() {
	# Continuation lines are joined, sentences are not: a line that already
	# ends in punctuation ends the description. Testing the *next* line's
	# first letter would have worked in French and broken in German, where a
	# wrapped line often starts with a capitalised noun.
	LC_ALL="$carrier" LANGUAGE="$1" "$staging/bin/$2" --help \
		| awk '
			BEGIN { p = 0 }
			/^$/  { if (p) exit ; p = 1 ; next }
			p     { printf "%s ", $0 ; if ($0 ~ /[.!?)]$/) exit }' \
		| sed 's/  *$//'
}

# Every action, in the order the program lists them.
actions() {
	LC_ALL="$carrier" LANGUAGE=en "$staging/bin/pgpid" --help | sed --silent '/^ACTIONS:/,/^$/ { /^  [a-z]/ s/^  \([a-z_0-9]*\).*/\1/p }'
}

for lang in $linguas ; do
	outdir="."
	[[ "$lang" == en ]] || { outdir="$lang" ; mkdir -p "$outdir" ; }

	for tool in pgpid pgpid-gen pgpid-qrscan ; do
		[[ -x "$staging/bin/$tool" ]] || { echo "$0: $tool not built, skipped" >&2 ; continue ; }
		# Only the C tool speaks other languages; the shell pair would come
		# out English under any LANGUAGE, and nine identical pages help nobody.
		[[ "$tool" == pgpid || "$lang" == en ]] || continue

		draft="$outdir/$tool.1.md.draft"
		cat <<-HEADER > "$draft"
		<!--
		© 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>
		Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>

		SPDX-License-Identifier: GPL-3.0-only

		Generated by man/help2man.sh — edit $tool.1.md.extra, not this file.
		-->

		---
		title: ${tool^^}
		section: 1
		header: User Commands
		footer: pgpid $versionstring
		---

		HEADER

		# help2man sets the child's locale from --locale, and takes its own
		# headings from its own environment. Those must not be the same
		# thing: the headings have to read the same on every machine, while
		# the tool has to speak the language of the page. A one-line wrapper
		# separates them.
		#
		# It carries the tool's own name, in a directory ahead of the real
		# one on PATH, because help2man names the page after the file it ran
		# and has no option to say otherwise.
		printf '#!/bin/sh\nLC_ALL=%s LANGUAGE=%s exec %s/bin/%s "$@"\n' \
			"$carrier" "$lang" "$staging" "$tool" > "$staging/wrap/$tool"
		chmod +x "$staging/wrap/$tool"

		# --name is not passed: help2man re-encodes it, and a UTF-8
		# description comes out the other side as Latin-1 mojibake — «modèle»
		# became «modÃ¨le». Its placeholder line is replaced afterwards
		# instead, which touches no encoding at all.
		LC_ALL=C.UTF-8 LANGUAGE=en help2man --no-info "$tool" \
			--locale C.UTF-8 \
			--version-string "$versionstring" \
			| pandoc --from man --to markdown > "$staging/body.md"
		NAMEDESC="$(namedesc "$lang" "$tool")" TOOL="$tool" python3 - \
			"$staging/body.md" <<-'FIXNAME'
		import os, re, sys
		p = sys.argv[1]
		s = open(p, encoding="utf-8").read()
		s = re.sub(r"^%s - manual page for .*$" % re.escape(os.environ["TOOL"]),
		           "%s - %s" % (os.environ["TOOL"], os.environ["NAMEDESC"]),
		           s, count=1, flags=re.M)
		open(p, "w", encoding="utf-8").write(s)
		FIXNAME
		cat "$staging/body.md" >> "$draft"

		# One section per action, verbatim. A code block, because these are
		# aligned tables and markdown would eat the columns.
		if [[ "$tool" == pgpid ]] ; then
			printf '\n# ACTIONS\n' >> "$draft"
			for action in $(actions) ; do
				printf '\n## %s %s\n\n```\n' "$tool" "$action" >> "$draft"
				LC_ALL="$carrier" LANGUAGE="$lang" "$staging/bin/$tool" "$action" --help >> "$draft"
				printf '```\n' >> "$draft"
			done
		fi

		[[ ! -r "$outdir/$tool.1.md.extra" ]] || cat "$outdir/$tool.1.md.extra" >> "$draft"

		cat <<-FOOTER >> "$draft"

		# DIAGNOSTICS

		Returns zero on normal operation, non-zero on errors. Each action names
		its own codes under **--help** where it has any.

		# SEE ALSO

		**pgpid**(1), **pgpid-gen**(1), **pgpid-qrscan**(1),
		[**bash-libs**](//codeberg.org/foopgp/bash-libs/src/branch/main/man/bash-libs.7.md)(7).

		# AUTHORS

		foopgp <info@foopgp.org>, Jean-Jacques Brucker <jjbrucker@foopgp.org>,
		Mnêmê <mneme@foopgp.org>.

		FOOTER

		# Artefacts pandoc leaves: the staging path in the synopsis, and the
		# mojibake it makes of Ɉ and €.
		sed --in-place "s,$staging/bin/,,g ; s,(É.),(Ɉ), ; s,(â\\\\\\\\¬),(€)," "$draft"

		if [[ "$assumeyes" ]] ; then
			mv -f "$draft" "$outdir/$tool.1.md"
			echo "$0: wrote $outdir/$tool.1.md" >&2
		elif ! colordiff --report-identical-files --unified "$outdir/$tool.1.md" "$draft" 2>/dev/null ; then
			mv -i "$draft" "$outdir/$tool.1.md" || true
		else
			rm -f "$draft"
		fi
	done
done
