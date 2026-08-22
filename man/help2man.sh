#!/bin/bash

# Generate draft for manual pages (using help2man).

set -eo pipefail

versionstring=$(git describe --tag | sed -E ' s:.*([0-9]+\.[0-9]+\.[0-9]+).*:\1: ')

usage="Usage: $BASH_SOURCE [OPTIONS]..."
helpmsg="
Internal tool for this git repository: Generates man pages.

Options:
  -v, --target-version     set target version (default: $versionstring)
  -h, --help               show help and exit
  -V, --version            show version and exit ($(git describe --tag))
"

for ((;$#;)) ; do
	case "$1" in
		-v|--target-version) shift ; versionstring="$1" ;;
		-h|--help) printf "%s\n%s\n" "$usage" "$helpmsg" ; exit ;;
		-V|--version) printf "%s %s\n" "$BASH_SOURCE" "$(git describe --tag)" ; exit ;;
		--) shift ; break ;;
		-*) printf "%s: Error: unrecognized option '%s'\nTry '%s --help' for more information.\n" "$BASH_SOURCE" "$1" "$BASH_SOURCE" >&2 ; return 2 ;;
		*) break ;;
	esac
	shift
done

cd "$(dirname "$0")"

PATH="../bin:../_build:$PATH"

# The compiled tool lives in _build, not bin, and is the reason this script
# exists at all now. It is listed first so that its page leads.
for bl in ../_build/pgpid $(find ../bin/ -maxdepth 1 -type f) ; do
	[[ -x "$bl" ]] || { echo "$bl: not built, skipped" >&2 ; continue ; }
	binname="$(basename "$bl")"
	cat <<EOF > "${binname}.1.md.draft"
<!--
© 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>
Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>

SPDX-License-Identifier: GPL-3.0-only
-->

---
title: ${binname^^}
section: 1
header: User Commands
footer: pgpid $versionstring
---

EOF
	# Without --name, help2man writes "manual page for pgpid 0.1.0" into NAME,
	# which is what whatis and apropos then show. One line each, here, so a
	# regeneration keeps them.
	case "$binname" in
		pgpid)         oneline="OpenPGP certificates that say whose they are" ;;
		pgpid-gen)     oneline="generate an OpenPGP certificate and its secrets on QR codes" ;;
		pgpid-qrscan)  oneline="move OpenPGP secrets from QR codes onto a smartcard" ;;
		*)             oneline="" ;;
	esac
	echo "help2man --no-info $binname --locale C.UTF-8 | pandoc -f man -t markdown >> ${binname}.1.md.draft" >&2
	help2man --no-info "$binname" --locale "C.UTF-8" --version-string "$versionstring" \
		${oneline:+--name="$oneline"} | pandoc -f man -t markdown >> "${binname}.1.md.draft"

	cat <<EOF >> "${binname}.1.md.draft"

# DIAGNOSTICS

Returns zero on normal operation, non-zero on errors.

# SEE ALSO

**pgpid**(1), **pgpid-gen**(1), **pgpid-qrscan**(1),
[**bash-libs**](//codeberg.org/foopgp/bash-libs/src/branch/main/man/bash-libs.7.md)(7).

Each action takes a **--help** of its own, which says more than this page:

    pgpid certify --help

# AUTHORS

foopgp <info@foopgp.org>, Jean-Jacques Brucker <jjbrucker@foopgp.org>.

EOF

	# Ask for erasing previous man
	if ! colordiff --report-identical-files --unified "${binname}.1.md" "${binname}.1.md.draft" ; then
		mv -i "${binname}.1.md.draft" "${binname}.1.md" || true
	else
		rm -v "${binname}.1.md.draft"
	fi
done
