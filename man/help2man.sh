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

PATH="../bin:$PATH"

for bl in $(find ../bin/ -maxdepth 1 -type f) ; do
	binname="$(basename "$bl")"
	cat <<EOF > "${binname}.1.md.draft"
<!--
© 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>

SPDX-License-Identifier: GPL-3.0-only
-->

---
title: ${binname^^}
section: 1
header: User Commands
footer: pgpid $versionstring
---

EOF
	echo "help2man --no-info $binname --locale C.UTF-8 | pandoc -f man -t markdown >> ${binname}.1.md.draft" >&2
	help2man --no-info "$binname" --locale "C.UTF-8" --version-string "$versionstring" | pandoc -f man -t markdown >> "${binname}.1.md.draft"

	cat <<EOF >> "${binname}.1.md.draft"

# DIAGNOSTICS

Returns zero on normal operation, non-zero on errors.

# SEE ALSO

[**bash-libs**](//codeberg.org/foopgp/bash-libs/src/branch/main/man/bash-libs.7.md)(7),
[**bl-pgpid**](//codeberg.org/foopgp/bash-libs/src/branch/main/man/bl-pgpid.1.md)(1),
[**bl-qrkey**](//codeberg.org/foopgp/bash-libs/src/branch/main/man/bl-qrkey.1.md)(1).

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
