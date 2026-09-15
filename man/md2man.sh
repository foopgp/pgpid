#!/bin/sh
#
# SPDX-FileCopyrightText: 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
# SPDX-FileCopyrightText: 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only
#
# One markdown page to one roff page, on stdout.
#
# Usage: md2man.sh FILE.md [DATE]
#
# This was `pandoc --standalone --to=man`, which meant a hundred and ninety
# megabytes of Haskell in the build dependencies of a package whose own binary
# is a third of a megabyte. lowdown does the same job in three hundred
# kilobytes of C, and the rendered pages come out line for line the same.
#
# What it does not do is read the YAML block at the head of the file: to
# lowdown a `---` is a horizontal rule, and the four lines after it are a
# paragraph. So the block is cut here and its four values are handed over as
# metadata — which is also where they were going under pandoc, only silently.

set -eu

src="$1"
date="${2:-}"

# The first block delimited by --- lines, and nothing outside it: a later ---
# in the body is a rule and means nothing here.
meta() {
	sed -n "/^---\$/,/^---\$/{ /^$1: /{ s/^$1: //p ; q ; } }" "$src"
}

# Everything but that block. The generated pages open with an SPDX comment
# before it, which lowdown passes through as HTML and man ignores.
body() {
	awk 'BEGIN { inside = 0 ; done = 0 }
	     /^---$/ && !done && !inside { inside = 1 ; next }
	     /^---$/ &&  inside          { inside = 0 ; done = 1 ; next }
	     !inside                     { print }' "$src"
}

body | lowdown -s -Tman \
	-M "title=$(meta title)" \
	-M "section=$(meta section)" \
	-M "volume=$(meta header)" \
	-M "source=$(meta footer)" \
	${date:+-M "date=$date"}
