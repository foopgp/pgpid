#!/bin/bash
#
# What `pgpid-gen` writes into pgpid.json.
#
# © 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>
# Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only
#
# The function lives in bash-libs now; pgpid-gen calls it at the end of a run
# to record everything it gathered. What is checked here is the escaping,
# because that file is the only machine-readable trace of a generation and a
# quote in the wrong place makes it unreadable.
#
# Compared as a sorted set of lines: a bash associative array does not iterate
# in any promised order, and a byte-exact reference would fail on the day the
# hash table decides otherwise.
#
# Open, and not ours to close: given an array with holes — a[0] a[3] a[12] —
# this returns a dense JSON array with empty strings where the holes were,
# losing the indices. It used to return an object keyed by index. Nothing in
# pgpid passes a sparse array, so nothing here breaks; whether bash-libs meant
# to change that is a question for bash-libs.

set -eo pipefail

here=$(dirname "$(readlink --canonicalize "$0")")
if ! source "$here/../bash-libs/bin/bl-json" >/dev/null 2>&1 ; then
	echo "bl-json not found — run: git submodule update --init" >&2
	exit 77
fi

declare -A m=(
	[nom]="tableau associatif"
	[accents]="où très"
	[echappes]='avec\t des tab\r'
	[reels]=$'avec\t une vraie tab\r'
	[slash]='sa/crément"'
	[multi]=$'deux\nlignes'
	[apostrophe]="le b'del"
	[vide]=""
)

expected() {
	cat <<-'JSON'
		{
		"m":{
		"accents": "où très",
		"apostrophe": "le b'del",
		"echappes": "avec\\t des tab\\r",
		"multi": "deux\nlignes",
		"nom": "tableau associatif",
		"reels": "avec\t une vraie tab\r",
		"slash": "sa\/crément\"",
		"vide": ""
		}
		}
	JSON
}

# Indentation and the trailing comma both depend on where a line landed, and
# sorting moves lines. What is compared is each pair, not its place in a list.
tidy() { sed 's/^[[:space:]]*// ; s/,$//' | sort ; }

if diff --unified <(expected | tidy) <(bl_json_from_var --nested m | tidy) ; then
	echo "ok    pgpid-gen's JSON escaping is unchanged"
	exit 0
fi
echo "FAIL  pgpid-gen's JSON escaping moved" >&2
exit 1
