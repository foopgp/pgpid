#!/bin/bash
#
# SPDX-FileCopyrightText: 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
# SPDX-FileCopyrightText: 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Regenerate src/coordinates.c from bl-pgpid's own table.
#
# Two hundred and thirty-one entries are not worth retyping, and will not stay
# right if they are. Run this when the shell table changes; until bl-pgpid is
# obsolete, it is still the source.
#
# Usage: tools/gen-coordinates.sh [path/to/bl-pgpid] > src/coordinates.c
set -euo pipefail
BL=${1:-$HOME/git/foopgp/bash-libs/bin/bl-pgpid}
[[ -r "$BL" ]] || { printf '%s: cannot read %s\n' "${0##*/}" "$BL" >&2 ; exit 1 ; }
# shellcheck disable=SC1090
source "$BL" 2>/dev/null || true
(( ${#BL_PGPID_COORDINATES[@]} > 0 )) || { printf '%s: no table in %s\n' "${0##*/}" "$BL" >&2 ; exit 1 ; }
for c in $(printf '%s\n' "${!BL_PGPID_COORDINATES[@]}" | sort) ; do
    v="${BL_PGPID_COORDINATES[$c]}"
    printf '    { "%s", "%s" },  /* %s */\n' "$c" "${v:0:14}" "${v:15}"
done
