#!/bin/bash
# pgpid-mip — checks that run against a keyring of their own.
#
# Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
# Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only
#
# Nothing here touches the caller's own keyring: a throwaway GNUPGHOME is
# built, used and removed. That is what makes the checks runnable by anyone,
# and what makes the ownertrust ones safe — they write.

set -u

BIN=${1:-./build/pgpid-mip}
[[ -x "$BIN" ]] || { printf 'run.sh: Error: no binary at %s\n' "$BIN" >&2 ; exit 2 ; }
BIN=$(readlink --canonicalize "$BIN")

GNUPGHOME=$(mktemp --directory --tmpdir pgpid-mip-check.XXXXXX)
export GNUPGHOME
chmod 700 "$GNUPGHOME"
trap 'gpgconf --homedir "$GNUPGHOME" --kill all >/dev/null 2>&1 ; rm -rf "$GNUPGHOME"' EXIT

pass=0 fail=0
ok()   { pass=$((pass+1)) ; printf '  ok    %s\n' "$1" ; }
nok()  { fail=$((fail+1)) ; printf '  FAIL  %s\n' "$1" ; [[ $# -lt 2 ]] || printf '        %s\n' "$2" ; }
is()   { [[ "$2" == "$3" ]] && ok "$1" || nok "$1" "expected '$3', got '$2'" ; }

printf 'Building a keyring in %s\n' "$GNUPGHOME"
# The identity uid is the standard shape, so the eid extraction is exercised
# on a certificate rather than on a string.
EID="u5001777236237.945e_43.30_005.38"
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key "UID:urn:eid:${EID}" ed25519 cert never 2>/dev/null \
  || { printf 'run.sh: Error: could not generate a key\n' >&2 ; exit 1 ; }
FPR=$(gpg --with-colons --list-keys 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
[[ "$FPR" ]] || { printf 'run.sh: Error: no fingerprint\n' >&2 ; exit 1 ; }

printf '\nlist\n'
out=$("$BIN" list)
is "finds the certificate"        "$(wc --lines <<<"$out")" "1"
is "prints its fingerprint"       "$(awk '{print $1}' <<<"$out")" "$FPR"
is "reads the eid off its uid"    "$(awk '{print $2}' <<<"$out")" "$EID"
out=$("$BIN" list --info)
is "--info gives key=value"       "$(grep --only-matching "eid=${EID}" <<<"$out")" "eid=${EID}"
"$BIN" list "no-such-certificate" >/dev/null 2>&1
is "says nothing found with 141"  "$?" "141"

printf '\nownertrust\n'
# A freshly generated key is ultimate: gpg trusts what it holds the secret of.
is "reads the generated key"      "$("$BIN" ownertrust "$FPR")" "ultimate"
# undefined is in the loop on purpose: gpgme reads it back as unknown, so
# this is the check that pgpid-mip goes to the trustdb rather than believing
# gpgme — see trustdb.c.
for value in undefined never marginal full ultimate ; do
    got=$("$BIN" ownertrust --replace-to "$value" "$FPR")
    is "--replace-to $value"      "$got" "$value"
done
"$BIN" ownertrust --replace-to nonsense "$FPR" >/dev/null 2>&1
is "refuses a value it does not know" "$?" "2"
"$BIN" ownertrust --replace-to unknown "$FPR" >/dev/null 2>&1
is "refuses to set unknown, which is an absence" "$?" "2"
"$BIN" ownertrust >/dev/null 2>&1
is "refuses to run without a target"  "$?" "2"
"$BIN" ownertrust 0000000000000000000000000000000000000000 >/dev/null 2>&1
is "says 141 for a certificate it has not" "$?" "141"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
