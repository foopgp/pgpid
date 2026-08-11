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
for value in never marginal full ultimate ; do
    got=$("$BIN" ownertrust --replace-to "$value" "$FPR")
    is "--replace-to $value"      "$got" "$value"
done
# One rung, two spellings: undefined is what gets written, unknown is what
# comes back, and the engine keeps no third state between them.
got=$("$BIN" ownertrust --replace-to undefined "$FPR")
is "--replace-to undefined reads back as unknown" "$got" "unknown"
"$BIN" ownertrust --replace-to nonsense "$FPR" >/dev/null 2>&1
is "refuses a value it does not know" "$?" "2"
"$BIN" ownertrust --replace-to unknown "$FPR" >/dev/null 2>&1
is "refuses to set unknown, which is an absence" "$?" "2"
"$BIN" ownertrust >/dev/null 2>&1
is "refuses to run without a target"  "$?" "2"
"$BIN" ownertrust 0000000000000000000000000000000000000000 >/dev/null 2>&1
is "says 141 for a certificate it has not" "$?" "141"

printf '\nproperty\n'
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-add-uid "$FPR" 'FN:Ada Lovelace' 2>/dev/null
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-add-uid "$FPR" 'URL:https://example.invalid/a' 2>/dev/null
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-add-uid "$FPR" 'URL:https://example.invalid/b' 2>/dev/null
# The comma is escaped in the uid, as RFC 6350 asks, and must come back plain.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-add-uid "$FPR" 'NOTE:one\, two' 2>/dev/null

is "reads a singular property"    "$("$BIN" property name "$FPR")" "Ada Lovelace"
is "reads every value of a repeatable one" "$("$BIN" property url "$FPR" | wc --lines)" "2"
is "unescapes what vCard escaped" "$("$BIN" property note "$FPR")" "one, two"
is "--info names the property"    "$("$BIN" property name --info "$FPR" 2>/dev/null || "$BIN" property --info name "$FPR")" "name=Ada Lovelace"
"$BIN" property phone "$FPR" >/dev/null 2>&1
is "says 141 for one it does not carry" "$?" "141"
"$BIN" property nonsense "$FPR" >/dev/null 2>&1
is "refuses a property it does not know" "$?" "2"

printf '\nsigs\n'
# A second certificate, which certifies the first: the smallest web of trust
# that has an edge in it.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key "witness <witness@example.invalid>" ed25519 cert never 2>/dev/null
WFPR=$(gpg --with-colons --list-keys witness@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
WKEYID=${WFPR: -16}
gpg --batch --yes --quiet --passphrase '' --pinentry-mode loopback \
    --default-key "$WFPR" --quick-sign-key "$FPR" >/dev/null 2>&1

out=$("$BIN" sigs "$FPR")
is "finds the one certifier"      "$(wc --lines <<<"$out")" "1"
is "names it by key identifier"   "$(awk '{print $2}' <<<"$out")" "$WKEYID"
is "dates it"                     "$(awk '{print $1}' <<<"$out" | grep --count --extended-regexp '^[0-9]{4}-[0-9]{2}-[0-9]{2}$')" "1"
out=$("$BIN" sigs --info "$FPR")
is "--info gives key=value"       "$(grep --only-matching "keyid=${WKEYID}" <<<"$out")" "keyid=${WKEYID}"
is "merging every uid says the same" "$("$BIN" sigs --all-uids "$FPR" | wc --lines)" "1"
# The witness signed nobody, and its own self-signature must not count.
"$BIN" sigs "$WFPR" >/dev/null 2>&1
is "leaves self-signatures out"   "$?" "141"

printf '\ndel\n'
"$BIN" del "not-a-fingerprint" >/dev/null 2>&1
is "refuses anything but a fingerprint" "$?" "2"
"$BIN" del "$FPR" "not-a-fingerprint" >/dev/null 2>&1
is "checks every target before deleting any" "$?" "2"
is "and deleted nothing"          "$("$BIN" list "$FPR" | wc --lines)" "1"
"$BIN" del --secret "$FPR" >/dev/null 2>&1
is "--secret keeps the certificate"  "$("$BIN" list "$FPR" | wc --lines)" "1"
is "and drops the secret part"    "$(gpg --list-secret-keys "$FPR" 2>/dev/null | wc --lines)" "0"
"$BIN" del "$FPR" >/dev/null 2>&1
is "deletes the certificate"      "$?" "0"
is "and it is gone"               "$("$BIN" list "$FPR" 2>/dev/null | wc --lines)" "0"
"$BIN" del "$FPR" >/dev/null 2>&1
is "says 141 for one it has not"  "$?" "141"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
