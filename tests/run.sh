#!/bin/bash
# pgpid — checks that run against a keyring of their own.
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

BIN=${1:-./build/pgpid}
[[ -x "$BIN" ]] || { printf 'run.sh: Error: no binary at %s\n' "$BIN" >&2 ; exit 2 ; }
BIN=$(readlink --canonicalize "$BIN")

GNUPGHOME=$(mktemp --directory --tmpdir pgpid-check.XXXXXX)
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
out=$("$BIN" --output-format=info list)
is "info format gives key=value"  "$(grep --only-matching "eid=${EID}" <<<"$out")" "eid=${EID}"
"$BIN" list "no-such-certificate" >/dev/null 2>&1
is "says nothing found with 141"  "$?" "141"

out=$("$BIN" list "$FPR")
is "says it is certified: we hold its secret" "$(awk '{print $5}' <<<"$out")" "certified"
is "says the credibility in words"            "$(awk '{print $6}' <<<"$out")" "ultimate"
is "dates its creation"       "$(awk '{print $7}' <<<"$out" | grep --count --extended-regexp '^[0-9]{4}-[0-9]{2}-[0-9]{2}$')" "1"
is "leaves no expiry as a dash"               "$(awk '{print $8}' <<<"$out")" "-"
is "leaves no revocation as a dash"           "$(awk '{print $9}' <<<"$out")" "-"
is "--hide-trust says nothing of it"          "$("$BIN" list --hide-trust "$FPR" | awk '{print $6}')" "-"
is "--machine-readable gives seconds"         "$("$BIN" list --machine-readable "$FPR" | awk '{print $7}' | grep --count --extended-regexp '^[0-9]+$')" "1"
is "--machine-readable gives a flag"          "$("$BIN" list --machine-readable "$FPR" | awk '{print $5}')" "u"

# A certificate with no entity identifier is broken, and only -L says otherwise.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key 'Nobody <nobody@example.invalid>' ed25519 cert never 2>/dev/null
NFPR=$(gpg --with-colons --list-keys nobody@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
is "calls a certificate with no eid broken"   "$("$BIN" list "$NFPR" | awk '{print $5}')" "broken"
is "-L stops calling it broken"               "$("$BIN" list -L "$NFPR" | awk '{print $5}')" "certified"

printf '\noutput formats\n'
is "info gives key=value"     "$("$BIN" --output-format=info list "$FPR" | grep --only-matching 'validity=certified')" "validity=certified"
is "md opens a table"         "$("$BIN" --output-format=md list "$FPR" | head --lines=1 | cut --characters=1-15)" "| fingerprint  "
is "md rules its header"      "$("$BIN" --output-format=md list "$FPR" | sed --quiet '2p' | cut --characters=1-3)" "| -"
is "md closes every row"      "$("$BIN" --output-format=md list "$FPR" | tail --lines=1 | rev | cut --characters=1)" "|"
"$BIN" --output-format=nonsense list >/dev/null 2>&1
is "refuses a format it does not know" "$?" "2"

printf '\ntrustdb local\n'
# Every line names the certificate it speaks of, so that reading one and
# reading the whole keyring parse the same way.
# A freshly generated key is ultimate: gpg trusts what it holds the secret of.
is "reads the generated key"      "$("$BIN" trustdb local "$FPR")" "$FPR  ultimate"
for value in never marginal full ultimate ; do
    got=$("$BIN" trustdb local --replace-to "$value" "$FPR")
    is "--replace-to $value"      "$got" "$FPR  $value"
done
# One rung, two spellings: undefined is what gets written, unknown is what
# comes back, and the engine keeps no third state between them.
got=$("$BIN" trustdb local --replace-to undefined "$FPR")
is "--replace-to undefined reads back as unknown" "$got" "$FPR  unknown"
# No target is the whole keyring, not a mistake.
is "no argument reads every certificate" \
    "$("$BIN" trustdb local | grep --count "^$FPR ")" "1"
# --long adds columns to the right; what was at $2 is still at $2.
got=$("$BIN" trustdb local --long "$FPR")
is "--long keeps the credibility where it was" "$(awk '{print $1, $2}' <<<"$got")" "$FPR unknown"
is "--long adds the identifier then the address" "$(awk '{print NF}' <<<"$got")" "4"
# --check recomputes after answering, which is what a page showing verdicts
# needs: gpg only marks its database stale when a credibility moves.
is "--check answers, then recomputes" \
   "$("$BIN" trustdb local --check "$FPR" 2>/dev/null)" "$FPR  unknown"
is "--update takes the same word"     "$("$BIN" trustdb local --update "$FPR" >/dev/null 2>&1 ; echo $?)" "0"
"$BIN" trustdb local --replace-to nonsense "$FPR" >/dev/null 2>&1
is "refuses a value it does not know" "$?" "2"
"$BIN" trustdb local --replace-to unknown "$FPR" >/dev/null 2>&1
is "refuses to set unknown, which is an absence" "$?" "2"
# Deciding needs something to decide about: the whole keyring is a reading,
# never a writing.
"$BIN" trustdb local --replace-to full >/dev/null 2>&1
is "refuses to set without a target"  "$?" "2"
"$BIN" trustdb local 0000000000000000000000000000000000000000 >/dev/null 2>&1
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
is "info format names the property" "$("$BIN" --output-format=info property name "$FPR")" "name=Ada Lovelace"
# An empty property is an answer, not a failure. 141 is reserved for a search
# that matched no certificate — foodjis surfaces any non-zero code as an error,
# and a contact with no phone number is not an error.
out=$("$BIN" property phone "$FPR" 2>/dev/null) ; rv=$?
is "says 0 for a property it does not carry" "$rv" "0"
is "and prints nothing"                      "$out" ""
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
out=$("$BIN" --output-format=info sigs "$FPR")
is "info format gives key=value"  "$(grep --only-matching "keyid=${WKEYID}" <<<"$out")" "keyid=${WKEYID}"
is "merging every uid says the same" "$("$BIN" sigs --all-uids "$FPR" | wc --lines)" "1"
# The witness signed nobody, and its own self-signature must not count.
"$BIN" sigs "$WFPR" >/dev/null 2>&1
is "leaves self-signatures out"   "$?" "141"

printf '\navatar\n'
# A certificate wearing two standing images is out of spec and it happened:
# one arrived on 2026-08-20, and the reader that took whichever packet came
# first showed a scan of an identity card instead of the portrait its owner
# had set a week later. addphoto rather than a replace, so that both stand.
if command -v gm >/dev/null 2>&1 ; then
    gm convert -size 180x180 'xc:#204080' jpeg:"$GNUPGHOME/old.jpg"
    gm convert -size 180x180 'xc:#c04020' jpeg:"$GNUPGHOME/new.jpg"
    pixels() { gm convert "$1" -depth 8 rgb:- | md5sum | cut --characters=1-32 ; }
    is "says 141 before there is one" \
       "$("$BIN" avatar --workdir "$GNUPGHOME" "$FPR" >/dev/null 2>&1 ; echo $?)" "141"
    for f in old new ; do
        gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
            --command-fd 0 --edit-key "$FPR" >/dev/null 2>&1 \
            <<<$'addphoto\n'"$GNUPGHOME/$f.jpg"$'\ny\nsave\n'
        sleep 1
    done
    out=$("$BIN" avatar --workdir "$GNUPGHOME" "$FPR")
    is "prints one path"              "$(wc --lines <<<"$out")" "1"
    is "and it is the newest image"   "$(pixels "$out")" "$(pixels "$GNUPGHOME/new.jpg")"
    out=$("$BIN" avatar --workdir "$GNUPGHOME" --extract-all "$FPR")
    is "--extract-all gives both"     "$(wc --lines <<<"$out")" "2"
    is "newest still first"           "$(pixels "$(sed 1q <<<"$out")")" "$(pixels "$GNUPGHOME/new.jpg")"
    is "then the older one"           "$(pixels "$(sed 2q <<<"$out" | tail --lines=1)")" "$(pixels "$GNUPGHOME/old.jpg")"
    is "names the file by packet order" "$(basename "$(sed 1q <<<"$out")")" "$FPR-2.jpg"

    # Writing. A fingerprint is required because revoking cannot be undone,
    # and a 400x300 image proves the resize happens on the way in.
    is "refuses a search as a target" \
       "$("$BIN" avatar --workdir "$GNUPGHOME" --replace-to "$GNUPGHOME/new.jpg" alice >/dev/null 2>&1 ; echo $?)" "2"
    gm convert -size 400x300 'xc:#7f5f2a' jpeg:"$GNUPGHOME/wide.jpg"
    "$BIN" avatar --workdir "$GNUPGHOME" --keyservers '' --replace-to "$GNUPGHOME/wide.jpg" "$FPR" >/dev/null 2>&1
    is "replace-to succeeds"          "$?" "0"
    out=$("$BIN" avatar --workdir "$GNUPGHOME" "$FPR")
    # Resized the same way here, so the assertion is about the image that
    # reached the certificate and not about where a temporary file landed.
    gm convert -geometry '180^' -gravity center -extent 180 -strip \
       "$GNUPGHOME/wide.jpg" jpeg:"$GNUPGHOME/wide-180.jpg"
    is "and it is the new image now"  "$(pixels "$out")" "$(pixels "$GNUPGHOME/wide-180.jpg")"
    is "brought to 180x180"           "$(gm identify -format '%wx%h' "$out")" "180x180"
    is "the two others were taken back" \
       "$(gpg --with-colons --list-key "$FPR" 2>/dev/null | grep --count '^uat:r')" "2"
    # Publishing is what happens unless told otherwise, so every write above
    # names nowhere. Here the address is a closed port: the attempt is proven
    # without a throwaway key reaching a real keyserver.
    is "refuses --keyservers with no change to publish" \
       "$("$BIN" avatar --workdir "$GNUPGHOME" --keyservers 'hkp://127.0.0.1:1' "$FPR" >/dev/null 2>&1 ; echo $?)" "2"
    out=$("$BIN" avatar --workdir "$GNUPGHOME" --revoke --keyservers 'hkp://127.0.0.1:1' "$FPR" 2>&1)
    is "says which server refused"    "$(grep --count 'would not take it' <<<"$out")" "1"
    "$BIN" avatar --workdir "$GNUPGHOME" --keyservers '' --revoke "$FPR" >/dev/null 2>&1
    is "--revoke takes the last one back" \
       "$("$BIN" avatar --workdir "$GNUPGHOME" "$FPR" >/dev/null 2>&1 ; echo $?)" "141"
else
    printf '  skip  no graphicsmagick to make test images with\n'
fi

printf '\nlist --short\n'
# The contract is not "similar to `get --no-fetch`" but indistinguishable
# from it: one line per address, fingerprint and identifier inside eighty
# columns — a dash when there is no identifier, or more than one — then the
# address. Both come out of one printer, so the two cannot drift apart; these
# checks pin the shape itself.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-add-uid "$FPR" 'Ada <Ada@Example.Invalid>' 2>/dev/null
out=$("$BIN" list --short "$FPR")
is "one line per address"          "$(grep --count . <<<"$out")" "1"
is "fingerprint first"             "$(awk '{print $1}' <<<"$out")" "$FPR"
is "identifier second"             "$(awk '{print $2}' <<<"$out")" "$EID"
is "and it starts at column 42"    "$(awk '{print index($0, "u5")}' <<<"$out")" "42"
is "address in column 82"          "$(awk '{print index($0, "ada@")}' <<<"$out")" "82"
is "lowercased, as gpg reports it" "$(awk '{print $3}' <<<"$out")" "ada@example.invalid"
is "no identifier prints a dash"   "$("$BIN" list --short "$NFPR" | awk '{print $2}')" "-"
is "a uid without an address is not one" \
   "$("$BIN" list --short "$FPR" | grep --count 'FN:')" "0"

printf '\nget\n'
# get and list --short print the same thing; what differs is that get insists
# on being told what to look for, and refreshes before answering.
is "insists on a search term"      "$("$BIN" get >/dev/null 2>&1 ; echo $?)" "2"
is "'*' means the whole keyring"   "$("$BIN" get --no-fetch '*' | grep --count .)" "$("$BIN" list --short | grep --count .)"
is "same answer as list --short"   "$("$BIN" get --no-fetch "$FPR")" "$("$BIN" list --short "$FPR")"
is "--fingerprint keeps one column" \
   "$("$BIN" get --no-fetch --fingerprint "$FPR")" "$FPR"
is "--email keeps the other"       "$("$BIN" get --no-fetch --email "$FPR")" "ada@example.invalid"
# The global format drives get too, and raw is left exactly as the shell has
# always printed it: the address at column 82, whatever the identifier's width.
is "md names the three columns" \
   "$("$BIN" --output-format=md get --no-fetch "$FPR" | head --lines=1 | tr --squeeze-repeats ' ' | tr --delete '| ')" \
   "fingerprinteidemail"
is "info names them, tab separated" \
   "$("$BIN" --output-format=info get --no-fetch "$FPR" \
      | awk --field-separator='\t' '{print NF, $1 ~ /^fingerprint=/, $2 ~ /^eid=/, $3 ~ /^email=/}')" \
   "3 1 1 1"
is "info follows --email down to one" \
   "$("$BIN" --output-format=info get --no-fetch --email "$FPR")" "email=ada@example.invalid"
is "raw keeps the address at column 82" \
   "$("$BIN" get --no-fetch "$FPR" | awk '{print index($0, "ada@example.invalid")}')" "82"
is "says 141 for what it has not"  "$("$BIN" get --no-fetch nobody@example.test >/dev/null 2>&1 ; echo $?)" "141"
is "--errexit-g=1 accepts one"     "$("$BIN" get --no-fetch --errexit-g=1 "$FPR" >/dev/null 2>&1 ; echo $?)" "0"
is "--errexit-g=1 refuses two"     "$("$BIN" get --no-fetch --errexit-g=1 '*' >/dev/null 2>&1 ; echo $?)" "1"
# Nowhere is named, so no test key reaches a real keyserver.
is "an empty keyserver list asks nobody" \
   "$("$BIN" get --keyservers '' "$FPR" >/dev/null 2>&1 ; echo $?)" "0"

printf '\ngen_u4\n'
# Fictional civil statuses only: a test file is a public thing, and a real
# date of birth in one is a real date of birth published. The values are what
# bl-pgpid produces for the same input, so a change of rule shows up here.
u4() { "$BIN" gen_u4 --surname "$1" --given-names "$2" --birth-date "$3" --birth-country "$4" 2>/dev/null ; }
is "a plain civil status"        "$(u4 DOE John 1970-01-01 FRA)" "NgSm8XXwb5v3PCJ8pUmwNQe_42.17-002.76"
is "keeps only the last surname component" \
   "$(u4 'DE LA TOUR' 'Marie Claire' 1980-06-15 FRA)" "$(u4 'TOUR' 'Marie Claire' 1980-06-15 FRA)"
is "keeps only two given names"  "$(u4 SMITH 'Alan Mathison Turing' 1912-06-23 GBR)" \
                                 "$(u4 SMITH 'Alan Mathison' 1912-06-23 GBR)"
is "a hyphen separates as a space does" \
   "$(u4 'PENA-NIETO' Enrique 1966-10-20 MEX)" "$(u4 'PENA NIETO' Enrique 1966-10-20 MEX)"
# Transliteration is the draft's rule and not iconv's: deterministic, and the
# same wherever it runs. The shell's depends on installed locales — the same
# civil status yields an identifier under fr_FR and an error under LC_ALL=C.
is "accents go, letters stay"    "$(u4 'MÜLLER' 'Jürgen Karl' 1970-01-01 DEU)" \
                                 "$(u4 'MULLER' 'Jurgen Karl' 1970-01-01 DEU)"
is "case does not matter"        "$(u4 'peña-nieto' 'enrique' 1966-10-20 MEX)" \
                                 "$(u4 'PEÑA-NIETO' 'Enrique' 1966-10-20 MEX)"
is "the country decides the tail" "$(u4 DOE John 1970-01-01 FRA | cut --characters=23-)" "e_42.17-002.76"
is "an unknown country is refused" \
   "$("$BIN" gen_u4 -s DOE -g John -d 1970-01-01 -c ZZZ >/dev/null 2>&1 ; echo $?)" "2"
is "an impossible date is refused" \
   "$("$BIN" gen_u4 -s DOE -g John -d 2026-02-30 -c FRA >/dev/null 2>&1 ; echo $?)" "2"
is "a leap day is not"           "$("$BIN" gen_u4 -s DOE -g John -d 2024-02-29 -c FRA >/dev/null 2>&1 ; echo $?)" "0"
is "everything is required"      "$("$BIN" gen_u4 -s DOE >/dev/null 2>&1 ; echo $?)" "2"

printf '\nto_vcard\n'
# Self-sufficient: earlier blocks revoke what they add, so this one puts back
# the address and the image it means to look for rather than depending on the
# order the file happens to be in.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-add-uid "$FPR" 'Ada <ada@example.invalid>' 2>/dev/null
gm convert -size 180x180 'xc:#3a6ea5' jpeg:"$GNUPGHOME/card.jpg" 2>/dev/null
"$BIN" avatar --workdir "$GNUPGHOME" --keyservers '' --replace-to "$GNUPGHOME/card.jpg" "$FPR" >/dev/null 2>&1
card=$("$BIN" to_vcard "$FPR")
is "opens and closes a vCard 4.0"  "$(printf '%s' "$card" | head --lines=2 | tr -d '\r' | tr '\n' ' ')" "BEGIN:VCARD VERSION:4.0 "
is "carries the identifier"        "$(grep --count "UID:urn:eid:$EID" <<<"$card")" "1"
is "carries the address"           "$(grep --count 'EMAIL;PREF=1:ada@example.invalid' <<<"$card")" "1"
is "carries the key inline"        "$(grep --count '^KEY:data:application/pgp-keys;base64,' <<<"$card")" "1"
is "and where to fetch it"         "$(grep --count '^KEY;MEDIATYPE=' <<<"$card")" "1"
is "and the photograph"            "$(grep --count '^PHOTO:data:image/jpeg;base64,' <<<"$card")" "1"
# RFC 6350 §3.2 asks for at most 75 octets per line, and never a fold inside
# a UTF-8 character — a reader given half a character shows a broken glyph.
is "no line beyond 75 octets"      "$(awk '{ sub(/\r$/,"") ; if (length($0) > 75) n++ } END { print n+0 }' <<<"$card")" "0"
is "--raw prints the uids instead" "$(grep --count 'BEGIN:VCARD' <<<"$("$BIN" to_vcard --raw "$FPR")")" "0"
# FN is required and singular (RFC 6350 §6.2.1). Ours carry it as a uid;
# certificates from elsewhere do not, and the shell emitted cards without it
# for 117 of the 122 it produced — files no reader should accept. So: the
# certificate's own FN, or one read off the name a uid carries, or no card.
is "always carries FN"             "$(grep --count '^FN[;:]' <<<"$card")" "1"
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key 'Grace Hopper <grace@example.invalid>' ed25519 cert never 2>/dev/null
GFPR=$(gpg --with-colons --list-keys grace@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
is "derives FN from the uid name"  "$("$BIN" to_vcard "$GFPR" | grep --only-matching '^FN:.*' | tr -d '\r')" "FN:Grace Hopper"
is "and still carries the address" "$("$BIN" to_vcard "$GFPR" | grep --count 'EMAIL;PREF=1:grace@example.invalid')" "1"
is "a bare 'Nobody' is a name"     "$("$BIN" to_vcard "$NFPR" | grep --only-matching '^FN:.*' | tr -d '\r')" "FN:Nobody"
# A uid holding nothing but an address has no name to show, and a card that
# would say who this is cannot be written.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback --allow-freeform-uid \
    --quick-generate-key '<anon@example.invalid>' ed25519 cert never 2>/dev/null
AFPR=$(gpg --with-colons --list-keys anon@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
is "no name at all means no card"  "$("$BIN" to_vcard "$AFPR" >/dev/null 2>&1 ; echo $?)" "141"
is "--output writes a file"        "$("$BIN" to_vcard --output "$GNUPGHOME/c.vcf" "$FPR" >/dev/null 2>&1 ; grep --count 'BEGIN:VCARD' "$GNUPGHOME/c.vcf")" "1"
# The card and the avatar must show the same face: the photograph is chosen
# by the rule `avatar` uses, not by packet order.
is "the card shows the avatar"     "$(grep --only-matching --extended-regexp '^PHOTO:data:image/jpeg;base64,.{40}' <<<"$card")" \
                                   "PHOTO:data:image/jpeg;base64,$(base64 --wrap=0 < "$("$BIN" avatar --workdir "$GNUPGHOME" "$FPR")" | cut --characters=1-40)"

printf '\ngen_u4 --from-passport-mrz\n'
# A specimen zone: 'Anna Maria Eriksson' is ICAO's own example and nobody's
# real passport. The country is changed to one the table knows.
MRZ='P<FRAERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<L898902C36FRA7408122F1204159ZE184226B<<<<<10'
is "reads a passport zone"        "$("$BIN" gen_u4 --from-passport-mrz --uncheck "$MRZ")" "d5lxCVBGwMMSrx3sAJrgZQe_42.17-002.76"
# The point of reading a passport at all: it must agree with the same civil
# status typed by hand, or the document is useless.
is "agrees with the civil status typed" \
   "$("$BIN" gen_u4 --from-passport-mrz --uncheck "$MRZ")" \
   "$("$BIN" gen_u4 -s ERIKSSON -g 'Anna Maria' -d 1974-08-12 -c FRA)"
is "the zone may arrive in two pieces" \
   "$("$BIN" gen_u4 --from-passport-mrz --uncheck "${MRZ:0:44}" "${MRZ:44}")" "$("$BIN" gen_u4 --from-passport-mrz --uncheck "$MRZ")"
is "spaces and newlines are layout" \
   "$("$BIN" gen_u4 --from-passport-mrz --uncheck "${MRZ:0:44} ${MRZ:44}")" "$("$BIN" gen_u4 --from-passport-mrz --uncheck "$MRZ")"
is "a failing check digit refuses"  "$("$BIN" gen_u4 --from-passport-mrz "$MRZ" >/dev/null 2>&1 ; echo $?)" "1"
is "--uncheck warns and goes on"    "$("$BIN" gen_u4 --from-passport-mrz --uncheck "$MRZ" >/dev/null 2>&1 ; echo $?)" "0"
is "not a passport is refused"      "$("$BIN" gen_u4 --from-passport-mrz 'X<FRAX' >/dev/null 2>&1 ; echo $?)" "1"
is "a short zone is refused"        "$("$BIN" gen_u4 --from-passport-mrz 'P<FRAERIKSSON' >/dev/null 2>&1 ; echo $?)" "1"
is "wants a zone at all"            "$("$BIN" gen_u4 --from-passport-mrz >/dev/null 2>&1 ; echo $?)" "2"
# Two digits cannot say which century, so anyone born before 1969 needs their
# date given. Without it the same zone reads as 2030 rather than 1930.
is "--birth-date overrides the two digits" \
   "$("$BIN" gen_u4 --from-passport-mrz --uncheck --birth-date 1930-11-16 "$MRZ")" \
   "$("$BIN" gen_u4 -s ERIKSSON -g 'Anna Maria' -d 1930-11-16 -c FRA)"
# One action, two sources of the same four fields — so an option of the other
# source completes the zone rather than fighting it. The documented failure is
# a surname truncated to fit, and correcting it must not mean typing the rest
# of the document again.
is "a typed surname replaces the zone's" \
   "$("$BIN" gen_u4 --from-passport-mrz --uncheck -s ANDERSSON "$MRZ")" \
   "$("$BIN" gen_u4 -s ANDERSSON -g 'Anna Maria' -d 1974-08-12 -c FRA)"
is "typed given names replace the zone's" \
   "$("$BIN" gen_u4 --from-passport-mrz --uncheck -g 'Eva Lisa' "$MRZ")" \
   "$("$BIN" gen_u4 -s ERIKSSON -g 'Eva Lisa' -d 1974-08-12 -c FRA)"
is "a typed country replaces the zone's" \
   "$("$BIN" gen_u4 --from-passport-mrz --uncheck -c DEU "$MRZ")" \
   "$("$BIN" gen_u4 -s ERIKSSON -g 'Anna Maria' -d 1974-08-12 -c DEU)"
# All four replaced leaves nothing of the document but the fact that it was
# read: the same identifier as typing the civil status on its own.
is "all four typed is the typed way" \
   "$("$BIN" gen_u4 --from-passport-mrz --uncheck -s DOE -g John -d 1970-01-01 -c FRA "$MRZ")" \
   "$("$BIN" gen_u4 -s DOE -g John -d 1970-01-01 -c FRA)"
# --birth-date means one thing whichever way one is minting.
is "eight bare digits read as a date" \
   "$("$BIN" gen_u4 -s DOE -g John -d 19700101 -c FRA)" \
   "$("$BIN" gen_u4 -s DOE -g John -d 1970-01-01 -c FRA)"
is "refuses --uncheck without a zone" \
   "$("$BIN" gen_u4 --uncheck -s ERIKSSON -g 'Anna Maria' -d 1974-08-12 -c FRA >/dev/null 2>&1 ; echo $?)" "2"
is "refuses a bare argument without a zone" \
   "$("$BIN" gen_u4 "$MRZ" >/dev/null 2>&1 ; echo $?)" "2"

printf '\ngen_uid\n'
# The number an identifier gives is a promise: accounts have been opened with
# it, and two machines that never met must agree on it. So these are not
# "some plausible numbers" but the ones bl-pgpid produced, written down.
is "a u4 gives its number"        "$("$BIN" gen_uid 'u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76')" "1702501105"
is "a u5 gives its number"        "$("$BIN" gen_uid 'u5001777236237.945e_43.30_005.38')" "319780676"
is "the same one from a whole uid" \
   "$("$BIN" gen_uid 'UID:urn:eid:u5001777236237.945e_43.30_005.38')" "319780676"
is "--free-input takes a string"  "$("$BIN" gen_uid --free-input 'hello')" "669450302"
is "and refuses one without it"   "$("$BIN" gen_uid 'hello' >/dev/null 2>&1 ; echo $?)" "2"
is "wants something to work on"   "$("$BIN" gen_uid >/dev/null 2>&1 ; echo $?)" "2"
# The range is what keeps the number out of the way of system accounts and
# out of reach of software that reads it as signed.
n=$("$BIN" gen_uid 'u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76')
is "inside the range, low"        "$(( n >= 262144 ))" "1"
is "inside the range, high"       "$(( n <= 2147483646 ))" "1"
# MD5 itself is not tested separately here: every number above depends on it,
# so a wrong digest would move them all. Its RFC 1321 vectors were checked
# directly when it was written — see src/md5.c.

printf '\npush\n'
# Nowhere is named everywhere below: a key made for a test has no business
# reaching a real keyserver, and the one closed port proves the attempt.
is "wants a certificate"          "$("$BIN" push >/dev/null 2>&1 ; echo $?)" "2"
is "takes fingerprints, not searches" \
   "$("$BIN" push alice >/dev/null 2>&1 ; echo $?)" "2"
is "an empty list sends nothing, and says so" \
   "$("$BIN" push --keyservers '' "$FPR" >/dev/null 2>&1 ; echo $?)" "0"
out=$("$BIN" push --keyservers 'hkp://127.0.0.1:1' "$FPR" 2>&1)
is "names the server that refused" "$(grep --count 'would not take it' <<<"$out")" "1"
# One bad target among good ones stops the lot: half a broadcast cannot be
# taken back any more than a whole one.
out=$("$BIN" push --keyservers 'hkp://127.0.0.1:1' "$FPR" notafingerprint 2>&1)
is "checks every target before sending any" "$(grep --count 'Sending' <<<"$out")" "0"

printf '\ncertify\n'
# Only the refusals: certifying writes, and a check that writes into somebody
# else's certificate is a check that has to undo itself. The option carries
# two names — the clearer one, and the one gpg gave the concept, which is
# already in people's fingers — and both must reach the same validation.
for spelling in --credibility --ownertrust -o ; do
    "$BIN" certify "$spelling" nonsense "$FPR" >/dev/null 2>&1
    is "$spelling checks its value"  "$?" "2"
done


printf '\ntrustdb export\n'
# A signing key of its own: the keyring's certificate can only certify, and
# gpg will not sign a message with a key that has no signing capability.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key 'signer <signer@example.invalid>' ed25519 sign never 2>/dev/null
SFPR=$(gpg --with-colons --list-keys signer@example.invalid 2>/dev/null \
       | awk --field-separator=: '$1=="fpr"{print $10; exit}')
# Nothing sits at never, marginal or full yet. Ultimate says "this one is
# mine", which means nothing to anybody else, and unknown is the absence of a
# decision — neither is worth a signature.
"$BIN" trustdb export --use-privkey "$SFPR" --export-file "$GNUPGHOME/none.gpg" >/dev/null 2>&1
is "refuses when nothing was decided" "$?" "141"
"$BIN" trustdb local --replace-to marginal "$WFPR" >/dev/null 2>&1
"$BIN" trustdb export --use-privkey "$SFPR" --export-file "$GNUPGHOME/ot.gpg" >/dev/null 2>&1
is "signs what was decided"       "$?" "0"
is "binary unless asked"          "$(head --lines=1 "$GNUPGHOME/ot.gpg" | grep --count 'BEGIN PGP')" "0"
"$BIN" trustdb export --armor --use-privkey "$SFPR" --export-file "$GNUPGHOME/ot.asc" >/dev/null 2>&1
is "--armor gives the ASCII form" "$(head --lines=1 "$GNUPGHOME/ot.asc")" "-----BEGIN PGP MESSAGE-----"
# The two shapes carry the same thing; what changes is whether a git history
# can say what moved between two revisions of the file.
is "both carry the same decision" \
   "$(gpg --decrypt "$GNUPGHOME/ot.gpg" 2>/dev/null)" "$(gpg --decrypt "$GNUPGHOME/ot.asc" 2>/dev/null)"
is "which is the one taken"       "$(gpg --decrypt "$GNUPGHOME/ot.gpg" 2>/dev/null)" "$WFPR:4:"
"$BIN" trustdb export --use-privkey "$SFPR" somewhere.gpg >/dev/null 2>&1
is "takes no positional argument" "$?" "2"

printf '\ntrustdb import\n'
# Everything here is weighed offline: --keyservers '', so a check never
# reaches for a keyserver. The anchor first — the local block left this
# certificate undecided, and without an anchor an import is refused outright.
"$BIN" trustdb local --replace-to ultimate "$FPR" >/dev/null 2>&1
"$BIN" trustdb local --replace-to full "$WFPR" >/dev/null 2>&1
# The signer is the key made for the export checks: locally generated, so
# ultimate, so valid — which is what a delegation's signer has to be.
deleg() {
    printf '%s\n' "$@" > "$GNUPGHOME/d.txt"
    gpg --batch --yes --quiet --passphrase '' --pinentry-mode loopback \
        --default-key "$SFPR" --output "$GNUPGHOME/d.gpg" --sign "$GNUPGHOME/d.txt" 2>/dev/null
    "$BIN" trustdb import --keyservers '' "$GNUPGHOME/d.gpg" 2>&1
}
level() { "$BIN" trustdb local "$1" | awk '{print $2}' ; }

out=$(deleg "$WFPR:6:")
is "ultimate from somebody else is capped" "$(grep --count 'beyond full' <<<"$out")" "1"
is "and lands on full"            "$(level "$WFPR")" "full"
out=$(deleg "$WFPR:2:")
# An absence is not a decision, and saying so on every line would be noise.
is "no opinion changes nothing"   "$(level "$WFPR")" "full"
is "and is not worth a word"      "$(grep --count 'Info: .*d.gpg' <<<"$out")" "0"
out=$(deleg "$WFPR:4:")
is "less than we credit is left alone" "$(level "$WFPR")" "full"
is "and it is said"               "$(grep --count 'credits less' <<<"$out")" "1"
out=$(deleg "$FPR:5:")
is "a line about the anchor is left alone" "$(grep --count 'anchors' <<<"$out")" "1"
is "and the anchor stands"        "$(level "$FPR")" "ultimate"
# Never is the one verdict that comes downwards: it is a warning, and one
# worth hearing even from somebody who credits others generously.
out=$(deleg "$WFPR:3:")
is "never comes down through a full" "$(level "$WFPR")" "never"
is "and is said"                  "$(grep --count 'credit with nothing' <<<"$out")" "1"
out=$(deleg "$WFPR:5:")
is "nothing lifts it afterwards"  "$(level "$WFPR")" "never"
is "which is said, not swallowed" "$(grep --count 'ruled never' <<<"$out")" "1"

# Order is part of what a chain means, and now for the weighing too: the
# second file is judged against what the first decided, not against the state
# before either ran.
"$BIN" trustdb local --replace-to full "$WFPR" >/dev/null 2>&1
printf '%s:3:\n' "$WFPR" > "$GNUPGHOME/a.txt"
printf '%s:5:\n' "$WFPR" > "$GNUPGHOME/b.txt"
for f in a b ; do
    gpg --batch --yes --quiet --passphrase '' --pinentry-mode loopback \
        --default-key "$SFPR" --output "$GNUPGHOME/$f.gpg" --sign "$GNUPGHOME/$f.txt" 2>/dev/null
done
out=$("$BIN" trustdb import --keyservers '' "$GNUPGHOME/a.gpg" "$GNUPGHOME/b.gpg" 2>&1)
is "the second file is weighed after the first" "$(level "$WFPR")" "never"
is "and says what it left alone"   "$(grep --count 'ruled never' <<<"$out")" "1"

printf '\nprint_secret\n'
# The QR header spells the fragment's number as a single digit — `scan` reads
# it back that way — so more than ten fragments make sheets nobody can put
# together. Refused here rather than found out on paper.
"$BIN" print_secret --printer '' --split 11 --passphrase '' \
    --workdir "$GNUPGHOME" "$FPR" >/dev/null 2>&1
is "more fragments than a header can number is refused" "$?" "2"
"$BIN" print_secret --printer '' --split 2 --passphrase '' \
    --workdir "$GNUPGHOME" "$FPR" >/dev/null 2>&1
is "and fewer than three, as before"  "$?" "2"

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

printf '\ncertify — the two eid spellings\n'
# An eid given glued must find the certificate that still spells it with the
# deprecated separator: a uid is matched by substring, so one spelling never
# finds the other, and the certifier was told the person had no certificate.
# Asserted on the identification alone — what follows would write a signature.
# Both keys are its own: certifying writes, and writing on a certificate the
# other checks rely on would make them depend on the order they run in.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key "old (${EID:0:2}=${EID:2}) <old@example.invalid>" ed25519 cert never 2>/dev/null
OFPR=$(gpg --with-colons --list-keys old@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key 'certifier <certifier@example.invalid>' ed25519 cert never 2>/dev/null
CFPR=$(gpg --with-colons --list-keys certifier@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
"$BIN" certify --keyservers '' --use-privkey "$CFPR" "$OFPR" "$EID" >/dev/null 2>&1
is "finds an eid spelled the deprecated way"  "$?" "0"
# The refusals still stand. Somebody here carries this identifier, so a
# fingerprint that is not among them is 143 — "that certificate does not carry
# that identifier" — and not 141, which says nobody carries it at all.
"$BIN" certify --keyservers '' --use-privkey "$CFPR" 0000000000000000000000000000000000000000 "$EID" >/dev/null 2>&1
is "refuses a fingerprint that is not among them" "$?" "143"
"$BIN" certify --keyservers '' --use-privkey "$CFPR" "$NFPR" "$EID" >/dev/null 2>&1
is "refuses a certificate that does not carry it" "$?" "143"
"$BIN" certify --keyservers '' --use-privkey "$CFPR" "$NFPR" u4ZZZZZZZZZZZZZZZZZZZZZZe_42.17-002.76 >/dev/null 2>&1
is "says 141 when nobody carries the identifier"  "$?" "141"

# The identifier is taken however it is written and wherever it sits among the
# operands: the shell regexps its arguments rather than counting them, and a
# value read aloud off a card rarely comes with its tag.
for spelling in "$EID" "u5=${EID#u5}" "${EID#u5}" ; do
    "$BIN" --batch certify --keyservers '' --use-privkey "$CFPR" "$spelling" "$NFPR" >/dev/null 2>&1
    is "reads the identifier written '$spelling'"  "$?" "143"
done

# Nothing given at all: the question is asked, unless --batch says there is
# nobody to ask. 2 is a usage error — what was missing was an operand.
"$BIN" --batch certify --keyservers '' --use-privkey "$CFPR" >/dev/null 2>&1
is "--batch refuses instead of asking"            "$?" "2"
is "and says so rather than failing mutely" \
   "$("$BIN" --batch certify --keyservers '' --use-privkey "$CFPR" 2>&1 | grep --count -- '--batch')" "1"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
