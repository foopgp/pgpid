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

# Every expectation here is an English string. Once the catalogues are
# installed, the binary speaks the caller's language and every one of them
# fails -- which says nothing about the code. C.UTF-8 keeps the messages
# English while leaving accented input alone; LANGUAGE has to go too, since
# gettext reads it in preference to LC_MESSAGES.
export LC_ALL=C.UTF-8
unset LANGUAGE

PGPI_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
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
out=$("$BIN" cert_list)
is "finds the certificate"        "$(wc --lines <<<"$out")" "1"
is "prints its fingerprint"       "$(awk '{print $1}' <<<"$out")" "$FPR"
is "reads the eid off its uid"    "$(awk '{print $2}' <<<"$out")" "$EID"
out=$("$BIN" --output-format=info cert_list)
is "info format gives key=value"  "$(grep --only-matching "eid=${EID}" <<<"$out")" "eid=${EID}"
"$BIN" cert_list "no-such-certificate" >/dev/null 2>&1
is "says nothing found with 141"  "$?" "141"

out=$("$BIN" cert_list "$FPR")
is "says it is certified: we hold its secret" "$(awk '{print $5}' <<<"$out")" "certified"
is "says the credibility in words"            "$(awk '{print $6}' <<<"$out")" "ultimate"
is "dates its creation"       "$(awk '{print $7}' <<<"$out" | grep --count --extended-regexp '^[0-9]{4}-[0-9]{2}-[0-9]{2}$')" "1"
is "leaves no expiry as a dash"               "$(awk '{print $8}' <<<"$out")" "-"
is "leaves no revocation as a dash"           "$(awk '{print $9}' <<<"$out")" "-"
is "--hide-trust says nothing of it"          "$("$BIN" cert_list --hide-trust "$FPR" | awk '{print $6}')" "-"
is "--machine-readable gives seconds"         "$("$BIN" cert_list --machine-readable "$FPR" | awk '{print $7}' | grep --count --extended-regexp '^[0-9]+$')" "1"
is "--machine-readable gives a flag"          "$("$BIN" cert_list --machine-readable "$FPR" | awk '{print $5}')" "u"

# A certificate with no entity identifier is broken, and only -L says otherwise.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key 'Nobody <nobody@example.invalid>' ed25519 cert never 2>/dev/null
NFPR=$(gpg --with-colons --list-keys nobody@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
is "calls a certificate with no eid broken"   "$("$BIN" cert_list "$NFPR" | awk '{print $5}')" "broken"
is "-L stops calling it broken"               "$("$BIN" cert_list -L "$NFPR" | awk '{print $5}')" "certified"

printf '\noutput formats\n'
is "info gives key=value"     "$("$BIN" --output-format=info cert_list "$FPR" | grep --only-matching 'validity=certified')" "validity=certified"
is "md opens a table"         "$("$BIN" --output-format=md cert_list "$FPR" | head --lines=1 | cut --characters=1-15)" "| fingerprint  "
is "md rules its header"      "$("$BIN" --output-format=md cert_list "$FPR" | sed --quiet '2p' | cut --characters=1-3)" "| -"
is "md closes every row"      "$("$BIN" --output-format=md cert_list "$FPR" | tail --lines=1 | rev | cut --characters=1)" "|"
"$BIN" --output-format=nonsense cert_list >/dev/null 2>&1
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
# undefined survives the round trip. It did not while this went through
# gpgme, whose parser knows n m f u and drops everything else onto unknown --
# the engine writes 2 and answers 'q', and that is what is read now.
got=$("$BIN" trustdb local --replace-to undefined "$FPR")
is "--replace-to undefined reads back as undefined" "$got" "$FPR  undefined"
# No target is the whole keyring, not a mistake.
is "no argument reads every certificate" \
    "$("$BIN" trustdb local | grep --count "^$FPR ")" "1"
# --long adds columns to the right; what was at $2 is still at $2.
got=$("$BIN" trustdb local --long "$FPR")
is "--long keeps the credibility where it was" "$(awk '{print $1, $2}' <<<"$got")" "$FPR undefined"
is "--long adds the identifier then the address" "$(awk '{print NF}' <<<"$got")" "4"
# --check recomputes after answering, which is what a page showing verdicts
# needs: gpg only marks its database stale when a credibility moves.
is "--check answers, then recomputes" \
   "$("$BIN" trustdb local --check "$FPR" 2>/dev/null)" "$FPR  undefined"
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

is "reads a singular property"    "$("$BIN" cert_property name "$FPR")" "Ada Lovelace"
is "reads every value of a repeatable one" "$("$BIN" cert_property url "$FPR" | wc --lines)" "2"
is "unescapes what vCard escaped" "$("$BIN" cert_property note "$FPR")" "one, two"
is "info format names the property" "$("$BIN" --output-format=info cert_property name "$FPR")" "name=Ada Lovelace"
# A certificate with no FN: uid at all, for the one absence a caller must be
# able to act on. Generated here rather than reusing the one above, which has
# a name and would have to lose it — and revoking a uid is irreversible.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key "Nameless <nameless@example.org>" ed25519 cert 2d 2>/dev/null
NONAME=$(gpg --with-colons --list-keys nameless@example.org 2>/dev/null \
         | awk --field-separator=: '$1=="fpr"{print $10; exit}')
# With a subkey, because that is what the expiry has to move along with it.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-add-key "$NONAME" ed25519 sign 2d 2>/dev/null

# An empty optional property is an answer, not a failure: foodjis surfaces any
# non-zero code as an error, and a contact with no phone number is not one. It
# is said all the same — silence and success together read as "done".
out=$("$BIN" cert_property phone "$FPR" 2>&1 >/dev/null) ; rv=$?
is "says 0 for an optional property it does not carry" \
   "$("$BIN" cert_property phone "$FPR" >/dev/null 2>&1 ; echo $?)" "0"
is "and says so rather than staying silent" "$(grep --count 'carries no phone' <<<"$out")" "1"
is "prints nothing on stdout"               "$("$BIN" cert_property phone "$FPR" 2>/dev/null)" ""
# The one property PGP ID requires. A caller has to be able to act on its
# absence, which it cannot do if the answer is the same as for a phone number.
is "but 141 for the name, which PGP ID requires" \
   "$("$BIN" cert_property name "$NONAME" >/dev/null 2>&1 ; echo $?)" "141"
"$BIN" cert_property nonsense "$FPR" >/dev/null 2>&1
is "refuses a property it does not know" "$?" "2"

# expire lives in the self-signature, not in a uid, and moves the primary key
# and every standing subkey together: prolonging the primary alone leaves an
# identity whose signing key died last year.
is "expire reads a date"  "$("$BIN" cert_property expire "$NONAME" | grep --count --extended-regexp '^[0-9]{4}-[0-9]{2}-[0-9]{2}$')" "1"
"$BIN" cert_property expire --replace-to 3y --keyservers '' "$NONAME" >/dev/null 2>&1
SUBEXP=$(gpg --with-colons --list-keys "$NONAME" | awk --field-separator=: '$1=="sub"{print $7; exit}')
is "and moves the primary" "$("$BIN" cert_property expire "$NONAME")" \
   "$(date --utc --date=@"$(gpg --with-colons --list-keys "$NONAME" | awk --field-separator=: '$1=="pub"{print $7; exit}')" +%Y-%m-%d)"
is "and the subkey with it"  "$(date --utc --date=@"$SUBEXP" +%Y-%m-%d)" "$("$BIN" cert_property expire "$NONAME")"
# Nothing lasts, so there is no way to ask for a certificate that does. Each
# of gpg's spellings for it is refused in the words somebody would have typed.
for forever in never 0 none ; do
    is "'$forever' is refused as an expiry" \
       "$("$BIN" cert_property expire --replace-to "$forever" --keyservers '' "$NONAME" >/dev/null 2>&1 ; echo $?)" "2"
done
is "and so is a date far enough off to mean the same" \
   "$("$BIN" cert_property expire --replace-to 2099-01-01 --keyservers '' "$NONAME" >/dev/null 2>&1 ; echo $?)" "2"
is "the date is still the one that was set" "$("$BIN" cert_property expire "$NONAME")" \
   "$(date --utc --date=@"$(gpg --with-colons --list-keys "$NONAME" | awk --field-separator=: '$1=="pub"{print $7; exit}')" +%Y-%m-%d)"
is "and expire cannot be revoked" \
   "$("$BIN" cert_property expire --revoke x "$NONAME" >/dev/null 2>&1 ; echo $?)" "2"

# OpenPGP flags one user id for the whole certificate, not one per address, so
# --set-primary moves a flag rather than setting one. On a certificate of its
# own: adding an address to the one above would change what every later check
# sees, which is how the first version of this block broke four of them.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key "Ada <first@example.org>" ed25519 cert never 2>/dev/null
ADA=$(gpg --with-colons --list-keys first@example.org 2>/dev/null \
      | awk --field-separator=: '$1=="fpr"{print $10; exit}')
"$BIN" cert_email --add second@example.org --yes --keyservers '' "$ADA" >/dev/null 2>&1

out=$("$BIN" cert_email "$ADA")
is "two addresses, each with a word after it" \
   "$(awk '{print NF}' <<<"$out" | sort --unique | tr -d '\n')" "2"
# None yet, and that is not a fault: gpg writes the primary subpacket only
# when somebody has had a reason to choose, so a certificate nobody has chosen
# for carries no flag at all. Reporting what the certificate says means
# reporting that too.
is "none is primary until somebody chooses" "$(grep --count 'primary$' <<<"$out")" "0"
"$BIN" cert_email --set-primary second@example.org --keyservers '' "$ADA" >/dev/null 2>&1
is "and the flag moves where it is told" \
   "$("$BIN" cert_email "$ADA" | awk '$2=="primary"{print $1}')" "second@example.org"
is "still exactly one" "$("$BIN" cert_email "$ADA" | grep --count 'primary$')" "1"
is "an address the certificate does not carry is refused" \
   "$("$BIN" cert_email --set-primary nobody@example.org --keyservers '' "$ADA" >/dev/null 2>&1 ; echo $?)" "141"
is "and the flag did not move" \
   "$("$BIN" cert_email "$ADA" | awk '$2=="primary"{print $1}')" "second@example.org"
is "info format names both columns" \
   "$("$BIN" --output-format=info cert_email "$ADA" | head -1 | grep --count --extended-regexp '^email=.*primary=')" "1"

# The preferred keyserver is written on the primary uid and re-asserts the flag
# there. It used to name uid 1 outright, which would have quietly moved the
# flag back the first time somebody set a keyserver after choosing an address.
"$BIN" cert_property ksprefrd --replace-to hkps://keys.foopgp.org --keyservers '' "$ADA" >/dev/null 2>&1
is "setting a keyserver leaves the primary where it was" \
   "$("$BIN" cert_email "$ADA" | awk '$2=="primary"{print $1}')" "second@example.org"
is "and the keyserver is set" "$("$BIN" cert_property ksprefrd "$ADA")" "hkps://keys.foopgp.org"

printf '\nsigs\n'
# A second certificate, which certifies the first: the smallest web of trust
# that has an edge in it.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key "witness <witness@example.invalid>" ed25519 cert never 2>/dev/null
WFPR=$(gpg --with-colons --list-keys witness@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
WKEYID=${WFPR: -16}
gpg --batch --yes --quiet --passphrase '' --pinentry-mode loopback \
    --default-key "$WFPR" --quick-sign-key "$FPR" >/dev/null 2>&1

out=$("$BIN" cert_sigs "$FPR")
# The witness, and the certificate's own signature, which counts now: onak
# counts it, and leaving it out made our number disagree with the keyserver's.
is "finds the certifier and the self-signature" "$(wc --lines <<<"$out")" "2"
is "names them by fingerprint"    "$(awk '{print $1}' <<<"$out" | grep --count --extended-regexp '^[0-9A-F]{40}$')" "2"
is "and dates them last"          "$(awk '{print $4}' <<<"$out" | grep --count --extended-regexp '^[0-9]{4}-[0-9]{2}-[0-9]{2}$')" "2"
out=$("$BIN" --output-format=info cert_sigs "$FPR")
is "info format gives key=value"  "$(grep --count "fingerprint=" <<<"$out")" "2"
is "merging every uid says the same" "$("$BIN" cert_sigs --all-uids "$FPR" | wc --lines)" "2"
is "--no-self-sig puts it back out" "$("$BIN" cert_sigs --no-self-sig "$FPR" | wc --lines)" "1"
# The witness signed nobody, so with its own signature left out there is nothing.
"$BIN" cert_sigs --no-self-sig "$WFPR" >/dev/null 2>&1
is "and says 141 when that leaves nothing" "$?" "141"

# The search that goes to a keyserver. No network in the suite, so what is
# checked is the term it would send: an identifier is searched by its body,
# which is the one string `u4=sRyU…` and `u4sRyU…` have in common. Forty-two
# certificates in one ordinary keyring carried only the legacy spelling on the
# day this was written, and searching either spelling whole finds only its own
# generation.
LEGACY="u5=${EID#u5}"
is "an identifier is found written glued" \
   "$("$BIN" --batch cert_get -f -F "$EID" 2>/dev/null)" "$FPR"
is "and written the way it used to be" \
   "$("$BIN" --batch cert_get -f -F "$LEGACY" 2>/dev/null)" "$FPR"
is "and by its body alone, which both spellings share" \
   "$("$BIN" --batch cert_get -f -F "${EID#u5}" 2>/dev/null)" "$FPR"
# A body that opens with '-' is not hypothetical: domvauthier@gmail.com carries
# u4=-zTIlaHT2SgpDmfMe5HAnAe_42.17-002.76, and JJB asked for it by name. The
# pattern reaches gpg after '--', so the dash is a character and not an option.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key 'dash (u4=-zTIlaHT2SgpDmfMe5HAnAe_42.17-002.76) <dash@example.invalid>' \
    ed25519 cert never 2>/dev/null
DFPR=$(gpg --with-colons --list-keys dash@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
is "a legacy certificate answers to the modern spelling" \
   "$("$BIN" --batch cert_get -f -F -- 'u4-zTIlaHT2SgpDmfMe5HAnAe_42.17-002.76' 2>/dev/null)" "$DFPR"
is "and to the one written on it" \
   "$("$BIN" --batch cert_get -f -F -- 'u4=-zTIlaHT2SgpDmfMe5HAnAe_42.17-002.76' 2>/dev/null)" "$DFPR"

# A certifier we do not hold. Printing '-' made the commonest case of all --
# somebody vouched for this and we have never met them -- into a dead end,
# when the identifier its signature carries is exactly what a search takes.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key "passer-by <passer@example.invalid>" ed25519 cert never 2>/dev/null
PFPR=$(gpg --with-colons --list-keys passer@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
gpg --batch --yes --quiet --passphrase '' --pinentry-mode loopback \
    --default-key "$PFPR" --quick-sign-key "$FPR" >/dev/null 2>&1
gpg --batch --yes --quiet --delete-secret-and-public-key "$PFPR" >/dev/null 2>&1
out=$("$BIN" cert_sigs "$FPR")
is "an unheld certifier keeps its key identifier" \
   "$(awk '{print $1}' <<<"$out" | grep --count --extended-regexp "^${PFPR: -16}$")" "1"
is "and no row is ever a dash"    "$(awk '$1=="-"' <<<"$out" | wc --lines)" "0"

printf '\nsecret_scan reads what zbar prints\n'
# The output of zbar has to reach the parser. It stopped doing so for one
# commit: pgpid_capture answers the number of bytes it kept, not a status, and
# read as a status it inverted every test built on it — a fragment read in two
# seconds was reported as a camera that had seen nothing. Nothing caught it,
# the camera being outside the suite; two images are.
if command -v qrencode >/dev/null 2>&1 && command -v zbarimg >/dev/null 2>&1 ; then
    qrencode -o "$GNUPGHOME/frag4.png" -- '~400AAAABBBBCCCC'
    qrencode -o "$GNUPGHOME/frag5.png" -- '~500AAAABBBBCCCC'
    # A given working directory is used, never created: the point of naming one
    # is to pick a place that is already safe to write secrets in.
    mkdir -p "$GNUPGHOME/scan"
    # Two headers that disagree on the version: the action must have read both
    # to be able to say so, which is the whole point of the check.
    out=$("$BIN" --batch secret_scan --workdir "$GNUPGHOME/scan" \
          "$GNUPGHOME/frag4.png" "$GNUPGHOME/frag5.png" 2>&1 || true)
    is "a fragment's head reaches the parser" \
       "$(grep --count "share the same version" <<<"$out")" "1"
    rm -rf "$GNUPGHOME/scan"
    mkdir -p "$GNUPGHOME/scan"
    # And one alone is read, then refused for what it is rather than for not
    # having been seen.
    out=$("$BIN" --batch secret_scan --workdir "$GNUPGHOME/scan" \
          "$GNUPGHOME/frag4.png" 2>&1 || true)
    is "and a single one is read, not missed" \
       "$(grep --count "QR code(s) with expected data read" <<<"$out")" "1"
else
    printf '  skip  qrencode or zbarimg missing\n'
fi

printf '\nthe shell programs call actions that exist\n'
# pgpid-gen and pgpid-qrscan drive the compiled binary, and the day the actions
# were put into groups -- gen_*, cert_*, secret_*, token_* -- nobody renamed
# the calls inside them. Both programs died on their first real step for weeks,
# and their --help kept working, so nothing looked wrong. Every action either
# script invokes is asked of the binary here.
called=$(grep --only-matching --extended-regexp \
    '\$\{?PGPID_BIN"?\}?( --homedir "[^"]+")? [a-z0-9_]+' \
    "$PGPI_ROOT"/bin/pgpid-gen "$PGPI_ROOT"/bin/pgpid-qrscan 2>/dev/null \
  | grep --only-matching --extended-regexp '(gen|cert|secret|token|system)_[a-z0-9_]+' \
  | sort --unique)
missing=0
for action in $called ; do
    "$BIN" "$action" --help >/dev/null 2>&1 || { printf '  missing: %s\n' "$action" ; missing=$((missing+1)) ; }
done
is "every action the shell programs call exists" "$missing" "0"
is "and they call at least a few" "$(wc --words <<<"$called")" "7"

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
       "$("$BIN" cert_avatar --workdir "$GNUPGHOME" "$FPR" >/dev/null 2>&1 ; echo $?)" "141"
    for f in old new ; do
        gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
            --command-fd 0 --edit-key "$FPR" >/dev/null 2>&1 \
            <<<$'addphoto\n'"$GNUPGHOME/$f.jpg"$'\ny\nsave\n'
        sleep 1
    done
    out=$("$BIN" cert_avatar --workdir "$GNUPGHOME" "$FPR")
    is "prints one path"              "$(wc --lines <<<"$out")" "1"
    is "and it is the newest image"   "$(pixels "$out")" "$(pixels "$GNUPGHOME/new.jpg")"
    out=$("$BIN" cert_avatar --workdir "$GNUPGHOME" --extract-all "$FPR")
    is "--extract-all gives both"     "$(wc --lines <<<"$out")" "2"
    is "newest still first"           "$(pixels "$(sed 1q <<<"$out")")" "$(pixels "$GNUPGHOME/new.jpg")"
    is "then the older one"           "$(pixels "$(sed 2q <<<"$out" | tail --lines=1)")" "$(pixels "$GNUPGHOME/old.jpg")"
    is "names the file by packet order" "$(basename "$(sed 1q <<<"$out")")" "$FPR-2.jpg"

    # Writing. A fingerprint is required because revoking cannot be undone,
    # and a 400x300 image proves the resize happens on the way in.
    is "refuses a search as a target" \
       "$("$BIN" cert_avatar --workdir "$GNUPGHOME" --replace-to "$GNUPGHOME/new.jpg" alice >/dev/null 2>&1 ; echo $?)" "2"
    gm convert -size 400x300 'xc:#7f5f2a' jpeg:"$GNUPGHOME/wide.jpg"
    "$BIN" cert_avatar --workdir "$GNUPGHOME" --keyservers '' --replace-to "$GNUPGHOME/wide.jpg" "$FPR" >/dev/null 2>&1
    is "replace-to succeeds"          "$?" "0"
    out=$("$BIN" cert_avatar --workdir "$GNUPGHOME" "$FPR")
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
       "$("$BIN" cert_avatar --workdir "$GNUPGHOME" --keyservers 'hkp://127.0.0.1:1' "$FPR" >/dev/null 2>&1 ; echo $?)" "2"
    out=$("$BIN" cert_avatar --workdir "$GNUPGHOME" --revoke --keyservers 'hkp://127.0.0.1:1' "$FPR" 2>&1)
    is "says which server refused"    "$(grep --count 'would not take it' <<<"$out")" "1"
    "$BIN" cert_avatar --workdir "$GNUPGHOME" --keyservers '' --revoke "$FPR" >/dev/null 2>&1
    is "--revoke takes the last one back" \
       "$("$BIN" cert_avatar --workdir "$GNUPGHOME" "$FPR" >/dev/null 2>&1 ; echo $?)" "141"
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
out=$("$BIN" cert_list --short "$FPR")
is "one line per address"          "$(grep --count . <<<"$out")" "1"
is "fingerprint first"             "$(awk '{print $1}' <<<"$out")" "$FPR"
is "identifier second"             "$(awk '{print $2}' <<<"$out")" "$EID"
is "and it starts at column 42"    "$(awk '{print index($0, "u5")}' <<<"$out")" "42"
is "address in column 82"          "$(awk '{print index($0, "ada@")}' <<<"$out")" "82"
is "lowercased, as gpg reports it" "$(awk '{print $3}' <<<"$out")" "ada@example.invalid"
is "no identifier prints a dash"   "$("$BIN" cert_list --short "$NFPR" | awk '{print $2}')" "-"
is "a uid without an address is not one" \
   "$("$BIN" cert_list --short "$FPR" | grep --count 'FN:')" "0"

printf '\nget\n'
# get and list --short print the same thing; what differs is that get insists
# on being told what to look for, and refreshes before answering.
is "insists on a search term"      "$("$BIN" cert_get >/dev/null 2>&1 ; echo $?)" "2"
is "'*' means the whole keyring"   "$("$BIN" cert_get --no-fetch '*' | grep --count .)" "$("$BIN" cert_list --short | grep --count .)"
is "same answer as list --short"   "$("$BIN" cert_get --no-fetch "$FPR")" "$("$BIN" cert_list --short "$FPR")"
is "--fingerprint keeps one column" \
   "$("$BIN" cert_get --no-fetch --fingerprint "$FPR")" "$FPR"
is "--email keeps the other"       "$("$BIN" cert_get --no-fetch --email "$FPR")" "ada@example.invalid"
# The global format drives get too, and raw is left exactly as the shell has
# always printed it: the address at column 82, whatever the identifier's width.
is "md names the three columns" \
   "$("$BIN" --output-format=md cert_get --no-fetch "$FPR" | head --lines=1 | tr --squeeze-repeats ' ' | tr --delete '| ')" \
   "fingerprinteidemail"
is "info names them, tab separated" \
   "$("$BIN" --output-format=info cert_get --no-fetch "$FPR" \
      | awk --field-separator='\t' '{print NF, $1 ~ /^fingerprint=/, $2 ~ /^eid=/, $3 ~ /^email=/}')" \
   "3 1 1 1"
is "info follows --email down to one" \
   "$("$BIN" --output-format=info cert_get --no-fetch --email "$FPR")" "email=ada@example.invalid"
is "raw keeps the address at column 82" \
   "$("$BIN" cert_get --no-fetch "$FPR" | awk '{print index($0, "ada@example.invalid")}')" "82"
is "says 141 for what it has not"  "$("$BIN" cert_get --no-fetch nobody@example.test >/dev/null 2>&1 ; echo $?)" "141"
is "--errexit-g=1 accepts one"     "$("$BIN" cert_get --no-fetch --errexit-g=1 "$FPR" >/dev/null 2>&1 ; echo $?)" "0"
is "--errexit-g=1 refuses two"     "$("$BIN" cert_get --no-fetch --errexit-g=1 '*' >/dev/null 2>&1 ; echo $?)" "1"
# Nowhere is named, so no test key reaches a real keyserver.
is "an empty keyserver list asks nobody" \
   "$("$BIN" cert_get --keyservers '' "$FPR" >/dev/null 2>&1 ; echo $?)" "0"

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
is "everything is required"      "$("$BIN" --batch gen_u4 -s DOE >/dev/null 2>&1 ; echo $?)" "2"
# A name taken differently from the way it was typed is said out loud, both
# spellings in one line: foodjis reads them off this very line to put them
# side by side on the identity page, and whoever is typing is the only one who
# can tell whether the passport agrees.
warned() { "$BIN" gen_u4 -s "$1" -g "$2" -d 1970-01-01 -c FRA 2>&1 >/dev/null \
           | grep --count "has been transliterated" ; }
is "a transliterated name is said, once per half" "$(warned 'MÜLLER' 'Jürgen')" "2"
is "and the name as it was typed, not uppercased"  \
   "$("$BIN" gen_u4 -s 'José' -g John -d 1970-01-01 -c FRA 2>&1 >/dev/null \
      | grep --count "'José' has been transliterated to 'JOSE'")" "1"
is "and only the half that changed"               "$(warned 'MÜLLER' 'Jurgen')" "1"
is "a name taken as typed says nothing"           "$(warned 'DOE' 'John')" "0"
is "nor does case, nor a separator"               "$(warned 'de la tour' 'marie-claire')" "0"
is "both spellings are in the line" \
   "$("$BIN" gen_u4 -s 'MÜLLER' -g John -d 1970-01-01 -c FRA 2>&1 >/dev/null \
      | grep --count "'MÜLLER' has been transliterated to 'MULLER'")" "1"

printf '\nto_vcard\n'
# Self-sufficient: earlier blocks revoke what they add, so this one puts back
# the address and the image it means to look for rather than depending on the
# order the file happens to be in.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-add-uid "$FPR" 'Ada <ada@example.invalid>' 2>/dev/null
gm convert -size 180x180 'xc:#3a6ea5' jpeg:"$GNUPGHOME/card.jpg" 2>/dev/null
"$BIN" cert_avatar --workdir "$GNUPGHOME" --keyservers '' --replace-to "$GNUPGHOME/card.jpg" "$FPR" >/dev/null 2>&1
card=$("$BIN" cert_tovcard "$FPR")
is "opens and closes a vCard 4.0"  "$(printf '%s' "$card" | head --lines=2 | tr -d '\r' | tr '\n' ' ')" "BEGIN:VCARD VERSION:4.0 "
is "carries the identifier"        "$(grep --count "UID:urn:eid:$EID" <<<"$card")" "1"
is "carries the address"           "$(grep --count 'EMAIL;PREF=1:ada@example.invalid' <<<"$card")" "1"
is "carries the key inline"        "$(grep --count '^KEY:data:application/pgp-keys;base64,' <<<"$card")" "1"
is "and where to fetch it"         "$(grep --count '^KEY;MEDIATYPE=' <<<"$card")" "1"
is "and the photograph"            "$(grep --count '^PHOTO:data:image/jpeg;base64,' <<<"$card")" "1"
# RFC 6350 §3.2 asks for at most 75 octets per line, and never a fold inside
# a UTF-8 character — a reader given half a character shows a broken glyph.
is "no line beyond 75 octets"      "$(awk '{ sub(/\r$/,"") ; if (length($0) > 75) n++ } END { print n+0 }' <<<"$card")" "0"
is "--raw prints the uids instead" "$(grep --count 'BEGIN:VCARD' <<<"$("$BIN" cert_tovcard --raw "$FPR")")" "0"
# FN is required and singular (RFC 6350 §6.2.1). Ours carry it as a uid;
# certificates from elsewhere do not, and the shell emitted cards without it
# for 117 of the 122 it produced — files no reader should accept. So: the
# certificate's own FN, or one read off the name a uid carries, or no card.
is "always carries FN"             "$(grep --count '^FN[;:]' <<<"$card")" "1"
gpg --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key 'Grace Hopper <grace@example.invalid>' ed25519 cert never 2>/dev/null
GFPR=$(gpg --with-colons --list-keys grace@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
is "derives FN from the uid name"  "$("$BIN" cert_tovcard "$GFPR" | grep --only-matching '^FN:.*' | tr -d '\r')" "FN:Grace Hopper"
is "and still carries the address" "$("$BIN" cert_tovcard "$GFPR" | grep --count 'EMAIL;PREF=1:grace@example.invalid')" "1"
is "a bare 'Nobody' is a name"     "$("$BIN" cert_tovcard "$NFPR" | grep --only-matching '^FN:.*' | tr -d '\r')" "FN:Nobody"
# A uid holding nothing but an address has no name to show, and a card that
# would say who this is cannot be written.
gpg --batch --quiet --passphrase '' --pinentry-mode loopback --allow-freeform-uid \
    --quick-generate-key '<anon@example.invalid>' ed25519 cert never 2>/dev/null
AFPR=$(gpg --with-colons --list-keys anon@example.invalid 2>/dev/null | awk --field-separator=: '$1=="fpr"{print $10; exit}')
is "no name at all means no card"  "$("$BIN" cert_tovcard "$AFPR" >/dev/null 2>&1 ; echo $?)" "141"
is "--output writes a file"        "$("$BIN" cert_tovcard --output "$GNUPGHOME/c.vcf" "$FPR" >/dev/null 2>&1 ; grep --count 'BEGIN:VCARD' "$GNUPGHOME/c.vcf")" "1"
# The card and the avatar must show the same face: the photograph is chosen
# by the rule `avatar` uses, not by packet order.
is "the card shows the avatar"     "$(grep --only-matching --extended-regexp '^PHOTO:data:image/jpeg;base64,.{40}' <<<"$card")" \
                                   "PHOTO:data:image/jpeg;base64,$(base64 --wrap=0 < "$("$BIN" cert_avatar --workdir "$GNUPGHOME" "$FPR")" | cut --characters=1-40)"

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
is "wants a certificate"          "$("$BIN" cert_push >/dev/null 2>&1 ; echo $?)" "2"
is "takes fingerprints, not searches" \
   "$("$BIN" cert_push alice >/dev/null 2>&1 ; echo $?)" "2"
is "an empty list sends nothing, and says so" \
   "$("$BIN" cert_push --keyservers '' "$FPR" >/dev/null 2>&1 ; echo $?)" "0"
out=$("$BIN" cert_push --keyservers 'hkp://127.0.0.1:1' "$FPR" 2>&1)
is "names the server that refused" "$(grep --count 'would not take it' <<<"$out")" "1"
# One bad target among good ones stops the lot: half a broadcast cannot be
# taken back any more than a whole one.
out=$("$BIN" cert_push --keyservers 'hkp://127.0.0.1:1' "$FPR" notafingerprint 2>&1)
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
"$BIN" secret_print --printer '' --split 11 --passphrase '' \
    --workdir "$GNUPGHOME" "$FPR" >/dev/null 2>&1
is "more fragments than a header can number is refused" "$?" "2"
"$BIN" secret_print --printer '' --split 2 --passphrase '' \
    --workdir "$GNUPGHOME" "$FPR" >/dev/null 2>&1
is "and fewer than three, as before"  "$?" "2"

# The file is a destination and a source like any other: what goes out through
# --export-to comes back in through --import-from, into a keyring that never
# touched a keyserver.
ROUNDTRIP=$(mktemp -d) ; chmod 700 "$ROUNDTRIP"
"$BIN" cert_push --export-to "$ROUNDTRIP/c.asc" --armor "$FPR" >/dev/null 2>&1
is "an armoured export is text"      "$(head -1 "$ROUNDTRIP/c.asc")" "-----BEGIN PGP PUBLIC KEY BLOCK-----"
is "and comes back through a file"   \
   "$("$BIN" --homedir "$ROUNDTRIP" cert_get --import-from "$ROUNDTRIP/c.asc" --fingerprint "$FPR" 2>/dev/null)" "$FPR"
rm -rf "$ROUNDTRIP"

printf '\ndel\n'
"$BIN" cert_del "not-a-fingerprint" >/dev/null 2>&1
is "refuses anything but a fingerprint" "$?" "2"
"$BIN" cert_del "$FPR" "not-a-fingerprint" >/dev/null 2>&1
is "checks every target before deleting any" "$?" "2"
is "and deleted nothing"          "$("$BIN" cert_list "$FPR" | wc --lines)" "1"
"$BIN" cert_del --secret "$FPR" >/dev/null 2>&1
is "--secret keeps the certificate"  "$("$BIN" cert_list "$FPR" | wc --lines)" "1"
is "and drops the secret part"    "$(gpg --list-secret-keys "$FPR" 2>/dev/null | wc --lines)" "0"
"$BIN" cert_del "$FPR" >/dev/null 2>&1
is "deletes the certificate"      "$?" "0"
is "and it is gone"               "$("$BIN" cert_list "$FPR" 2>/dev/null | wc --lines)" "0"
"$BIN" cert_del "$FPR" >/dev/null 2>&1
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

printf '\n--batch, everywhere something used to be refused\n'
# Each of these asks the shell's question rather than sending the caller back
# to the usage. --batch is what a program driving pgpid gives so that a
# missing operand never becomes a wait nobody is there to end.
for act in gen_u4 secret_totoken secret_passphrase ; do
    out=$("$BIN" --batch "$act" 2>&1)
    is "$act asks, and --batch refuses" "$(grep --count -- '--batch was given' <<<"$out")" "1"
done
# token_meta reads by default, so it is --replace that has something to ask for.
out=$("$BIN" --batch token_meta --replace 2>&1)
is "token_meta --replace asks, and --batch refuses" \
   "$(grep --count -- '--batch was given' <<<"$out")" "1"

# system_admins changes the machine, so only its refusals are exercised: the
# ones that answer before anything is touched.
is "nobody removes themselves" \
   "$("$BIN" system_admins --remove "$(id --user --name)" 2>&1 | grep --count 'is you')" "1"
is "and an account that does not exist is named as such" \
   "$("$BIN" system_admins --add no-such-account-here 2>&1 | grep --count 'No account named')" "1"

# system_users reads the machine it runs on, so what it says depends on the
# machine -- what can be checked anywhere is the shape of the answer and that
# it refuses what it does not know.
is "system_users lists five columns" \
   "$("$BIN" system_users 2>/dev/null | head -1 | awk '{print NF}')" "5"
is "and names the second one 'user', not 'alias'" \
   "$("$BIN" --output-format=info system_users 2>/dev/null | head -1 | grep --count 'user=')" "1"
is "and refuses an option it has not got" \
   "$("$BIN" system_users --nonesuch >/dev/null 2>&1 ; echo $?)" "2"

# system_adduser and system_deluser open and close accounts, so what is
# exercised here is everything they answer BEFORE touching the machine. The
# order matters and is deliberate: a malformed request is a malformed request
# whether or not the caller happens to be root, so those checks come first and
# these run the same for anybody.
is "--sweep without --migrate has no old account to sweep" \
   "$("$BIN" system_adduser --sweep >/dev/null 2>&1 ; echo $?)" "2"
is "a name starting with a digit is not an account name" \
   "$("$BIN" system_adduser --user 9nope >/dev/null 2>&1 ; echo $?)" "2"
is "and an option it has not got is refused" \
   "$("$BIN" system_adduser --nonesuch >/dev/null 2>&1 ; echo $?)" "2"
is "system_deluser wants to know which account" \
   "$("$BIN" system_deluser >/dev/null 2>&1 ; echo $?)" "2"
if [[ $EUID -ne 0 ]] ; then
    is "opening an account says it needs administrator rights" \
       "$("$BIN" system_adduser --fingerprint "$FPR" 2>&1 | grep --count 'administrator rights')" "1"
    is "closing one says the same" \
       "$("$BIN" system_deluser nobody 2>&1 | grep --count 'administrator rights')" "1"
fi

# An identifier is for life, so a card written years ago still says what it
# said then: three spellings, one answer. This covers gen_uid's own reader.
# token_check's card reader takes the same three, and nothing here reaches it
# -- that path needs a card, and the suite has none.
for spelling in "u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76" \
                "u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76" \
                "udid4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76" ; do
    is "gen_uid takes the eid written '${spelling%%[=s]*}…'" \
       "$("$BIN" gen_uid "$spelling" >/dev/null 2>&1 ; echo $?)" "0"
done

# The note pgpid keeps beside GnuPG's stub: written under the home it is given,
# read back by token_list, and forgotten by token_del.
mkdir -p "$GNUPGHOME/pgpid/tokens"
printf "token_seen='2026-01-01T00:00:00Z'\ntoken_ID='DEADBEEF'\npgpid_id='u5test'\n" \
    > "$GNUPGHOME/pgpid/tokens/DEADBEEF"
is "token_list reads the note"       "$("$BIN" token_list | grep --count "u5test")" "1"
is "and its observation date"        "$("$BIN" token_list | grep --count 'token_seen=')" "1"
"$BIN" --batch token_del --yes DEADBEEF >/dev/null 2>&1
is "token_del forgets it"            "$(ls "$GNUPGHOME/pgpid/tokens/" | wc --lines)" "0"

# secret_del is destructive too: the three refusals are what gets tested.
is "secret_del wants a fingerprint" \
   "$("$BIN" secret_del mneme@example.invalid 2>&1 | grep --count 'is not a fingerprint')" "1"
is "secret_del refuses to act unasked in batch" \
   "$("$BIN" --batch secret_del 0000000000000000000000000000000000000000 >/dev/null 2>&1 ; echo $?)" "141"

# token_del is destructive, so the safe halves are what gets tested: it refuses
# to act unasked in batch, and a serial nothing points at removes nothing.
is "token_del refuses to act unasked in batch" \
   "$("$BIN" --batch token_del FFFFFFFFFFFFFFFF >/dev/null 2>&1 ; echo $?)" "2"
is "an unknown serial touches nothing" \
   "$("$BIN" --batch token_del --yes FFFFFFFFFFFFFFFF 2>&1 | grep --count 'No stub pointed at')" "1"

# What it asks for is a question, not the usage dumped again.
is "gen_u4 names the field it wants" \
   "$("$BIN" --batch gen_u4 2>&1 | grep --count 'Birth surname')" "1"
# And the fields still arrive from stdin, giving what the options give.
BYOPT=$("$BIN" gen_u4 --surname Dupont --given-names Jean --birth-date 1980-01-01 --birth-country FRA 2>/dev/null)
BYASK=$(printf 'Dupont\nJean\n1980-01-01\nFRA\n' | "$BIN" gen_u4 2>/dev/null)
is "asked and given agree"                        "$BYASK" "$BYOPT"
is "and says so rather than failing mutely" \
   "$("$BIN" --batch certify --keyservers '' --use-privkey "$CFPR" 2>&1 | grep --count -- '--batch')" "1"

printf '\nscan — versions 4 and 5, and no passphrase\n'
# The extra passphrase belonged to versions 1 to 3, where it also protected
# the key it rebuilt. Those are not read here, so scan has no passphrase to
# take: a key that arrives protected stays protected until totoken strips it.
"$BIN" --batch secret_scan --passphrase whatever /dev/null >/dev/null 2>&1
is "no --passphrase to give"      "$?" "2"
"$BIN" --batch secret_scan --passfrom /dev/null /dev/null >/dev/null 2>&1
is "no --passfrom either"         "$?" "2"
is "the help says which versions" \
   "$("$BIN" secret_scan --help | grep --count 'versions 4 and 5')" "1"
is "and where the old ones are read" \
   "$("$BIN" secret_scan --help | grep --count -- 'bl-pgpkey')" "1"

printf '\ntotoken — the two passphrase answers\n'
# The codes themselves cannot be reached without a card, and reaching them
# would wipe it — so what is checked here is that they are declared, unique
# and announced. 41 is "give me a passphrase", 40 is "that one is wrong";
# a caller driving pgpid --batch acts on the difference.
is "announces 41, a passphrase is needed" \
   "$("$BIN" secret_totoken --help | grep --count '^- 41 ')" "1"
is "announces 40, the passphrase is wrong" \
   "$("$BIN" secret_totoken --help | grep --count '^- 40 ')" "1"
is "and they say which is which" \
   "$("$BIN" secret_totoken --help | grep --count -- '- 41 The key is protected and no passphrase')" "1"

printf '\nbash completion\n'
# The program completes itself: nothing beside it lists the actions, so
# nothing beside it can fall behind a release.
COMP=$("$BIN" --bash-completion)
is "emits a completion function"  "$(grep --count '^_pgpid_completion()' <<<"$COMP")" "1"
is "and registers it"             "$(grep --count '^complete -F _pgpid_completion' <<<"$COMP")" "1"
# Every action the dispatch knows, and only those.
for act in cert_list certify trustdb token_meta ; do
    is "offers $act"              "$(grep --count "\<$act\>" <<<"$(sed --silent '2p' <<<"$COMP")")" "1"
done
is "no action invented"           "$(sed --silent '2p' <<<"$COMP" | grep --count 'nonesuch')" "0"
# It runs, and answers.
BINDIR=$(dirname "$BIN")
out=$(PATH="$BINDIR:$PATH" bash -c '
    eval "$('"$BIN"' --bash-completion)"
    COMP_WORDS=(pgpid certi) ; COMP_CWORD=1 ; _pgpid_completion ; printf "%s" "${COMPREPLY[*]}"')
is "completes an action prefix"   "$out" "certify"
out=$(PATH="$BINDIR:$PATH" bash -c '
    eval "$('"$BIN"' --bash-completion)"
    COMP_WORDS=(pgpid --) ; COMP_CWORD=1 ; _pgpid_completion ; printf "%s" "${COMPREPLY[*]}"')
is "global options with no action" "$out" "--homedir --output-format= --batch --help --version"

printf '\nprint_secret asks for what is missing\n'
# The shell says "Missing input will be asked interactively"; this now does
# too. Under --batch the same three become errexit, which is the whole point
# of the flag.
out=$("$BIN" --batch secret_print 2>&1 </dev/null)
is "batch refuses, does not ask"  "$(grep --count -- '--batch was given' <<<"$out")" "1"
is "and names the missing key"    "$(grep --count -- 'Which secret key' <<<"$out")" "2"
# A menu is offered rather than an error, and the first entry is the one that
# is not a printer -- so a machine with no CUPS can still produce sheets.
out=$("$BIN" --batch secret_print --passphrase '' 2>&1 </dev/null)
is "passphrase given, key still asked" "$(grep --count -- 'Which secret key' <<<"$out")" "2"
# Several secret keys here, so the menu is put -- and with nothing on stdin
# to answer it, the refusal names that rather than the operand. One key alone
# would be picked without asking, which is why this is not tested by printing.
out=$("$BIN" secret_print --passphrase '' --printer '' 2>&1 </dev/null)
is "several keys: a menu is put"   "$(grep --count -- 'Its number' <<<"$out")" "1"
is "and an unanswerable one fails" "$(grep --count -- 'Nothing to read' <<<"$out")" "1"

printf '\ntotoken -- where to send, and what to engrave\n'
# Two questions, and only --certurl answers the second. --keyserver moved the
# card's URL too, so sending a copy somewhere for a day engraved that somewhere
# for the life of the key.
H=$("$BIN" secret_totoken --help)
is "certurl shows the whole default" \
   "$(grep --count -- 'Default: https://keys.foopgp.org/pks/lookup?op=get&search=0x<FPR>' <<<"$H")" "1"
is "keyserver names its default"     "$(grep --count -- 'Default: hkps://keys.foopgp.org' <<<"$H")" "1"
is "and says it engraves nothing"    "$(grep --count -- 'Does not change --certurl' <<<"$H")" "1"
is "empty means send nowhere"        "$(grep --count -- 'Empty to send it nowhere' <<<"$H")" "1"

printf '\nupgrading a legacy certificate\n'
# The shape a certificate had before vCard-property uids: one uid carrying
# the name, the eid in a comment, and the address. Touching a property mints
# UID:urn:eid: and FN: beside it -- and that reshaping is a change of its
# own, which nobody else sees unless it is published and which must not take
# the primary flag away from the address.
LEGACY=$GNUPGHOME/legacy
mkdir -p "$LEGACY" && chmod 700 "$LEGACY"
gpg --homedir "$LEGACY" --batch --quiet --passphrase '' --pinentry-mode loopback \
    --quick-generate-key 'Old Shape (udid4=TESTONLYtestonlyTESTONe_00.00_000.00) <old@example.invalid>' \
    ed25519 cert never 2>/dev/null
LFPR=$(gpg --homedir "$LEGACY" --with-colons --list-keys 2>/dev/null \
       | awk -F: '$1=="fpr"{print $10 ; exit}')
# --keyservers '' throughout: a throwaway keyring is not a throwaway network.
out=$("$BIN" --homedir "$LEGACY" cert_property note --revoke nothing --yes --keyservers '' "$LFPR" 2>&1)
is "a no-op still mints the identity uid" "$(grep --count -- 'Minting the identity uid' <<<"$out")" "1"
first=$(gpg --homedir "$LEGACY" --with-colons --list-keys "$LFPR" 2>/dev/null \
        | awk -F: '$1=="uid"{print $10 ; exit}')
# gpg lists the primary uid first, and the primary is what mail clients show.
is "the primary flag stays on the address" "$(grep --count -- '<old@example.invalid>' <<<"$first")" "1"
is "and not on the identity anchor"        "$(grep --count -- 'urn' <<<"$first")" "0"

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
