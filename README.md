# pgpid-mip

`mip` stands for *migration in progress*, and the name is meant to go away.

This is the beginning of the **pgpid API** in a compiled language. The shape of
that API was settled in the shell libraries — `bl-pgpid`, `bl-pgpkey` — and what
moves here is what the shell cannot do well: the calls it never had, and the
ones that pay a process per certificate.

The order the rest moves in, and why, is in [MIGRATION.md](MIGRATION.md).

foodjis will straddle the two for a while. As an action lands here, the
application stops calling `bl-*` for it. When the last one has moved,
`bl-pgpid` and `bl-pgpkey` are obsolete, this leaves for a repository and a
package of its own, and the binary gets its real name: `pgpid`.

Until then it is not a project, it is a part. It ships inside the foodjis
package — `djibian-onboarding`, which installs it as `/usr/bin/pgpid-mip` —
and it wears that package's version, read from `package.json` by the Makefile
rather than written down a second time. Two numbers meant to be equal drift
the day somebody bumps one of them. Built outside the repository it falls
back to `0.0.0-standalone`, which is the honest thing for a part with no
whole around it.

## What it does today

```
pgpid-mip list [--short] [--certs] [--info] [SEARCH]
pgpid-mip get [--no-fetch] [--fingerprint|--email] NAME|EMAIL|KEYID|'*'
pgpid-mip property [--info] NAME [SEARCH]
pgpid-mip sigs [--all-uids] [--info] FINGERPRINT
pgpid-mip ownertrust [--replace-to VALUE] [--info] FINGERPRINT
pgpid-mip del [--secret] FINGERPRINT...
pgpid-mip avatar [--extract-all] [--workdir DIR] [SEARCH]
pgpid-mip avatar --replace-to IMAGE | --revoke [--keyservers SERVERS] FINGERPRINT
pgpid-mip push [--keyservers SERVERS] FINGERPRINT...
pgpid-mip gen_u4 --surname S --given-names G --birth-date D --birth-country C
pgpid-mip gen_uid [--free-input] U4|U5|STRING
```

`list` prints one row per certificate: fingerprint, entity identifier, first
address, validity, ownertrust.

`list --short` answers what `bl-pgpid get --no-fetch` answers, to the
column: one line per address rather than per certificate, fingerprint and
address inside eighty columns, then the entity identifier — a dash when
there is none or more than one. Being *indistinguishable* is the point, not
being similar: callers have been reading those columns for a year. Checked
across sixteen search patterns, the whole keyring included, byte for byte.

It also answers about eight times faster: 2.1 s against 98 ms on 128
certificates. That is the same reason `list` replaced `cert_check`, and the
reason there will be no `cert_check` here.

Two details were read off gpg rather than assumed, and both were wrong in
the first attempt. A revoked address is not printed — unless the whole
certificate is revoked, where hiding it would leave it with no identity at
all. And the identifier is read from every uid whatever its validity, where
the long form reads only from those that still stand: replacing one's
identifier must not make the certificate read as broken ever after. The
shell's own helper takes that same distinction as a parameter.

`get` prints what `list --short` prints, and differs in what it is *for*.
`list` shows what is at hand, so no pattern means the whole keyring; `get`
looks something up, so it insists on being told what — a search with no term
is almost always a caller that lost its variable, and `'*'` is there for the
rare occasion when everything really is meant. It also refreshes before
answering, unless told not to: a certificate is a claim other people update,
and answering from a stale copy is how one certifies a key whose owner
revoked it last week.

Refreshing goes through the engine — an address by Web Key Directory then
keyservers, a fingerprint or key identifier by `--recv-keys`. **A free-text
name is not searched**, and says so rather than failing quietly: the shell
searches keyservers by name over HTTP, and carrying an HTTP client here for a
case that is both rare and ambiguous — a name matches whoever else chose it —
is not worth it yet.

There is no `cert_check` and there will not be: `list` answers what it
answered, for less.

`gen_u4` prints the identifier a civil status gives: the last component of
the surname, the first two given names, the date of birth, the country. Not
a secret and not a key — a name two strangers can compute the same way,
which is the whole point.

Its transliteration is the reference one, decided on 2026-08-22:
`iconv --to-code ascii//TRANSLIT` under **`LC_ALL=C.utf8`**. The locale is
the point — under one merely absent from the machine, the same civil status
yields an outright error instead of an identifier, and an identifier that
depends on where it was computed is not one. C.utf8 exists everywhere.

The table is **generated** from that reference by `tools/gen-translit.sh`,
not written. Writing it by hand produced twenty wrong entries out of 192 and
none of them looked wrong: the parity of upper/lower pairs flips halfway
through Latin Extended-A, `ÿ` has its capital far from its neighbours, and
the reference sometimes answers with something that is not a letter — `÷`
becomes `/`. Checked codepoint by codepoint against the shell across
Latin-1, Latin Extended-A, -B and Additional: 288 characters, no divergence.

The name components are **matched, not composed**: the shell builds
`SURNAME<<GIVEN<<` and takes the first match of its pattern, which is not
the same as taking the last surname component and the first two given names.
A character surviving as a non-letter breaks a run, so two components stay
two; and one given name matches through the trailing pair, giving
`NIETO<<ENRIQUE<<`.

`gen_uid` prints the Unix account number an entity identifier gives — not
an OpenPGP uid, a Unix one. Opening an account for somebody from their
certificate means giving them a number, and deriving it from their
identifier means two machines that never met agree on it. That is what lets
an account be opened again elsewhere from the certificate alone.

It is the first of the calls that touch no engine, no keyring and no
network: a hash, a fold, a range. Which is why it came first — it is also
the piece that has to exist wherever the model goes, Android included.

Two things in it are reproduced rather than improved, and both would have
been tidier done differently. The fold's modulo is **signed**, because the
shell computes in signed sixty-four bits and a digest whose top bit is set
reads as negative there. And the hash covers a **trailing newline**, because
the shell pipes through `echo`. Either change would renumber people who
already have accounts. Checked against `bl-pgpid gen_uid` on all 46
identifiers of a real keyring, and about ninety times faster: 41 ms against
3.8 s for twenty calls.

MD5 is written here rather than linked — see `src/md5.c` for why that is not
the usual mistake: an identifier *is* a digest, nothing here defends against
an adversary, and linking libgcrypt would add a dependency gpgme does not
bring while being unavailable where the model must also run.

`property` prints the values of one vCard property a certificate carries on
uids of its own — `name`, `note`, `phone`, `address`, `url`, `lang`, `geo`.
Reading only: writing revokes a uid and adds another, needs the card and its
PIN, and stays with `bl-pgpid` for now. Without SEARCH the certificate is the
one whose secret key is at hand, the card-held one winning when several
answer.

`sigs` prints who has certified one certificate — date, key identifier,
address, oldest first. Only the identity uid is read, because a certification
is about the entity and not about one of its addresses; `--all-uids` merges
every uid, which on our certificates gives the same answer and on older ones
gives the right one. Self-signatures are left out: they make a uid stand, they
do not certify anyone. The key identifier is what goes back into a search to
walk one step further, and it is the identifier and not the fingerprint
because a signature packet only carries the former.

`ownertrust` reads or sets how far one certificate is trusted to certify
others — one word in, one word out.

`del` removes certificates. It takes fingerprints and nothing else: every
other action here accepts a search pattern because being shown too much costs
nothing, but this one deletes. `--secret` drops only the secret part, which is
what one does after moving a key onto a security token.

`avatar` writes out the image a certificate wears and prints its path. The
one that stands today comes first, so the first line is the avatar;
`--extract-all` adds the ones that were taken back, newest first. Files are
named by certificate and packet order, the same number a keyserver asks for
under `idx=`.

This is the one action gpgme cannot help with at all: a user id carries its
text, its validity and its signatures, and nothing of the attribute packet an
image lives in. So the certificate is exported and its packets are read here —
which is also what lets every image arrive knowing when it was certified and
whether a later signature took it back. `bl-pgpid avatar` gets the files by
pointing gpg's `--photo-viewer` at a shell that copies them aside, and that
yields pictures with no dates attached; on 2026-08-20 a certificate carrying
two standing images showed the wrong one for want of them.

`--replace-to` takes back every image that stands and puts a new one on;
`--revoke` does the first half alone. Both want a fingerprint and nothing
else, as `del` does, because a revocation cannot be undone and a search must
never become a target. Two things are worth knowing about how it works:

The number `uid N` selects is **not** the packet order the reading side
walks. gpg numbers what it displays, and it displays the primary uid first —
on the certificate that started all this, its two addresses come out
reversed. So the numbering used for writing is read back from gpg's own
listing, never derived from the packets.

Resizing to 180×180 runs `gm` in a process of its own rather than linking a
library. The operation happens once when someone changes a picture, so the
process costs nothing next to the card operation that follows — and it is the
one step that parses a file we were handed, which is a reason to keep it away
from the address space holding key material.

A changed certificate is sent to the keyservers afterwards, because a
change nobody can fetch is a change nobody can check. The default list is
compiled in — this tool reads no configuration file, as `bl-pgpid` and
`bl-pgpkey` read none — and `--keyservers` overrides it, empty for nowhere.
Configuring belongs above: whoever knows which servers matter, or that
publication should wait, passes the list.

`push` sends a certificate as it stands, changing nothing. It exists
because publishing and changing are not the same act, and until now there
was no way to do the one without the other — not here, not in `bl-pgpid`,
not in `bl-pgpkey`. An application that wants to let somebody try three
avatars before showing the world any of them writes with `--keyservers ""`
and pushes when the dust settles.

It takes fingerprints only, as `del` does. The reasons differ — one cannot
be undone, the other cannot be recalled — but they come to the same rule:
an act with no way back does not guess which certificate was meant. Every
target is checked before any is sent, because half a broadcast cannot be
taken back any more than a whole one.

Conventions follow `bl-*`: an action then its options, human output by default
and `key=value` under `--info`, long options everywhere, and `0` fine, `1`
failed, `2` the caller is wrong, `141` nothing found.

## Why it exists — measured, not assumed

On a keyring of 128 certificates (2026-08-11, gpgme 1.24.2, GnuPG 2.4.7):

| | time | what it answers |
|---|---|---|
| `gpg --list-options show-only-fpr-mbox -k` | 71 ms | fingerprint and address |
| `pgpid-mip list` | 140 ms | + identifier, validity, ownertrust |
| `pgpid-mip sigs` | 84 ms | who certified one certificate |
| `pgpid-mip property url` | 31 ms | one property of one certificate |
| `bl-pgpid property url` | 252 ms | the same |
| `pgpid-mip list --certs` | 6.0 s | + certifier count |
| `bl-pgpid cert_check --certs-count` | 28.4 s | identifier and certifier count |

The shell walk spawns a `gpg` per certificate; here one engine streams the
whole keyring. The 128 fingerprint→identifier pairs match `bl-pgpid cert_check`
exactly — the identifier patterns are a character-for-character port.

**The useful consequence for the application**: it never needs the 28-second
walk. Whether a certificate is certified is its validity reaching `f` or `u`,
which the fast pass already says — that is a verdict, not a count. How many
people certified it is `sigs`, 84 ms, run when someone opens that certificate
rather than for all 128 at once.

**And one of them was not only slow.** `bl-pgpid property` went through an
interactive helper that, run with no terminal, could not stop asking its
question: `read` returns at once at EOF, the answer is rejected, the loop
starts again. Six of those per card refresh is how a workstation ends up with
35 orphaned processes at 40% CPU, the oldest two days old (measured
2026-08-11). The shell fix exists; moving the read here removes the trigger
rather than waiting for it to be packaged.

## One rung, two spellings

gpgme reads *undefined* back as *unknown*: its colon parser switches on `n`,
`m`, `f`, `u` and lets the rest fall through. That is fine, and GnuPG's own
documentation says to treat the two alike. So there are five rungs — never,
unknown, marginal, full, ultimate — and *undefined* is simply the word written
when the second one is chosen, since it is the settable spelling of it.
`unknown` itself cannot be set: the engine answers *Invalid argument*, which
is right, an absence of decision not being a decision.

## Building

```
make          # build/pgpid-mip
make check    # against a keyring it builds and throws away
make install  # PREFIX=/usr/local
```

Needs `libgpgme-dev`. Nothing else.

## Where the seams are

- **The identifier patterns** in `src/eid.c` are a port of `BL_PGPID_*_REGEX`
  in `bl-pgpid`. They are the one thing duplicated between the two, and when
  one moves the other must. Whichever ends up owning the definition, it will
  not stay two copies for long.
- **gpgme is GnuPG.** Putting the API behind this binary does not remove the
  dependency on GnuPG; it moves it behind a seam, which is the point — the
  engine can become Sequoia, or nothing at all, without the callers noticing.
  Saying it removes the dependency today would be false.
