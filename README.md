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
pgpid-mip list [--certs] [--info] [SEARCH]
pgpid-mip property [--info] NAME [SEARCH]
pgpid-mip sigs [--all-uids] [--info] FINGERPRINT
pgpid-mip ownertrust [--replace-to VALUE] [--info] FINGERPRINT
pgpid-mip del [--secret] FINGERPRINT...
pgpid-mip avatar [--extract-all] [--workdir DIR] [SEARCH]
pgpid-mip avatar --replace-to IMAGE | --revoke [--keyservers SERVERS] FINGERPRINT
pgpid-mip push [--keyservers SERVERS] FINGERPRINT...
```

`list` prints one row per certificate: fingerprint, entity identifier, first
address, validity, ownertrust.

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
