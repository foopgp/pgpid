# pgpid-mip

`mip` stands for *migration in progress*, and the name is meant to go away.

This is the beginning of the **pgpid API** in a compiled language. The shape of
that API was settled in the shell libraries — `bl-pgpid`, `bl-pgpkey` — and what
moves here is what the shell cannot do well: the calls it never had, and the
ones that pay a process per certificate.

foodjis will straddle the two for a while. As an action lands here, the
application stops calling `bl-*` for it. When the last one has moved, the
binary gets its real name.

## What it does today

```
pgpid-mip list [--certs] [--info] [SEARCH]
pgpid-mip ownertrust [--replace-to VALUE] [--info] FINGERPRINT
```

`list` prints one row per certificate: fingerprint, entity identifier, first
address, validity, ownertrust. `ownertrust` reads or sets how far one
certificate is trusted to certify others — one word in, one word out.

Conventions follow `bl-*`: an action then its options, human output by default
and `key=value` under `--info`, long options everywhere, and `0` fine, `1`
failed, `2` the caller is wrong, `141` nothing found.

## Why it exists — measured, not assumed

On a keyring of 128 certificates (2026-08-11, gpgme 1.24.2, GnuPG 2.4.7):

| | time | what it answers |
|---|---|---|
| `gpg --list-options show-only-fpr-mbox -k` | 71 ms | fingerprint and address |
| `pgpid-mip list` | 409 ms | + identifier, validity, ownertrust |
| `pgpid-mip list --certs` | 6.0 s | + certifier count |
| `bl-pgpid cert_check --certs-count` | 28.4 s | identifier and certifier count |

The shell walk spawns a `gpg` per certificate; here one engine streams the
whole keyring. The 128 fingerprint→identifier pairs match `bl-pgpid cert_check`
exactly — the identifier patterns are a character-for-character port.

**The useful consequence for the application**: it never needs the 28-second
walk. Whether a certificate is certified is its validity reaching `f` or `u`,
and that comes out of the fast pass. The certifier count is a number to show,
not a verdict to compute.

## Two things gpgme cannot do, and what is done about them

**It loses `undefined`.** gpgme's colon parser switches on `n`, `m`, `f`, `u`
and lets everything else fall to unknown, so a certificate set to *undefined*
and one nobody has ruled on arrive indistinguishable. They are not the same
thing, and a control offering five rungs cannot show which one it sits on. So
the ownertrust is read from `gpg --export-ownertrust` — once, for the whole
keyring, which is what the extra 270 ms above buys. Everything else still comes
from gpgme.

**`unknown` cannot be set.** The engine answers *Invalid argument*, and it is
right to: unknown is the absence of a decision, not one more decision to take.
`--replace-to unknown` is refused up front, with that as the reason.

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
