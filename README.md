<!--
SPDX-FileCopyrightText: 2021-2026 Friends Of OpenPGP organization <info@foopgp.org>
SPDX-FileCopyrightText: 2021-2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
SPDX-FileCopyrightText: 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>

SPDX-License-Identifier: GPL-3.0-only
-->

# pgpid

Tools for the PGP ID model: an OpenPGP certificate that carries a decentralised
**entity identifier** — who this key belongs to, said once and checked by
people rather than by an authority.

Two generations live in this repository.

## `pgpid` — the current tool, in C over gpgme

One program, one action at a time:

```
pgpid list                          what this keyring holds, and how far it is trusted
pgpid get PATTERN                   fingerprints, addresses and identifiers
pgpid gen_u4 …                      derive an identifier from a civil status
pgpid mrz_to_u4 …                   the same, read off a passport
pgpid to_vcard                      a certificate as a vCard
pgpid certify KEYFPR                vouch for somebody else
pgpid email --add … --revoke …      the addresses a certificate answers to
pgpid property NAME …               its name, note, phone, address, url, lang
pgpid avatar --replace-to FILE      the face it wears
pgpid token_check                   what the connected security key says
pgpid totoken KEY                   move a secret key onto one
pgpid print_secret KEY              put a secret key on paper, in fragments
pgpid scan IMAGE…                   put it back together
pgpid print_card                    a card somebody can hand over
```

`pgpid ACTION --help` for any of them, and `pgpid --help` for the rest.

It replaces the `bl-pgpid` and `bl-pgpkey` shell libraries, action for action.
Every one was checked against the shell it replaces — same output, same return
codes, same keyring afterwards — on a throwaway keyring and, for the ones that
write to a security key, on a spare card. `MIGRATION.md` records how, and what
was deliberately done differently.

### Building

```
make            # needs a C compiler, gpgme, and pandoc for the manual pages
make check      # runs against a keyring it builds on the spot
sudo make install
```

The version is the commit, as `git describe` gives it — the same answer
`bl-pgpid` gives, so that a report names something anybody can check out.

### Deliberately different from the shell

`pgpid` never asks. Where the shell opens a dialogue for what it is missing,
this refuses and says which argument to pass. That is what makes it usable from
a program, and it is also why an incomplete command can never spend one of the
three attempts a security key allows.

The operations that cannot be undone — certifying, revoking a user id, deleting,
publishing — take a whole fingerprint and never a search pattern.

## `pgpid-gen` and `pgpid-qrscan` — what came before

Shell programs, still working, that generate a certificate from a passport and
move secrets onto a smartcard through QR codes. `pgpid mrz_to_u4`, `print_secret`
and `scan` cover most of what they do; they are kept because the web of trust
rests on what they produced, and because nobody has yet checked that the
replacement covers every case they handle.

## Licence

GPL-3.0-only, the whole repository. Every file of ours carries an
`SPDX-License-Identifier` header, and `LICENSES/GPL-3.0-only.txt` holds the
text — the REUSE convention, the same one `bash-libs` follows.

What is **not** ours and therefore not covered by it: the reference documents
under `doc/`, the passport specimen images under `imgsamples/`, and the OCR
training data under `data/` and `oldies/data/`. They belong to whoever
published them and are here for reference. `REUSE.toml` says so file by file.
