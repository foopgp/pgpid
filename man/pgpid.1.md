<!--
© 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>
Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>

SPDX-License-Identifier: GPL-3.0-only
-->

---
title: PGPID
section: 1
header: User Commands
footer: pgpid 0.0.7
---

# NAME

pgpid - OpenPGP certificates that say whose they are

# SYNOPSIS

**pgpid** \[*OPTIONS*\]\... *ACTION *\[*ARGS*\]\...

# DESCRIPTION

Read and act on OpenPGP certificates through the pgpid model: entity
identifiers, validity, ownertrust.

## ACTIONS:

list

:   List the certificates of the keyring

get

:   Look a certificate up, refreshing it first

property

:   Print a vCard property of one certificate

sigs

:   List who has certified one certificate

ownertrust

:   Print or set how far one is trusted to certify

del

:   Delete certificates, by fingerprint only

avatar

:   Extract the image a certificate wears

push

:   Send certificates to the keyservers

gen_u4

:   Print the identifier a civil status gives

mrz_to_u4

:   Print the identifier a passport\'s machine zone gives

gen_uid

:   Print the Unix account number an identifier gives

## OPTIONS:

**-H**, **\--homedir** DIR

:   GnuPG home directory - Environment variable: GNUPGHOME

**\--output-format**=*FORMAT*

:   Specify output format between {raw, info, md} - Default: \'raw\'

**-h**, **\--help**

:   Print this help and exit

**-V**, **\--version**

:   Print the version and exit

Every action takes **\--help** of its own.

# DIAGNOSTICS

Returns zero on normal operation, non-zero on errors.

# SEE ALSO

**pgpid**(1), **pgpid-gen**(1), **pgpid-qrscan**(1),
[**bash-libs**](//codeberg.org/foopgp/bash-libs/src/branch/main/man/bash-libs.7.md)(7).

Each action takes a **--help** of its own, which says more than this page:

    pgpid certify --help

# AUTHORS

foopgp <info@foopgp.org>, Jean-Jacques Brucker <jjbrucker@foopgp.org>.

