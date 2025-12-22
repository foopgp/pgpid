<!--
© 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>

SPDX-License-Identifier: GPL-3.0-only
-->

---
title: PGPID-GEN
section: 1
header: User Commands
footer: pgpid 0.0.6
---

# NAME

pgpid-gen - manual page for pgpid-gen 0.0.6

# SYNOPSIS

**pgpid-gen** \[*OPTIONS*\]\... \[*\--*\] \[*PASSPORT_IMAGE*\]

# DESCRIPTION

Generate OpenPGP certifcates and secrets on multiple QR codes (physical
secret sharing scheme) It may take the main page of an international
passport as input (ICAO 9303 compliant). If pgpid-gen succeed, it will :

> \* create a subdirectory containing the public certificate and the
> pubkey to be use for ssh. \* print the secret keys on multiple
> QRcodes. To be put on a OpenPGP card (eg. yubikey) using pgpid-qrscan.

# OPTIONS

**-o**, **\--output-path** PATH

:   location for generated subdirs and files (default: current dir \$PWD
    )

**-s**, **\--split** NUM

:   number of shares to be generated (default: 5)

**-t**, **\--threshold** NUM

:   number of shares necessary to reconstruct the secret (default: 3)

**-v**, **\--verbose**

:   increase log verbosity: \...\<notice\[5\]\<info\[6\]\<debug\[7\]
    (default: 5)

**-q**, **\--quiet**

:   decrease log verbosity:
    \...\<err\[3\]\<warning\[4\]\<notice\[5\]\<\... (default: 5)

**-C**, **\--extra-comment** STR

:   (Free to use part of) comment beside new EMAIL (default: ).

**-h**, **\--help**

:   show this help and exit

**-V**, **\--version**

:   show version and exit

# DIAGNOSTICS

Returns zero on normal operation, non-zero on errors.

# SEE ALSO

[**bash-libs**](//codeberg.org/foopgp/bash-libs/src/branch/main/man/bash-libs.7.md)(7),
[**bl-pgpid**](//codeberg.org/foopgp/bash-libs/src/branch/main/man/bl-pgpid.1.md)(1),
[**bl-qrkey**](//codeberg.org/foopgp/bash-libs/src/branch/main/man/bl-qrkey.1.md)(1).

# AUTHORS

foopgp <info@foopgp.org>, Jean-Jacques Brucker <jjbrucker@foopgp.org>.

