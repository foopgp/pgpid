<!--
© 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>

SPDX-License-Identifier: GPL-3.0-only
-->

---
title: PGPID-GEN
section: 1
header: User Commands
footer: pgpid 0.0.5
---

# NAME

pgpid-gen - manual page for pgpid-gen 0.0.5

# SYNOPSIS

**pgpid-gen** \[*OPTIONS*\]\... \[*\--*\] \[*IMAGE*\]

# DESCRIPTION

## If pgpid-gen succeed, it will :

> \* create a subdirectory containing the public certificate and the
> pubkey to be use for ssh. \* print the secret keys on multiple
> QRcodes. To be put on a OpenPGP card (eg. yubikey) using pgpid-qrscan.

If no IMAGE is given, pgpid-gen will try to use webcam.

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

**-f**, **\--free-comment** STR

:   free form comment, imply also no image face detection

**-h**, **\--help**

:   show this help and exit

**-V**, **\--version**

:   show version and exit

# DIAGNOSTICS

Returns zero on normal operation, non-zero on errors.

# SEE ALSO

[**bash-libs**](https://codeberg.org/foopgp/bash-libs/src/branch/main/man/bash-libs.7.md)(7),
[**bl-pgpid**](https://codeberg.org/foopgp/bash-libs/src/branch/main/man/bl-pgpid.1.md)(1),
[**bl-qrkey**](https://codeberg.org/foopgp/bash-libs/src/branch/main/man/bl-qrkey.1.md)(1).

# AUTHORS

foopgp <info@foopgp.org>, Jean-Jacques Brucker <jjbrucker@foopgp.org>.

