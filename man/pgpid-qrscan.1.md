<!--
© 2025 Jean-Jacques Brucker <jjbrucker@foopgp.org>

SPDX-License-Identifier: GPL-3.0-only
-->

---
title: PGPID-QRSCAN
section: 1
header: User Commands
footer: pgpid 0.0.5
---

# NAME

pgpid-qrscan - manual page for pgpid-qrscan 0.0.5

# SYNOPSIS

**pgpid-qrscan** \[*OPTIONS*\]\... \[*\--*\] \[*IMAGES*\]\...

# DESCRIPTION

pgpid-qrscan scan QRcodes containing parts of OpenPGP secrets from
IMAGES or webcam, and import this secrets into a factory reseted OpenPGP
secured device (eg yubikey).

# OPTIONS

**-k**, **\--no-send**

:   don\'t send public key (certificate) to HKPS keyserver ()

**-v**, **\--verbose**

:   increase log verbosity: \...\<notice\[5\]\<info\[6\]\<debug\[7\]
    (current: 6)

**-q**, **\--quiet**

:   decrease log verbosity:
    \...\<err\[3\]\<warning\[4\]\<notice\[5\]\<\... (current: 6)

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

