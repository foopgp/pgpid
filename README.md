---
title: PGPID
section: 1
header: User Commands
footer: pgpid
date: Dec 2025
---

# NAME

pgpid-gen - generate OpenPGP certifcates and secrets on multiple QR codes (physical secret sharing scheme)

pgpid-qrscan - transfers OpenPGP secrets from pgpid QR codes to OpenPGP smartcard (eg: yubikey, nitrokey, ...)

# SYNOPSIS



# DESCRIPTION

# OPTIONS

# FILES

# ENVIRONMENT VARIABLES

# DIAGNOSTICS

Returns zero on normal operation, non-zero on errors.

# TRY IT

On Debian (or some derivated) :

```
$ git clone --recurse-submodules https://codeberg.org/foopgp/pgpid.git
$ sudo apt install facedetect graphicsmagick tesseract-ocr qrencode gpg-wks-client cups-client zbar-tools scdaemon pandoc texlive-extra-utils xxd libgfshare-bin cups-bsd
$ cd pgpid
$ ./bin/pgpid-gen
```

# EXAMPLES

# CONTRIBUTE

To sign your commits and push over ssh (and use the YubiKey or NitroKey
you have configured with pgpid-gen and pgpid-qrscan) :
```
$ git config url.git@codeberg.org:.pushInsteadOf https://codeberg.org/
$ git config --global commit.gpgsign true
```

# SEE ALSO

[**bash-libs**](https://codeberg.org/foopgp/bash-libs/src/branch/main/man/bash-libs.7.md)(7),
[**pgpid-gen**](man/pgpid-gen.1.md)(1),
[**pgpid-qrscan**](man/pgpid-qrscan.1.md)(1),
[**mrtdreader**](https://github.com/rubund/mrtdreader)(1).

# AUTHOR

Jean-Jacques Brucker

