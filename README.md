---
title: PGPID
section: 1
header: User Commands
footer: pgpid
date: May 2021
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
$ sudo apt install facedetect graphicsmagick tesseract-ocr qrencode cups-client zbar-tools scdaemon pandoc texlive-extra-utils xxd
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

**pgpid-note**(7), **mrtdreader**(1).


# AUTHOR

Jean-Jacques Brucker

