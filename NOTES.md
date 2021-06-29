---
title: PGPID-NOTES
section: 7
header: Miscellaneous informations
footer: pgpid
date: May 2021
---

# NAME

pgpid - Programmer and user notes.


# DESCRIPTION

**pgpid** aims to generate or update OpenPGP public certificates and private keys, in a
standardized way that fit most of its usages.

This tool is an initiative of the [FoOPGP organization](https://foopgp.org).

# CONTEXT

## History

The **OpenPGP format** is the concretization of a vision embodied [in its infancy](https://tools.ietf.org/html/rfc1991) by Philip Zimmerman.

Since the late 1990s, this vision has been widely shared, and OpenPGP can now no longer be reduced to a format for signing or encrypting emails.

Then we now talk about **OpenPGP technologies** to embrace all its specified usages.

One of its uses is to mirror ID used in the analogic world (traveling, voting,
owning, healthcare, etc.), inside numeric world (Internet).

In the early 2020s, this use has however still not widespread. **FoOPGP** and **pgpid** aim to fix this.

### Miscellaneous historical links

* https://linuxfr.org/users/jbar/journaux/thttpgpd-ou-comment-openudc-a-ressuscite-le-bon-vieux-thttpd
* https://linuxfr.org/users/mgautier/journaux/presentation-d-idee-pgpid

## Technology watch

Everything concerning OpenPGP should be at least indexed in [FoOPGP
website](https://foopgp.org).

:  Non related with OpenPGP:
* https://en.wikipedia.org/wiki/Machine-readable_passport

## Marketing watch

:  "zero trust" - *very trendy since the [SolarWinds story](https://en.wikipedia.org/wiki/2020_United_States_federal_government_data_breach)*
* https://www.zdnet.fr/actualites/dsi-qu-est-ce-que-l-approche-zero-trust-et-comment-la-mettre-en-place-39921425.htm
* https://www.google.com/search?q=zero+trust ...

## Initiative watch

* Internet search for "idcert" or "pgpid"
* https://www.idcert.fr/demande/cgu.aspx
* https://www.consilium.europa.eu/prado/en/prado-start-page.html

## Existing pieces of software

* https://github.com/konstantint/PassportEye
* https://github.com/rubund/mrtdreader
* $ apt search passport


# Ideas

* use Scrypt instead of md5sum for udid4
* use ed25519 for main key then we can use "mnemonic" instead of paperkey to
  print secret key
* Maybe use ed25519 for main key to use derivations
* Shamir shared secret.

# TODO

* being able to directly read RFID of existing Passport, ID card, etc...

# SEE ALSO

pgpid, tesseract, facedetect, mrtdreader

# AUTHOR

Jean-Jacques Brucker

