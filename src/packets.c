/* Reading an OpenPGP certificate's packets, for what gpgme will not say.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * gpgme hands over a user id's text, its validity and its signatures, and
 * nothing else. The image a certificate wears, and the keyserver it names as
 * its own, are both in packets it never surfaces — so they are read here,
 * once, by whoever needs them. Two copies of a packet walk would be two
 * answers waiting to differ.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>



/* One packet at P. False at the end of the stream, or on a header we do not
 * read — a truncated export must stop the walk, not wander into it. */
bool pgpid_packet_next(const unsigned char *p, const unsigned char *end,
                        struct pgpid_packet *out)
{
    if (p >= end || !(*p & 0x80))
        return false;
    unsigned b0 = *p++;
    size_t len;

    if (b0 & 0x40) {                      /* current format */
        out->tag = b0 & 0x3F;
        if (p >= end)
            return false;
        unsigned l0 = *p++;
        if (l0 < 192) {
            len = l0;
        } else if (l0 < 224) {
            if (p >= end)
                return false;
            len = ((size_t)(l0 - 192) << 8) + *p++ + 192;
        } else if (l0 == 255) {
            if ((size_t)(end - p) < 4)
                return false;
            len = ((size_t)p[0] << 24) | ((size_t)p[1] << 16)
                | ((size_t)p[2] << 8) | p[3];
            p += 4;
        } else {
            return false;             /* partial length: not on these packets */
        }
    } else {                              /* historical format */
        out->tag = (b0 >> 2) & 0x0F;
        unsigned lt = b0 & 0x03;
        if (lt == 0) {
            if (p >= end)
                return false;
            len = *p++;
        } else if (lt == 1) {
            if ((size_t)(end - p) < 2)
                return false;
            len = ((size_t)p[0] << 8) | p[1];
            p += 2;
        } else if (lt == 2) {
            if ((size_t)(end - p) < 4)
                return false;
            len = ((size_t)p[0] << 24) | ((size_t)p[1] << 16)
                | ((size_t)p[2] << 8) | p[3];
            p += 4;
        } else {
            len = (size_t)(end - p);              /* runs to the end */
        }
    }

    if (len > (size_t)(end - p))
        return false;
    out->body = p;
    out->len = len;
    out->next = p + len;
    return true;
}

/* A subpacket length, shared by attribute and signature subpackets (§5.2.3.7
 * and §5.12). Advances P past the length itself. */
bool pgpid_sub_length(const unsigned char **p, const unsigned char *end,
                       size_t *len)
{
    if (*p >= end)
        return false;
    unsigned b0 = *(*p)++;
    if (b0 < 192) {
        *len = b0;
        return true;
    }
    if (b0 < 224) {
        if (*p >= end)
            return false;
        *len = ((size_t)(b0 - 192) << 8) + *(*p)++ + 192;
        return true;
    }
    if (b0 == 255) {
        if ((size_t)(end - *p) < 4)
            return false;
        *len = ((size_t)(*p)[0] << 24) | ((size_t)(*p)[1] << 16)
             | ((size_t)(*p)[2] << 8) | (*p)[3];
        *p += 4;
        return true;
    }
    return false;
}

/* The JPEG inside an attribute packet, or false when it carries none.
 * The image subpacket opens with a header whose own length is given first,
 * so an unknown header version is skipped rather than guessed at. */
bool pgpid_attribute_image(const struct pgpid_packet *pkt,
                            const unsigned char **data, size_t *len)
{
    const unsigned char *p = pkt->body, *end = pkt->body + pkt->len;
    while (p < end) {
        size_t sl;
        if (!pgpid_sub_length(&p, end, &sl) || sl == 0 || sl > (size_t)(end - p))
            return false;
        const unsigned char *sub = p + 1;         /* past the type byte */
        size_t sublen = sl - 1;
        unsigned type = *p;
        p += sl;
        if (type != ATTR_IMAGE || sublen < 3)
            continue;
        size_t hdr = (size_t)sub[0] | ((size_t)sub[1] << 8);   /* little endian */
        if (hdr < 4 || hdr > sublen)
            continue;
        /* Version 1, encoding 1: the only image an attribute packet has ever
         * been allowed to hold. We write .jpg files, so we check rather than
         * assume. */
        if (sub[2] != 1 || sub[3] != 1)
            continue;
        *data = sub + hdr;
        *len = sublen - hdr;
        return *len > 0;
    }
    return false;
}

/* What a signature says about the packet before it: its kind, when it was
 * made, and who made it. Only the hashed half is read — the unhashed half is
 * not covered by the signature, so nothing there may decide anything. */
bool pgpid_signature_read(const struct pgpid_packet *pkt, unsigned *type,
                           unsigned long *created, const char **issuer_hex)
{
    static char issuer[17];
    const unsigned char *p = pkt->body, *end = pkt->body + pkt->len;
    if (p >= end)
        return false;
    unsigned version = *p++;
    size_t hashed_len;

    if (version == 4) {
        if ((size_t)(end - p) < 5)
            return false;
        *type = *p++;
        p += 2;                                   /* public key, hash */
        hashed_len = ((size_t)p[0] << 8) | p[1];
        p += 2;
    } else if (version == 6) {
        if ((size_t)(end - p) < 7)
            return false;
        *type = *p++;
        p += 2;
        hashed_len = ((size_t)p[0] << 24) | ((size_t)p[1] << 16)
                   | ((size_t)p[2] << 8) | p[3];
        p += 4;
    } else {
        return false;                             /* v3 and older: gone */
    }
    if (hashed_len > (size_t)(end - p))
        return false;

    *created = 0;
    *issuer_hex = NULL;
    issuer[0] = '\0';
    const unsigned char *hp = p, *hend = p + hashed_len;
    while (hp < hend) {
        size_t sl;
        if (!pgpid_sub_length(&hp, hend, &sl) || sl == 0 || sl > (size_t)(hend - hp))
            break;
        unsigned st = *hp & 0x7F;                 /* the critical bit is not the type */
        const unsigned char *sv = hp + 1;
        size_t svlen = sl - 1;
        hp += sl;
        if (st == 2 && svlen >= 4) {              /* creation time */
            *created = ((unsigned long)sv[0] << 24) | ((unsigned long)sv[1] << 16)
                     | ((unsigned long)sv[2] << 8) | sv[3];
        } else if (st == 16 && svlen >= 8) {      /* issuer key id */
            for (int i = 0; i < 8; i++)
                snprintf(issuer + i * 2, 3, "%02X", sv[i]);
            *issuer_hex = issuer;
        } else if (st == 33 && svlen >= 21) {     /* issuer fingerprint */
            /* The key id sits at the end of a v4 fingerprint and at the
             * front of a v6 one, so the version byte decides where to look. */
            const unsigned char *id = (sv[0] == 6) ? sv + 1 : sv + svlen - 8;
            for (int i = 0; i < 8; i++)
                snprintf(issuer + i * 2, 3, "%02X", id[i]);
            *issuer_hex = issuer;
        }
    }
    return *created != 0;
}

/**
 * One hashed subpacket of a signature, by type.
 *
 * Only the hashed half is read: the unhashed half is not covered by the
 * signature, so a value found there is something anybody could have written.
 * Type 24 is the keyserver a certificate names as its own, which is the one
 * this was written for.
 */
bool pgpid_signature_subpacket(const struct pgpid_packet *pkt, unsigned want,
                               const unsigned char **data, size_t *len)
{
    const unsigned char *p = pkt->body, *end = pkt->body + pkt->len;
    if (p >= end)
        return false;
    unsigned version = *p++;
    size_t hashed_len;

    if (version == 4) {
        if ((size_t)(end - p) < 5)
            return false;
        p += 3;                       /* type, public key, hash */
        hashed_len = ((size_t)p[0] << 8) | p[1];
        p += 2;
    } else if (version == 6) {
        if ((size_t)(end - p) < 7)
            return false;
        p += 3;
        hashed_len = ((size_t)p[0] << 24) | ((size_t)p[1] << 16)
                   | ((size_t)p[2] << 8) | p[3];
        p += 4;
    } else {
        return false;
    }
    if (hashed_len > (size_t)(end - p))
        return false;

    const unsigned char *hp = p, *hend = p + hashed_len;
    while (hp < hend) {
        size_t sl;
        if (!pgpid_sub_length(&hp, hend, &sl) || sl == 0 || sl > (size_t)(hend - hp))
            break;
        unsigned st = *hp & 0x7F;     /* the critical bit is not the type */
        if (st == want) {
            *data = hp + 1;
            *len = sl - 1;
            return true;
        }
        hp += sl;
    }
    return false;
}
