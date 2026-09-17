/* base45, the text a QR code stores most tightly.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * RFC 9285. Its forty-five characters are exactly the ones the alphanumeric
 * mode of a QR code stores, eleven bits a pair: a secret written this way
 * costs 8.25 bits an octet inside the symbol, where base64url, which only
 * byte mode can hold, costs 10.67. That is the whole reason version 6 of the
 * secret sheets exists (draft-foopgp-secret-sheets).
 *
 * Two octets become three characters, least significant first; a last odd
 * octet becomes two. The text has spaces in it, never at its end.
 */
#include "pgpid.h"

#include <string.h>

static const char B45[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

void pgpid_base45(const unsigned char *in, size_t len, char *out)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i += 2) {
        if (i + 1 < len) {
            unsigned v = (unsigned)in[i] << 8 | in[i + 1];
            out[o++] = B45[v % 45];
            out[o++] = B45[v / 45 % 45];
            out[o++] = B45[v / 2025];
        } else {
            out[o++] = B45[in[i] % 45];
            out[o++] = B45[in[i] / 45];
        }
    }
    out[o] = '\0';
}

/* The value of one character, or -1 for one that is not in the alphabet.
 * strchr would also find the terminating NUL, which is not a character. */
static int value_of(char c)
{
    const char *at = c ? strchr(B45, c) : NULL;
    return at ? (int)(at - B45) : -1;
}

/* The octets back. Refused, as RFC 9285 requires, on a character outside the
 * alphabet and on a group worth more than 65535; refused too, since neither
 * can come out of an encoder, on a last group of one character and on a last
 * pair worth more than 255. Answers the number of octets, or -1. */
int pgpid_base45_decode(const char *in, unsigned char *out, size_t max)
{
    size_t len = strlen(in), n = 0;
    if (len % 3 == 1)
        return -1;
    for (size_t i = 0; i < len; i += 3) {
        int a = value_of(in[i]), b = value_of(in[i + 1]);
        if (a < 0 || b < 0)
            return -1;
        if (i + 2 < len) {
            int c = value_of(in[i + 2]);
            if (c < 0)
                return -1;
            unsigned v = (unsigned)(a + b * 45 + c * 2025);
            if (v > 0xFFFF || n + 2 > max)
                return -1;
            out[n++] = (unsigned char)(v >> 8);
            out[n++] = (unsigned char)v;
        } else {
            unsigned v = (unsigned)(a + b * 45);
            if (v > 0xFF || n + 1 > max)
                return -1;
            out[n++] = (unsigned char)v;
        }
    }
    return (int)n;
}
