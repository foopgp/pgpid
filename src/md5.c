/* MD5, because an entity identifier is one.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Written here rather than linked, for one reason and against the usual
 * advice. The usual advice is about *security*: do not write your own
 * cryptography. This is not cryptography — a u4 is a deterministic name
 * derived from a civil status, and MD5 is the function the specification
 * names. Nothing here defends against an adversary; being wrong would
 * produce a different identifier, loudly, not a weak one.
 *
 * Against that, linking libgcrypt would add a dependency gpgme does not
 * already bring — it talks to the engine over assuan, not by linking crypto —
 * and the identifier derivation has to exist wherever the model does,
 * Android included, where libgcrypt is not.
 *
 * RFC 1321. The test vectors from its appendix are in the harness; so is
 * JJB's own identifier, derived from his civil status, which is the vector
 * that actually matters.
 */
#include "pgpid.h"

#include <string.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* Table T[i] = floor(2^32 × abs(sin(i))), i in radians — RFC 1321 §3.4. */
static const uint32_t T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

/* Per-round left rotations, and which message word each step reads. */
static const unsigned S[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
};

static unsigned word_of_step(unsigned i)
{
    if (i < 16) return i;
    if (i < 32) return (5 * i + 1) % 16;
    if (i < 48) return (3 * i + 5) % 16;
    return (7 * i) % 16;
}

static void transform(uint32_t state[4], const unsigned char block[64])
{
    uint32_t m[16];
    for (unsigned i = 0; i < 16; i++)
        m[i] = (uint32_t)block[i * 4]
             | ((uint32_t)block[i * 4 + 1] << 8)
             | ((uint32_t)block[i * 4 + 2] << 16)
             | ((uint32_t)block[i * 4 + 3] << 24);

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    for (unsigned i = 0; i < 64; i++) {
        uint32_t f;
        if (i < 16)      f = (b & c) | (~b & d);
        else if (i < 32) f = (d & b) | (~d & c);
        else if (i < 48) f = b ^ c ^ d;
        else             f = c ^ (b | ~d);

        uint32_t tmp = d;
        d = c;
        c = b;
        b = b + ROTL(a + f + T[i] + m[word_of_step(i)], S[i]);
        a = tmp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void pgpid_md5(const void *data, size_t len, unsigned char out[16])
{
    uint32_t state[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
    const unsigned char *p = data;
    size_t whole = len / 64;

    for (size_t i = 0; i < whole; i++)
        transform(state, p + i * 64);

    /* The tail: what is left, a 0x80 byte, zeroes, and the length in bits as
     * a little-endian 64-bit number. Two blocks when the remainder leaves no
     * room for the length. */
    unsigned char tail[128] = { 0 };
    size_t rest = len - whole * 64;
    memcpy(tail, p + whole * 64, rest);
    tail[rest] = 0x80;
    size_t tail_len = (rest < 56) ? 64 : 128;

    uint64_t bits = (uint64_t)len * 8;
    for (unsigned i = 0; i < 8; i++)
        tail[tail_len - 8 + i] = (unsigned char)(bits >> (8 * i));

    transform(state, tail);
    if (tail_len == 128)
        transform(state, tail + 64);

    for (unsigned i = 0; i < 4; i++) {
        out[i * 4]     = (unsigned char)(state[i]);
        out[i * 4 + 1] = (unsigned char)(state[i] >> 8);
        out[i * 4 + 2] = (unsigned char)(state[i] >> 16);
        out[i * 4 + 3] = (unsigned char)(state[i] >> 24);
    }
}

/* base64url, the alphabet an identifier is written in: the same sixty-four
 * characters as base64 with '-' and '_' where '+' and '/' would be, so that
 * an identifier survives a URL and a file name. Padding is the caller's
 * business — a u4 is the first twenty-two characters and drops it. */
static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

void pgpid_base64url(const unsigned char *in, size_t len, char *out)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = in[i] << 16;
        if (i + 1 < len) v |= in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = B64URL[(v >> 18) & 63];
        out[o++] = B64URL[(v >> 12) & 63];
        out[o++] = (i + 1 < len) ? B64URL[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < len) ? B64URL[v & 63] : '=';
    }
    out[o] = '\0';
}

/* The reverse, for reading an identifier back into the bytes it stands for.
 * Returns how many bytes were written, or -1 on a character that is not in
 * the alphabet — a malformed identifier must be refused, not guessed at. */
int pgpid_base64url_decode(const char *in, unsigned char *out, size_t max)
{
    unsigned acc = 0, bits = 0;
    size_t n = 0;
    for (; *in && *in != '='; in++) {
        const char *at = strchr(B64URL, *in);
        if (!at || !*in)
            return -1;
        acc = (acc << 6) | (unsigned)(at - B64URL);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= max)
                return -1;
            out[n++] = (unsigned char)(acc >> bits);
        }
    }
    return (int)n;
}

/* Standard base64, the one a vCard carries — '+' and '/' where an identifier
 * would use '-' and '_', and the padding kept, because a data: URI is read by
 * things that expect it. */
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void pgpid_base64(const unsigned char *in, size_t len, char *out)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < len) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = (i + 1 < len) ? B64[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < len) ? B64[v & 63] : '=';
    }
    out[o] = '\0';
}
