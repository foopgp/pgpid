/* Reading the keyring, by asking gpg rather than gpgme.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * gpgme does not implement OpenPGP: it drives the gpg binary, and adds its
 * own probing on the way -- one `pgpid list` through it runs gpg three
 * times, gpgconf three times and gpgsm once, where asking gpg directly runs
 * one process. So this is not a fallback for want of a library; it is the
 * shorter road to the same place.
 *
 * It is also the only road that reaches every distribution we ship to.
 * gpgme_op_setownertrust arrived in gpgme 1.24 and wants GnuPG 2.4.6, which
 * Ubuntu 24.04 has neither of, and gpgme 2.0 changed the library's SONAME,
 * so a binary linked against libgpgme.so.11 does not load on 26.04 at all.
 * Depending on no library depends on no version of one.
 *
 * The colon format is gpg's machine interface and is documented to stay
 * stable: doc/DETAILS in the GnuPG tree names every field by number.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Split a colon line in place. strtok_r cannot do this: it folds empty
 * fields together, and a uid line with a blank validity would shift every
 * field after it. Returns how many were found; field[i] is never NULL below
 * that. */
static unsigned colon_split(char *line, char **field, unsigned max)
{
    unsigned n = 0;
    char *start = line;
    for (char *p = line; n < max; p++) {
        if (*p == ':' || !*p) {
            field[n++] = start;
            if (!*p)
                break;
            *p = '\0';
            start = p + 1;
        }
    }
    return n;
}

static const char *fld(char **field, unsigned nf, unsigned i)
{
    return i < nf && field[i] ? field[i] : "";
}

/* gpg spells "revoked" and the rest in field 2, the validity letter. */
static void set_flags(char v, bool *revoked, bool *expired, bool *invalid)
{
    *revoked = (v == 'r');
    *expired = (v == 'e');
    *invalid = (v == 'i' || v == 'd' || v == 'n');
}

/* The address inside the angle brackets, wherever they sit.
 *
 * Not pgpid_uid_address: that one answers "is this uid an address form",
 * and refuses "piseb <piseb@mailo.com> (udid4=...)" because a comment
 * follows the bracket. Its callers want that strictness. What is wanted
 * here is what gpgme put in u->email -- the address a uid carries, comment
 * or no comment. */
static void uid_mailbox(const char *uid, char *out, size_t max)
{
    *out = '\0';
    const char *lt = NULL;
    for (const char *p = uid; *p; p++)
        if (*p == '<')
            lt = p;
    if (!lt)
        return;
    const char *gt = strchr(lt, '>');
    if (!gt || gt == lt + 1)
        return;
    size_t n = (size_t)(gt - lt - 1);
    if (n >= max)
        n = max - 1;
    memcpy(out, lt + 1, n);
    out[n] = '\0';
}

struct pgpid_keyring {
    struct pgpid_key *key;
    size_t n, cap;
};

static struct pgpid_key *add_key(struct pgpid_keyring *kr)
{
    if (kr->n == kr->cap) {
        size_t cap = kr->cap ? kr->cap * 2 : 16;
        struct pgpid_key *p = realloc(kr->key, cap * sizeof *p);
        if (!p)
            return NULL;
        kr->key = p;
        kr->cap = cap;
    }
    struct pgpid_key *k = &kr->key[kr->n++];
    memset(k, 0, sizeof *k);
    return k;
}

/* Room for one more, doubling rather than reallocating on every element:
 * a keyring of 125 certificates walks this a few thousand times, and
 * growing by one each time made the listing slower than gpgme's, which was
 * not the point. The capacity is the next power of two, so a realloc only
 * happens when n crosses one -- no extra field to carry. */
static void *grow(void *base, size_t n, size_t size)
{
    if (n && (n & (n - 1)))
        return base;                     /* still inside the current block */
    size_t want = n ? n * 2 : 1;
    return realloc(base, want * size);
}

void pgpid_keys_free(struct pgpid_keyring *kr)
{
    if (!kr)
        return;
    for (size_t i = 0; i < kr->n; i++) {
        free(kr->key[i].uid);
        free(kr->key[i].sub);
    }
    free(kr->key);
    free(kr);
}

size_t pgpid_keys_count(const struct pgpid_keyring *kr)
{
    return kr ? kr->n : 0;
}

const struct pgpid_key *pgpid_keys_at(const struct pgpid_keyring *kr, size_t i)
{
    return kr && i < kr->n ? &kr->key[i] : NULL;
}

struct pgpid_keyring *pgpid_keys_load(const char *const *patterns, size_t npat,
                                      unsigned flags)
{
    /* --with-colons alone gives no fingerprint for the primary key and none
     * for subkeys; --with-fingerprint twice is what gpg wants for both. */
    const char *argv[64];
    unsigned a = 0;
    argv[a++] = "--with-colons";
    argv[a++] = "--with-fingerprint";
    argv[a++] = "--with-fingerprint";
    if (flags & PGPID_KEYS_SIGS)
        argv[a++] = "--with-sig-list";
    argv[a++] = (flags & PGPID_KEYS_SECRET) ? "--list-secret-keys" : "--list-keys";
    /* An eid may begin with a dash. */
    argv[a++] = "--";
    for (size_t i = 0; i < npat && a < 62; i++)
        argv[a++] = patterns[i];
    argv[a] = NULL;

    size_t room = 1u << 20;
    char *listing = malloc(room);
    if (!listing)
        return NULL;
    int got = pgpid_capture_engine(argv, listing, room);
    if (got <= 0) {
        free(listing);
        /* No key is not an error: an empty keyring answers nothing. */
        struct pgpid_keyring *kr = calloc(1, sizeof *kr);
        return kr;
    }

    struct pgpid_keyring *kr = calloc(1, sizeof *kr);
    if (!kr) {
        free(listing);
        return NULL;
    }

    struct pgpid_key *k = NULL;
    enum { NOWHERE, ON_PRIMARY, ON_SUB, ON_UID } last = NOWHERE;

    for (char *line = listing, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        char *field[24] = { NULL };
        unsigned nf = colon_split(line, field, 24);
        if (nf < 2)
            continue;
        const char *rec = field[0];

        if (!strcmp(rec, "pub") || !strcmp(rec, "sec")) {
            k = add_key(kr);
            if (!k)
                break;
            k->secret = (rec[0] == 's');
            k->validity = *fld(field, nf, 1) ? fld(field, nf, 1)[0] : '-';
            set_flags(k->validity, &k->revoked, &k->expired, &k->invalid);
            snprintf(k->keyid, sizeof k->keyid, "%s", fld(field, nf, 4));
            k->created = strtol(fld(field, nf, 5), NULL, 10);
            k->expires = strtol(fld(field, nf, 6), NULL, 10);
            k->ownertrust = *fld(field, nf, 8) ? fld(field, nf, 8)[0] : '-';
            snprintf(k->caps, sizeof k->caps, "%s", fld(field, nf, 11));
            last = ON_PRIMARY;
            continue;
        }
        if (!k)
            continue;

        if (!strcmp(rec, "sub") || !strcmp(rec, "ssb")) {
            struct pgpid_subkey *s = grow(k->sub, k->nsub, sizeof *s);
            if (!s)
                break;
            k->sub = s;
            s = &k->sub[k->nsub++];
            memset(s, 0, sizeof *s);
            s->validity = *fld(field, nf, 1) ? fld(field, nf, 1)[0] : '-';
            set_flags(s->validity, &s->revoked, &s->expired, &s->invalid);
            snprintf(s->keyid, sizeof s->keyid, "%s", fld(field, nf, 4));
            s->created = strtol(fld(field, nf, 5), NULL, 10);
            s->expires = strtol(fld(field, nf, 6), NULL, 10);
            snprintf(s->caps, sizeof s->caps, "%s", fld(field, nf, 11));
            /* Field 15 carries the serial of the card the secret sits on --
             * gpgme spelled this is_cardkey. */
            snprintf(s->card, sizeof s->card, "%s", fld(field, nf, 14));
            last = ON_SUB;
            continue;
        }
        if (!strcmp(rec, "uid")) {
            struct pgpid_keyuid *u = grow(k->uid, k->nuid, sizeof *u);
            if (!u)
                break;
            k->uid = u;
            u = &k->uid[k->nuid++];
            memset(u, 0, sizeof *u);
            u->validity = *fld(field, nf, 1) ? fld(field, nf, 1)[0] : '-';
            set_flags(u->validity, &u->revoked, &u->expired, &u->invalid);
            u->created = strtol(fld(field, nf, 5), NULL, 10);
            pgpid_colon_unescape(fld(field, nf, 9), u->text, sizeof u->text);
            uid_mailbox(u->text, u->address, sizeof u->address);
            last = ON_UID;
            continue;
        }
        if (!strcmp(rec, "uat")) {
            /* An attribute packet -- a photograph. It is a user id to gpg,
             * which is the whole of foopgp/0001 upstream, but it carries no
             * text and nothing here wants one. Counted so that indexes into
             * the uid list stay honest. */
            k->nuat++;
            last = ON_UID;
            continue;
        }
        if (!strcmp(rec, "fpr")) {
            const char *f = fld(field, nf, 9);
            if (last == ON_SUB && k->nsub)
                snprintf(k->sub[k->nsub - 1].fpr, 41, "%s", f);
            else if (last == ON_PRIMARY && !*k->fpr)
                snprintf(k->fpr, sizeof k->fpr, "%s", f);
            continue;
        }
        if (!strcmp(rec, "sig") && (flags & PGPID_KEYS_SIGS) && k->nuid) {
            struct pgpid_keyuid *u = &k->uid[k->nuid - 1];
            struct pgpid_keysig *g = grow(u->sig, u->nsig, sizeof *g);
            if (!g)
                break;
            u->sig = g;
            g = &u->sig[u->nsig++];
            memset(g, 0, sizeof *g);
            snprintf(g->keyid, sizeof g->keyid, "%s", fld(field, nf, 4));
            g->created = strtol(fld(field, nf, 5), NULL, 10);
            pgpid_colon_unescape(fld(field, nf, 9), g->text, sizeof g->text);
            uid_mailbox(g->text, g->address, sizeof g->address);
            continue;
        }
    }
    free(listing);
    return kr;
}

/* The certificate's own bytes. Through a file rather than a pipe read into
 * a string: an export is binary, and the first NUL would end it. */
unsigned char *pgpid_export_key(const char *fpr, bool minimal, size_t *len)
{
    char path[] = "/tmp/pgpid-export.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0)
        return NULL;
    close(fd);

    const char *argv[8];
    unsigned a = 0;
    argv[a++] = "--export";
    if (minimal) {
        argv[a++] = "--export-options";
        argv[a++] = "export-minimal";
    }
    argv[a++] = "--";
    argv[a++] = fpr;
    argv[a] = NULL;

    unsigned char *buf = NULL;
    *len = 0;
    if (!pgpid_run_engine_io(argv, NULL, path)) {
        FILE *f = fopen(path, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long n = ftell(f);
            if (n > 0 && (buf = malloc((size_t)n))) {
                rewind(f);
                *len = fread(buf, 1, (size_t)n, f);
                if (!*len) {
                    free(buf);
                    buf = NULL;
                }
            }
            fclose(f);
        }
    }
    unlink(path);
    return buf;
}
