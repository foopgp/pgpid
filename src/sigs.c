/* Who has certified this certificate — one step of the web of trust.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * `gpg --list-sigs` answers per uid, which is the wrong unit: a certification
 * is about the entity, not about one of the addresses it happens to carry.
 * So this lists the signatures of the identity uid — the UID:urn:eid:… one,
 * the only uid every certificate of ours has — and offers the merged list of
 * every uid under --all-uids, for the certificates minted before that
 * convention, where the same certifiers signed whatever uid existed then.
 *
 * Each row is date, key identifier, address. The key identifier is what goes
 * back into a search to walk one step further, and it is the identifier
 * rather than the fingerprint because a signature packet only carries the
 * former — which is also why a search on it may find more than one
 * certificate, and why it is the caller's business to say which.
 *
 * Self-signatures are left out. A certificate vouching for itself is what
 * makes a uid stand, not a certification, and counting it would give every
 * certificate one friend it does not have.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct row {
    char keyid[33];
    long timestamp;
    char *email;
};

static void row_free(struct row *r)
{
    free(r->email);
    r->email = NULL;
}

/* Newest wins: a signer who certified twice has said the second thing. */
static void remember(struct row **rows, size_t *n, size_t *cap,
                     const char *keyid, long ts, const char *email)
{
    for (size_t i = 0; i < *n; i++) {
        if (strcmp((*rows)[i].keyid, keyid))
            continue;
        if (ts > (*rows)[i].timestamp) {
            (*rows)[i].timestamp = ts;
            free((*rows)[i].email);
            (*rows)[i].email = email && *email ? strdup(email) : NULL;
        }
        return;
    }
    if (*n == *cap) {
        size_t grown = *cap ? *cap * 2 : 32;
        struct row *bigger = realloc(*rows, grown * sizeof *bigger);
        if (!bigger)
            return;
        *rows = bigger;
        *cap = grown;
    }
    snprintf((*rows)[*n].keyid, sizeof (*rows)[*n].keyid, "%s", keyid);
    (*rows)[*n].timestamp = ts;
    (*rows)[*n].email = email && *email ? strdup(email) : NULL;
    (*n)++;
}

static int by_date(const void *a, const void *b)
{
    long ta = ((const struct row *)a)->timestamp;
    long tb = ((const struct row *)b)->timestamp;
    return ta < tb ? -1 : ta > tb ? 1 : 0;
}

static bool is_identity_uid(const char *uid)
{
    return uid && !strncmp(uid, "UID:urn:eid:", 12);
}

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: " PGPID_NAME " sigs [OPTIONS]... FINGERPRINT\n"
        "\n"
        "List who has certified that certificate, oldest first: date, key\n"
        "identifier, address. The key identifier is what a search takes to walk\n"
        "one step further into the web of trust.\n"
        "\n"
        "Only the identity uid (UID:urn:eid:...) is read, because a certification\n"
        "is about the entity and not about one of its addresses. A certificate\n"
        "carrying no identity uid falls back to the merged list, with a notice.\n"
        "\n"
        "Self-signatures are left out: they make a uid stand, they do not\n"
        "certify anyone.\n"
        "\n"
        "OPTIONS:\n"
        "  -a, --all-uids              Merge the signatures of every uid\n"
        "  -h, --help                  Print this help and exit\n");
}

int pgpid_action_sigs(int argc, char **argv)
{
    bool all_uids = false;
    const char *pattern = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-a") || !strcmp(a, "--all-uids")) {
            all_uids = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            if (i + 1 < argc)
                pattern = argv[i + 1];
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error("Error: Unrecognized option '%s'.", a);
            pgpid_error("Try '" PGPID_NAME " sigs --help' for more information.");
            return PGPID_USAGE;
        } else {
            pattern = a;
            break;
        }
    }

    if (!pattern) {
        pgpid_error("Error: A fingerprint is required.");
        return PGPID_USAGE;
    }

    gpgme_ctx_t ctx = NULL;
    gpgme_error_t err = pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL |
                                            GPGME_KEYLIST_MODE_SIGS);
    if (err) {
        pgpid_gpgme_error("opening the engine", err);
        return PGPID_FAIL;
    }

    err = gpgme_op_keylist_start(ctx, pattern, 0);
    if (err) {
        pgpid_gpgme_error("looking the certificate up", err);
        gpgme_release(ctx);
        return PGPID_FAIL;
    }
    gpgme_key_t key = NULL;
    err = gpgme_op_keylist_next(ctx, &key);
    gpgme_op_keylist_end(ctx);
    if (gpg_err_code(err) == GPG_ERR_EOF) {
        pgpid_error("Error: No certificate matching '%s'.", pattern);
        gpgme_release(ctx);
        return PGPID_NOTHING;
    }
    if (err) {
        pgpid_gpgme_error("reading the certificate", err);
        gpgme_release(ctx);
        return PGPID_FAIL;
    }

    /* Without an identity uid there is nothing to be selective about, and an
     * empty answer would read as "nobody certified this" — which is a
     * different statement. */
    bool has_identity = false;
    for (gpgme_user_id_t u = key->uids; u; u = u->next)
        if (!u->revoked && !u->invalid && is_identity_uid(u->uid))
            has_identity = true;
    if (!all_uids && !has_identity) {
        pgpid_error("Notice: No identity uid; merging every uid instead.");
        all_uids = true;
    }

    const char *own = key->subkeys ? key->subkeys->keyid : NULL;
    struct row *rows = NULL;
    size_t n = 0, cap = 0;

    for (gpgme_user_id_t u = key->uids; u; u = u->next) {
        if (u->revoked || u->invalid)
            continue;
        if (!all_uids && !is_identity_uid(u->uid))
            continue;
        for (gpgme_key_sig_t s = u->signatures; s; s = s->next) {
            if (s->revoked || s->invalid || s->expired || !s->keyid)
                continue;
            if (own && !strcmp(s->keyid, own))
                continue;
            remember(&rows, &n, &cap, s->keyid, s->timestamp, s->email);
        }
    }

    qsort(rows, n, sizeof *rows, by_date);

    static const char *const COLUMNS[] = { "date", "keyid", "email" };
    pgpid_table_start(COLUMNS, 3);
    for (size_t i = 0; i < n; i++) {
        char date[11] = "-";
        if (rows[i].timestamp > 0) {
            struct tm tm;
            time_t t = (time_t)rows[i].timestamp;
            if (gmtime_r(&t, &tm))
                strftime(date, sizeof date, "%Y-%m-%d", &tm);
        }
        const char *values[] = { date, rows[i].keyid,
                                 rows[i].email ? rows[i].email : "-" };
        pgpid_table_row(values);
        row_free(&rows[i]);
    }
    pgpid_table_end();
    free(rows);
    gpgme_key_unref(key);
    gpgme_release(ctx);
    return n ? PGPID_OK : PGPID_NOTHING;
}
