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
 * Each row is fingerprint, identifier, address, date -- the same first three
 * columns as every other listing. The certifier is looked up in the keyring,
 * not read off the signature record, which carries whichever user id gpg
 * happened to write and for some certificates is no address at all.
 *
 * The first column is what goes back into a search to walk one step further.
 * It is the fingerprint when the keyring holds the certifier and the key
 * identifier when it does not — sixteen characters against forty, which is
 * how the caller tells the two apart. It is never '-': a signature packet
 * always names its signer, and printing nothing turned "we have not met this
 * one yet" into a dead end where the whole point was to go and fetch them.
 * A search on an identifier may find more than one certificate, and which is
 * the caller's business to say.
 *
 * Self-signatures are counted, as onak counts them. Leaving them out made our
 * number disagree with the keyserver's for no reason a reader could see;
 * --no-self-sig puts them back out. A certificate vouching for itself is what
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
    char fpr[41];
    char *eid;
    char *name;
    bool self;
};

static void row_free(struct row *r)
{
    free(r->email);
    r->email = NULL;
    free(r->eid);
    r->eid = NULL;
    free(r->name);
    r->name = NULL;
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
    fprintf(out, _("Usage: "
        "%s"
        " cert_sigs [OPTIONS]... FINGERPRINT\n"
        "\n"
        "List who has certified that certificate, oldest first: date, key\n"
        "identifier, address and date. The fingerprint is what a search takes to walk\n"
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
        "      --no-self-sig           Leave out the certificate's own signature, counted by default\n"
        "  -h, --help                  Print this help and exit\n"),
            PGPID_NAME);
}

int pgpid_action_cert_sigs(int argc, char **argv)
{
    bool all_uids = false, no_self = false;
    const char *pattern = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-a") || !strcmp(a, "--all-uids")) {
            all_uids = true;
        } else if (!strcmp(a, "--no-self-sig")) {
            no_self = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            if (i + 1 < argc)
                pattern = argv[i + 1];
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("cert_sigs");
            return PGPID_USAGE;
        } else {
            pattern = a;
            break;
        }
    }

    /* Nothing given: the security key last seen. When one is plugged in,
     * token_check has just written its note, so that is the connected key --
     * the same answer as before, reached without needing anything in a reader.
     * A phone meeting a card over NFC has nothing plugged in by the time the
     * question is asked. */
    static char from_token[41];
    if (!pattern && pgpid_token_last_signing_key(from_token, sizeof from_token))
        pattern = from_token;

    if (!pattern) {
        pgpid_error(_("Error: A fingerprint is required, and no security key was ever seen."));
        return PGPID_USAGE;
    }

    const char *pat[] = { pattern };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, PGPID_KEYS_SIGS);
    const struct pgpid_key *key = pgpid_keys_at(kr, 0);
    if (!key) {
        pgpid_error(_("Error: No certificate matching '%s'."), pattern);
        pgpid_keys_free(kr);
        return PGPID_NOTHING;
    }

    /* Without an identity uid there is nothing to be selective about, and an
     * empty answer would read as "nobody certified this" — which is a
     * different statement. */
    bool has_identity = false;
    for (size_t i = 0; i < key->nuid; i++)
        if (!key->uid[i].revoked && !key->uid[i].invalid
            && is_identity_uid(key->uid[i].text))
            has_identity = true;
    if (!all_uids && !has_identity) {
        pgpid_error(_("Notice: No identity uid; merging every uid instead."));
        all_uids = true;
    }

    const char *own = *key->keyid ? key->keyid : NULL;
    struct row *rows = NULL;
    size_t n = 0, cap = 0;

    for (size_t ui = 0; ui < key->nuid; ui++) {
        const struct pgpid_keyuid *u = &key->uid[ui];
        if (u->revoked || u->invalid)
            continue;
        if (!all_uids && !is_identity_uid(u->text))
            continue;
        /* Revoked signatures never reach here: gpg writes those as `rev`
         * records, and only `sig` is read. */
        for (size_t si = 0; si < u->nsig; si++) {
            const struct pgpid_keysig *s = &u->sig[si];
            if (!*s->keyid)
                continue;
            bool is_self = own && !strcmp(s->keyid, own);
            /* Kept by default now: a self-signature is a real certification,
             * it is what onak counts, and leaving it out made our number
             * disagree with the keyserver's for no reason a reader could see.
             * --no-self-sig puts it back out for those who want the others
             * alone. */
            if (is_self && no_self)
                continue;
            remember(&rows, &n, &cap, s->keyid, s->created, s->address);
            rows[n - 1].self = is_self;
        }
    }

    qsort(rows, n, sizeof *rows, by_date);

    /* Each certifier looked up in the keyring rather than read off the
     * signature record. The record carries whichever user id gpg happened to
     * write, which for a certificate whose first uid is a vCard note is no
     * address at all -- that is why a real certifier showed as '-'. The
     * certificate itself has the fingerprint, the identifier, and an address
     * that is one. */
    struct pgpid_keyring *all = pgpid_keys_load(NULL, 0, 0);
    for (size_t i = 0; i < n; i++) {
        /* The key identifier until something better is found. A certifier the
         * keyring has not got used to print '-', which is a dead end: the
         * identifier is all a signature packet carries and it is exactly what
         * a search takes to go and fetch the certificate. Forty characters
         * mean we hold it, sixteen mean we do not and know where to ask. */
        snprintf(rows[i].fpr, sizeof rows[i].fpr, "%s", rows[i].keyid);
        if (!all)
            continue;
        for (size_t k = 0; k < pgpid_keys_count(all); k++) {
            const struct pgpid_key *c = pgpid_keys_at(all, k);
            if (strcmp(c->keyid, rows[i].keyid))
                continue;
            snprintf(rows[i].fpr, sizeof rows[i].fpr, "%s", c->fpr);
            unsigned count = 0;
            rows[i].eid = pgpid_eid_of_key(c, &count, true);
            char fn[512];
            if (pgpid_key_name(c, fn, sizeof fn))
                rows[i].name = strdup(fn);
            if (!rows[i].email)
                for (size_t ui = 0; ui < c->nuid; ui++)
                    if (*c->uid[ui].address && !c->uid[ui].revoked) {
                        rows[i].email = strdup(c->uid[ui].address);
                        break;
                    }
            break;
        }
    }

    /* Same first three columns as every other listing: what identifies, then
     * who, then how to write to them. */
    /* The name goes last because a name has spaces in it: a reader taking the
     * first four columns positionally is unaffected, and one that wants the
     * name takes the rest of the line. */
    static const char *const COLUMNS[] = {
        "fingerprint", "eid", "email", "certification_date", "name",
    };
    pgpid_table_start(COLUMNS, 5);
    for (size_t i = 0; i < n; i++) {
        char date[11] = "-";
        if (rows[i].timestamp > 0) {
            struct tm tm;
            time_t t = (time_t)rows[i].timestamp;
            if (gmtime_r(&t, &tm))
                strftime(date, sizeof date, "%Y-%m-%d", &tm);
        }
        const char *values[] = { rows[i].fpr,
                                 rows[i].eid ? rows[i].eid : "-",
                                 rows[i].email ? rows[i].email : "-",
                                 date,
                                 rows[i].name ? rows[i].name : "-" };
        pgpid_table_row(values);
        row_free(&rows[i]);
    }
    pgpid_keys_free(all);
    pgpid_table_end();
    free(rows);
    pgpid_keys_free(kr);
    return n ? PGPID_OK : PGPID_NOTHING;
}
