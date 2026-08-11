/* One pass over the keyring, everything a contact card needs.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This is the one that had to be rewritten. The shell walk spawns a gpg per
 * key and pays a process for every row; here a single engine streams the
 * whole keyring, and every column comes out of the same record.
 *
 * Two words that look alike and are not:
 *
 *   validity     what the web of trust concludes about this certificate
 *   credibility  what *you* decided about its holder's ability to certify
 *
 * GnuPG prints both with the same letters, which is a fine way to lose an
 * afternoon. Here they are words, and different ones.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The best validity any surviving uid reaches — validity is carried per uid,
 * and it takes one good uid to answer yes. */
static gpgme_validity_t best_uid_validity(gpgme_key_t key)
{
    gpgme_validity_t best = GPGME_VALIDITY_UNKNOWN;
    for (gpgme_user_id_t u = key->uids; u; u = u->next) {
        if (u->revoked || u->invalid)
            continue;
        if (u->validity > best)
            best = u->validity;
    }
    return best;
}

/* The first address on a uid that still stands. A certificate carries its
 * name and its identifier on uids of their own, so the first uid is rarely
 * the one with an address on it. */
static const char *first_mbox(gpgme_key_t key)
{
    for (gpgme_user_id_t u = key->uids; u; u = u->next) {
        if (u->revoked || u->invalid)
            continue;
        if (u->email && *u->email)
            return u->email;
    }
    return NULL;
}

/*
 * The identifier the certificate claims — and how many distinct ones it
 * claims, which is the interesting part.
 *
 * Two identifiers on one certificate is not more information than one: it is
 * a certificate saying two things about whose it is. The caller reads that as
 * broken. Caller frees.
 */
static char *eid_of_key(gpgme_key_t key, unsigned *count)
{
    char *found = NULL;
    *count = 0;
    for (gpgme_user_id_t u = key->uids; u; u = u->next) {
        if (u->revoked || u->invalid)
            continue;
        char *eid = pgpid_eid_of_uid(u->uid);
        if (!eid)
            continue;
        if (!found) {
            found = eid;
            *count = 1;
        } else {
            if (strcmp(found, eid))
                (*count)++;
            free(eid);
        }
    }
    return found;
}

/* How many distinct other certificates have signed a uid of this one.
 * Self-signatures do not count: a certificate vouching for itself says
 * nothing. Needs GPGME_KEYLIST_MODE_SIGS, which costs a second pass in gpg. */
static unsigned count_certifiers(gpgme_key_t key)
{
    const char *own = key->subkeys ? key->subkeys->keyid : NULL;
    unsigned n = 0;
    /* Small and quadratic on purpose: a certificate with enough signatures
     * for this to matter does not exist in a personal keyring, and a hash
     * table here would be more code than the thing it saves. */
    const char *seen[256];
    unsigned nseen = 0;

    for (gpgme_user_id_t u = key->uids; u; u = u->next) {
        if (u->revoked || u->invalid)
            continue;
        for (gpgme_key_sig_t s = u->signatures; s; s = s->next) {
            if (s->revoked || s->invalid || s->expired || !s->keyid)
                continue;
            if (own && !strcmp(s->keyid, own))
                continue;
            bool dup = false;
            for (unsigned i = 0; i < nseen; i++)
                if (!strcmp(seen[i], s->keyid)) {
                    dup = true;
                    break;
                }
            if (dup)
                continue;
            if (nseen < sizeof seen / sizeof *seen)
                seen[nseen++] = s->keyid;
            n++;
        }
    }
    return n;
}

/* ISO 8601, the way onak-foopgp writes a date; or the seconds themselves
 * under --machine-readable. A dash when there is nothing to say. */
static void put_date(char *out, size_t n, long t, bool machine)
{
    if (t <= 0) {
        snprintf(out, n, "-");
        return;
    }
    if (machine) {
        snprintf(out, n, "%ld", t);
        return;
    }
    struct tm tm;
    time_t tt = (time_t)t;
    if (gmtime_r(&tt, &tm))
        strftime(out, n, "%Y-%m-%d", &tm);
    else
        snprintf(out, n, "-");
}

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: " PGPID_MIP_NAME " list [OPTIONS]... [SEARCH]\n"
        "\n"
        "List the certificates of the keyring, one per line.\n"
        "\n"
        "Columns:\n"
        "fingerprint, entity identifier, email (primary), certifications\n"
        "(optional), validity, credibility, creation_date, expiration_date,\n"
        "revocation_date\n"
        "\n"
        "Single dash '-' means hidden or unknown value.\n"
        "\n"
        "Values for validity: certified|uncertified|expired|revoked|broken|-\n"
        "Order of importance for unusable certificates: broken>revoked>expired\n"
        "\n"
        "Values for credibility: never|undefined|marginal|full|ultimate|-\n"
        "\n"
        "SEARCH, when given, is passed to the engine as a pattern; without it\n"
        "the whole keyring is listed.\n"
        "\n"
        "OPTIONS:\n"
        "  -L, --no-check-eid          Legacy: don't consider certificate as 'broken' if there is no consistent eid inside\n"
        "      --count-certs           Count the distinct certifiers of each certificates and fill *certifications* column (may take time !)\n"
        "      --hide-trust            Credibility (aka ownertrust) is a sensible information used to calculate validity — sometimes both need to stay private\n"
        "      --machine-readable      Output time (seconds since epoch) instead of date (iso-8601) and flags instead of human-readable validity and credibility\n"
        "  -h, --help                  Print this help and exit\n");
}

int pgpid_action_list(int argc, char **argv)
{
    bool check_eid = true, count_certs = false, hide_trust = false, machine = false;
    const char *pattern = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-L") || !strcmp(a, "--no-check-eid")) {
            check_eid = false;
        } else if (!strcmp(a, "--count-certs")) {
            count_certs = true;
        } else if (!strcmp(a, "--hide-trust")) {
            hide_trust = true;
        } else if (!strcmp(a, "--machine-readable")) {
            machine = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            if (i + 1 < argc)
                pattern = argv[i + 1];
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error("Error: Unrecognized option '%s'.", a);
            pgpid_error("Try '" PGPID_MIP_NAME " list --help' for more information.");
            return PGPID_USAGE;
        } else {
            pattern = a;
            break;
        }
    }

    gpgme_keylist_mode_t mode = GPGME_KEYLIST_MODE_LOCAL | GPGME_KEYLIST_MODE_VALIDATE;
    /* Signatures are what a certifier count and a revocation date are made
     * of, and they are what makes a listing slow — 6 s against 140 ms on a
     * keyring of 128. Asked for only when one of the two is wanted. */
    if (count_certs)
        mode |= GPGME_KEYLIST_MODE_SIGS;

    gpgme_ctx_t ctx = NULL;
    gpgme_error_t err = pgpid_ctx_new(&ctx, mode);
    if (err) {
        pgpid_gpgme_error("opening the engine", err);
        return PGPID_FAIL;
    }

    err = gpgme_op_keylist_start(ctx, pattern, 0);
    if (err) {
        pgpid_gpgme_error("listing the keyring", err);
        gpgme_release(ctx);
        return PGPID_FAIL;
    }

    static const char *const COLUMNS[] = {
        "fingerprint", "eid", "email", "certifications",
        "validity", "credibility",
        "creation_date", "expiration_date", "revocation_date",
    };
    pgpid_table_start(COLUMNS, sizeof COLUMNS / sizeof *COLUMNS);

    unsigned rows = 0;
    for (;;) {
        gpgme_key_t key = NULL;
        err = gpgme_op_keylist_next(ctx, &key);
        if (gpg_err_code(err) == GPG_ERR_EOF)
            break;
        if (err) {
            pgpid_gpgme_error("reading a certificate", err);
            gpgme_release(ctx);
            return PGPID_FAIL;
        }

        const char *fpr = key->subkeys ? key->subkeys->fpr : NULL;
        if (!fpr) {
            gpgme_key_unref(key);
            continue;
        }

        unsigned neids = 0;
        char *eid = eid_of_key(key, &neids);
        const char *mbox = first_mbox(key);
        gpgme_validity_t uidv = best_uid_validity(key);

        /* Order of importance, as agreed: broken beats revoked beats
         * expired. A certificate that says two things about whose it is, or
         * nothing at all, is broken whatever else is true of it. */
        char vflag[2] = { pgpid_validity_letter(uidv), '\0' };
        const char *validity;
        if (check_eid && neids != 1)
            validity = machine ? "b" : "broken";
        else if (key->revoked)
            validity = machine ? "r" : "revoked";
        else if (key->expired)
            validity = machine ? "e" : "expired";
        else if (uidv >= GPGME_VALIDITY_FULL)
            validity = machine ? vflag : "certified";
        else
            validity = machine ? vflag : "uncertified";

        char credflag[2] = { pgpid_validity_letter(key->owner_trust), '\0' };
        const char *credibility = hide_trust
            ? "-"
            : machine ? credflag : pgpid_validity_word(key->owner_trust);

        char certs[16] = "-";
        if (count_certs)
            snprintf(certs, sizeof certs, "%u", count_certifiers(key));

        char created[24], expires[24], revoked[24];
        put_date(created, sizeof created,
                 key->subkeys ? key->subkeys->timestamp : 0, machine);
        put_date(expires, sizeof expires,
                 key->subkeys ? key->subkeys->expires : 0, machine);
        /* Paid for only when a revoked certificate actually turns up: the
         * date lives in a gpg record gpgme does not carry. */
        put_date(revoked, sizeof revoked,
                 key->revoked ? pgpid_revocation_time(fpr, pattern) : 0, machine);

        const char *values[] = {
            fpr, eid ? eid : "-", mbox ? mbox : "-", certs,
            validity, credibility, created, expires, revoked,
        };
        pgpid_table_row(values);
        free(eid);
        rows++;
        gpgme_key_unref(key);
    }

    pgpid_table_end();
    gpgme_release(ctx);
    return rows ? PGPID_OK : PGPID_NOTHING;
}
