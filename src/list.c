/* One pass over the keyring, everything a contact card needs.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This is the one that had to be rewritten. The shell walk spawns a gpg per
 * key and pays a process for every row; here a single engine streams the
 * whole keyring, and the identifier, the address, the validity and the
 * ownertrust come out of the same record.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The best validity any surviving uid of the key reaches — what "is this
 * certificate certified" means, since validity is carried per uid and it
 * takes one good uid to answer yes. */
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

/* The first address on a uid that still stands. Certificates carry their name
 * and their identifier on uids of their own, so the first uid is rarely the
 * one with an address on it. */
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

/* The identifier the certificate claims, from the first uid that carries one.
 * Caller frees. */
static char *eid_of_key(gpgme_key_t key)
{
    for (gpgme_user_id_t u = key->uids; u; u = u->next) {
        if (u->revoked || u->invalid)
            continue;
        char *eid = pgpid_eid_of_uid(u->uid);
        if (eid)
            return eid;
    }
    return NULL;
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
            if (s->revoked || s->invalid || s->expired)
                continue;
            if (!s->keyid)
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

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: " PGPID_MIP_NAME " list [OPTIONS]... [SEARCH]\n"
        "\n"
        "List the certificates of the keyring, one per line: fingerprint, entity\n"
        "identifier, first address, validity and ownertrust.\n"
        "\n"
        "SEARCH, when given, is passed to the engine as a pattern; without it the\n"
        "whole keyring is listed.\n"
        "\n"
        "OPTIONS:\n"
        "  -c, --certs                 Count the distinct certifiers of each certificate\n"
        "  -i, --info                  Output key=value pairs rather than columns\n"
        "  -h, --help                  Print this help and exit\n");
}

int pgpid_action_list(int argc, char **argv)
{
    bool info = false, certs = false;
    const char *pattern = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-c") || !strcmp(a, "--certs")) {
            certs = true;
        } else if (!strcmp(a, "-i") || !strcmp(a, "--info")) {
            info = true;
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
    if (certs)
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
        if (fpr) {
            char *eid = eid_of_key(key);
            const char *mbox = first_mbox(key);
            char validity = pgpid_validity_letter(best_uid_validity(key));
            const char *trust = pgpid_validity_word(key->owner_trust);

            if (info) {
                printf("fpr=%s\teid=%s\tmbox=%s\tvalidity=%c\townertrust=%s",
                       fpr, eid ? eid : "", mbox ? mbox : "", validity, trust);
                if (certs)
                    printf("\tcerts=%u", count_certifiers(key));
                putchar('\n');
            } else {
                printf("%-40s  %-38s  %c  %-9s", fpr, eid ? eid : "-",
                       validity, trust);
                if (certs)
                    printf("  %3u", count_certifiers(key));
                printf("  %s\n", mbox ? mbox : "");
            }
            free(eid);
            rows++;
        }
        gpgme_key_unref(key);
    }

    gpgme_release(ctx);
    return rows ? PGPID_OK : PGPID_NOTHING;
}
