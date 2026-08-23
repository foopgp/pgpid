/* Removing a certificate from the keyring.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Fingerprints, and nothing else. Every other action here takes a search
 * pattern, because being shown too much costs nothing; this one deletes, and
 * a pattern that matches two certificates on the day someone's name is a
 * substring of someone else's is not a risk worth the convenience. Forty or
 * sixty-four hexadecimal characters or no.
 *
 * Two things can be removed and they are not the same. By default the
 * certificate goes entirely, secret part included — the answer to "I do not
 * want this person in my keyring". With --secret only the secret part goes,
 * which is what one does after moving a key onto a security token: the
 * certificate stays, its signatures stay, only the ability to sign with it
 * from this disk is gone.
 */
#include "pgpid.h"

#include <stdio.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " del [OPTIONS]... FINGERPRINT...\n"
        "\n"
        "Delete certificates from the keyring, secret part included.\n"
        "\n"
        "Only fingerprints are accepted — 40 or 64 hexadecimal characters. An\n"
        "action that deletes does not guess which certificate was meant.\n"
        "\n"
        "OPTIONS:\n"
        "  -s, --secret                Delete only the secret part, keep the certificate\n"
        "  -h, --help                  Print this help and exit\n"),
            PGPID_NAME);
}

/* Exactly one certificate for that fingerprint, or nothing. */
static int one_key(gpgme_ctx_t ctx, const char *fpr, gpgme_key_t *out)
{
    gpgme_error_t err = gpgme_op_keylist_start(ctx, fpr, 0);
    if (err) {
        pgpid_gpgme_error(_("looking the certificate up"), err);
        return PGPID_FAIL;
    }
    gpgme_key_t first = NULL, extra = NULL;
    err = gpgme_op_keylist_next(ctx, &first);
    if (gpg_err_code(err) == GPG_ERR_EOF) {
        gpgme_op_keylist_end(ctx);
        pgpid_error(_("Error: No certificate matching '%s'."), fpr);
        return PGPID_NOTHING;
    }
    if (err) {
        gpgme_op_keylist_end(ctx);
        pgpid_gpgme_error(_("reading the certificate"), err);
        return PGPID_FAIL;
    }
    err = gpgme_op_keylist_next(ctx, &extra);
    gpgme_op_keylist_end(ctx);
    if (gpg_err_code(err) != GPG_ERR_EOF) {
        gpgme_key_unref(first);
        if (extra)
            gpgme_key_unref(extra);
        pgpid_error(_("Error: '%s' matches more than one certificate."), fpr);
        return PGPID_USAGE;
    }
    *out = first;
    return PGPID_OK;
}

int pgpid_action_del(int argc, char **argv)
{
    bool secret_only = false;
    int first_target = 0;

    int i = 1;
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-s") || !strcmp(a, "--secret")) {
            secret_only = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            i++;
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("del");
            return PGPID_USAGE;
        } else {
            break;
        }
    }
    first_target = i;

    if (first_target >= argc) {
        pgpid_error(_("Error: At least one fingerprint is required."));
        return PGPID_USAGE;
    }
    /* Every argument is checked before the first one is deleted: a run that
     * removes three certificates and then refuses the fourth leaves the
     * caller with no idea what happened. */
    for (int t = first_target; t < argc; t++) {
        if (!pgpid_is_fingerprint(argv[t])) {
            pgpid_error(_("Error: '%s' is not a fingerprint."), argv[t]);
            pgpid_error(_("Notice: 40 or 64 hexadecimal characters, nothing else."));
            return PGPID_USAGE;
        }
    }

    gpgme_ctx_t ctx = NULL;
    gpgme_error_t err = pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL);
    if (err) {
        pgpid_gpgme_error(_("opening the engine"), err);
        return PGPID_FAIL;
    }

    int rc = PGPID_OK;
    for (int t = first_target; t < argc && rc == PGPID_OK; t++) {
        const char *fpr = argv[t];
        gpgme_key_t key = NULL;
        rc = one_key(ctx, fpr, &key);
        if (rc != PGPID_OK)
            break;

        if (secret_only) {
            /* gpgme deletes a certificate, or a certificate and its secret;
             * it has no call for the secret alone. The engine does, so the
             * engine is asked. */
            const char *args[] = { "--batch", "--yes",
                                   "--delete-secret-keys", fpr, NULL };
            int status = pgpid_run_engine(args);
            if (status != 0) {
                pgpid_error(_("Error: The engine refused to delete the secret part of %s."), fpr);
                rc = PGPID_FAIL;
            }
        } else {
            err = gpgme_op_delete_ext(ctx, key,
                                      GPGME_DELETE_ALLOW_SECRET | GPGME_DELETE_FORCE);
            if (err) {
                pgpid_gpgme_error(_("deleting the certificate"), err);
                rc = PGPID_FAIL;
            }
        }
        gpgme_key_unref(key);
    }

    gpgme_release(ctx);
    return rc;
}
