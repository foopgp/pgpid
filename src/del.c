/* Removing a certificate from the keyring.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
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
        " cert_del [OPTIONS]... FINGERPRINT...\n"
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
static int one_key(const char *fpr)
{
    const char *pat[] = { fpr };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
    size_t n = pgpid_keys_count(kr);
    pgpid_keys_free(kr);
    if (n == 0) {
        pgpid_error(_("Error: No certificate matching '%s'."), fpr);
        return PGPID_NOTHING;
    }
    if (n > 1) {
        pgpid_error(_("Error: '%s' matches more than one certificate."), fpr);
        return PGPID_USAGE;
    }
    return PGPID_OK;
}

int pgpid_action_cert_del(int argc, char **argv)
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
            pgpid_try_help("cert_del");
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

    int rc = PGPID_OK;
    for (int t = first_target; t < argc && rc == PGPID_OK; t++) {
        const char *fpr = argv[t];
        rc = one_key(fpr);
        if (rc != PGPID_OK)
            break;

        if (secret_only) {
            const char *args[] = { "--batch", "--yes",
                                   "--delete-secret-keys", fpr, NULL };
            int status = pgpid_run_engine(args);
            if (status != 0) {
                pgpid_error(_("Error: The engine refused to delete the secret part of %s."), fpr);
                rc = PGPID_FAIL;
            }
        } else {
            const char *args[] = { "--batch", "--yes",
                                   "--delete-secret-and-public-key", fpr, NULL };
            if (pgpid_run_engine(args) != 0) {
                pgpid_error(_("Error: The engine refused to delete %s."), fpr);
                rc = PGPID_FAIL;
            }
        }
    }

    return rc;
}
