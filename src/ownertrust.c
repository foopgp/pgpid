/* Reading and setting how far a certificate is trusted to certify others.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * GnuPG has --quick-set-ownertrust and nothing to read one back: the value
 * hides in colon field 9 of a listing, or in the numbers of
 * --export-ownertrust, so every caller re-invents the same awk. Here it is one
 * word in, one word out, the vocabulary --quick-set-ownertrust already takes.
 *
 * Not to be confused with validity. The ownertrust is what *you* decided about
 * a person's ability to certify others; the validity is what the web of trust
 * concludes from it about a certificate. gpg prints them with the same
 * letters, which is a fine way to lose an afternoon.
 */
#include "pgpid.h"

#include <stdio.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " ownertrust [OPTIONS]... FINGERPRINT\n"
        "\n"
        "Print how far that certificate is trusted to certify others: one of\n"
        "unknown, never, marginal, full, ultimate.\n"
        "\n"
        "'undefined' can be set and reads back as 'unknown': the engine does not\n"
        "keep them apart, and neither does anyone who has had to explain the\n"
        "difference. One rung, two spellings.\n"
        "\n"
        "OPTIONS:\n"
        "  -r, --replace-to VALUE      Set it to VALUE instead of printing it\n"
        "  -h, --help                  Print this help and exit\n"),
            PGPID_NAME);
}

/* One certificate, exactly. A fingerprint that matches two is a caller error,
 * not something to guess at — this action writes. */
static int one_key(gpgme_ctx_t ctx, const char *pattern, gpgme_key_t *out)
{
    gpgme_error_t err = gpgme_op_keylist_start(ctx, pattern, 0);
    if (err) {
        pgpid_gpgme_error(_("looking the certificate up"), err);
        return PGPID_FAIL;
    }
    gpgme_key_t first = NULL, extra = NULL;
    err = gpgme_op_keylist_next(ctx, &first);
    if (gpg_err_code(err) == GPG_ERR_EOF) {
        gpgme_op_keylist_end(ctx);
        pgpid_error(_("Error: No certificate matching '%s'."), pattern);
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
        pgpid_error(_("Error: '%s' matches more than one certificate."), pattern);
        return PGPID_USAGE;
    }
    *out = first;
    return PGPID_OK;
}

int pgpid_action_ownertrust(int argc, char **argv)
{
    const char *value = NULL, *pattern = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-r") || !strcmp(a, "--replace-to")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a value."), a);
                return PGPID_USAGE;
            }
            value = argv[i];
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            if (i + 1 < argc)
                pattern = argv[i + 1];
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("ownertrust");
            return PGPID_USAGE;
        } else {
            pattern = a;
            break;
        }
    }

    if (!pattern) {
        pgpid_error(_("Error: A fingerprint is required."));
        return PGPID_USAGE;
    }
    if (value) {
        if (pgpid_validity_from_word(value) < 0) {
            pgpid_error(_("Error: Unknown ownertrust value '%s'."), value);
            pgpid_error(_("Notice: One of undefined, never, marginal, full, ultimate."));
            return PGPID_USAGE;
        }
        /* The engine refuses this one, and it is right to: unknown is the
         * absence of a decision, not one more decision to take. */
        if (!strcmp(value, "unknown")) {
            pgpid_error(_("Error: 'unknown' cannot be set; it is what a certificate"));
            pgpid_error(_("Notice: no one has ruled on already reads as."));
            return PGPID_USAGE;
        }
    }

    gpgme_ctx_t ctx = NULL;
    gpgme_error_t err = pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL);
    if (err) {
        pgpid_gpgme_error(_("opening the engine"), err);
        return PGPID_FAIL;
    }

    gpgme_key_t key = NULL;
    int rc = one_key(ctx, pattern, &key);
    if (rc != PGPID_OK) {
        gpgme_release(ctx);
        return rc;
    }

    if (value) {
        err = gpgme_op_setownertrust(ctx, key, value);
        if (err) {
            pgpid_gpgme_error(_("setting the ownertrust"), err);
            gpgme_key_unref(key);
            gpgme_release(ctx);
            return PGPID_FAIL;
        }
        /* Read it back rather than echo what was asked: the engine is what
         * decides, and a write that did not take should not look like one
         * that did. */
        gpgme_key_unref(key);
        rc = one_key(ctx, pattern, &key);
        if (rc != PGPID_OK) {
            gpgme_release(ctx);
            return rc;
        }
    }

    static const char *const COLUMNS[] = { "credibility" };
    const char *values[] = { pgpid_validity_word(key->owner_trust) };
    pgpid_table_start(COLUMNS, 1);
    pgpid_table_row(values);
    pgpid_table_end();

    gpgme_key_unref(key);
    gpgme_release(ctx);
    return PGPID_OK;
}
