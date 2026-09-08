/* Delete secret material that is really on this machine.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Not an alias for cert_del --secret, though it looked like one at first.
 * cert_del works on a certificate and can strip its secret part; this works on
 * the secrets secret_list shows -- the ones whose material is here -- and
 * refuses a stub, because a stub has nothing local to delete. Forgetting a
 * security key is token_del's job.
 *
 * Only fingerprints, like cert_del: an action that destroys does not guess
 * which key was meant.
 */
#include "pgpid.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static bool looks_like_fingerprint(const char *s)
{
    size_t n = strlen(s);
    if (n != 40 && n != 64)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]))
            return false;
    return true;
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " secret_del [OPTIONS]... FINGERPRINT...\n"
        "\n"
        "Delete the secret material held on this machine, leaving the certificate.\n"
        "Only what secret_list shows can be deleted here: an entry that is a stub\n"
        "pointing at a security key has nothing local to remove -- token_del forgets\n"
        "those, and the key itself still holds the secret.\n"
        "\n"
        "Only fingerprints are accepted — 40 or 64 hexadecimal characters. An action\n"
        "that destroys does not guess which key was meant.\n"
        "\n"
        "OPTIONS:\n"
        "  -y, --yes                   Assume yes: skip the confirmation\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "This is irreversible unless the key was printed, moved onto a security key,\n"
        "or backed up somewhere. The certificate remains, and stays unusable for\n"
        "signing and decryption without its secret.\n"),
            PGPID_NAME);
}

int pgpid_action_secret_del(int argc, char **argv)
{
    const char *want[64];
    size_t nwant = 0;
    bool assume_yes = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-y") || !strcmp(a, "--yes")) {
            assume_yes = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", PGPID_NAME, PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("secret_del");
            return PGPID_USAGE;
        } else if (nwant < sizeof want / sizeof want[0]) {
            if (!looks_like_fingerprint(a)) {
                pgpid_error(_("Error: '%s' is not a fingerprint."), a);
                pgpid_error(_("Notice: 40 or 64 hexadecimal characters. See '%s secret_list'."),
                            PGPID_NAME);
                return PGPID_USAGE;
            }
            want[nwant++] = a;
        }
    }

    if (!nwant) {
        pgpid_error(_("Error: Which secret? Name it by fingerprint."));
        pgpid_try_help("secret_del");
        return PGPID_USAGE;
    }

    struct pgpid_keyring *kr = pgpid_keys_load(NULL, 0, PGPID_KEYS_SECRET);
    if (!kr) {
        pgpid_error(_("Error: Cannot read the keyring."));
        return PGPID_FAIL;
    }

    /* Everything is checked before anything is deleted: half a deletion, with
     * the reason arriving after the first key is gone, is worse than none. */
    const char *doomed[64];
    size_t ndoomed = 0;
    int verdict = PGPID_OK;
    for (size_t w = 0; w < nwant; w++) {
        const struct pgpid_key *found = NULL;
        for (size_t i = 0; i < pgpid_keys_count(kr) && !found; i++) {
            const struct pgpid_key *k = pgpid_keys_at(kr, i);
            if (k->secret && !strcasecmp(k->fpr, want[w]))
                found = k;
        }
        if (!found) {
            pgpid_error(_("Error: No secret for '%s' here."), want[w]);
            verdict = PGPID_NOTHING;
        } else if (!pgpid_secret_is_local(found)) {
            pgpid_error(_("Error: '%s' is a stub on a security key, not a local secret."),
                        want[w]);
            pgpid_error(_("Notice: '%s token_del' forgets the key; the secret stays on it."),
                        PGPID_NAME);
            verdict = PGPID_FAIL;
        } else {
            doomed[ndoomed++] = want[w];
        }
    }
    pgpid_keys_free(kr);
    if (verdict != PGPID_OK)
        return verdict;

    if (!assume_yes) {
        if (pgpid_batch) {
            pgpid_error(_("Error: --batch was given, so nothing is asked. Add --yes."));
            return PGPID_USAGE;
        }
        char answer[8];
        pgpid_error(_("Notice: %zu secret(s) will be deleted. The certificates stay."),
                    ndoomed);
        if (!pgpid_ask(_("Type yes to go on: "), answer, sizeof answer)
            || strcmp(answer, "yes")) {
            pgpid_error(_("Notice: Nothing done."));
            return PGPID_CANCEL;
        }
    }

    for (size_t i = 0; i < ndoomed; i++) {
        const char *del[] = { "--batch", "--yes", "--delete-secret-keys", doomed[i], NULL };
        if (pgpid_run_engine(del)) {
            pgpid_error(_("Error: '%s' would not go."), doomed[i]);
            verdict = PGPID_FAIL;
        }
    }
    return verdict;
}
