/* Changing what protects a secret key on this machine.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The passphrase guards the secret key where it sits on disk. It is not the
 * PIN of a card and does not travel with the certificate: changing it here
 * changes nothing anybody else can see.
 *
 * The current one is checked with a dry run before anything is written. gpg
 * would otherwise take the new passphrase, fail on the old, and leave the
 * caller unable to tell which of the two they got wrong.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " change_passphrase [OPTIONS]... KEY_ID|FPR|EMAIL|NAME\n"
        "\n"
        "Change GnuPG passphrase protecting secret parts of an OpenPGP key.\n"
        "\n"
        "OPTIONS:\n"
        "  -p, --passphrase PASSPHRASE    Current passphrase protecting secret parts of OpenPGP key (empty \"\" for none)\n"
        "  -P, --passfrom FILE            Get passphrase from first line of FILE (eg: fifo, tmpfs, /dev/stdin ...)\n"
        "  -n, --newpassphrase PASSPHRASE New passphrase to protect secret parts of OpenPGP key (empty \"\" for none)\n"
        "  -N, --newpassfrom FILE         Get new passphrase from the first line of FILE (eg: fifo, tmpfs, /dev/stdin ...)\n"
        "  -h, --help                     Print this help and exit\n"
        "  -V, --version                  Print the version and exit\n"
        "\n"
        "Passing a passphrase as an argument shows it to everything that can read\n"
        "this machine's process list. The file forms exist for that reason.\n"),
            PGPID_NAME);
}

/** The first line of a file, its ending removed. */
static bool first_line_of(const char *path, char *out, size_t max)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        pgpid_error(_("Error: Cannot read %s."), path);
        return false;
    }
    if (!fgets(out, (int)max, f))
        *out = '\0';
    fclose(f);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return true;
}

int pgpid_action_change_passphrase(int argc, char **argv)
{
    char current[512] = "", fresh[512] = "";
    bool current_given = false, fresh_given = false;
    const char *keyid = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        bool wants_value = false;
        char *into = NULL;
        bool *flag = NULL;
        bool from_file = false;

        if (!strcmp(a, "-p") || !strcmp(a, "--passphrase")) {
            wants_value = true; into = current; flag = &current_given;
        } else if (!strcmp(a, "-P") || !strcmp(a, "--passfrom")
                   || !strcmp(a, "--pass-from")) {
            wants_value = true; into = current; flag = &current_given; from_file = true;
        } else if (!strcmp(a, "-n") || !strcmp(a, "--newpassphrase")) {
            wants_value = true; into = fresh; flag = &fresh_given;
        } else if (!strcmp(a, "-N") || !strcmp(a, "--newpassfrom")
                   || !strcmp(a, "--newpass-from")) {
            wants_value = true; into = fresh; flag = &fresh_given; from_file = true;
        }

        if (wants_value) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a %s."), a, from_file ? "file" : "passphrase");
                return PGPID_USAGE;
            }
            if (from_file) {
                if (!first_line_of(argv[i], into, 512))
                    return PGPID_FAIL;
            } else {
                snprintf(into, 512, "%s", argv[i]);
            }
            *flag = true;
            continue;
        }

        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("change_passphrase");
            return PGPID_USAGE;
        } else if (!keyid) {
            keyid = a;
        }
    }

    if (!keyid) {
        pgpid_error(_("Error: Which key? Naming it is not something to guess at:"));
        pgpid_error(_("this machine may hold several secret keys."));
        usage(stderr);
        return PGPID_USAGE;
    }
    if (!current_given || !fresh_given) {
        pgpid_error(_("Error: Both passphrases are needed — the current one with "
                    "--passphrase or --passfrom, the new one with"));
        pgpid_error(_("--newpassphrase or --newpassfrom. Empty strings mean none."));
        return PGPID_USAGE;
    }

    char listing[8192];
    const char *find[] = { "--list-secret-keys", "--with-colons", keyid, NULL };
    if (pgpid_capture_engine(find, listing, sizeof listing) <= 0
        || !strstr(listing, "sec:")) {
        pgpid_error(_("Error: No secret for '%s' here."), keyid);
        return PGPID_FAIL;
    }

    /* The dry run answers "is the current passphrase right?" and nothing
     * else, before anything is written. */
    char answer[1100];
    snprintf(answer, sizeof answer, "%s\n", current);
    const char *dry[] = { "--command-fd", "0", "--batch", "--pinentry-mode",
                          "loopback", "--dry-run", "--change-passphrase", keyid, NULL };
    int said = pgpid_run_engine_input(dry, answer);
    if (said) {
        pgpid_error(_("Error: That is not the current passphrase of '%s'."), keyid);
        /* gpg's own code, not ours: the caller can tell a wrong passphrase
         * from a key that would not open for another reason. */
        return said;
    }

    if (!strcmp(current, fresh)) {
        pgpid_error(_("Notice: Passphrase unchanged."));
        return PGPID_OK;
    }

    /* gpg asks for the new one three times when there is no old one to give
     * first, and four answers in the other case: the old, then the new twice,
     * then once more for the confirmation it insists on when it is empty. */
    char script[2600];
    if (*current)
        snprintf(script, sizeof script, "%s\n%s\n%s\n%s\n", current, fresh, fresh, fresh);
    else
        snprintf(script, sizeof script, "%s\n%s\n%s\n", fresh, fresh, fresh);

    const char *change[] = { "--command-fd", "0", "--batch", "--pinentry-mode",
                             "loopback", "--change-passphrase", keyid, NULL };
    said = pgpid_run_engine_input(change, script);
    if (said) {
        pgpid_error(_("Error: gpg would not change the passphrase of '%s'."), keyid);
        return said;
    }
    pgpid_error(_("Notice: Passphrase successfully changed."));
    return PGPID_OK;
}
