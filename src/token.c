/* What the security key says about itself.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The card is not reached through gpgme: its business is keys and data, and
 * how many attempts remain before a PIN locks is neither. It comes from
 * scdaemon, asked through gpg-connect-agent — the same road the shell takes.
 *
 * The number matters more than it looks. Somebody about to type a PIN needs
 * to know it is their last attempt *before* they type, not after, because
 * after there is nothing left to know.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: " PGPID_MIP_NAME " token_retries [OPTIONS]...\n"
        "\n"
        "Print how many attempts remain on the connected security key's codes,\n"
        "before each one locks. All three unless one is asked for.\n"
        "\n"
        "OPTIONS:\n"
        "  -P, --pin                   The PIN, usually six digits\n"
        "  -R, --rc                    The reset code, usually unused\n"
        "  -A, --admin                 The admin code, usually eight digits\n"
        "  -q, --quiet                 The numbers alone, one per line\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n");
}

/**
 * The three counters, from scdaemon's CHV-STATUS.
 *
 * The answer looks like `S CHV-STATUS +0+127+127+127+3+0+3`: seven numbers of
 * which the last three are what remains on the PIN, the reset code and the
 * admin code. The first four say whether a PIN is needed for signing and how
 * long each may be — not our business here.
 */
bool pgpid_card_retries(int *pin, int *rc, int *admin)
{
    char out[1024];
    /* The home directory travels here too: scdaemon belongs to an agent, an
     * agent belongs to a keyring, and only one of them can hold the reader.
     * Asking without saying which one starts a second agent that then finds
     * "no such device" — from every keyring at once. */
    const char *argv[8];
    size_t nargs = 0;
    argv[nargs++] = "gpg-connect-agent";
    if (pgpid_homedir) {
        argv[nargs++] = "--homedir";
        argv[nargs++] = pgpid_homedir;
    }
    argv[nargs++] = "SCD GETATTR CHV-STATUS";
    argv[nargs++] = "/bye";
    argv[nargs] = NULL;
    if (pgpid_capture(argv, out, sizeof out) < 0) {
        pgpid_error("Error: Cannot run gpg-connect-agent.");
        return false;
    }

    const char *at = strstr(out, "CHV-STATUS");
    if (!at) {
        /* No card, no reader, or a daemon that will not start. The first line
         * of what came back says which, and is worth passing on rather than
         * replacing with a guess. */
        char first[256];
        size_t n = 0;
        for (const char *p = out; *p && *p != '\n' && n < sizeof first - 1; p++)
            first[n++] = *p;
        first[n] = '\0';
        pgpid_error("Error: No security key answered%s%s.",
                    n ? " — " : "", n ? first : "");
        return false;
    }

    int v[8];
    unsigned got = 0;
    for (const char *p = at; *p && *p != '\n' && got < 8; p++) {
        if (*p == '+' || (*p >= '0' && *p <= '9' && (p == at || p[-1] == '+'))) {
            const char *q = (*p == '+') ? p + 1 : p;
            if (*q >= '0' && *q <= '9')
                v[got++] = atoi(q);
            while (q[0] >= '0' && q[0] <= '9')
                q++;
            p = q - 1;
        }
    }
    if (got < 7) {
        pgpid_error("Error: The card answered %u numbers, not seven.", got);
        return false;
    }
    *pin = v[got - 3];
    *rc = v[got - 2];
    *admin = v[got - 1];
    return true;
}

int pgpid_action_token_retries(int argc, char **argv)
{
    bool show_pin = false, show_rc = false, show_admin = false, quiet = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-P") || !strcmp(a, "--pin") || !strcmp(a, "--pw1"))
            show_pin = true;
        else if (!strcmp(a, "-R") || !strcmp(a, "--rc") || !strcmp(a, "--reset"))
            show_rc = true;
        else if (!strcmp(a, "-A") || !strcmp(a, "--admin") || !strcmp(a, "--pw3"))
            show_admin = true;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet"))
            quiet = true;
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_MIP_VERSION);
            return PGPID_OK;
        } else {
            pgpid_error("Error: Unrecognized option '%s'.", a);
            pgpid_error("Try '" PGPID_MIP_NAME " token_retries --help' for more information.");
            return PGPID_USAGE;
        }
    }
    /* Asking for none means asking for all: the common case is wanting to
     * see the state of the card, not one number of it. */
    if (!show_pin && !show_rc && !show_admin)
        show_pin = show_rc = show_admin = true;

    int pin, rc, admin;
    if (!pgpid_card_retries(&pin, &rc, &admin))
        return PGPID_FAIL;

    struct { bool show; const char *key; int value; const char *what; } rows[] = {
        { show_pin,   "token_pinretries",   pin,
          "remaining attempts on the PIN, usually six digits" },
        { show_rc,    "token_rcretries",    rc,
          "remaining attempts on the reset code, usually unused" },
        { show_admin, "token_adminretries", admin,
          "remaining attempts on the admin code, usually eight digits" },
    };
    for (unsigned i = 0; i < 3; i++) {
        if (!rows[i].show)
            continue;
        if (quiet)
            printf("%d\n", rows[i].value);
        else
            printf("%s=%d\t# %s\n", rows[i].key, rows[i].value, rows[i].what);
    }
    return PGPID_OK;
}
