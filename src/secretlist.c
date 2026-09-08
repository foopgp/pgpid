/* The secret keys whose material is really on this machine.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * gpg -K shows two different things under one heading: keys it holds, and stubs
 * that only point at a security key. It marks the second with '>', which is easy
 * to miss and impossible to act on programmatically without reading field 15.
 *
 * Telling them apart is not cosmetic. A key that lives on a card cannot be put
 * on paper -- print_secret used to offer exactly that -- and on a phone reading
 * a card over NFC there is no "connected key" to speak of, so the question
 * "which keys do I have here" has to be answerable without one.
 */
#include "pgpid.h"

#include <stdio.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s %s"
        " [OPTIONS]... [NAME|EMAIL|KEYID|U4|U5]...\n"
        "\n"
        "List the secret keys whose material is really here, leaving out the stubs\n"
        "that only point at a security key. See '"
        "%s token_list"
        "' for those.\n"
        "\n"
        "OPTIONS:\n"
        "  -F, --fingerprint           Output only fingerprints\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"),
            PGPID_NAME, "secret_list", PGPID_NAME);
}

int pgpid_action_secret_list(int argc, char **argv)
{
    bool onlyfpr = false;
    const char *pat[64];
    size_t npat = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-F") || !strcmp(a, "--fpr") || !strcmp(a, "--fingerprint")) {
            onlyfpr = true;
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
            return PGPID_USAGE;
        } else if (npat < sizeof pat / sizeof pat[0]) {
            pat[npat++] = a;
        }
    }

    struct pgpid_keyring *kr = pgpid_keys_load(pat, npat, PGPID_KEYS_SECRET);
    if (!kr) {
        pgpid_error(_("Error: Cannot read the keyring."));
        return PGPID_FAIL;
    }

    size_t shown = 0;
    for (size_t i = 0; i < pgpid_keys_count(kr); i++) {
        const struct pgpid_key *k = pgpid_keys_at(kr, i);
        if (!k->secret || !pgpid_secret_is_local(k))
            continue;
        shown++;
        if (onlyfpr) {
            printf("%s\n", k->fpr);
            continue;
        }
        printf("%s %s\n", k->fpr, k->nuid ? k->uid[0].text : "-");
    }
    pgpid_keys_free(kr);

    if (!shown)
        pgpid_error(_("Notice: No secret key is held on this machine."));
    return PGPID_OK;
}
