/* The security keys this system knows, plugged in or not.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The other half of secret_list. Every secret stub in the keyring names, in
 * field 15, the serial of the card its material sits on; the distinct serials
 * are the security keys this system has met.
 *
 * Deliberately not "the connected key": token_check answers that, and it cannot
 * answer anything on a phone reading a card over NFC, where nothing stays
 * connected. This one reads the keyring, so it works with the card in a drawer.
 */
#include "pgpid.h"

#include <stdio.h>
#include <string.h>

/* Card serials seen so far, so each is reported once however many keys of ours
 * live on it. */
struct seen {
    char serial[64][64];
    size_t n;
};

/* Field 15 holds a card serial only sometimes: gpg also writes "+" there when
 * the secret is really on disk, and "#" when it is not available at all.
 * Neither is a security key. */
static bool remember(struct seen *s, const char *serial)
{
    if (!*serial || !strcmp(serial, "+") || !strcmp(serial, "#"))
        return false;
    for (size_t i = 0; i < s->n; i++)
        if (!strcmp(s->serial[i], serial))
            return false;
    if (s->n >= sizeof s->serial / sizeof s->serial[0])
        return false;
    snprintf(s->serial[s->n++], sizeof s->serial[0], "%s", serial);
    return true;
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s %s"
        " [OPTIONS]...\n"
        "\n"
        "List the security keys this system knows, whether or not one is plugged in:\n"
        "every secret stub in the keyring names the card its material sits on.\n"
        "'"
        "%s token_check"
        "' answers about the connected one; this answers about all of them.\n"
        "\n"
        "OPTIONS:\n"
        "  -q, --quiet                 Output only the serials\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"),
            PGPID_NAME, "token_list", PGPID_NAME);
}

int pgpid_action_token_list(int argc, char **argv)
{
    bool quiet = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            quiet = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", PGPID_NAME, PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            return PGPID_USAGE;
        }
    }

    struct pgpid_keyring *kr = pgpid_keys_load(NULL, 0, PGPID_KEYS_SECRET);
    if (!kr) {
        pgpid_error(_("Error: Cannot read the keyring."));
        return PGPID_FAIL;
    }

    struct seen seen = { .n = 0 };
    for (size_t i = 0; i < pgpid_keys_count(kr); i++) {
        const struct pgpid_key *k = pgpid_keys_at(kr, i);
        if (!k->secret)
            continue;
        const char *owner = k->nuid ? k->uid[0].text : "-";
        if (remember(&seen, k->card))
            quiet ? printf("%s\n", k->card)
                  : printf("%s %s %s\n", k->card, k->fpr, owner);
        for (size_t j = 0; j < k->nsub; j++)
            if (remember(&seen, k->sub[j].card))
                quiet ? printf("%s\n", k->sub[j].card)
                      : printf("%s %s %s\n", k->sub[j].card, k->fpr, owner);
    }
    pgpid_keys_free(kr);

    if (!seen.n)
        pgpid_error(_("Notice: This system knows no security key."));
    return PGPID_OK;
}
