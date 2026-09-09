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
            pgpid_try_help("token_del");
            return PGPID_USAGE;
        }
    }

    /* Two sources, and neither alone is the answer. GnuPG's stubs say which
     * cards hold a secret of ours, and nothing else about them. Our own notes
     * say what a card carried when it was last seen, including cards whose
     * stub has since gone. Both, deduplicated. */
    struct seen seen = { .n = 0 };
    char fprs[64][41];
    for (size_t i = 0; i < 64; i++)
        *fprs[i] = '\0';

    struct pgpid_keyring *kr = pgpid_keys_load(NULL, 0, PGPID_KEYS_SECRET);
    if (kr) {
        for (size_t i = 0; i < pgpid_keys_count(kr); i++) {
            const struct pgpid_key *k = pgpid_keys_at(kr, i);
            if (!k->secret)
                continue;
            if (remember(&seen, k->card))
                snprintf(fprs[seen.n - 1], 41, "%s", k->fpr);
            for (size_t j = 0; j < k->nsub; j++)
                if (remember(&seen, k->sub[j].card))
                    snprintf(fprs[seen.n - 1], 41, "%s", k->fpr);
        }
        pgpid_keys_free(kr);
    }

    char cached[64][64];
    size_t ncached = pgpid_token_known(cached, 64);
    for (size_t i = 0; i < ncached; i++)
        remember(&seen, cached[i]);

    if (!seen.n) {
        pgpid_error(_("Notice: This system knows no security key."));
        return PGPID_OK;
    }

    for (size_t i = 0; i < seen.n; i++) {
        if (quiet) {
            printf("%s\n", seen.serial[i]);
            continue;
        }
        if (i)
            printf("\n");
        char note[4096];
        if (pgpid_token_recall(seen.serial[i], note, sizeof note)) {
            fputs(note, stdout);
        } else {
            /* Never checked, or checked before we kept notes: say what the
             * keyring knows and say plainly that the rest is unknown, rather
             * than leaving a reader to guess which. */
            printf("token_ID='%s'\n", seen.serial[i]);
            printf("token_seen=''\n");
            if (*fprs[i])
                printf("pgpid_Skeyfpr='%s'\n", fprs[i]);
        }
    }
    return PGPID_OK;
}
