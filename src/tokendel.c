/* Forget a security key, and optionally wipe it.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Forgetting means removing the stubs -- the secret entries that hold no key
 * material, only the serial of the card the material sits on. The public
 * certificate stays: it has nothing to do with which piece of metal carried
 * its secret, and other people's certificates are not ours to tidy away.
 *
 * There was little use for this over USB, where a card is either in the port or
 * it is not. Over NFC there is no port: a phone meets many cards and should be
 * able to forget one.
 */
#include "pgpid.h"

#include <stdio.h>
#include <string.h>

/* gpg asks twice before wiping a card: once for the y/n, once for the word. */
static int factory_reset(void)
{
    const char *edit[] = { "--command-fd", "0", "--batch", "--card-edit", NULL };
    return pgpid_run_engine_input(edit, "admin\nfactory-reset\ny\nyes\nquit\n");
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " token_del [OPTIONS]... [SERIAL]\n"
        "\n"
        "Forget a security key: remove the stubs that point at it, and nothing else.\n"
        "The public certificates stay -- what carried a secret is not part of what\n"
        "the certificate says. Without SERIAL, the connected key.\n"
        "\n"
        "OPTIONS:\n"
        "      --reset                 Factory-reset the connected key first, wiping it\n"
        "  -y, --yes                   Assume yes: skip the confirmation\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "A factory reset is irreversible: whatever the key held is gone, and no\n"
        "backup of it exists unless you made one.\n"),
            PGPID_NAME);
}

int pgpid_action_token_del(int argc, char **argv)
{
    const char *serial = NULL;
    bool reset = false, assume_yes = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--reset")) {
            reset = true;
        } else if (!strcmp(a, "-y") || !strcmp(a, "--yes")) {
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
            pgpid_try_help("token_del");
            return PGPID_USAGE;
        } else if (!serial) {
            serial = a;
        }
    }

    /* No serial: the one in the reader. A reset has no other candidate anyway. */
    char connected[64] = "";
    if (!serial || reset) {
        char status[16384];
        if (pgpid_capture_card_status(status, sizeof status) > 0) {
            const char *at = strstr(status, "Serial number");
            const char *colon = at ? strchr(at, ':') : NULL;
            if (colon) {
                colon++;
                while (*colon == ' ')
                    colon++;
                size_t n = 0;
                while (colon[n] && colon[n] != '\n' && colon[n] != ' '
                       && n + 1 < sizeof connected)
                    n++;
                snprintf(connected, sizeof connected, "%.*s", (int)n, colon);
            }
        }
        if (!serial)
            serial = connected;
    }

    if (reset && !*connected) {
        pgpid_error(_("Error: --reset wipes the connected key, and none answered."));
        return PGPID_FAIL;
    }
    if (!serial || !*serial) {
        pgpid_error(_("Error: Which security key? Name its serial, or plug one in."));
        return PGPID_USAGE;
    }

    /* Which of our secret entries are stubs on that serial. */
    struct pgpid_keyring *kr = pgpid_keys_load(NULL, 0, PGPID_KEYS_SECRET);
    if (!kr) {
        pgpid_error(_("Error: Cannot read the keyring."));
        return PGPID_FAIL;
    }
    char fpr[64][41];
    size_t nfpr = 0;
    for (size_t i = 0; i < pgpid_keys_count(kr) && nfpr < 64; i++) {
        const struct pgpid_key *k = pgpid_keys_at(kr, i);
        if (!k->secret)
            continue;
        bool here = !strcmp(k->card, serial);
        for (size_t j = 0; !here && j < k->nsub; j++)
            here = !strcmp(k->sub[j].card, serial);
        if (here)
            snprintf(fpr[nfpr++], sizeof fpr[0], "%s", k->fpr);
    }
    pgpid_keys_free(kr);

    if (!assume_yes && !pgpid_batch) {
        char answer[8];
        if (reset)
            pgpid_error(_("Notice: About to wipe the key %s. This cannot be undone."),
                        connected);
        pgpid_error(_("Notice: %zu stub(s) will be forgotten; the certificates stay."),
                    nfpr);
        if (!pgpid_ask(_("Type yes to go on: "), answer, sizeof answer)
            || strcmp(answer, "yes")) {
            pgpid_error(_("Notice: Nothing done."));
            return PGPID_CANCEL;
        }
    } else if (!assume_yes) {
        pgpid_error(_("Error: --batch was given, so nothing is asked. Add --yes."));
        return PGPID_USAGE;
    }

    if (reset && factory_reset()) {
        pgpid_error(_("Error: The key refused the factory reset."));
        return PGPID_FAIL;
    }

    for (size_t i = 0; i < nfpr; i++) {
        const char *del[] = { "--batch", "--yes", "--delete-secret-keys", fpr[i], NULL };
        if (pgpid_run_engine(del))
            pgpid_error(_("Warning: The stub of %s would not go."), fpr[i]);
    }
    /* Both caches, since token_check writes to both: a note left behind would
     * have token_list still answering about a key we were told to forget. */
    if (pgpid_token_forget(serial))
        pgpid_error(_("Notice: What we knew of %s is forgotten too."), serial);

    if (!nfpr)
        pgpid_error(_("Notice: No stub pointed at %s."), serial);

    return PGPID_OK;
}
