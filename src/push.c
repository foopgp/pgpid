/* Hand a certificate to the keyservers, as it stands.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Every action that changes a certificate publishes it afterwards, because a
 * change nobody can fetch is a change nobody can check. But publishing and
 * changing are not the same act, and until now there was no way to do the
 * one without the other — not here, not in bl-pgpid, not in bl-pgpkey. So an
 * application that wanted to let somebody try three avatars before showing
 * the world any of them had no way to wait.
 *
 * This is that way. `--keyservers ""` on the change, then `push` when the
 * dust settles.
 *
 * Fingerprints only, as `del` takes fingerprints only. The reasons differ —
 * one cannot be undone, the other cannot be recalled — but they come to the
 * same rule: an act with no way back does not guess which certificate was
 * meant.
 */
#include "pgpid.h"

#include <stdio.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: " PGPID_NAME " push [OPTIONS]... FINGERPRINT...\n"
        "\n"
        "Send certificates to the keyservers as they stand, changing nothing.\n"
        "Fingerprints only: what is published cannot be recalled.\n"
        "\n"
        "OPTIONS:\n"
        "  -K, --keyservers SERVERS    Send to these, space separated\n"
        "                              Empty for none. Default: " PGPID_KEYSERVERS "\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n");
}

int pgpid_action_push(int argc, char **argv)
{
    const char *keyservers = NULL;
    int first = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-K") || !strcmp(a, "--keyservers")) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants a list of servers, empty for none.", a);
                return PGPID_USAGE;
            }
            keyservers = argv[i];
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            first = i + 1;
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error("Error: Unrecognized option '%s'.", a);
            pgpid_error("Try '" PGPID_NAME " push --help' for more information.");
            return PGPID_USAGE;
        } else {
            first = i;
            break;
        }
    }

    if (!first || first >= argc) {
        pgpid_error("Error: Which certificate?");
        usage(stderr);
        return PGPID_USAGE;
    }

    /* Every target checked before any is sent, so a typo in the third one
     * does not leave the first two already published. `del` weighs its
     * arguments the same way, for the same reason: neither act has a way
     * back, so both look at the whole list first. */
    for (int i = first; i < argc; i++) {
        if (!pgpid_is_fingerprint(argv[i])) {
            pgpid_error("Error: '%s' is not a fingerprint.", argv[i]);
            pgpid_error("Notice: Publishing takes fingerprints, so a search never becomes a broadcast.");
            return PGPID_USAGE;
        }
    }

    const char *list = keyservers ? keyservers : PGPID_KEYSERVERS;
    if (!*list) {
        pgpid_error("Notice: No keyserver asked for; nothing sent.");
        return PGPID_OK;
    }

    int ret = PGPID_OK;
    for (int i = first; i < argc; i++)
        if (pgpid_send_to_keyservers(argv[i], list))
            ret = PGPID_FAIL;
    return ret;
}
