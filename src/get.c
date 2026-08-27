/* Finding a certificate, locally or in the world.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * `get` and `list --short` print the same thing; they differ in what they
 * are for. `list` shows what is at hand, so a missing pattern means the whole
 * keyring. `get` looks something up, so it wants to be told what — a search
 * with no term is almost always a caller that lost its variable, and `'*'`
 * is there for the rare occasion when everything really is meant.
 *
 * The other difference is the network: `get` refreshes before it answers,
 * unless told not to. A certificate is a claim other people update, and
 * answering from a stale copy is how one certifies a key whose owner revoked
 * it last week.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " get [OPTIONS]... NAME|EMAIL|KEYID|U4|U5|'*'\n"
        "\n"
        "Print the fingerprints, addresses and entity identifiers of the\n"
        "certificates matching what is asked for, one line per address.\n"
        "Refreshes them from the keyservers first, unless told otherwise.\n"
        "\n"
        "A search term is required — '*' for the whole keyring. `list` is the\n"
        "one that shows everything when asked nothing.\n"
        "\n"
        "OPTIONS:\n"
        "  -F, --fingerprint           Print only fingerprints\n"
        "  -E, --email                 Print only addresses\n"
        "  -f, --no-fetch              Do not refresh from keyservers or Web Key Directories\n"
        "  -m, --errexit-g=N           Fail if more than N certificates match\n"
        "  -K, --keyservers SERVERS    Refresh from these, space separated\n"
        "                              Empty for none, same as --no-fetch. Default: "
        "%s"
        "\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "There is no 'cert_check': `list` answers what it answered, for less.\n"),
            PGPID_NAME, PGPID_KEYSERVERS);
}

/**
 * Refresh what the engine knows how to refresh on its own.
 *
 * An address goes through `--locate-external-keys`, which asks the Web Key
 * Directory of its domain and then the keyservers. A fingerprint or key
 * identifier goes through `--recv-keys`. A free-text name goes nowhere: the
 * shell searches keyservers by name over HTTP, and doing the same here would
 * mean carrying an HTTP client for a case that is rare and ambiguous — a name
 * matches whoever else chose it. Said plainly rather than silently skipped.
 */
void pgpid_refresh(const char *term, const char *keyservers)
{
    if (!keyservers || !*keyservers)
        return;

    bool is_address = strchr(term, '@') != NULL;
    bool is_key = pgpid_is_fingerprint(term);
    if (!is_key) {
        /* A key identifier: sixteen or eight hexadecimal characters, with or
         * without the 0x a keyserver would print. */
        const char *p = term + (strncmp(term, "0x", 2) == 0 || strncmp(term, "0X", 2) == 0 ? 2 : 0);
        size_t n = strlen(p);
        if (n == 8 || n == 16) {
            is_key = true;
            for (size_t i = 0; i < n && is_key; i++)
                is_key = (p[i] >= '0' && p[i] <= '9')
                      || (p[i] >= 'a' && p[i] <= 'f')
                      || (p[i] >= 'A' && p[i] <= 'F');
        }
    }

    if (!is_address && !is_key) {
        pgpid_error(_("Notice: '%s' is a name, not an address or a key — asking nobody."), term);
        pgpid_error(_("Notice: Searching keyservers by name is not here yet; give an address or a fingerprint."));
        return;
    }

    char *copy = strdup(keyservers);
    if (!copy)
        return;
    for (char *save = NULL, *ks = strtok_r(copy, " \t,", &save); ks;
         ks = strtok_r(NULL, " \t,", &save)) {
        const char *locate[] = {
            "--keyserver", ks, "--auto-key-locate", "clear,wkd,keyserver",
            "--locate-external-keys", term, NULL,
        };
        const char *recv[] = { "--keyserver", ks, "--recv-keys", term, NULL };
        /* Failure is ordinary here — a server may be down, a key absent —
         * and it must not stop the answer: what is already local is still
         * worth printing. */
        pgpid_run_engine(is_address ? locate : recv);
    }
    free(copy);
}

int pgpid_action_get(int argc, char **argv)
{
    bool only_fpr = false, only_mbox = false, fetch = true;
    const char *keyservers = NULL;
    long errexit = -1;
    int first = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-F") || !strcmp(a, "--fpr") || !strcmp(a, "--fingerprint")) {
            only_fpr = true;
            only_mbox = false;
        } else if (!strcmp(a, "-E") || !strcmp(a, "--mbox") || !strcmp(a, "--email")) {
            only_mbox = true;
            only_fpr = false;
        } else if (!strcmp(a, "-f") || !strcmp(a, "--no-fetch")) {
            fetch = false;
        } else if (!strcmp(a, "-K") || !strcmp(a, "--keyservers")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a list of servers, empty for none."), a);
                return PGPID_USAGE;
            }
            keyservers = argv[i];
        } else if (!strncmp(a, "--errexit-g=", 12) || !strcmp(a, "-m")) {
            const char *v = a[1] == 'm' ? "1" : a + 12;
            char *end = NULL;
            errexit = strtol(v, &end, 10);
            if (!*v || (end && *end) || errexit < 1) {
                pgpid_error(_("Error: '%s' wants a number of one or more."), a);
                return PGPID_USAGE;
            }
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
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("get");
            return PGPID_USAGE;
        } else {
            first = i;
            break;
        }
    }

    if (!first || first >= argc) {
        pgpid_error(_("Error: What are you looking for? '*' for everything."));
        usage(stderr);
        return PGPID_USAGE;
    }

    /* '*' is the whole keyring, which is what an empty pattern means to the
     * engine — and nothing to fetch, since there is no one thing to ask for. */
    bool everything = argc - first == 1 && !strcmp(argv[first], "*");

    if (fetch && !everything)
        for (int i = first; i < argc; i++)
            pgpid_refresh(argv[i], keyservers ? keyservers : PGPID_KEYSERVERS);

    /* One pattern at a time, as the engine takes them; several terms are
     * several searches whose answers meet in the output. */
    int ret = PGPID_NOTHING;
    size_t matched = 0;
    pgpid_list_short_start(only_fpr, only_mbox);
    for (int i = first; i < argc; i++) {
        size_t n = 0;
        int r = pgpid_list_short(everything ? NULL : argv[i], only_fpr, only_mbox, &n);
        if (r == PGPID_FAIL)
            return PGPID_FAIL;
        if (r == PGPID_OK)
            ret = PGPID_OK;
        matched += n;
    }
    pgpid_list_short_end();

    if (ret == PGPID_NOTHING) {
        pgpid_error(_("Error: No certificate for what was asked."));
        return ret;
    }

    /* The answer is printed first and judged after, deliberately: a caller
     * who asked for one certificate and got three wants to see which three,
     * not just to be told the count was wrong. */
    if (errexit > 0 && matched > (size_t)errexit) {
        pgpid_error(_("Error: %zu certificates matched, more than the %ld asked for."),
                    matched, errexit);
        return PGPID_FAIL;
    }
    return ret;
}
