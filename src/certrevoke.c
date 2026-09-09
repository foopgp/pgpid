/* Revoke a whole certificate, and say so to the keyservers.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Deliberately not an option of cert_del. Deleting removes a certificate from
 * this machine and changes nothing for anybody else; revoking tells everybody,
 * for good. Putting them behind one verb would have made the smaller act look
 * like a lesser dose of the larger one, which it is not.
 *
 * The revocation is generated, imported, and published -- publishing is the
 * point: a revocation nobody fetches protects nobody. --keyservers '' keeps it
 * local for those who mean to.
 */
#include "pgpid.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Two numberings, and they disagree on the two that matter. RFC 4880 §5.2.3.23
 * stores 1 for superseded and 2 for compromised; gpg's --gen-revoke menu offers
 * 1 for compromised and 2 for superseded. A number given here is the standard's
 * -- it is what ends up in the packet and what every other tool will show -- and
 * gets translated to gpg's menu on the way. */
static const struct { const char *word; char rfc, menu; } REASONS[] = {
    { "unspecified", '0', '0' },
    { "superseded",  '1', '2' },
    { "compromised", '2', '1' },
    { "unused",      '3', '3' },
};

static bool reason_code(const char *given, char *out)
{
    for (unsigned i = 0; i < 4; i++)
        if (!strcasecmp(given, REASONS[i].word)
            || (strlen(given) == 1 && given[0] == REASONS[i].rfc)) {
            *out = REASONS[i].menu;
            return true;
        }
    return false;
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " cert_revoke [OPTIONS]... FINGERPRINT\n"
        "\n"
        "Revoke a whole certificate and publish the revocation. Needs its secret key,\n"
        "so only a certificate this machine can still speak for: one of those\n"
        "'"
        "%s secret_list"
        "' or '"
        "%s token_list"
        "' shows.\n"
        "\n"
        "OPTIONS:\n"
        "  -r, --reason REASON         unspecified | superseded | compromised | unused,\n"
        "                              or 0..3 as RFC 4880 numbers them (not as gpg's\n"
        "                              menu does, which swaps 1 and 2) - Default: unspecified\n"
        "  -d, --description TEXT      A line saying why, kept in the revocation\n"
        "  -y, --yes                   Assume yes: skip the confirmation\n"
        "  -K, --keyservers KEYSERVERS Where to publish - empty to keep it local\n"
        "                              Default: "
        "%s"
        "\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "Revoking is final. OpenPGP has no way back: every copy that ever fetches this\n"
        "certificate, anywhere, will see it revoked, and no later signature will count.\n"),
            PGPID_NAME, PGPID_NAME, PGPID_NAME, PGPID_KEYSERVERS);
}

int pgpid_action_cert_revoke(int argc, char **argv)
{
    const char *fpr = NULL, *description = "", *keyservers = NULL;
    char code = '0';
    bool assume_yes = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if ((!strcmp(a, "-r") || !strcmp(a, "--reason")) && i + 1 < argc) {
            if (!reason_code(argv[++i], &code)) {
                pgpid_error(_("Error: Unknown reason '%s'."), argv[i]);
                pgpid_error(_("Notice: unspecified, compromised, superseded, unused."));
                return PGPID_USAGE;
            }
        } else if ((!strcmp(a, "-d") || !strcmp(a, "--description")) && i + 1 < argc) {
            description = argv[++i];
        } else if ((!strcmp(a, "-K") || !strcmp(a, "--keyservers")) && i + 1 < argc) {
            keyservers = argv[++i];
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
            pgpid_try_help("cert_revoke");
            return PGPID_USAGE;
        } else if (!fpr) {
            fpr = a;
        }
    }

    if (!fpr) {
        pgpid_error(_("Error: Which certificate? Name it by fingerprint."));
        pgpid_try_help("cert_revoke");
        return PGPID_USAGE;
    }

    /* The secret has to be here, or on a key we can reach: gpg will not sign a
     * revocation otherwise, and finding that out after the confirmation would
     * be a poor way to learn it. */
    struct pgpid_keyring *kr = pgpid_keys_load(NULL, 0, PGPID_KEYS_SECRET);
    bool ours = false;
    if (kr) {
        for (size_t i = 0; i < pgpid_keys_count(kr) && !ours; i++) {
            const struct pgpid_key *k = pgpid_keys_at(kr, i);
            ours = k->secret && !strcasecmp(k->fpr, fpr);
        }
        pgpid_keys_free(kr);
    }
    if (!ours) {
        pgpid_error(_("Error: No secret for '%s' here, so it cannot be revoked."), fpr);
        pgpid_error(_("Notice: Revoking needs the key itself. '%s cert_del' only forgets it."),
                    PGPID_NAME);
        return PGPID_NOTHING;
    }

    if (!assume_yes) {
        if (pgpid_batch) {
            pgpid_error(_("Error: --batch was given, so nothing is asked. Add --yes."));
            return PGPID_USAGE;
        }
        char answer[8];
        pgpid_error(_("Notice: About to revoke %s, for good, and tell the keyservers."), fpr);
        if (!pgpid_ask(_("Type yes to go on: "), answer, sizeof answer)
            || strcmp(answer, "yes")) {
            pgpid_error(_("Notice: Nothing done."));
            return PGPID_CANCEL;
        }
    }

    char path[] = "/tmp/pgpid-revoke.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        pgpid_error(_("Error: Cannot write the revocation anywhere."));
        return PGPID_FAIL;
    }
    close(fd);

    /* gpg asks, in order: create it?, which reason, the description ended by an
     * empty line, and one confirmation. */
    char script[1200];
    snprintf(script, sizeof script, "y\n%c\n%s\n\ny\n", code, description);
    /* --no-tty or gpg goes looking for a terminal it will not find and stops on
     * "cannot open '/dev/tty'", whatever is on the command file descriptor. */
    const char *gen[] = { "--command-fd", "0", "--status-fd", "2", "--no-tty",
                          "--armor", "--yes", "--output", path,
                          "--gen-revoke", fpr, NULL };
    if (pgpid_run_engine_input(gen, script)) {
        pgpid_error(_("Error: The revocation was not produced."));
        unlink(path);
        return PGPID_FAIL;
    }

    const char *imp[] = { "--batch", "--import", path, NULL };
    int failed = pgpid_run_engine(imp);
    unlink(path);
    if (failed) {
        pgpid_error(_("Error: The revocation was produced but would not import."));
        return PGPID_FAIL;
    }
    pgpid_error(_("Notice: %s is revoked here."), fpr);

    const char *where = keyservers ? keyservers : PGPID_KEYSERVERS;
    if (!*where) {
        pgpid_error(_("Notice: Not published. Until it is, others still trust this key."));
        return PGPID_OK;
    }
    if (pgpid_send_to_keyservers(fpr, where)) {
        pgpid_error(_("Warning: The revocation could not be published. Others still trust this key."));
        return PGPID_FAIL;
    }
    return PGPID_OK;
}
