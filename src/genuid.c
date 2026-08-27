/* The Unix account number an entity identifier gives.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Not an OpenPGP uid — a Unix one. Opening an account for somebody from
 * their certificate means giving them a number, and taking it from their
 * identifier means two machines that never met agree on it. That is what
 * makes an account restorable elsewhere from the certificate alone.
 *
 * No engine, no keyring, no network: a hash, a fold and a range. It is
 * therefore the piece that ports anywhere the model goes, Android included,
 * and the reason this wave came first.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Above 2^31 the number breaks software that reads it as signed; below 2^18
 * it collides with the accounts a distribution hands out. */
#define XUID_MIN ((int64_t)1 << 18)
#define XUID_MAX ((((int64_t)1) << 31) - 2)

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " gen_uid [OPTIONS]... U4|U5|STRING\n"
        "\n"
        "Generate a 32bit Unix User ID, from 2^18 to (2^31)-2 ([%lld,%lld]).\n"
        "The same identifier always gives the same number, on any machine — which\n"
        "is what lets an account be opened again elsewhere from the certificate\n"
        "alone.\n"
        "\n"
        "OPTIONS:\n"
        "  -f, --free-input            Accept any input, not only valid PGPID U4 string\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "An argument is required: asking interactively for a civil status is the\n"
        "caller's business.\n"),
            PGPID_NAME, (long long)XUID_MIN, (long long)XUID_MAX);
}

/* The shell hashes through `echo … | md5sum`, and echo adds a newline. The
 * digest therefore covers one byte the string does not, and every account
 * number already handed out was derived that way. Reproduced deliberately:
 * dropping it would be tidier and would renumber people. */
static void md5_line(const char *text, unsigned char out[16])
{
    size_t n = strlen(text);
    char *buf = malloc(n + 2);
    if (!buf) {
        pgpid_md5(text, n, out);
        return;
    }
    memcpy(buf, text, n);
    buf[n] = '\n';
    buf[n + 1] = '\0';
    pgpid_md5(buf, n + 1, out);
    free(buf);
}

/**
 * The sixteen bytes an identifier stands for.
 *
 * A u4 *is* a hash: its twenty-two characters decode straight back to the
 * digest, so nothing is recomputed. A u5 is a timestamp and a place, which
 * are not a hash — so it is hashed. Free input likewise.
 */
static bool digest_of(const char *input, bool free_input, unsigned char out[16])
{
    if (free_input) {
        md5_line(input, out);
        return true;
    }

    char *eid = pgpid_eid_of_uid(input);
    /* The identifier may arrive bare rather than inside a uid. */
    const char *found = eid ? eid : input;

    if (found[0] == 'u' && found[1] == '4' && strlen(found + 2) >= 22) {
        char padded[26];
        snprintf(padded, sizeof padded, "%.22s==", found + 2);
        int n = pgpid_base64url_decode(padded, out, 16);
        free(eid);
        return n == 16;
    }
    if (found[0] == 'u' && found[1] == '5') {
        /* Hashed without the 'u5' prefix: the shell hashes what its pattern
         * captured, and the pattern is the timestamp and the place, not the
         * two letters announcing them. */
        md5_line(found + 2, out);
        free(eid);
        return true;
    }
    free(eid);
    return false;
}

/**
 * Fold sixteen bytes into the range, exactly as the shell folds them.
 *
 * Two big-endian words exclusive-ORed, then a modulo — and the modulo is
 * *signed*, because the shell does its arithmetic in signed sixty-four bits
 * and a digest whose top bit is set therefore reads as negative there. Doing
 * it unsigned gives a different, equally plausible number, and the accounts
 * already opened were opened with this one.
 */
static int64_t fold(const unsigned char digest[16])
{
    uint64_t word = 0, acc = 0;
    for (unsigned half = 0; half < 2; half++) {
        word = 0;
        for (unsigned i = 0; i < 8; i++)
            word = (word << 8) | digest[half * 8 + i];
        acc ^= word;
    }
    int64_t size = XUID_MAX - XUID_MIN;
    int64_t signed_acc = (int64_t)acc;
    return ((signed_acc % size) + size) % size + XUID_MIN;
}

int pgpid_action_gen_uid(int argc, char **argv)
{
    bool free_input = false;
    int first = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-f") || !strcmp(a, "--free-input")) {
            free_input = true;
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
            pgpid_try_help("gen_uid");
            return PGPID_USAGE;
        } else {
            first = i;
            break;
        }
    }

    if (!first || first >= argc) {
        pgpid_error(_("Error: Which identifier?"));
        usage(stderr);
        return PGPID_USAGE;
    }

    /* Several arguments are one string, as the shell joins them: a civil
     * status arrives as words. */
    size_t len = 0;
    for (int i = first; i < argc; i++)
        len += strlen(argv[i]) + 1;
    char *joined = malloc(len + 1);
    if (!joined)
        return PGPID_FAIL;
    joined[0] = '\0';
    for (int i = first; i < argc; i++) {
        if (i > first)
            strcat(joined, " ");
        strcat(joined, argv[i]);
    }

    unsigned char digest[16];
    bool ok = digest_of(joined, free_input, digest);
    if (!ok) {
        pgpid_error(_("Error: No entity identifier in '%.50s'."), joined);
        pgpid_error(_("Notice: '--free-input' takes any string instead."));
        free(joined);
        return PGPID_USAGE;
    }
    free(joined);

    printf("%lld\n", (long long)fold(digest));
    return PGPID_OK;
}
