/* An identifier from a civil status.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * A u4 is what a person was called at birth, where, and when — folded into
 * twenty-two characters and followed by the fourteen that say which country.
 * It is not a secret and not a key: it is a name two strangers can compute
 * the same way, which is the whole point.
 *
 * The last component of the surname and the first two given names, because
 * that is what fits on a passport and what a second machine can reproduce.
 * Splitting happens before transliteration, so the hyphen of
 * DE CLÉREL-DE-TOCQUEVILLE marks a boundary before it is dropped and the
 * component that survives is TOCQUEVILLE.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " gen_u4 [OPTIONS]...\n"
        "\n"
        "Print the entity identifier a civil status gives: the last component\n"
        "of the surname, the first two given names, the date of birth, and\n"
        "the country.\n"
        "\n"
        "OPTIONS:\n"
        "  -s, --surname SURNAME            Surname at birth\n"
        "  -g, --given-names NAMES          Given names at birth, separated by space, comma or hyphen\n"
        "  -d, --birth-date YYYY-MM-DD      Date of birth\n"
        "  -c, --birth-country CODE         Three-letter country code of the place of birth\n"
        "  -h, --help                       Print this help and exit\n"
        "  -V, --version                    Print the version and exit\n"
        "\n"
        "Everything is required: asking for what is missing belongs to whoever\n"
        "has somebody to ask.\n"),
            PGPID_NAME);
}

/** YYYY-MM-DD, and a date that exists. A wrong date mints a wrong name. */
static bool date_is_sound(const char *d)
{
    if (strlen(d) != 10 || d[4] != '-' || d[7] != '-')
        return false;
    for (int i = 0; i < 10; i++)
        if (i != 4 && i != 7 && (d[i] < '0' || d[i] > '9'))
            return false;
    int y = atoi(d), m = atoi(d + 5), day = atoi(d + 8);
    if (m < 1 || m > 12 || day < 1)
        return false;
    static const int len[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    int last = len[m - 1];
    if (m == 2 && ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0))
        last = 29;
    return day <= last;
}

int pgpid_action_gen_u4(int argc, char **argv)
{
    const char *surname = NULL, *given = NULL, *date = NULL, *country = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char **want = NULL;
        if (!strcmp(a, "-s") || !strcmp(a, "--surname")) want = &surname;
        else if (!strcmp(a, "-g") || !strcmp(a, "--given-names")) want = &given;
        else if (!strcmp(a, "-d") || !strcmp(a, "--birth-date")) want = &date;
        else if (!strcmp(a, "-c") || !strcmp(a, "--birth-country")) want = &country;
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); return PGPID_OK; }
        else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("gen_u4");
            return PGPID_USAGE;
        }
        if (want) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a value."), a);
                return PGPID_USAGE;
            }
            *want = argv[i];
        }
    }

    if (!surname || !given || !date || !country) {
        pgpid_error(_("Error: Surname, given names, date and country are all needed."));
        usage(stderr);
        return PGPID_USAGE;
    }
    if (!date_is_sound(date)) {
        pgpid_error(_("Error: '%s' is not a date of the shape YYYY-MM-DD."), date);
        return PGPID_USAGE;
    }
    const char *coord = pgpid_country_coordinates(country);
    if (!coord) {
        pgpid_error(_("Error: '%s' is not a three-letter country code we know."), country);
        return PGPID_USAGE;
    }

    /* Separators first, then transliteration, then the match — the shell's
     * order, and it is the order that makes a hyphen a boundary. */
    char s[300], g[300], composed[640], names[640];
    if (pgpid_transliterate(surname, s, sizeof s) < 0
        || pgpid_transliterate(given, g, sizeof g) < 0) {
        pgpid_error(_("Error: The name is not valid UTF-8."));
        return PGPID_USAGE;
    }
    snprintf(composed, sizeof composed, "%s<<%s<<", s, g);
    if (!pgpid_extract_names(composed, names, sizeof names)) {
        pgpid_error(_("Error: No surname and given names could be read from '%s'."), composed);
        pgpid_error(_("Notice: Both need at least one letter once reduced to A-Z."));
        return PGPID_USAGE;
    }

    /* Hashed without a trailing newline — the shell uses printf here, where
     * gen_uid uses echo. The difference is invisible and decides everything. */
    char material[640];
    int n = snprintf(material, sizeof material, "%s%s", names, date);
    unsigned char digest[16];
    pgpid_md5(material, (size_t)n, digest);

    char b64[32];
    pgpid_base64url(digest, 16, b64);
    b64[22] = '\0';   /* the padding says nothing; twenty-two characters do */

    printf("%s%s\n", b64, coord);
    return PGPID_OK;
}
