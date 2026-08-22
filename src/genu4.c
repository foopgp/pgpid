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
    fprintf(out,
        "Usage: " PGPID_MIP_NAME " gen_u4 [OPTIONS]...\n"
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
        "has somebody to ask.\n");
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

/**
 * The names as the format wants them: LAST<<FIRST<SECOND<
 *
 * Only the last component of the surname, and at most two given names —
 * whatever else was given is dropped, deliberately, because a passport does
 * the same and the identifier must match one.
 */
static bool compose(const char *surname, const char *given, char *out, size_t max)
{
    char s[256], g[256], warned[64];
    if (pgpid_transliterate(surname, s, sizeof s, warned, sizeof warned) < 0) {
        pgpid_error("Error: The surname is not valid UTF-8.");
        return false;
    }
    if (*warned)
        pgpid_error("Warning: '%s' has no accent to remove; written as it is read here. Check it.", warned);
    if (pgpid_transliterate(given, g, sizeof g, warned, sizeof warned) < 0) {
        pgpid_error("Error: The given names are not valid UTF-8.");
        return false;
    }
    if (*warned)
        pgpid_error("Warning: '%s' has no accent to remove; written as it is read here. Check it.", warned);

    const char *last = strrchr(s, '<');
    last = last ? last + 1 : s;
    if (!*last) {
        pgpid_error("Error: No surname left once reduced to letters.");
        return false;
    }

    char *first = g, *second = NULL;
    char *cut = strchr(g, '<');
    if (cut) {
        *cut = '\0';
        second = cut + 1;
        char *third = strchr(second, '<');
        if (third)
            *third = '\0';   /* a third given name is not part of the name */
    }
    if (!*first) {
        pgpid_error("Error: No given name left once reduced to letters.");
        return false;
    }

    snprintf(out, max, "%s<<%s<%s<", last, first, second ? second : "");
    return true;
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
            printf("%s %s\n", argv[0], PGPID_MIP_VERSION);
            return PGPID_OK;
        } else {
            pgpid_error("Error: Unrecognized option '%s'.", a);
            pgpid_error("Try '" PGPID_MIP_NAME " gen_u4 --help' for more information.");
            return PGPID_USAGE;
        }
        if (want) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants a value.", a);
                return PGPID_USAGE;
            }
            *want = argv[i];
        }
    }

    if (!surname || !given || !date || !country) {
        pgpid_error("Error: Surname, given names, date and country are all needed.");
        usage(stderr);
        return PGPID_USAGE;
    }
    if (!date_is_sound(date)) {
        pgpid_error("Error: '%s' is not a date of the shape YYYY-MM-DD.", date);
        return PGPID_USAGE;
    }
    const char *coord = pgpid_country_coordinates(country);
    if (!coord) {
        pgpid_error("Error: '%s' is not a three-letter country code we know.", country);
        return PGPID_USAGE;
    }

    char names[600];
    if (!compose(surname, given, names, sizeof names))
        return PGPID_USAGE;

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
