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
 *
 * The same four can be typed in or read off a passport, and that is why one
 * action answers for both: what changes is where the civil status comes from,
 * not what is computed from it. The reading of the zone itself lives in
 * mrz.c — ICAO 9303 is a format, not an identifier.
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
        "   or: "
        "%s"
        " gen_u4 --from-passport-mrz [OPTIONS]... MRZ...\n"
        "\n"
        "Print the entity identifier a civil status gives: the last component\n"
        "of the surname, the first two given names, the date of birth, and\n"
        "the country.\n"
        "\n"
        "With --from-passport-mrz the four are read off the machine readable\n"
        "zone of a passport instead — 88 characters over two lines, spaces and\n"
        "newlines ignored, so it can be pasted as it was read.\n"
        "\n"
        "OPTIONS:\n"
        "  -s, --surname SURNAME            Surname at birth\n"
        "  -g, --given-names NAMES          Given names at birth, separated by space, comma or hyphen\n"
        "  -d, --birth-date YYYY-MM-DD      Date of birth\n"
        "  -c, --birth-country CODE         Three-letter country code of the place of birth\n"
        "      --from-passport-mrz          Read the civil status off a passport zone given as arguments\n"
        "  -u, --uncheck                    With a zone: report a failing check digit rather than refusing\n"
        "  -h, --help                       Print this help and exit\n"
        "  -V, --version                    Print the version and exit\n"
        "\n"
        "Typed in, everything is required: asking for what is missing belongs\n"
        "to whoever has somebody to ask. From a passport, only --birth-date is\n"
        "worth adding, for anyone the two digits cannot place.\n"
        "\n"
        "Roughly one passport in five gives the wrong identifier: a surname\n"
        "truncated to fit, a name changed since birth, another transliteration,\n"
        "or a year of birth two digits cannot place. It has to be checked.\n"),
            PGPID_NAME, PGPID_NAME);
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

/*
 * The same identifier, read off a passport rather than typed.
 *
 * Not transliterated on the way through: the zone is already in the format's
 * alphabet, and putting it through the path a typed name takes would squeeze
 * its runs of '<' into one — destroying the double bracket that separates the
 * surname from the given names, which is the only structure it has.
 */
static int from_passport_mrz(int argc, char **argv, int first,
                             const char *given_date, bool uncheck)
{
    /* The two lines arrive as several arguments as often as one. */
    char raw[512] = "";
    for (int i = first; i < argc; i++) {
        if (strlen(raw) + strlen(argv[i]) + 1 >= sizeof raw)
            break;
        strcat(raw, argv[i]);
    }

    struct pgpid_mrz mrz;
    bool sound = pgpid_mrz_parse(raw, &mrz);
    const char *level = uncheck ? "Warning" : "Error";

    if (!mrz.is_passport) {
        pgpid_error(_("Error: Only a passport zone is read, and this does not begin with 'P'."));
        return PGPID_FAIL;
    }
    if (!mrz.right_length) {
        pgpid_error(_("%s: The zone is %zu characters, not 88."), level, mrz.length);
        if (!uncheck)
            return PGPID_FAIL;
        if (mrz.length < 88)
            return PGPID_FAIL;   /* nothing to read past the end */
    }
    if (!sound) {
        static const char *what[5] = {
            "document number", "date of birth", "date of expiry",
            "personal number", "the whole zone",
        };
        for (unsigned i = 0; i < 5; i++)
            if (mrz.bad[i])
                pgpid_error(_("%s: The check digit for %s does not agree."), level, what[i]);
        if (!uncheck)
            return PGPID_FAIL;
    }

    char extracted[640];
    if (!pgpid_extract_names(mrz.names, extracted, sizeof extracted)) {
        pgpid_error(_("Error: No complete surname and given names in '%s'."), mrz.names);
        return PGPID_FAIL;
    }

    char date[16];
    if (given_date) {
        /* Digits only, as the shell keeps them, then either shape. */
        char digits[16];
        size_t n = 0;
        for (const char *p = given_date; *p && n < sizeof digits - 1; p++)
            if (*p >= '0' && *p <= '9')
                digits[n++] = *p;
        digits[n] = '\0';
        if (n == 8)
            snprintf(date, sizeof date, "%.4s-%.2s-%.2s", digits, digits + 4, digits + 6);
        else if (n == 6)
            pgpid_mrz_expand_year(digits, date, sizeof date);
        else {
            pgpid_error(_("Error: '%s' is not a date this can read."), given_date);
            return PGPID_USAGE;
        }
    } else {
        pgpid_mrz_expand_year(mrz.birth, date, sizeof date);
    }

    const char *coord = pgpid_country_coordinates(mrz.country);
    if (!coord) {
        pgpid_error(_("Error: '%s' is not a three-letter country code we know."), mrz.country);
        return PGPID_FAIL;
    }

    char material[660];
    int len = snprintf(material, sizeof material, "%s%s", extracted, date);
    unsigned char digest[16];
    pgpid_md5(material, (size_t)len, digest);
    char b64[32];
    pgpid_base64url(digest, 16, b64);
    b64[22] = '\0';

    printf("%s%s\n", b64, coord);
    return PGPID_OK;
}

int pgpid_action_gen_u4(int argc, char **argv)
{
    const char *surname = NULL, *given = NULL, *date = NULL, *country = NULL;
    bool from_mrz = false, uncheck = false;
    int first = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char **want = NULL;
        if (!strcmp(a, "-s") || !strcmp(a, "--surname")) want = &surname;
        else if (!strcmp(a, "-g") || !strcmp(a, "--given-names")) want = &given;
        else if (!strcmp(a, "-d") || !strcmp(a, "--birth-date")) want = &date;
        else if (!strcmp(a, "-c") || !strcmp(a, "--birth-country")) want = &country;
        else if (!strcmp(a, "--from-passport-mrz")) from_mrz = true;
        else if (!strcmp(a, "-u") || !strcmp(a, "--uncheck")) uncheck = true;
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); return PGPID_OK; }
        else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            first = i + 1;
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("gen_u4");
            return PGPID_USAGE;
        } else {
            first = i;
            break;
        }
        if (want) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a value."), a);
                return PGPID_USAGE;
            }
            *want = argv[i];
        }
    }

    if (from_mrz) {
        /* Refused rather than ignored. A name typed beside a passport looks
         * like it is being used, and an identifier minted from the other one
         * is wrong in the way that matters: silently. */
        if (surname || given || country) {
            pgpid_error(_("Error: With --from-passport-mrz the name and the country "
                        "come from the zone."));
            return PGPID_USAGE;
        }
        if (!first || first >= argc) {
            pgpid_error(_("Error: Where is the machine readable zone?"));
            usage(stderr);
            return PGPID_USAGE;
        }
        return from_passport_mrz(argc, argv, first, date, uncheck);
    }

    if (uncheck) {
        pgpid_error(_("Error: '--uncheck' is about a passport's check digits; "
                    "it needs --from-passport-mrz."));
        return PGPID_USAGE;
    }
    if (first) {
        pgpid_error(_("Error: A civil status is given by options; '%s' is not one."),
                    argv[first]);
        pgpid_try_help("gen_u4");
        return PGPID_USAGE;
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
