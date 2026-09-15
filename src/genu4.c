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
#include <strings.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " gen_u4 [OPTIONS]...\n"
        "   or: "
        "%s"
        " gen_u4 --from-passport-mrz [OPTIONS]... MRZ...\n"
        "\n"
        "Generate an eid u4 string, from a civil status: the last component of the\n"
        "surname, the first two given names, the date of birth, and the country.\n"
        "\n"
        "With --from-passport-mrz you pass the Machine Readable Zone of an\n"
        "international passport instead — 88 characters over two lines, spaces and\n"
        "newlines ignored, so it can be pasted as it was read. The four options\n"
        "below still work beside it and replace what the zone says: that is how a\n"
        "surname truncated to fit gets corrected without typing the rest.\n"
        "\n"
        "OPTIONS:\n"
        "  -s, --surname SURNAME            Surname/family name at birth\n"
        "  -g, --given-names GIVEN_NAMES    Given names at birth, separated by space ' ' or comma ',' or hyphen '-'\n"
        "  -d, --birth-date YYYY-MM-DD      Birth date, expected format : Year-Month-Day\n"
        "  -c, --birth-country COUNTRY_CODE 3 letters country code of birth place: GBR, NGA, FRA, …\n"
        "      --from-passport-mrz          Read the civil status off a passport zone given as arguments\n"
        "  -u, --uncheck                    With a zone: report a failing check digit rather than refusing\n"
        "      --verify                     Show the civil status and let it be corrected before computing\n"
        "  -h, --help                       Print this help and exit\n"
        "  -V, --version                    Print the version and exit\n"
        "\n"
        "Typed in, whatever is missing is asked for, unless --batch. From a\n"
        "passport, nothing is required — and only --birth-date is worth adding, for\n"
        "anyone the zone's two digits cannot place.\n"
        "\n"
        "--verify shows the four values and lets them be corrected before anything is\n"
        "computed, which is what a zone read by OCR usually needs. It also stops a\n"
        "failing check digit from refusing outright, the way --uncheck does: the\n"
        "point is to correct the reading rather than to be sent away from it. It\n"
        "does nothing under --batch, where there is nobody to show it to.\n"
        "\n"
        "There are ~20%% chances that a *u4* generated from a passport is incorrect:\n"
        "a surname truncated to fit, a name changed since birth, another\n"
        "transliteration, or a year of birth two digits cannot place. Check it.\n"),
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
 * A date as somebody gives it, whichever way they are minting: YYYY-MM-DD,
 * or the same eight digits bare, or — because that is how a passport writes
 * it — six, which cannot say which century and is the whole reason
 * --birth-date exists. One rule for both ways in, so that the option does not
 * mean two things depending on the flag beside it.
 */
static bool read_birth_date(const char *given, char *out, size_t max)
{
    char digits[16];
    size_t n = 0;
    for (const char *p = given; *p && n < sizeof digits - 1; p++)
        if (*p >= '0' && *p <= '9')
            digits[n++] = *p;
    digits[n] = '\0';

    if (n == 8)
        snprintf(out, max, "%.4s-%.2s-%.2s", digits, digits + 4, digits + 6);
    else if (n == 6)
        pgpid_mrz_expand_year(digits, out, max);
    else
        return false;
    return date_is_sound(out);
}

/*
 * What a name looked like before the reference transliteration touched it.
 *
 * Separators are squeezed exactly as pgpid_transliterate squeezes them, so
 * that whatever difference is left between this and its answer is the
 * transliteration itself rather than the shape of the field. The case is kept
 * and the comparison ignores it: the shell showed the name as it was typed,
 * and foodjis looks the typed spelling up in what it reads back here.
 * Uppercasing would make José into JOSé, which is neither.
 */
static void before_translit(const char *in, char *out, size_t max)
{
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && o < max - 1; p++) {
        if (*p == ' ' || *p == ';' || *p == ',' || *p == '-' || *p == '<') {
            if (o && out[o - 1] != '<')
                out[o++] = '<';
            continue;
        }
        out[o++] = (char)*p;
    }
    out[o] = '\0';
}

/*
 * Say when a name was not taken as it was typed.
 *
 * MÜLLER becomes MULLER and JOSÉ becomes JOSE, and an identifier derived from
 * the second spelling is a different identifier -- from the one a passport
 * will give, most of the time, which is the whole reason the reference
 * transliteration is the one used. It is right often enough to be the default
 * and wrong often enough that whoever is typing has to see it: a name changed
 * since birth, another country's transliteration, a surname truncated to fit.
 *
 * The shell said so and this did not. foodjis reads the two spellings off this
 * very line to show them side by side on the identity page, so silence there
 * was a page that had nothing to warn with.
 */
static void warn_if_transliterated(const char *typed, const char *taken)
{
    char before[300];
    before_translit(typed, before, sizeof before);
    if (strcasecmp(before, taken))
        pgpid_error(_("Warning: '%s' has been transliterated to '%s'. "
                      "It may be WRONG!"), before, taken);
}

/*
 * The name field the format uses: SURNAME<<GIVEN<GIVEN<. Built from its two
 * halves rather than as a whole, so that one of them can come off a passport
 * while the other comes from somebody who can see the document and knows it
 * was read wrong.
 *
 * Each half arrives already in the alphabet — transliterated by the caller
 * when it was typed, lifted as-is when it was read. Putting a read half
 * through the transliteration would squeeze its runs of '<' into one, and
 * those runs are the only structure the field has.
 */
static void compose_names(const char *surname, const char *given,
                          char *out, size_t max)
{
    snprintf(out, max, "%s<<%s<<", surname, given);
}

/* The zone's field, split back into the two halves, filler dropped. */
static void split_zone_names(const char *field, char *surname, size_t sn,
                             char *given, size_t gn)
{
    const char *sep = strstr(field, "<<");
    size_t len = sep ? (size_t)(sep - field) : strlen(field);
    if (len >= sn)
        len = sn - 1;
    memcpy(surname, field, len);
    surname[len] = '\0';

    snprintf(given, gn, "%s", sep ? sep + 2 : "");
    for (size_t i = strlen(given); i > 0 && given[i - 1] == '<'; i--)
        given[i - 1] = '\0';
}

/*
 * What a u4 is made of, whatever it was read from: a name field in the
 * format's alphabet, a date, and the coordinates of a country. Both ways in
 * end here, which is what makes them the same identifier.
 */
static bool u4_print(const char *field, const char *date, const char *coord)
{
    char names[640];
    if (!pgpid_extract_names(field, names, sizeof names)) {
        pgpid_error(_("Error: No surname and given names could be read from '%s'."), field);
        pgpid_error(_("Notice: Both need at least one letter once reduced to A-Z."));
        return false;
    }

    /* Hashed without a trailing newline — the shell uses printf here, where
     * gen_uid uses echo. The difference is invisible and decides everything. */
    char material[660];
    int n = snprintf(material, sizeof material, "%s%s", names, date);
    unsigned char digest[16];
    pgpid_md5(material, (size_t)n, digest);

    char b64[32];
    pgpid_base64url(digest, 16, b64);
    b64[22] = '\0';   /* the padding says nothing; twenty-two characters do */

    printf("%s%s\n", b64, coord);
    return true;
}

/*
 * The same identifier, read off a passport — with whatever the caller knows
 * better put back over it.
 *
 * The zone is one source of the four fields, not a different computation: a
 * surname truncated to fit gets corrected by naming it, and the other three
 * still come from the document.
 */

/** '<' back to a space, for a value a person is meant to read and correct. */
static void readable(const char *in, char *out, size_t max)
{
    size_t o = 0;
    for (const char *p = in; *p && o < max - 1; p++)
        out[o++] = (*p == '<') ? ' ' : *p;
    while (o && out[o - 1] == ' ')
        o--;
    out[o] = '\0';
}

/** Ask, keeping WHAT is already there when the answer is empty. */
static bool ask_with_default(const char *label, char *value, size_t max)
{
    char prompt[512], answer[300];
    snprintf(prompt, sizeof prompt, "%s [%s]: ", label, value);
    if (!pgpid_ask(prompt, answer, sizeof answer))
        return false;
    if (*answer)
        snprintf(value, max, "%s", answer);
    return true;
}

/**
 * Show the civil status, and let it be corrected until it is right.
 *
 * What `--verify` was for in the shell, and the reason it existed: a zone read
 * by OCR is wrong about one character often enough, a name has changed since
 * birth often enough, and an identifier minted from a wrong civil status is a
 * different person's identifier -- discovered, if ever, long afterwards.
 *
 * The default is "no": nothing is accepted by pressing enter. Four values are
 * quick to reread and this is the only moment they can be reread at all.
 */
static bool verify_civil_status(char *surname, size_t sn, char *given, size_t gn,
                                char *date, size_t dn, char *country, size_t cn)
{
    for (;;) {
        pgpid_error(_("Notice: Surname at birth:     %s"), surname);
        pgpid_error(_("Notice: Given names:         %s"), given);
        pgpid_error(_("Notice: Date of birth:       %s"), date);
        pgpid_error(_("Notice: Country of birth:    %s"), country);
        char answer[8];
        if (!pgpid_ask(_("Is that correct? [y/N]: "), answer, sizeof answer))
            return false;
        /* 'y' as well as 'yes', and the default is no. A read-back is not a
         * destructive act -- the strict "type yes" belongs where something is
         * about to be lost -- but nothing here is accepted by pressing enter
         * either: four values are quick to reread, and this is the only
         * moment they can be reread at all. */
        if (!strcasecmp(answer, "y") || !strcasecmp(answer, "yes"))
            return true;
        if (!ask_with_default(_("Birth surname (family name)"), surname, sn)
            || !ask_with_default(_("Birth names (all given names)"), given, gn)
            || !ask_with_default(_("Birth date (YYYY-MM-DD)"), date, dn)
            || !ask_with_default(_("Birth country (3 letter code)"), country, cn))
            return false;
    }
}

/**
 * The one computation, wherever the four values came from.
 *
 * Typed in or read off a passport, what is hashed is the same: the names
 * through the reference transliteration, the date, and the country's
 * coordinates. Which is why --verify can sit in front of it once rather than
 * in each way in.
 */
static int u4_from_fields(char *surname, size_t sn, char *given, size_t gn,
                          char *date, size_t dn, char *country, size_t cn,
                          bool verify)
{
    if (verify && !pgpid_batch && !verify_civil_status(surname, sn, given, gn,
                                                       date, dn, country, cn))
        return PGPID_USAGE;

    char birth[16];
    if (!read_birth_date(date, birth, sizeof birth)) {
        pgpid_error(_("Error: '%s' is not a date. Give it as YYYY-MM-DD."), date);
        return PGPID_USAGE;
    }
    const char *coord = pgpid_country_coordinates(country);
    if (!coord) {
        pgpid_error(_("Error: '%s' is not a three-letter country code we know."), country);
        return PGPID_USAGE;
    }

    char s[300], g[300], field[640];
    if (pgpid_transliterate(surname, s, sizeof s) < 0
        || pgpid_transliterate(given, g, sizeof g) < 0) {
        pgpid_error(_("Error: The name is not valid UTF-8."));
        return PGPID_USAGE;
    }
    warn_if_transliterated(surname, s);
    warn_if_transliterated(given, g);
    compose_names(s, g, field, sizeof field);

    return u4_print(field, birth, coord) ? PGPID_OK : PGPID_USAGE;
}

static int from_passport_mrz(int argc, char **argv, int first,
                             const char *surname, const char *given,
                             const char *date_given, const char *country,
                             bool uncheck, bool verify)
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

    /* The zone's two halves, read back as a person would write them: the
     * separators go, because what leaves here may be shown, corrected, and
     * put through the transliteration again -- and because a half never holds
     * a run of them, only the boundary between the two does, and that is
     * rebuilt on the way out. */
    char part_surname[300], part_given[300];
    split_zone_names(mrz.names, part_surname, sizeof part_surname,
                     part_given, sizeof part_given);

    char f_surname[300], f_given[300], f_date[16], f_country[8];
    if (surname)
        snprintf(f_surname, sizeof f_surname, "%s", surname);
    else
        readable(part_surname, f_surname, sizeof f_surname);
    if (given)
        snprintf(f_given, sizeof f_given, "%s", given);
    else
        readable(part_given, f_given, sizeof f_given);

    if (date_given) {
        if (!read_birth_date(date_given, f_date, sizeof f_date)) {
            pgpid_error(_("Error: '%s' is not a date. Give it as YYYY-MM-DD."), date_given);
            return PGPID_USAGE;
        }
    } else {
        pgpid_mrz_expand_year(mrz.birth, f_date, sizeof f_date);
    }
    snprintf(f_country, sizeof f_country, "%s", country ? country : mrz.country);

    /* Whose mistake it is decides how it is reported: what somebody typed is
     * a usage error, what a document carries is a failure to read it. Asked
     * before the computation so that the country read off the zone can be
     * corrected rather than merely refused. */
    if (!verify && !pgpid_country_coordinates(f_country)) {
        pgpid_error(_("Error: '%s' is not a three-letter country code we know."), f_country);
        return country ? PGPID_USAGE : PGPID_FAIL;
    }

    return u4_from_fields(f_surname, sizeof f_surname, f_given, sizeof f_given,
                          f_date, sizeof f_date, f_country, sizeof f_country,
                          verify);
}

int pgpid_action_gen_u4(int argc, char **argv)
{
    const char *surname = NULL, *given = NULL, *date = NULL, *country = NULL;
    bool from_mrz = false, uncheck = false, verify = false;
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
        else if (!strcmp(a, "--verify")) verify = true;
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
        if (!first || first >= argc) {
            pgpid_error(_("Error: Where is the machine readable zone?"));
            usage(stderr);
            return PGPID_USAGE;
        }
        return from_passport_mrz(argc, argv, first, surname, given, date,
                                 country, uncheck || verify, verify);
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
    /* Asked for one by one rather than refused wholesale, as the shell does:
     * somebody typing their civil status has no reason to be sent back to the
     * usage for the one field they left out. --batch refuses instead. */
    char asked[4][128];
    const struct { const char **slot; const char *question; } fields[] = {
        { &surname, N_("Birth surname (family name): ") },
        { &given,   N_("Birth names (all given names): ") },
        { &date,    N_("Birth date (YYYY-MM-DD): ") },
        { &country, N_("Birth country (3 letter code): ") },
    };
    for (size_t f = 0; f < 4; f++) {
        if (*fields[f].slot)
            continue;
        if (!pgpid_ask(_(fields[f].question), asked[f], sizeof asked[f])
            || !*asked[f]) {
            pgpid_error(_("Error: Surname, given names, date and country are all needed."));
            return PGPID_USAGE;
        }
        *fields[f].slot = asked[f];
    }

    char f_surname[300], f_given[300], f_date[16], f_country[8];
    snprintf(f_surname, sizeof f_surname, "%s", surname);
    snprintf(f_given, sizeof f_given, "%s", given);
    snprintf(f_date, sizeof f_date, "%s", date);
    snprintf(f_country, sizeof f_country, "%s", country);
    return u4_from_fields(f_surname, sizeof f_surname, f_given, sizeof f_given,
                          f_date, sizeof f_date, f_country, sizeof f_country,
                          verify);
}
