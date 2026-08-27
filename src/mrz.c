/* Reading the two lines at the bottom of a passport.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * ICAO 9303, the TD3 form: eighty-eight characters carrying a name, a
 * country, a date of birth and five check digits. Enough to mint an
 * identifier without typing anything — which is the point, since typing a
 * civil status is where the mistakes are.
 *
 * "Enough" with a caveat the shell states and this repeats: roughly one
 * passport in five yields the wrong identifier. A surname can be truncated to
 * fit, a name can have changed since birth, a transliteration can have been
 * done differently, and the year of birth is written with two digits so
 * anyone born before 1969 needs their date given separately. The machine
 * proposes; a human checks.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The check digit ICAO defines: weights 7, 3, 1 cycling, letters counting
 * from ten, filler counting nothing, and the total taken modulo ten. */
int pgpid_mrz_check_digit(const char *s, size_t len)
{
    static const int weight[3] = { 7, 3, 1 };
    int sum = 0;
    for (size_t i = 0; i < len; i++) {
        int v;
        if (s[i] >= '0' && s[i] <= '9')
            v = s[i] - '0';
        else if (s[i] >= 'A' && s[i] <= 'Z')
            v = s[i] - 'A' + 10;
        else
            continue;   /* '<' and anything else weigh nothing */
        sum += v * weight[i % 3];
    }
    return sum % 10;
}

/**
 * The fields, and whether their check digits agree.
 *
 * Filled even when they do not: `--uncheck` exists because a passport read
 * by a camera in poor light is wrong in one character more often than it is
 * unreadable, and refusing outright helps nobody who can see the document.
 */
bool pgpid_mrz_parse(const char *raw, struct pgpid_mrz *out)
{
    /* Whitespace of any kind is layout, not content. */
    size_t n = 0;
    for (const char *p = raw; *p && n < sizeof out->line - 1; p++)
        if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
            out->line[n++] = *p;
    out->line[n] = '\0';
    out->length = n;

    memset(out->bad, 0, sizeof out->bad);
    out->is_passport = (n >= 1 && out->line[0] == 'P');
    out->right_length = (n == 88);
    if (!out->is_passport)
        return false;

    const char *m = out->line;
    /* Reading past the end would invent fields; a short line keeps what it
     * has and the caller is told the length was wrong. */
    if (n < 88) {
        out->names[0] = out->country[0] = out->birth[0] = '\0';
        return false;
    }

    memcpy(out->country, m + 2, 3);
    out->country[3] = '\0';
    memcpy(out->names, m + 5, 39);
    out->names[39] = '\0';
    memcpy(out->birth, m + 57, 6);
    out->birth[6] = '\0';

    /* The five checks, in the order ICAO numbers them. The composite covers
     * the document number, the two dates and the personal number together —
     * it is what catches a digit corrected in one place and not the other. */
    struct { const char *at; size_t len; char expected; unsigned slot; } checks[] = {
        { m + 44, 9,  m[53], 0 },   /* document number   */
        { m + 57, 6,  m[63], 1 },   /* date of birth     */
        { m + 65, 6,  m[71], 2 },   /* date of expiry    */
        { m + 72, 14, m[86], 3 },   /* personal number   */
    };
    bool all_good = true;
    for (unsigned i = 0; i < 4; i++) {
        int got = pgpid_mrz_check_digit(checks[i].at, checks[i].len);
        out->bad[checks[i].slot] = (got != checks[i].expected - '0');
        all_good = all_good && !out->bad[checks[i].slot];
    }

    char composite[40];
    memcpy(composite, m + 44, 10);
    memcpy(composite + 10, m + 57, 7);
    memcpy(composite + 17, m + 65, 20);
    out->bad[4] = pgpid_mrz_check_digit(composite, 37) != m[87] - '0';
    all_good = all_good && !out->bad[4];

    return all_good;
}

/**
 * YYMMDD to YYYY-MM-DD, resolving the century the way the tools do.
 *
 * POSIX pivots at sixty-eight: 00–68 read as twenty-first century, 69–99 as
 * twentieth. Right for a passport's expiry, and wrong for the birth of
 * anyone born before 1969 whose two digits are low — someone born in 1930
 * comes out as 2030. That is not a defect to fix here but the reason
 * `--birth-date` exists, and the reason a human checks.
 */
void pgpid_mrz_expand_year(const char *yymmdd, char *out, size_t max)
{
    int yy = (yymmdd[0] - '0') * 10 + (yymmdd[1] - '0');
    int century = (yy <= 68) ? 20 : 19;
    snprintf(out, max, "%d%02d-%c%c-%c%c", century, yy,
             yymmdd[2], yymmdd[3], yymmdd[4], yymmdd[5]);
}
