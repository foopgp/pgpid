/* Reading a surname and given names out of the format's own alphabet.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Shared by gen_u4 and mrz_to_u4 because it is the one thing the two must
 * agree about: a passport and a typed civil status have to give the same
 * identifier, or the passport is useless.
 */
#include "pgpid.h"

#include <string.h>

/**
 * The names, extracted as the shell extracts them.
 *
 * Not composed from parts: matched. The shell builds `SURNAME<<GIVEN<<` and
 * runs `grep -o "[A-Z]\{1,32\}<<[A-Z]\{1,32\}<[A-Z]\{0,32\}<"` over it,
 * taking the first match — and that is not the same thing as taking the last
 * surname component and the first two given names.
 *
 * It differs in two ways that matter. A character which survives
 * transliteration as a non-letter — '÷' becomes '/' — breaks a run, so two
 * components stay two rather than silently joining. And a person with one
 * given name matches through the trailing pair, giving NIETO<<ENRIQUE<<
 * with two brackets rather than one.
 */
static bool run_of_capitals(const char *s, size_t *len, size_t max)
{
    size_t n = 0;
    while (n < max && s[n] >= 'A' && s[n] <= 'Z')
        n++;
    *len = n;
    return true;
}

bool pgpid_extract_names(const char *composed, char *out, size_t max)
{
    for (const char *at = composed; *at; at++) {
        const char *p = at;
        size_t n;

        run_of_capitals(p, &n, 32);
        if (n < 1)
            continue;
        p += n;
        if (p[0] != '<' || p[1] != '<')
            continue;
        p += 2;

        run_of_capitals(p, &n, 32);
        if (n < 1)
            continue;
        p += n;
        if (*p != '<')
            continue;
        p += 1;

        run_of_capitals(p, &n, 32);
        p += n;
        if (*p != '<')
            continue;
        p += 1;

        size_t len = (size_t)(p - at);
        if (len >= max)
            return false;
        memcpy(out, at, len);
        out[len] = '\0';
        return true;
    }
    return false;
}

