/* The entity identifier carried by an OpenPGP uid.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Two shapes are in the wild and both must be read, because certificates
 * minted before the vCard-uid process are still in everyone's keyring:
 *
 *   UID:urn:eid:u4D9SrwuxesuMU90PM8xypxQe_48.78_002.19   the standard one
 *   piseb <piseb@mailo.com> (udid4=D9Srwuxesu…)          the deprecated one
 *
 * Both render the same way — "u4" or "u5" glued to the body — so that a
 * certificate does not change identity the day it is upgraded.
 *
 * ⚠ The patterns below are a port of BL_PGPID_*_REGEX in bl-pgpid, character
 * for character. They are the one thing duplicated between the shell libraries
 * and this program; when one moves, the other must. Whichever of the two ends
 * up owning the definition, it will not be two copies for long.
 */
#include "pgpid.h"

#include <regex.h>
#include <stdlib.h>
#include <string.h>

/* From bl-pgpid, lines 93-107. */
#define CO_RE   "e[_-][0-9]{2}\\.[0-9]{2}[_-][01][0-9]{2}\\.[0-9]{2}"
#define U4H_RE  "[a-zA-Z0-9_-]{22}"
#define TIME_RE "[01-][0-9]{11}\\.[0-9]{3}"
#define U4_RE   U4H_RE CO_RE
#define U5_RE   TIME_RE CO_RE

/* The standard shape: a uid that opens with UID and carries u4…/u5… */
#define STANDARD_RE "^UID.*(u4" U4_RE "|u5" U5_RE ")"
/* The deprecated one: udid4=…/u5:… anywhere, the digit and body captured
 * apart because the rendering glues "u" to them without the separator. */
#define DEPRECATED_RE "u(did)?(4|5)([=:]|\\.x3a)(" U4_RE "|" U5_RE ")"

static regex_t re_standard, re_deprecated;
static bool compiled = false;

static bool compile_once(void)
{
    if (compiled)
        return true;
    if (regcomp(&re_standard, STANDARD_RE, REG_EXTENDED) != 0)
        return false;
    if (regcomp(&re_deprecated, DEPRECATED_RE, REG_EXTENDED) != 0) {
        regfree(&re_standard);
        return false;
    }
    compiled = true;
    return true;
}

static char *dup_range(const char *s, regoff_t start, regoff_t end)
{
    size_t n = (size_t)(end - start);
    char *out = malloc(n + 1);
    if (!out)
        return NULL;
    memcpy(out, s + start, n);
    out[n] = '\0';
    return out;
}

char *pgpid_eid_of_uid(const char *uid)
{
    regmatch_t m[5];

    if (!uid || !compile_once())
        return NULL;

    /* The deprecated shape is tried first, exactly as the sed script does:
     * a legacy uid may also start with UID, and its udid4= body is the one
     * that names the entity. */
    if (regexec(&re_deprecated, uid, 5, m, 0) == 0) {
        char digit = uid[m[2].rm_so];
        char *body = dup_range(uid, m[4].rm_so, m[4].rm_eo);
        if (!body)
            return NULL;
        size_t n = strlen(body) + 3;
        char *out = malloc(n);
        if (!out) {
            free(body);
            return NULL;
        }
        snprintf(out, n, "u%c%s", digit, body);
        free(body);
        return out;
    }

    if (regexec(&re_standard, uid, 2, m, 0) == 0)
        return dup_range(uid, m[1].rm_so, m[1].rm_eo);

    return NULL;
}

/**
 * Does an identifier written bare start here?
 *
 * `u4` then twenty-two characters of the identifier alphabet, or `u5` then a
 * timestamp of sixteen; either followed by the fourteen that say where. The
 * card's "Login data" field holds one exactly so, with nothing around it.
 */
bool pgpid_eid_body_is_sound(const char *at)
{
    static const char ALPHABET[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if (at[0] != 'u' || (at[1] != '4' && at[1] != '5'))
        return false;
    const char *p = at + 2;

    if (at[1] == '4') {
        for (unsigned i = 0; i < 22; i++, p++)
            if (!*p || !strchr(ALPHABET, *p))
                return false;
    } else {
        /* Twelve digits, a dot, three digits: an instant to the millisecond. */
        for (unsigned i = 0; i < 12; i++, p++)
            if (*p < '0' || *p > '9')
                return false;
        if (*p++ != '.')
            return false;
        for (unsigned i = 0; i < 3; i++, p++)
            if (*p < '0' || *p > '9')
                return false;
    }

    /* Then where: 'e', a sign, two digits, a dot, two digits, a sign, three
     * digits, a dot, two digits. */
    static const char SHAPE[] = "eSDD.DDSDDD.DD";
    for (const char *s = SHAPE; *s; s++, p++) {
        if (!*p)
            return false;
        if (*s == 'e' && *p != 'e')
            return false;
        if (*s == 'S' && *p != '_' && *p != '-')
            return false;
        if (*s == 'D' && (*p < '0' || *p > '9'))
            return false;
        if (*s == '.' && *p != '.')
            return false;
    }
    return true;
}
