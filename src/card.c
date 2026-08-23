/* Speaking to the card directly.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * gpgme has nothing to say about PINs, and gpg's own card commands ask
 * questions rather than take arguments. So these go through scdaemon, as raw
 * ISO 7816 commands, the same road the shell takes.
 *
 * The status word is the card's whole answer. Two of its shapes matter more
 * than the rest: 63CX says how many attempts remain, and 6982 or 6983 are
 * what some cards return instead — the count then has to be fetched
 * separately, which is why a wrong PIN can otherwise look like a card fault.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Send one command to the card and keep its status word.
 *
 * Only commands whose answer is the status word alone: that is all any of
 * these need, and reading a longer answer as if it were short would take two
 * bytes of data for the verdict.
 */
bool pgpid_card_apdu(const char *apdu, char *sw, size_t max)
{
    char command[512];
    snprintf(command, sizeof command, "SCD APDU %.400s", apdu);

    const char *argv[8];
    size_t at = 0;
    argv[at++] = "gpg-connect-agent";
    if (pgpid_homedir) {
        argv[at++] = "--homedir";
        argv[at++] = pgpid_homedir;
    }
    argv[at++] = "--hex";
    argv[at++] = command;
    argv[at++] = "/bye";
    argv[at] = NULL;

    char out[4096];
    if (pgpid_capture(argv, out, sizeof out) < 0) {
        pgpid_error(_("Error: Cannot run gpg-connect-agent."));
        return false;
    }
    if (!strstr(out, "OK")) {
        char first[256] = "";
        size_t n = 0;
        for (const char *p = out; *p && *p != '\n' && n < sizeof first - 1; p++)
            first[n++] = *p;
        first[n] = '\0';
        pgpid_error(_("Error: %s …"), *first ? first : "The card said nothing");
        return false;
    }

    const char *at_data = strstr(out, "D[");
    if (!at_data) {
        pgpid_error(_("Error: The card answered nothing readable."));
        return false;
    }
    const char *p = strchr(at_data, ']');
    if (!p) {
        pgpid_error(_("Error: The card answered nothing readable."));
        return false;
    }
    p++;

    /* The first two bytes after the offset marker. */
    char bytes[5] = "";
    size_t got = 0;
    for (; *p && *p != '\n' && got < 4; p++) {
        if (*p == ' ' || *p == '\t')
            continue;
        if (!strchr("0123456789ABCDEFabcdef", *p))
            break;
        bytes[got++] = (*p >= 'a' && *p <= 'f') ? (char)(*p - 32) : *p;
    }
    if (got != 4) {
        pgpid_error(_("Error: The card answered %zu hex digits, not four."), got);
        return false;
    }
    bytes[4] = '\0';
    snprintf(sw, max, "%s", bytes);
    return true;
}

/**
 * What a status word means, as a return code.
 *
 * 0 when the card agreed. 192 to 194 when a code has that many attempts left,
 * blocked included — those three are what callers switch on, because they are
 * the difference between "try again" and "this card is finished". Anything
 * else comes back as its first byte, which is what ISO calls the class of the
 * problem, with a sentence saying which.
 */
int pgpid_sw_analyse(const char *raw)
{
    char sw[5] = "";
    size_t n = 0;
    for (const char *p = raw; *p && n < 4; p++) {
        if (!strchr("0123456789ABCDEFabcdef", *p))
            continue;
        sw[n++] = (*p >= 'a' && *p <= 'f') ? (char)(*p - 32) : *p;
    }
    sw[n] = '\0';
    if (n != 4) {
        pgpid_error(_("Error: Invalid status word '%s'."), raw);
        return 2;
    }

    int sw1 = (int)strtol((char[]){ sw[0], sw[1], 0 }, NULL, 16);
    int low = (int)strtol((char[]){ sw[3], 0 }, NULL, 16);
    int sw2 = (int)strtol((char[]){ sw[2], sw[3], 0 }, NULL, 16);

    if (!strcmp(sw, "9000"))
        return PGPID_OK;
    if (!strncmp(sw, "00", 2)) {
        pgpid_error(_("Error: Unknown Status Word (%s)."), sw);
        return 0x90;
    }
    if (!strcmp(sw, "6300")) {
        pgpid_error(_("Error: Verification/authentication failed (%s) - no retry info."), sw);
        return sw1;
    }
    if (!strncmp(sw, "63", 2)) {
        pgpid_error(_("Error: Verification/authentication failed (%s) - remaining "
                    "retries: %d ."), sw, low);
        return 0xC0 + low;
    }
    if (!strncmp(sw, "6C", 2)) {
        pgpid_error(_("Error: Wrong expected length (%s) - correct lenght: %d ."), sw, sw2);
        return sw1;
    }

    static const struct { const char *sw; const char *what; } KNOWN[] = {
        { "6700", "Wrong length (67 00). Incorrect Lc and/or Le." },
        { "6982", "Security status not satisfied (69 82). Likely need prior VERIFY "
                  "or secure messaging." },
        { "6983", "Authentication method blocked (69 83). PIN/method probably "
                  "blocked; follow reset/unblock procedure." },
        { "6985", "Conditions of use not satisfied (69 85). Operation not allowed "
                  "in current state." },
        { "6A82", "File / application not found (6A 82). Check AID or object "
                  "reference (P1/P2)." },
        { "6B00", "Wrong parameters P1-P2 (6B 00). Verify P1/P2 are correct for "
                  "this INS." },
        { "6D00", "INS not supported (6D 00). The card does not implement this "
                  "instruction." },
        { "6E00", "CLA not supported (6E 00). The class byte is not acceptable." },
        { "6F00", "No precise diagnosis / internal error (6F 00). Card refused "
                  "without a detailed reason." },
    };
    for (size_t i = 0; i < sizeof KNOWN / sizeof *KNOWN; i++)
        if (!strcmp(sw, KNOWN[i].sw)) {
            pgpid_error(_("Error: %s"), KNOWN[i].what);
            return sw1;
        }

    if (!strncmp(sw, "61", 2)) {
        pgpid_error(_("Error: More data available (%s) - bytes to retrieve: %d ."), sw, sw2);
        return sw1;
    }
    if (!strncmp(sw, "62", 2) || !strncmp(sw, "64", 2)) {
        pgpid_error(_("Error: Warning/non-fatal condition (%s). Check returned data "
                    "or card documentation for details."), sw);
        return sw1;
    }
    pgpid_error(_("Error: Unhandled or unknown Status Word (%s)."), sw);
    return sw1;
}

/** Put the OpenPGP application in front, before anything is asked of it. */
bool pgpid_card_select_openpgp(int *ret)
{
    char sw[8];
    if (!pgpid_card_apdu("00 A4 04 00 06 D2 76 00 01 24 01", sw, sizeof sw)) {
        *ret = PGPID_FAIL;
        return false;
    }
    *ret = pgpid_sw_analyse(sw);
    return *ret == PGPID_OK;
}

/** A string as the card wants it: its bytes, in hexadecimal, space separated. */
void pgpid_to_hex(const char *in, char *out, size_t max)
{
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        if (n + 4 >= max)
            break;
        n += (size_t)snprintf(out + n, max - n, "%s%02X", n ? " " : "", *p);
    }
    out[n] = '\0';
}
