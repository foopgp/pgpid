/* Checking and changing the codes that guard a card.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Every wrong attempt costs one of three, and the third one ends the card:
 * the keys on it are then unreachable, by anybody, forever. That is the whole
 * point of a card and it is also why this returns 194, 193 and 192 rather
 * than a plain failure — somebody about to type needs to know it is their
 * last attempt before they type it, not after.
 *
 * The current code is verified first even when only a change was asked for.
 * The card would refuse the change anyway; verifying separately is what makes
 * the difference between "wrong code" and "wrong new code" visible.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " token_code [OPTIONS]...\n"
        "\n"
        "Check and change PIN (or Admin) code protecting use of a security token\n"
        "(OpenPGP smartcard). Both codes are needed in full: nothing here asks for\n"
        "what it is missing.\n"
        "\n"
        "OPTIONS:\n"
        "  -p, --code CURRENTCODE    Current PIN (or Admin) code protecting use of security token (empty \"\" for none)\n"
        "  -P, --codefrom FILE       Get current PIN (or Admin) code from first line of FILE (eg: fifo, tmpfs, /dev/stdin ...)\n"
        "  -n, --newcode NEWCODE     New PIN (or Admin) code to protect use of security token\n"
        "  -N, --newcodefrom FILE    Get new PIN (or Admin) code from the first line of FILE (eg: fifo, tmpfs ...)\n"
        "  -C, --onlycheck           Only check current PIN (or Admin) code, don't change it\n"
        "  -A, --admin               Change (or check) Admin code instead of PIN code\n"
        "  -U, --unblock             Unblock PIN. Need Admin code to be passed to --code, and new PIN code to be passed to --newcode\n"
        "  -h, --help                Print this help and exit\n"
        "  -V, --version             Print the version and exit\n"
        "\n"
        "Return value:\n"
        "- 194 (0xC2) if only 2 remaining attempt.\n"
        "- 193 (0xC1) if only 1 remaining attempt.\n"
        "- 192 (0xC0) if code is blocked.\n"
        "- other non-zero value on other errors.\n"),
            PGPID_NAME);
}

static bool first_line_of(const char *path, char *out, size_t max)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        pgpid_error(_("Error: Cannot read %s."), path);
        return false;
    }
    if (!fgets(out, (int)max, f))
        *out = '\0';
    fclose(f);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return true;
}

static bool all_digits(const char *s, size_t want)
{
    if (strlen(s) != want)
        return false;
    for (; *s; s++)
        if (*s < '0' || *s > '9')
            return false;
    return true;
}

int pgpid_action_token_code(int argc, char **argv)
{
    char current[128] = "", fresh[128] = "";
    bool current_given = false, fresh_given = false;
    bool only_check = false, unblock = false, admin = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-p") || !strcmp(a, "--code")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a code."), a); return PGPID_USAGE; }
            snprintf(current, sizeof current, "%s", argv[i]);
            current_given = true;
        } else if (!strcmp(a, "-P") || !strcmp(a, "--codefrom") || !strcmp(a, "--code-from")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a file."), a); return PGPID_USAGE; }
            if (!first_line_of(argv[i], current, sizeof current))
                return PGPID_FAIL;
            current_given = true;
        } else if (!strcmp(a, "-n") || !strcmp(a, "--newcode")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a code."), a); return PGPID_USAGE; }
            snprintf(fresh, sizeof fresh, "%s", argv[i]);
            fresh_given = true;
        } else if (!strcmp(a, "-N") || !strcmp(a, "--newcodefrom")
                   || !strcmp(a, "--newcode-from")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a file."), a); return PGPID_USAGE; }
            if (!first_line_of(argv[i], fresh, sizeof fresh))
                return PGPID_FAIL;
            fresh_given = true;
        } else if (!strcmp(a, "-C") || !strcmp(a, "--onlycheck") || !strcmp(a, "--only-check")) {
            only_check = true;
        } else if (!strcmp(a, "-U") || !strcmp(a, "--unblock")) {
            /* Unblocking is done with the Admin code, so it implies --admin;
             * the shell falls through to it for the same reason. */
            unblock = true;
            admin = true;
        } else if (!strcmp(a, "-A") || !strcmp(a, "--admin")) {
            admin = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("change_token_code");
            return PGPID_USAGE;
        }
    }

    const char *kind = admin ? "Admin" : "PIN";
    const char *reference = admin ? "83" : "81";
    size_t length = admin ? 8 : 6;

    /* Asked for rather than refused, as the shell does — and asked for without
     * echo: a code read over a shoulder is a code lost, and one the terminal
     * echoed stays in the scrollback for the rest of the session. A caller
     * that has nobody to ask says so with --batch. */
    char prompt[128];
    if (!current_given) {
        snprintf(prompt, sizeof prompt,
                 _("Current %s code (%zu digits): "), kind, length);
        if (!pgpid_ask_secret(prompt, current, sizeof current)) {
            pgpid_error(_("Notice: Give --code, or --codefrom to keep it off "
                        "the process list."));
            return PGPID_USAGE;
        }
    }
    if (!only_check && !fresh_given) {
        snprintf(prompt, sizeof prompt,
                 _("New %s code (%zu digits): "), kind, length);
        if (!pgpid_ask_secret(prompt, fresh, sizeof fresh)) {
            pgpid_error(_("Notice: Give --newcode, or --onlycheck to only "
                        "check the current one."));
            return PGPID_USAGE;
        }
        char again[sizeof fresh];
        if (!pgpid_ask_secret(_("The same again: "), again, sizeof again))
            return PGPID_USAGE;
        if (strcmp(fresh, again)) {
            pgpid_error(_("Error: The two do not match."));
            return PGPID_USAGE;
        }
    }

    int ret = PGPID_OK;
    if (!pgpid_card_select_openpgp(&ret))
        return ret;

    if (!all_digits(current, length))
        pgpid_error(_("Warning: Given %s code doesn't match %zu digits."), kind, length);

    /* Verifying is not free: a wrong code costs one of the three attempts,
     * and a right one puts the counter back to full. */
    char hex[512], apdu[1200], sw[8];
    pgpid_to_hex(current, hex, sizeof hex);
    snprintf(apdu, sizeof apdu, "00 20 00 %s %02X %s", reference,
             (unsigned)strlen(current), hex);
    if (!pgpid_card_apdu(apdu, sw, sizeof sw))
        return PGPID_FAIL;
    ret = pgpid_sw_analyse(sw);
    if (ret) {
        /* Some cards answer a wrong VERIFY with 6982 or 6983 rather than the
         * 63CX that carries the count. The count is then worth fetching: the
         * difference between two attempts left and none is the card itself. */
        if (!strcmp(sw, "6982") || !strcmp(sw, "6983")) {
            int pin = -1, rc = -1, adm = -1;
            if (pgpid_card_retries(&pin, &rc, &adm)) {
                int left = admin ? adm : pin;
                if (left >= 0 && left < 3) {
                    pgpid_error(_("Notice: %s code: remaining retries: %d."), kind, left);
                    ret = 0xC0 + left;
                }
            }
        }
        return ret;
    }

    if (only_check) {
        pgpid_error(_("Notice: %s code successfully verified."), kind);
        return PGPID_OK;
    }

    /* Past the verification, unblocking is about the PIN — the Admin code was
     * only the permission to do it. */
    if (unblock) {
        kind = "PIN";
        reference = "81";
        length = 6;
    }

    if (!strcmp(fresh, current)) {
        pgpid_error(_("Notice: %s code unchanged."), kind);
        return PGPID_OK;
    }
    if (!all_digits(fresh, length)) {
        pgpid_error(_("Error: Given %s code doesn't match %zu digits."), kind, length);
        return PGPID_USAGE;
    }

    char freshhex[512];
    pgpid_to_hex(fresh, freshhex, sizeof freshhex);
    if (unblock)
        snprintf(apdu, sizeof apdu, "00 2C 02 %s %02X %s", reference,
                 (unsigned)strlen(fresh), freshhex);
    else
        snprintf(apdu, sizeof apdu, "00 24 00 %s %02X %.511s %.511s", reference,
                 (unsigned)(strlen(current) + strlen(fresh)), hex, freshhex);

    if (!pgpid_card_apdu(apdu, sw, sizeof sw))
        return PGPID_FAIL;
    ret = pgpid_sw_analyse(sw);
    if (ret)
        return ret;

    pgpid_error(_("Notice: %s code successfully %s."), kind,
                unblock ? "unblocked" : "changed");
    return PGPID_OK;
}
