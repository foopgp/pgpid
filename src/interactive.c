/* Asking the person in front of the terminal.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The command line and nothing else. The shell libraries can put the same
 * question through zenity, whiptail or a terminal, which is why they carry a
 * --frontend ; here there is one way to ask, and a caller that cannot bear
 * being asked says so with --batch.
 *
 * Every question goes to stderr and every answer is read from stdin, so that
 * the useful output of an action stays pipeable while it is being asked.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

bool pgpid_batch = false;

/**
 * Ask, and return what was typed with its newline removed.
 *
 * False when there is nothing to ask with: --batch was given, or stdin is not
 * a terminal and holds nothing. A question nobody can answer is an error the
 * caller has to report in its own words — it knows what it was missing.
 */
bool pgpid_ask(const char *prompt, char *out, size_t max)
{
    if (pgpid_batch) {
        pgpid_error(_("Error: %s"), prompt);
        pgpid_error(_("Notice: --batch was given, so nothing is asked."));
        return false;
    }
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (!fgets(out, (int)max, stdin)) {
        pgpid_error(_("Error: Nothing to read: the question stays unanswered."));
        return false;
    }
    out[strcspn(out, "\r\n")] = '\0';
    return true;
}

/**
 * Ask for something that must not appear on the screen.
 *
 * A PIN read over somebody's shoulder is a PIN lost, and a terminal that
 * echoed it leaves it in the scrollback for the rest of the session. Echo is
 * turned off around the question and put back afterwards, whatever happens —
 * including when the answer never comes.
 */
bool pgpid_ask_secret(const char *prompt, char *out, size_t max)
{
    if (pgpid_batch) {
        pgpid_error(_("Error: %s"), prompt);
        pgpid_error(_("Notice: --batch was given, so nothing is asked."));
        return false;
    }
    struct termios saved, quiet;
    bool restore = isatty(STDIN_FILENO) && !tcgetattr(STDIN_FILENO, &saved);
    if (restore) {
        quiet = saved;
        quiet.c_lflag &= (tcflag_t)~ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
    }
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    bool got = fgets(out, (int)max, stdin) != NULL;
    if (restore) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
        fputc('\n', stderr);            /* the newline the echo would have shown */
    }
    if (!got) {
        pgpid_error(_("Error: Nothing to read: the question stays unanswered."));
        return false;
    }
    out[strcspn(out, "\r\n")] = '\0';
    return true;
}

/**
 * Offer a numbered list and return what was picked, zero-based.
 *
 * The shell puts the same question through a radiolist; here the items are
 * printed and a number is read. Out of range is asked again rather than
 * rounded to something — picking the wrong secret key is not a small mistake.
 */
bool pgpid_choose(const char *prompt, const char *const *items, size_t n,
                  size_t *picked)
{
    if (!n)
        return false;
    if (n == 1) {
        *picked = 0;
        return true;
    }
    /* Checked before printing anything: a caller that cannot be asked has no
     * use for a menu, and a refusal buried under twenty lines reads as a
     * listing that failed. */
    if (pgpid_batch) {
        pgpid_error(_("Error: %s"), prompt);
        pgpid_error(_("Notice: --batch was given, so nothing is asked."));
        return false;
    }
    for (unsigned tries = 0; tries < 3; tries++) {
        for (size_t i = 0; i < n; i++)
            pgpid_error("  %2zu. %s", i + 1, items[i]);
        char line[64];
        if (!pgpid_ask(prompt, line, sizeof line))
            return false;
        char *end = NULL;
        long v = strtol(line, &end, 10);
        if (end != line && v >= 1 && (size_t)v <= n) {
            *picked = (size_t)v - 1;
            return true;
        }
        pgpid_error(_("Notice: A number between 1 and %zu is wanted."), n);
    }
    return false;
}

/**
 * Ask until the answer holds exactly N hexadecimal characters, or give up.
 *
 * Spacing and case are ignored: a fingerprint is read off a card in groups of
 * four, and asking somebody to strip the spaces themselves is asking them to
 * make a mistake. Three attempts, because a fourth is no longer a typo.
 */
bool pgpid_ask_hex(const char *prompt, size_t want, char *out, size_t max)
{
    if (want >= max)
        return false;
    for (unsigned tries = 0; tries < 3; tries++) {
        char line[256];
        if (!pgpid_ask(prompt, line, sizeof line))
            return false;
        size_t n = 0;
        for (const char *p = line; *p && n < want; p++) {
            if (*p >= '0' && *p <= '9')
                out[n++] = *p;
            else if (*p >= 'a' && *p <= 'f')
                out[n++] = (char)(*p - 32);
            else if (*p >= 'A' && *p <= 'F')
                out[n++] = *p;
        }
        out[n] = '\0';
        if (n == want)
            return true;
        pgpid_error(_("Notice: %zu hexadecimal characters are wanted, %zu were read."),
                    want, n);
    }
    return false;
}
