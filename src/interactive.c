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
#include <signal.h>
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

/* The terminal, as it was before a secret was asked for.
 *
 * Echo goes off for the question; a Ctrl-C in the middle of it used to leave
 * it off, and the shell underneath inherited a terminal that showed nothing
 * of what was typed into it. The signal handler puts it back and then lets
 * the signal do what it came to do. */
static struct termios asked_saved;
static volatile sig_atomic_t asked_restore;

static void give_the_terminal_back(int sig)
{
    if (asked_restore)
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &asked_saved);
    asked_restore = 0;
    signal(sig, SIG_DFL);
    raise(sig);
}

bool pgpid_ask_secret(const char *prompt, char *out, size_t max)
{
    if (pgpid_batch) {
        pgpid_error(_("Error: %s"), prompt);
        pgpid_error(_("Notice: --batch was given, so nothing is asked."));
        return false;
    }

    /* Not a terminal: something is driving this, and a star per character
     * would be noise in its log. Read the line and be done. */
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, "%s", prompt);
        fflush(stderr);
        if (!fgets(out, (int)max, stdin)) {
            pgpid_error(_("Error: Nothing to read: the question stays unanswered."));
            return false;
        }
        out[strcspn(out, "\r\n")] = '\0';
        return true;
    }

    struct termios saved, quiet;
    bool restore = !tcgetattr(STDIN_FILENO, &saved);
    void (*was_int)(int) = SIG_DFL, (*was_term)(int) = SIG_DFL, (*was_hup)(int) = SIG_DFL;
    if (restore) {
        asked_saved = saved;
        asked_restore = 1;
        was_int = signal(SIGINT, give_the_terminal_back);
        was_term = signal(SIGTERM, give_the_terminal_back);
        was_hup = signal(SIGHUP, give_the_terminal_back);
        quiet = saved;
        /* Echo off, and line editing off: the characters have to arrive one
         * by one for a star to be printed in their place. ISIG stays on, so
         * Ctrl-C still ends this the way it ends everything else. */
        quiet.c_lflag &= (tcflag_t)~(ECHO | ICANON);
        quiet.c_cc[VMIN] = 1;
        quiet.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet);
    }

    fprintf(stderr, "%s", prompt);
    fflush(stderr);

    /* A star for each character typed, backspace to take one back, Ctrl-U to
     * take back the lot — what `bl-interactive input --password` did, and what
     * anybody typing a PIN with no echo at all is entitled to: some sign that
     * the keyboard is being read. The stars count characters and not bytes:
     * a continuation byte of a UTF-8 sequence prints none of its own. */
    size_t n = 0, stars = 0;
    for (;;) {
        int c = fgetc(stdin);
        if (c == EOF || c == '\n' || c == '\r')
            break;
        if (c == 0x7f || c == 0x08) {            /* backspace */
            while (n && ((unsigned char)out[n - 1] & 0xC0) == 0x80)
                n--;                              /* back over a UTF-8 tail */
            if (n) {
                n--;
                stars--;
                fputs("\b \b", stderr);
                fflush(stderr);
            }
            continue;
        }
        if (c == 0x15) {                          /* Ctrl-U */
            while (stars--)
                fputs("\b \b", stderr);
            fflush(stderr);
            n = 0;
            stars = 0;
            continue;
        }
        if (n + 1 >= max)
            continue;                             /* full: the bell is worse */
        out[n++] = (char)c;
        if (((unsigned char)c & 0xC0) != 0x80) {
            stars++;
            fputc('*', stderr);
            fflush(stderr);
        }
    }
    out[n] = '\0';

    if (restore) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
        asked_restore = 0;
        signal(SIGINT, was_int);
        signal(SIGTERM, was_term);
        signal(SIGHUP, was_hup);
    }
    fputc('\n', stderr);                          /* the newline the echo would have shown */

    if (!n && feof(stdin)) {
        pgpid_error(_("Error: Nothing to read: the question stays unanswered."));
        return false;
    }
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

/**
 * Ask for a secret that does not exist yet, and have it typed twice.
 *
 * What `bl_new_password` did, minus the suggested passphrase: that one comes
 * out of a word list, and the C carries none. A mistyped passphrase on a key
 * being born is not a wrong password to try again — it is a key nobody can
 * ever open, so the second typing is not optional and there is no way past it
 * but agreement or Ctrl-C.
 */
bool pgpid_ask_new_secret(const char *what, char *out, size_t max)
{
    char prompt[256], again[512];
    snprintf(prompt, sizeof prompt, _("%s: "), what);
    for (;;) {
        if (!pgpid_ask_secret(prompt, out, max))
            return false;
        snprintf(prompt, sizeof prompt, _("Retype %s: "), what);
        if (!pgpid_ask_secret(prompt, again, sizeof again))
            return false;
        if (!strcmp(out, again))
            return true;
        pgpid_error(_("Notice: The two do not match. Please retype."));
        snprintf(prompt, sizeof prompt, _("%s: "), what);
    }
}
