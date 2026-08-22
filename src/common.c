/* The bits every action needs: a context, an error, a vocabulary.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */
#include "pgpid.h"

#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

const char *pgpid_homedir = NULL;

gpgme_error_t pgpid_ctx_new(gpgme_ctx_t *ctx, gpgme_keylist_mode_t mode)
{
    gpgme_error_t err = gpgme_new(ctx);
    if (err)
        return err;
    err = gpgme_set_protocol(*ctx, GPGME_PROTOCOL_OpenPGP);
    if (err)
        goto fail;
    /* NULL file_name keeps the engine gpgme found; only the home moves. */
    err = gpgme_ctx_set_engine_info(*ctx, GPGME_PROTOCOL_OpenPGP, NULL, pgpid_homedir);
    if (err)
        goto fail;
    if (mode) {
        err = gpgme_set_keylist_mode(*ctx, mode);
        if (err)
            goto fail;
    }
    return 0;
fail:
    gpgme_release(*ctx);
    *ctx = NULL;
    return err;
}

void pgpid_error(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "%s: ", PGPID_MIP_NAME);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void pgpid_gpgme_error(const char *what, gpgme_error_t err)
{
    pgpid_error("Error: %s: %s (%s)", what,
                gpgme_strerror(err), gpgme_strsource(err));
}

/* gpg writes one letter for a validity and the same letter for an ownertrust,
 * and the trustdb stores the same enum for both. One table, therefore. */
char pgpid_validity_letter(gpgme_validity_t v)
{
    switch (v) {
    case GPGME_VALIDITY_UNKNOWN:   return '-';
    case GPGME_VALIDITY_UNDEFINED: return 'q';
    case GPGME_VALIDITY_NEVER:     return 'n';
    case GPGME_VALIDITY_MARGINAL:  return 'm';
    case GPGME_VALIDITY_FULL:      return 'f';
    case GPGME_VALIDITY_ULTIMATE:  return 'u';
    }
    return '-';
}

const char *pgpid_validity_word(gpgme_validity_t v)
{
    switch (v) {
    case GPGME_VALIDITY_UNKNOWN:   return "unknown";
    case GPGME_VALIDITY_UNDEFINED: return "undefined";
    case GPGME_VALIDITY_NEVER:     return "never";
    case GPGME_VALIDITY_MARGINAL:  return "marginal";
    case GPGME_VALIDITY_FULL:      return "full";
    case GPGME_VALIDITY_ULTIMATE:  return "ultimate";
    }
    return "unknown";
}

int pgpid_validity_from_word(const char *word)
{
    static const struct { const char *word; gpgme_validity_t v; } words[] = {
        { "unknown",   GPGME_VALIDITY_UNKNOWN   },
        { "undefined", GPGME_VALIDITY_UNDEFINED },
        { "never",     GPGME_VALIDITY_NEVER     },
        { "marginal",  GPGME_VALIDITY_MARGINAL  },
        { "full",      GPGME_VALIDITY_FULL      },
        { "ultimate",  GPGME_VALIDITY_ULTIMATE  },
    };
    for (size_t i = 0; i < sizeof words / sizeof *words; i++)
        if (!strcmp(word, words[i].word))
            return (int)words[i].v;
    return -1;
}

/* The engine gpgme resolved, so that the two agree on which gpg they mean. */
static const char *engine_path(void)
{
    gpgme_engine_info_t info;
    if (gpgme_get_engine_info(&info))
        return "gpg";
    for (; info; info = info->next)
        if (info->protocol == GPGME_PROTOCOL_OpenPGP && info->file_name)
            return info->file_name;
    return "gpg";
}

/* The child side of a pipe: replace this process with the engine. Never
 * returns on success. Used where the output has to be read back. */
void pgpid_exec_engine(const char *const *argv)
{
    size_t n = 0;
    while (argv[n])
        n++;
    const char **full = calloc(n + 4, sizeof *full);
    if (!full)
        return;
    size_t at = 0;
    full[at++] = engine_path();
    if (pgpid_homedir) {
        full[at++] = "--homedir";
        full[at++] = pgpid_homedir;
    }
    for (size_t i = 0; i < n; i++)
        full[at++] = argv[i];
    full[at] = NULL;
    execv(full[0], (char *const *)full);
    free(full);
}

/* For the one thing gpgme has no call for. execv, not a shell: --homedir and
 * the fingerprints go through as they are, with nothing to quote and nothing
 * to get wrong. argv is NULL-terminated and starts after the program name;
 * --homedir is prepended here when one was given. */
/**
 * Run a program, optionally speaking to it and optionally keeping what it says.
 *
 * One primitive rather than three near-copies: the differences between
 * "run it", "tell it something" and "keep its output" are two redirections,
 * and three functions that each set up a fork were three places for the same
 * mistake.
 *
 * A closed pipe is ignored rather than fatal — a program that gives up before
 * reading everything says so with its exit status, which is more use than a
 * signal that kills us instead.
 */
int pgpid_run_program(const char *const *argv, const char *text, const char *out_path)
{
    int fds[2] = { -1, -1 };
    if (text && pipe(fds))
        return -1;

    pid_t pid = fork();
    if (pid < 0) {
        if (text) {
            close(fds[0]);
            close(fds[1]);
        }
        return -1;
    }
    if (pid == 0) {
        if (text) {
            close(fds[1]);
            dup2(fds[0], STDIN_FILENO);
            close(fds[0]);
        }
        if (out_path) {
            int out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (out < 0)
                _exit(126);
            dup2(out, STDOUT_FILENO);
            close(out);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    if (text) {
        close(fds[0]);
        signal(SIGPIPE, SIG_IGN);
        size_t len = strlen(text), written = 0;
        while (written < len) {
            ssize_t got = write(fds[1], text + written, len - written);
            if (got <= 0)
                break;
            written += (size_t)got;
        }
        close(fds[1]);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* The engine and the home directory in front of what the caller asked for. */
static const char **with_engine(const char *const *argv)
{
    size_t n = 0;
    while (argv[n])
        n++;
    const char **full = calloc(n + 4, sizeof *full);
    if (!full)
        return NULL;
    size_t at = 0;
    full[at++] = engine_path();
    if (pgpid_homedir) {
        full[at++] = "--homedir";
        full[at++] = pgpid_homedir;
    }
    for (size_t i = 0; i < n; i++)
        full[at++] = argv[i];
    full[at] = NULL;
    return full;
}

int pgpid_run_engine(const char *const *argv)
{
    const char **full = with_engine(argv);
    if (!full)
        return -1;
    int ret = pgpid_run_program(full, NULL, NULL);
    free(full);
    return ret;
}

int pgpid_run_engine_io(const char *const *argv, const char *text, const char *out_path)
{
    const char **full = with_engine(argv);
    if (!full)
        return -1;
    int ret = pgpid_run_program(full, text, out_path);
    free(full);
    return ret;
}

bool pgpid_is_fingerprint(const char *s)
{
    if (!s)
        return false;
    size_t n = strlen(s);
    /* v4 is 40, v6 is 64. Nothing else is a fingerprint. */
    if (n != 40 && n != 64)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]))
            return false;
    return true;
}

/* Hand a certificate to each server named, and say which ones refused.
 * An empty list is a deliberate "nowhere" and not a failure. */
int pgpid_send_to_keyservers(const char *fpr, const char *list)
{
    if (!list || !*list)
        return PGPID_OK;
    char *copy = strdup(list);
    if (!copy)
        return PGPID_FAIL;
    int ret = PGPID_OK;
    for (char *save = NULL, *ks = strtok_r(copy, " \t,", &save); ks;
         ks = strtok_r(NULL, " \t,", &save)) {
        const char *argv[] = { "--keyserver", ks, "--send-keys", fpr, NULL };
        pgpid_error("Info: Sending %s to %s…", fpr, ks);
        if (pgpid_run_engine(argv)) {
            pgpid_error("Warning: %s would not take it.", ks);
            ret = PGPID_FAIL;
        }
    }
    free(copy);
    return ret;
}

/**
 * The validity letter gpg gives each uid, in the order it lists them.
 *
 * Needed because gpgme cannot say "expired": a uid gpg marks 'e' arrives
 * here as revoked=0, invalid=0, validity=unknown — indistinguishable from
 * one nobody has vouched for. Measured 2026-08-22; the third thing gpgme
 * will not tell us, after attribute packets and their images.
 *
 * Zipping by position is sound here and only here: gpgme parses this very
 * output, so the two lists are the same list.
 */
size_t pgpid_uid_validities(const char *fpr, char *out, size_t max)
{
    int fds[2];
    if (pipe(fds))
        return 0;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return 0;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, STDERR_FILENO);
            close(null);
        }
        const char *argv[] = { "--with-colons", "--list-key", fpr, NULL };
        pgpid_exec_engine(argv);
        _exit(127);
    }
    close(fds[1]);
    FILE *f = fdopen(fds[0], "r");
    size_t n = 0;
    char line[8192];
    while (f && fgets(line, sizeof line, f)) {
        if (strncmp(line, "uid:", 4))
            continue;
        if (n + 1 < max)
            out[n++] = line[4] ? line[4] : '-';
    }
    if (f)
        fclose(f);
    int st;
    waitpid(pid, &st, 0);
    out[n] = '\0';
    return n;
}

/**
 * Run a program and keep what it writes, up to `max` bytes.
 *
 * Not the engine: the card is reached through gpg-connect-agent, which
 * speaks to scdaemon. gpgme has no call for it — its business is keys and
 * data, and a smartcard's remaining attempts are neither.
 *
 * Returns the number of bytes captured, or -1 if the program could not run.
 * Its exit status is deliberately not the answer: a program can fail and
 * still have said something worth reading.
 */
int pgpid_capture(const char *const *argv, char *out, size_t max)
{
    int fds[2];
    if (pipe(fds))
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, STDERR_FILENO);
            close(null);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(fds[1]);
    size_t n = 0;
    ssize_t got;
    while (n + 1 < max && (got = read(fds[0], out + n, max - n - 1)) > 0)
        n += (size_t)got;
    out[n] = '\0';
    close(fds[0]);
    int st;
    waitpid(pid, &st, 0);
    return (int)n;
}

/**
 * Run the engine and keep what it said.
 *
 * `pgpid_capture` takes a whole command line; this one prepends the engine
 * and the home directory, so that a caller asking gpg a question cannot
 * forget which keyring the answer is about.
 */
int pgpid_capture_engine(const char *const *argv, char *out, size_t max)
{
    size_t n = 0;
    while (argv[n])
        n++;

    const char **full = calloc(n + 4, sizeof *full);
    if (!full)
        return -1;
    size_t at = 0;
    full[at++] = engine_path();
    if (pgpid_homedir) {
        full[at++] = "--homedir";
        full[at++] = pgpid_homedir;
    }
    for (size_t i = 0; i < n; i++)
        full[at++] = argv[i];
    full[at] = NULL;

    int got = pgpid_capture(full, out, max);
    free(full);
    return got;
}

/**
 * The certification key of whoever holds the connected card.
 *
 * The card carries subkeys; the key that certifies stays off it, in a safe
 * place. So the card is asked for a subkey it does have, and the keyring is
 * asked which certificate that subkey belongs to.
 */
bool pgpid_card_certification_key(char *out, size_t max)
{
    char status[16384];
    const char *argv[] = { "gpg", "--card-status", NULL };
    if (pgpid_capture(argv, status, sizeof status) <= 0)
        return false;

    /* Whichever of the three the card holds: any of them names the same
     * certificate, and a card missing one is not a card missing all. */
    static const char *const WANTED[] = {
        "Signature key", "Encryption key", "Authentication key",
    };
    char anchor[64] = "";
    for (unsigned w = 0; w < 3 && !*anchor; w++) {
        const char *at = strstr(status, WANTED[w]);
        if (!at)
            continue;
        const char *colon = strchr(at, ':');
        if (!colon)
            continue;
        size_t n = 0;
        for (const char *p = colon + 1; *p && *p != '\n' && n < sizeof anchor - 1; p++)
            if ((*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'F')
                || (*p >= 'a' && *p <= 'f'))
                anchor[n++] = *p;
        anchor[n] = '\0';
        if (n != 40)
            *anchor = '\0';
    }
    if (!*anchor)
        return false;

    gpgme_ctx_t ctx;
    if (pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL))
        return false;
    gpgme_key_t key = NULL;
    bool got = false;
    if (!gpgme_op_keylist_start(ctx, anchor, 0)
        && !gpgme_op_keylist_next(ctx, &key)) {
        if (key->subkeys && key->subkeys->fpr) {
            snprintf(out, max, "%s", key->subkeys->fpr);
            got = true;
        }
        gpgme_key_unref(key);
    }
    gpgme_op_keylist_end(ctx);
    gpgme_release(ctx);
    return got;
}

/* gpg's colon listing escapes ':' and '\' and every control byte as \xNN.
 * What the caller wants back is the uid as its owner wrote it — gpg's own
 * --quick-*-uid will not match anything else. */
static void colon_unescape(const char *in, char *out, size_t max)
{
    size_t n = 0;
    for (; *in && n + 1 < max; in++) {
        if (in[0] == '\\' && in[1] == 'x' && in[2] && in[3]) {
            char hex[3] = { in[2], in[3], '\0' };
            char *end = NULL;
            long v = strtol(hex, &end, 16);
            if (end && !*end) {
                out[n++] = (char)v;
                in += 3;
                continue;
            }
        }
        out[n++] = *in;
    }
    out[n] = '\0';
}

/**
 * Does this uid still stand?
 *
 * Field 2 of the colon listing mixes two things: how far the web of trust
 * vouches for the uid (o i n m f u q -) and whether it is still alive
 * (r e d). This asks the second, as an allow list — a letter gpg has yet to
 * invent counts as unusable, because defaulting to "usable" is the dangerous
 * side to be wrong on.
 *
 * 'm' belongs in the list. Marginal says the web of trust vouches weakly, not
 * that the address is dead; leaving it out hid a third of the addresses on a
 * real certificate.
 */
bool pgpid_uid_stands(char validity)
{
    return strchr("ounmfqws-", validity) != NULL;
}

/**
 * The uids of a certificate, with what gpg knows about each.
 *
 * From the colon listing rather than gpgme, for two things gpgme does not
 * carry: the letter that tells an expired uid from an uncertified one, and
 * the date the uid's self-signature was made — which is how "the newest
 * address" gets decided when one has to be kept.
 */
size_t pgpid_list_uids(const char *user, bool secret,
                       struct pgpid_uid *out, size_t max)
{
    char listing[262144];
    const char *argv[] = { "--with-colons",
                           secret ? "--list-secret-key" : "--list-key",
                           user, NULL };
    if (pgpid_capture_engine(argv, listing, sizeof listing) <= 0)
        return 0;

    size_t n = 0;
    unsigned keys = 0;
    for (char *line = listing, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        if (!strncmp(line, "pub:", 4) || !strncmp(line, "sec:", 4)) {
            /* The first keyring only: a second certificate in the same
             * listing is a different key that happens to match too. */
            if (++keys > 1)
                break;
            continue;
        }
        if (strncmp(line, "uid:", 4) || n >= max)
            continue;

        /* Split by hand: strtok_r folds empty fields together, and a uid
         * line with a blank validity would shift every field after it. */
        char *field[12] = { NULL };
        unsigned nf = 0;
        char *start = line;
        for (char *p = line; nf < 12; p++) {
            if (*p == ':' || !*p) {
                field[nf++] = start;
                if (!*p)
                    break;
                *p = '\0';
                start = p + 1;
            }
        }
        if (nf < 10)
            continue;
        out[n].validity = field[1] && *field[1] ? field[1][0] : '-';
        out[n].created = field[5] && *field[5] ? strtol(field[5], NULL, 10) : 0;
        colon_unescape(field[9] ? field[9] : "", out[n].text, sizeof out[n].text);
        n++;
    }
    return n;
}

/**
 * Run the engine with something to say to it.
 *
 * `--quick-*` covers most of what gpg can be told; the preferred keyserver is
 * one of the things it does not, and that one is reached by holding an
 * edit-key conversation. The answers are written to the engine's standard
 * input, in order, and the pipe is closed so gpg knows the conversation ended
 * rather than waiting for a line that never comes.
 */
int pgpid_run_engine_input(const char *const *argv, const char *text)
{
    return pgpid_run_engine_io(argv, text, NULL);
}
