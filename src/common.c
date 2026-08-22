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
int pgpid_run_engine(const char *const *argv)
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

    pid_t pid = fork();
    if (pid < 0) {
        free(full);
        return -1;
    }
    if (pid == 0) {
        execv(full[0], (char *const *)full);
        _exit(127);
    }
    free(full);
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
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
