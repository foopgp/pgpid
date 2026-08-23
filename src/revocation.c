/* When a certificate was revoked — the one date gpgme does not carry.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * A key revocation is a signature on the primary key, not on a uid, and
 * gpgme's key structure only walks uid signatures: `key->revoked` says *that*
 * it was revoked and nothing says *when*. GnuPG does, in a `rev:` record of
 * `--list-sigs --with-colons`:
 *
 *     pub:r:…:1295029403:…
 *     rev:::…:1299258738:…
 *
 * So one gpg is spawned for the whole listing, once, and only if a revoked
 * certificate actually turned up — the same bargain as everywhere else here:
 * one process for every row rather than one per row, and none at all when the
 * answer is not wanted.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

struct entry {
    char fpr[65];
    long when;
};

static struct entry *table = NULL;
static size_t count = 0;
static bool loaded = false;

/* Field N of a colon line, or NULL. Fields are 1-based, as gpg documents. */
static char *field(char *line, int n)
{
    char *p = line;
    for (int i = 1; i < n && p; i++) {
        p = strchr(p, ':');
        if (p)
            p++;
    }
    if (!p)
        return NULL;
    char *end = strchr(p, ':');
    if (end)
        *end = '\0';
    return p;
}

static void remember(const char *fpr, long when)
{
    static size_t capacity = 0;
    if (count == capacity) {
        size_t grown = capacity ? capacity * 2 : 16;
        struct entry *bigger = realloc(table, grown * sizeof *bigger);
        if (!bigger)
            return;
        table = bigger;
        capacity = grown;
    }
    snprintf(table[count].fpr, sizeof table[count].fpr, "%s", fpr);
    table[count].when = when;
    count++;
}

static void load(const char *pattern)
{
    if (loaded)
        return;
    loaded = true;

    int fds[2];
    if (pipe(fds) < 0)
        return;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return;
    }
    if (pid == 0) {
        dup2(fds[1], STDOUT_FILENO);
        close(fds[0]);
        close(fds[1]);
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, STDERR_FILENO);
            close(null);
        }
        const char *args[] = { "--with-colons", "--list-sigs", pattern, NULL };
        if (!pattern)
            args[2] = NULL;
        pgpid_exec_engine(args);
        _exit(127);
    }
    close(fds[1]);

    FILE *fp = fdopen(fds[0], "r");
    if (!fp) {
        close(fds[0]);
        waitpid(pid, NULL, 0);
        return;
    }

    /* A `rev:` belongs to the certificate whose `fpr:` came last. */
    char *line = NULL;
    size_t len = 0;
    char current[65] = "";
    long pending = 0;
    while (getline(&line, &len, fp) != -1) {
        if (!strncmp(line, "pub:", 4)) {
            current[0] = '\0';
            pending = 0;
        } else if (!strncmp(line, "fpr:", 4) && !current[0]) {
            char copy[512];
            snprintf(copy, sizeof copy, "%s", line);
            char *f = field(copy, 10);
            if (f)
                snprintf(current, sizeof current, "%s", f);
            if (pending && current[0]) {
                remember(current, pending);
                pending = 0;
            }
        } else if (!strncmp(line, "rev:", 4)) {
            char copy[512];
            snprintf(copy, sizeof copy, "%s", line);
            char *t = field(copy, 6);
            long when = t ? atol(t) : 0;
            if (when <= 0)
                continue;
            /* The revocation may be read before the fingerprint of the very
             * first certificate; hold it until one is known. */
            if (current[0])
                remember(current, when);
            else
                pending = when;
        }
    }
    free(line);
    fclose(fp);
    waitpid(pid, NULL, 0);
}

long pgpid_revocation_time(const char *fpr, const char *pattern)
{
    if (!fpr)
        return 0;
    load(pattern);
    for (size_t i = 0; i < count; i++)
        if (!strcasecmp(table[i].fpr, fpr))
            return table[i].when;
    return 0;
}
