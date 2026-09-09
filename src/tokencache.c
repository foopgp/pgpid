/* What pgpid remembers of the security keys it has met.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * GnuPG keeps a stub saying which card holds a secret, and nothing more. It has
 * no room for what a PGP ID key carries -- the identifier, the addresses, the
 * certificate URL -- so token_list could only answer about the key in the
 * reader. On a phone reading over NFC nothing stays in a reader at all.
 *
 * So pgpid keeps its own note beside GnuPG's, one file per card, under a
 * subdirectory of the same home: one --homedir for both, created at the first
 * write and never announced.
 *
 * Every note carries the day it was written. A field read six months ago is
 * what the card said then, and without the date nobody can tell that from what
 * it says now.
 */
#include "pgpid.h"

#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

const char *pgpid_home(void)
{
    static char resolved[512];
    if (*resolved)
        return resolved;
    const char *h = pgpid_homedir;
    if (!h)
        h = getenv("GNUPGHOME");
    if (h && *h) {
        snprintf(resolved, sizeof resolved, "%s", h);
        return resolved;
    }
    /* gpg's own default, rather than the working directory: writing a cache
     * wherever the caller happened to stand is how notes get lost. */
    const char *home = getenv("HOME");
    snprintf(resolved, sizeof resolved, "%s/.gnupg", home && *home ? home : ".");
    return resolved;
}

/** The directory our notes live in, made if it is not there yet. */
static bool cache_dir(char *out, size_t max, bool create)
{
    snprintf(out, max, "%s/pgpid/tokens", pgpid_home());
    if (!create)
        return true;
    char parent[512];
    snprintf(parent, sizeof parent, "%s/pgpid", pgpid_home());
    if (mkdir(parent, 0700) && errno != EEXIST)
        return false;
    if (mkdir(out, 0700) && errno != EEXIST)
        return false;
    return true;
}

/* A serial names a file, so it may not wander out of the directory. */
static bool serial_is_sane(const char *serial)
{
    if (!serial || !*serial || strlen(serial) > 64)
        return false;
    for (const char *p = serial; *p; p++)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'F')
              || (*p >= 'a' && *p <= 'f')))
            return false;
    return true;
}

bool pgpid_token_remember(const char *serial, const char *info)
{
    char dir[512], path[640];
    if (!serial_is_sane(serial) || !cache_dir(dir, sizeof dir, true))
        return false;
    snprintf(path, sizeof path, "%s/%s", dir, serial);

    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    char stamp[32];
    strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%SZ", &tm);
    fprintf(f, "token_seen='%s'\n", stamp);
    fputs(info, f);
    fclose(f);
    chmod(path, 0600);
    return true;
}

bool pgpid_token_forget(const char *serial)
{
    char dir[512], path[640];
    if (!serial_is_sane(serial) || !cache_dir(dir, sizeof dir, false))
        return false;
    snprintf(path, sizeof path, "%s/%s", dir, serial);
    return remove(path) == 0;
}

bool pgpid_token_recall(const char *serial, char *out, size_t max)
{
    char dir[512], path[640];
    *out = '\0';
    if (!serial_is_sane(serial) || !cache_dir(dir, sizeof dir, false))
        return false;
    snprintf(path, sizeof path, "%s/%s", dir, serial);
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    size_t n = fread(out, 1, max - 1, f);
    out[n] = '\0';
    fclose(f);
    return n > 0;
}

size_t pgpid_token_known(char serials[][64], size_t max)
{
    char dir[512];
    if (!cache_dir(dir, sizeof dir, false))
        return 0;
    DIR *d = opendir(dir);
    if (!d)
        return 0;
    size_t n = 0;
    const struct dirent *e;
    while ((e = readdir(d)) && n < max)
        if (serial_is_sane(e->d_name))
            /* Bounded explicitly: serial_is_sane already refuses anything
             * longer, but the compiler cannot see that from here. */
            snprintf(serials[n++], 64, "%.63s", e->d_name);
    closedir(d);
    return n;
}

/** One key='value' line out of a note. */
static bool note_value(const char *note, const char *key, char *out, size_t max)
{
    char want[64];
    snprintf(want, sizeof want, "\n%s='", key);
    const char *at = strstr(note, want + 1) == note ? note : strstr(note, want);
    if (!at)
        return false;
    at = strchr(at, '\'');
    if (!at)
        return false;
    at++;
    const char *end = strchr(at, '\'');
    if (!end)
        return false;
    snprintf(out, max, "%.*s", (int)(end - at), at);
    return *out != '\0';
}

bool pgpid_token_last_signing_key(char *out, size_t max)
{
    char serials[64][64];
    size_t n = pgpid_token_known(serials, 64);
    char best_seen[32] = "", note[4096], seen[32], fpr[41];
    *out = '\0';
    for (size_t i = 0; i < n; i++) {
        if (!pgpid_token_recall(serials[i], note, sizeof note))
            continue;
        if (!note_value(note, "pgpid_Skeyfpr", fpr, sizeof fpr))
            continue;
        if (!note_value(note, "token_seen", seen, sizeof seen))
            continue;
        /* ISO-8601 in UTC, so the newest is the greatest string. */
        if (strcmp(seen, best_seen) <= 0)
            continue;
        snprintf(best_seen, sizeof best_seen, "%s", seen);
        snprintf(out, max, "%s", fpr);
    }
    return *out != '\0';
}
