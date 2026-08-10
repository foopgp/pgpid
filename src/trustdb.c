/* The ownertrust table, read whole and read exactly.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Why this file exists, measured on 2026-08-11 with gpgme 1.24.2:
 *
 *   gpg field 9   gpgme owner_trust
 *   -             unknown
 *   q             unknown      ← the loss
 *   n             never
 *   m             marginal
 *   f             full
 *   u             ultimate
 *
 * gpgme's colon parser switches on n/m/f/u and lets everything else fall to
 * UNKNOWN, so "undefined" and "no decision recorded" arrive indistinguishable.
 * They are not the same thing: one is a person who has been considered and
 * set aside, the other is a person nobody has looked at yet — and a control
 * that offers five rungs cannot show which one it is sitting on.
 *
 * So the table is read from `gpg --export-ownertrust`, once, for the whole
 * keyring: one process for every certificate rather than one per row, and the
 * numbers it prints keep all six states apart. gpgme still answers for
 * everything else.
 *
 * The other measured surprise: `ultimate` and the rest can be set, `unknown`
 * cannot — the engine answers "Invalid argument". Which is right. Unknown is
 * the absence of a decision, and there is no way to un-decide except to edit
 * the trustdb behind gpg's back.
 */
#include "pgpid.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct entry {
    char fpr[41];
    gpgme_validity_t trust;
};

static struct entry *table = NULL;
static size_t count = 0;
static bool loaded = false;

/* The numbers `gpg --export-ownertrust` prints, which are the trustdb's own
 * and not the same as gpgme's enum. */
static gpgme_validity_t from_export_number(int n)
{
    switch (n) {
    case 2: return GPGME_VALIDITY_UNDEFINED;
    case 3: return GPGME_VALIDITY_NEVER;
    case 4: return GPGME_VALIDITY_MARGINAL;
    case 5: return GPGME_VALIDITY_FULL;
    case 6: return GPGME_VALIDITY_ULTIMATE;
    default: return GPGME_VALIDITY_UNKNOWN;
    }
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

/* Shell-quote for the one place a path and a home directory reach a command
 * line: both come from the environment or from --homedir, so neither is
 * trusted to be free of spaces or quotes. */
static char *shell_quote(const char *s)
{
    size_t n = strlen(s) * 4 + 3;
    char *out = malloc(n);
    if (!out)
        return NULL;
    char *p = out;
    *p++ = '\'';
    for (; *s; s++) {
        if (*s == '\'') {
            memcpy(p, "'\\''", 4);
            p += 4;
        } else {
            *p++ = *s;
        }
    }
    *p++ = '\'';
    *p = '\0';
    return out;
}

static void load(void)
{
    if (loaded)
        return;
    loaded = true;

    char *gpg = shell_quote(engine_path());
    char *home = pgpid_homedir ? shell_quote(pgpid_homedir) : NULL;
    if (!gpg || (pgpid_homedir && !home)) {
        free(gpg);
        free(home);
        return;
    }

    char *cmd = NULL;
    int written = home
        ? asprintf(&cmd, "%s --homedir %s --export-ownertrust 2>/dev/null", gpg, home)
        : asprintf(&cmd, "%s --export-ownertrust 2>/dev/null", gpg);
    free(gpg);
    free(home);
    if (written < 0)
        return;

    FILE *fp = popen(cmd, "r");
    free(cmd);
    if (!fp)
        return;

    size_t capacity = 0;
    char *line = NULL;
    size_t len = 0;
    while (getline(&line, &len, fp) != -1) {
        if (line[0] == '#')
            continue;
        char *colon = strchr(line, ':');
        if (!colon)
            continue;
        size_t flen = (size_t)(colon - line);
        if (flen != 40)
            continue;
        int n = atoi(colon + 1);
        if (count == capacity) {
            size_t grown = capacity ? capacity * 2 : 64;
            struct entry *bigger = realloc(table, grown * sizeof *bigger);
            if (!bigger)
                break;
            table = bigger;
            capacity = grown;
        }
        memcpy(table[count].fpr, line, 40);
        table[count].fpr[40] = '\0';
        table[count].trust = from_export_number(n);
        count++;
    }
    free(line);
    pclose(fp);
}

gpgme_validity_t pgpid_ownertrust_of(const char *fpr)
{
    if (!fpr)
        return GPGME_VALIDITY_UNKNOWN;
    load();
    for (size_t i = 0; i < count; i++)
        if (!strcasecmp(table[i].fpr, fpr))
            return table[i].trust;
    /* Absent from the table means no decision was ever recorded. */
    return GPGME_VALIDITY_UNKNOWN;
}

void pgpid_ownertrust_forget(void)
{
    free(table);
    table = NULL;
    count = 0;
    loaded = false;
}
