/* The local accounts, and which of them are PGP ID entities.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * A PGP ID entity may hold up to two entries in the account database with the
 * same number: one named by its identifier, and a shorter human-friendly alias.
 * They are one account, so they are one row here, and the identifier is what
 * names it -- the alias is a convenience, not an identity.
 *
 * An account whose home is /home/<eid> counts as one even when only the alias
 * has an entry, which is how the accounts made before this were laid out.
 *
 * The home is also where the identifier is read from now: the entry naming it
 * carries it cut to the 32 characters every account database stops at, which
 * no longer reads as an identifier on its own.
 */
#include "pgpid.h"

#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ROWS 256

#define MAX_NAMES 4

struct account {
    uid_t uid;
    char names[MAX_NAMES][64];
    size_t nname;
    char eid[64];
    char alias[64];
    char home[256];
    char gecos[256];
    bool admin;
};

/* The identifier as this project writes it, or nothing. Accepts the shape at
 * the start of a string, which is what a home path and an account name give. */
static bool eid_at(const char *s, char *out, size_t max)
{
    if ((s[0] != 'u') || (s[1] != '4' && s[1] != '5'))
        return false;
    size_t n = (s[1] == '4') ? 2 + 22 + 14 : 2 + 16 + 14;
    if (n >= max || strlen(s) < n)
        return false;
    char cand[64];
    snprintf(cand, sizeof cand, "%.*s", (int)n, s);
    if (!pgpid_eid_body_is_sound(cand))
        return false;
    snprintf(out, max, "%s", cand);
    return true;
}

/* The range the system hands out to people, from its own configuration.
 * Packages allocate service accounts above it -- libvirt-qemu lands at 64055 --
 * and a naive "1000 and up" lists those as users. */
static void human_uid_range(uid_t *lo, uid_t *hi)
{
    *lo = 1000;
    *hi = 60000;
    FILE *f = fopen("/etc/login.defs", "r");
    if (!f)
        return;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        unsigned v;
        if (sscanf(line, " UID_MIN %u", &v) == 1)
            *lo = v;
        else if (sscanf(line, " UID_MAX %u", &v) == 1)
            *hi = v;
    }
    fclose(f);
}

static bool in_admin_group(const char *name)
{
    const struct group *g = getgrnam("sudo");
    if (!g)
        return false;
    for (char **m = g->gr_mem; m && *m; m++)
        if (!strcmp(*m, name))
            return true;
    return false;
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " system_users [OPTIONS]...\n"
        "\n"
        "List the accounts of this system, and which of them are PGP ID entities.\n"
        "An entity may hold two entries with the same number -- one named by its\n"
        "identifier, one a shorter alias -- and they are one account, so one row.\n"
        "\n"
        "OPTIONS:\n"
        "  -p, --pgpid-only            Leave out the accounts that are not entities\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"),
            PGPID_NAME);
}

int pgpid_action_system_users(int argc, char **argv)
{
    bool pgpid_only = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-p") || !strcmp(a, "--pgpid-only")) {
            pgpid_only = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", PGPID_NAME, PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("system_users");
            return PGPID_USAGE;
        }
    }

    static struct account rows[MAX_ROWS];
    size_t n = 0;

    uid_t lo, hi;
    human_uid_range(&lo, &hi);

    setpwent();
    const struct passwd *pw;
    while ((pw = getpwent()) && n < MAX_ROWS) {
        /* Inside the range the system hands out to people, or a PGP ID entity:
         * our own numbers come from an identifier and land far above UID_MAX,
         * so the range alone would hide exactly the accounts this lists. */
        char probe[64];
        const char *base = strrchr(pw->pw_dir, '/');
        bool is_entity = eid_at(pw->pw_name, probe, sizeof probe)
                      || (base && eid_at(base + 1, probe, sizeof probe));
        if (!is_entity && (pw->pw_uid < lo || pw->pw_uid > hi))
            continue;

        struct account *row = NULL;
        for (size_t i = 0; i < n; i++)
            if (rows[i].uid == pw->pw_uid)
                row = &rows[i];
        if (!row) {
            row = &rows[n++];
            memset(row, 0, sizeof *row);
            row->uid = pw->pw_uid;
            snprintf(row->home, sizeof row->home, "%s", pw->pw_dir);
            snprintf(row->gecos, sizeof row->gecos, "%s", pw->pw_gecos);
        }

        if (row->nname < MAX_NAMES)
            snprintf(row->names[row->nname++], sizeof row->names[0], "%s", pw->pw_name);

        if (in_admin_group(pw->pw_name))
            row->admin = true;
    }
    endpwent();

    /* Which of an account's names is the identifier, and which is the alias.
     * The identifier itself comes from the path of the home -- whole there,
     * and cut in the entry that is named by it. An account laid out before
     * this tool has only the alias in the database and the identifier in that
     * path, which the same reading covers. */
    for (size_t i = 0; i < n; i++) {
        struct account *row = &rows[i];
        const char *base = strrchr(row->home, '/');
        if (base)
            eid_at(base + 1, row->eid, sizeof row->eid);
        for (size_t k = 0; k < row->nname && !*row->eid; k++)
            eid_at(row->names[k], row->eid, sizeof row->eid);

        char named[64] = "";
        if (*row->eid)
            pgpid_account_of_eid(row->eid, named, sizeof named);
        for (size_t k = 0; k < row->nname; k++)
            if (strcmp(row->names[k], named))
                snprintf(row->alias, sizeof row->alias, "%s", row->names[k]);
    }

    static const char *const COLUMNS[] = {
        "eid", "alias", "uid", "admin", "home",
    };
    pgpid_table_start(COLUMNS, 5);
    size_t shown = 0;
    for (size_t i = 0; i < n; i++) {
        if (pgpid_only && !*rows[i].eid)
            continue;
        char uid[16];
        snprintf(uid, sizeof uid, "%u", (unsigned)rows[i].uid);
        const char *values[] = {
            *rows[i].eid ? rows[i].eid : "-",
            *rows[i].alias ? rows[i].alias : "-",
            uid,
            rows[i].admin ? "yes" : "-",
            rows[i].home,
        };
        pgpid_table_row(values);
        shown++;
    }
    pgpid_table_end();
    return shown ? PGPID_OK : PGPID_NOTHING;
}
