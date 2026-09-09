/* The local accounts, and which of them are PGP ID entities.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * One entry per account, named by the local part of its address, with the
 * identifier in the path of its home -- so an account is an entity when its
 * home is /home/<eid>, whatever it is called. Naming the account by the
 * identifier was tried and dropped, and so was the alias that went with it.
 */
#include "pgpid.h"

#include <pwd.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ROWS 256

struct account {
    uid_t uid;
    char user[64];
    char eid[64];
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
        "An account is one when its home is /home/<eid>, whatever it is called.\n"
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

        struct account *row = &rows[n++];
        memset(row, 0, sizeof *row);
        row->uid = pw->pw_uid;
        snprintf(row->user, sizeof row->user, "%s", pw->pw_name);
        snprintf(row->home, sizeof row->home, "%s", pw->pw_dir);
        snprintf(row->gecos, sizeof row->gecos, "%s", pw->pw_gecos);
        row->admin = in_admin_group(pw->pw_name);

        /* The identifier lives in the path of the home, and on an account
         * named by one -- which some still are -- in the name as well. */
        const char *at = strrchr(pw->pw_dir, '/');
        if (!(at && eid_at(at + 1, row->eid, sizeof row->eid)))
            eid_at(pw->pw_name, row->eid, sizeof row->eid);
    }
    endpwent();

    static const char *const COLUMNS[] = {
        "eid", "user", "uid", "admin", "home",
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
            rows[i].user,
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
