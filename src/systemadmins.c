/* The local administrators: who has root through the sudo group.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Listing needs nothing; adding or removing needs root. Nobody may remove
 * themselves: an administrator who takes away their own last right locks the
 * machine's administration behind a door only another administrator can open,
 * and on a single-admin machine there is no other administrator.
 *
 * sudo is only recommended by this package, not required. Without it there is
 * no sudo group and this action has nothing to talk about -- it says so rather
 * than inventing one.
 */
#include "pgpid.h"

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ADMIN_GROUP "sudo"

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " system_admins [OPTIONS]...\n"
        "\n"
        "List, add or remove local administrators (root power through the '"
        ADMIN_GROUP
        "'\n"
        "group). Adding or removing needs administrator rights. Nobody is allowed to\n"
        "remove themselves.\n"
        "\n"
        "OPTIONS:\n"
        "  -a, --add USER              Add a user to the administrators. May be repeated\n"
        "  -r, --remove USER           Remove a user from them. May be repeated\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"),
            PGPID_NAME);
}

/* Who is asking: the person behind sudo when there is one, the account
 * otherwise. This is the one nobody may remove. */
static const char *asking(void)
{
    const char *who = getenv("SUDO_USER");
    if (who && *who)
        return who;
    const struct passwd *pw = getpwuid(getuid());
    return pw ? pw->pw_name : "";
}

static int gpasswd(const char *flag, const char *user)
{
    char cmd[512];
    /* The user name is checked against the account database before it reaches
     * here, so it is a name and not a sentence. */
    snprintf(cmd, sizeof cmd, "gpasswd %s '%s' " ADMIN_GROUP " >&2", flag, user);
    return system(cmd);
}

int pgpid_action_system_admins(int argc, char **argv)
{
    const char *add[32], *remove[32];
    size_t nadd = 0, nremove = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if ((!strcmp(a, "-a") || !strcmp(a, "--add")) && i + 1 < argc) {
            if (nadd < 32)
                add[nadd++] = argv[++i];
        } else if ((!strcmp(a, "-r") || !strcmp(a, "--remove")) && i + 1 < argc) {
            if (nremove < 32)
                remove[nremove++] = argv[++i];
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
            pgpid_try_help("system_admins");
            return PGPID_USAGE;
        }
    }

    if (!getgrnam(ADMIN_GROUP)) {
        pgpid_error(_("Error: This system has no '%s' group, so it has no administrators"),
                    ADMIN_GROUP);
        pgpid_error(_("Notice: to speak of. Installing sudo creates one."));
        return PGPID_NOTHING;
    }

    int ret = PGPID_OK;

    /* What was asked is judged before how it was asked: someone who names
     * themselves for removal should hear that, not hear about root. */
    for (size_t i = 0; i < nadd; i++)
        if (!getpwnam(add[i])) {
            pgpid_error(_("Error: No account named '%s'."), add[i]);
            return PGPID_NOTHING;
        }
    for (size_t i = 0; i < nremove; i++) {
        if (!getpwnam(remove[i])) {
            pgpid_error(_("Error: No account named '%s'."), remove[i]);
            return PGPID_NOTHING;
        }
        if (!strcmp(remove[i], asking())) {
            pgpid_error(_("Error: '%s' is you, and nobody removes their own "
                        "administrator rights."), remove[i]);
            return PGPID_USAGE;
        }
    }

    if ((nadd || nremove) && geteuid() != 0) {
        pgpid_error(_("Error: Adding or removing an administrator needs root."));
        return PGPID_FAIL;
    }

    for (size_t i = 0; i < nadd; i++)
        if (gpasswd("--add", add[i]))
            ret = PGPID_FAIL;
    for (size_t i = 0; i < nremove; i++)
        if (gpasswd("--delete", remove[i]))
            ret = PGPID_FAIL;

    /* Listed afterwards, always: what somebody wants after changing this is to
     * see what it is now. */
    const struct group *g = getgrnam(ADMIN_GROUP);
    static const char *const COLUMNS[] = { "admin" };
    pgpid_table_start(COLUMNS, 1);
    size_t shown = 0;
    for (char **m = g ? g->gr_mem : NULL; m && *m; m++) {
        const char *values[] = { *m };
        pgpid_table_row(values);
        shown++;
    }
    pgpid_table_end();

    if (!shown)
        pgpid_error(_("Notice: Nobody is an administrator of this system."));
    return ret;
}
