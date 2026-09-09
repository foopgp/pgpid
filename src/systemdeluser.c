/* Close a local account.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The counterpart of system_adduser, and it has to know the same thing: an
 * entity holds up to two entries with one number. Removing the one that was
 * typed and leaving the other is how an alias outlives its account and hands
 * somebody else's files to whoever gets the number next -- so both go.
 *
 * The home stays unless it is asked for. An account can be opened again from
 * the certificate; what its home held cannot, and a secret key that never
 * left it goes with it.
 */
#include "pgpid.h"

#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmpx.h>

#define MAX_NAMES 8

/** An account tool, by argument list. No argument may be NULL but the last. */
static int tool(const char *first, ...)
{
    const char *argv[8];
    size_t n = 0;
    argv[n++] = first;
    va_list ap;
    va_start(ap, first);
    const char *a;
    while ((a = va_arg(ap, const char *)) && n < 7)
        argv[n++] = a;
    va_end(ap);
    argv[n] = NULL;
    return pgpid_run_program(argv, NULL, NULL);
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " system_deluser [OPTIONS]... USER|EID\n"
        "\n"
        "Remove a local account. Administrator rights required (sudo).\n"
        "An entity may hold two entries with one number -- its identifier and a\n"
        "shorter alias -- and both go, whichever of the two was named.\n"
        "\n"
        "The home directory is kept unless '--remove-home' says otherwise: an\n"
        "account can be opened again from the certificate, what its home held\n"
        "cannot, and a secret key that never left it would go with it.\n"
        "\n"
        "OPTIONS:\n"
        "  -r, --remove-home           Remove the home directory and its contents too\n"
        "  -a, --alias-only            Remove only the name given, and leave the account\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"),
            PGPID_NAME);
}

/** Is somebody sitting in one of these names right now? */
static bool anyone_in(const char *const *names, size_t n)
{
    const char *su = getenv("SUDO_USER");
    for (size_t i = 0; i < n; i++)
        if (su && !strcmp(su, names[i]))
            return true;
    bool here = false;
    setutxent();
    const struct utmpx *u;
    while ((u = getutxent()) && !here)
        if (u->ut_type == USER_PROCESS)
            for (size_t i = 0; i < n; i++)
                if (!strncmp(u->ut_user, names[i], sizeof u->ut_user)) {
                    here = true;
                    break;
                }
    endutxent();
    return here;
}

int pgpid_action_system_deluser(int argc, char **argv)
{
    bool remove_home = false, alias_only = false;
    const char *who = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-r") || !strcmp(a, "--remove-home")) {
            remove_home = true;
        } else if (!strcmp(a, "-a") || !strcmp(a, "--alias-only")) {
            alias_only = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", PGPID_NAME, PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("system_deluser");
            return PGPID_USAGE;
        } else if (!who) {
            who = a;
        }
    }

    if (!who) {
        pgpid_error(_("Error: Which account?"));
        usage(stderr);
        return PGPID_USAGE;
    }
    if (alias_only && remove_home) {
        pgpid_error(_("Error: '--alias-only' leaves the account, so its home is not to remove."));
        return PGPID_USAGE;
    }
    if (geteuid() != 0) {
        pgpid_error(_("Error: Closing an account needs administrator rights (sudo)."));
        return PGPID_FAIL;
    }

    char named[64];
    if (!pgpid_account_name(who, named, sizeof named)) {
        pgpid_error(_("Error: No account for '%s' on this system."), who);
        return PGPID_NOTHING;
    }
    const struct passwd *pw = getpwnam(named);
    if (!pw)
        return PGPID_NOTHING;
    uid_t uid = pw->pw_uid;
    char home[320];
    snprintf(home, sizeof home, "%s", pw->pw_dir);

    if (uid == 0) {
        pgpid_error(_("Error: '%s' is the administrator of this machine."), named);
        return PGPID_FAIL;
    }

    /* Every name the number answers to: the identifier and its alias. */
    static char names[MAX_NAMES][64];
    const char *list[MAX_NAMES];
    size_t n = 0;
    if (alias_only) {
        snprintf(names[n], sizeof names[0], "%s", named);
        list[n] = names[n];
        n++;
    } else {
        setpwent();
        const struct passwd *p;
        while ((p = getpwent()) && n < MAX_NAMES)
            if (p->pw_uid == uid) {
                snprintf(names[n], sizeof names[0], "%s", p->pw_name);
                list[n] = names[n];
                n++;
            }
        endpwent();
    }
    if (!n)
        return PGPID_NOTHING;

    if (anyone_in(list, n)) {
        pgpid_error(_("Error: '%s' is logged in; an account cannot be closed under its owner."),
                    named);
        return PGPID_FAIL;
    }

    if (alias_only) {
        char eid[64];
        if (pgpid_account_eid(pw, eid, sizeof eid) && !strcmp(eid, named)) {
            pgpid_error(_("Error: '%s' is the account itself, not an alias of it."), named);
            return PGPID_USAGE;
        }
    }

    /* The identifier last: it is the entry '--remove-home' hangs on, and the
     * aliases have to be gone before the home they point at. */
    size_t primary = 0;
    for (size_t i = 0; i < n; i++)
        if (pgpid_eid_body_is_sound(list[i]))
            primary = i;

    int ret = PGPID_OK;
    for (size_t pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < n; i++) {
            if ((pass == 0) == (i == primary))
                continue;
            bool last = (i == primary) && remove_home && !alias_only;
            if (last ? tool("userdel", "--remove", list[i], NULL)
                     : tool("userdel", list[i], NULL)) {
                pgpid_error(_("Error: '%s' could not be removed."), list[i]);
                ret = PGPID_FAIL;
                continue;
            }
            /* userdel takes the group with the entry when it is that entry's
             * own; a non-unique alias group is left standing, so it goes here. */
            const struct group *g = getgrnam(list[i]);
            if (g && g->gr_gid == uid)
                tool("groupdel", list[i], NULL);
            pgpid_error(_("Notice: '%s' is no longer an account here."), list[i]);
        }
    }

    if (!alias_only && !remove_home)
        pgpid_error(_("Notice: %s is left standing, and still belongs to %lu."),
                    home, (unsigned long)uid);
    return ret;
}
