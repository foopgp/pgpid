/* Close a local account.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The counterpart of system_adduser: one account, one entry, one group.
 *
 * The home stays unless it is asked for. An account can be opened again from
 * the certificate; what its home held cannot, and a secret key that never
 * left it goes with it.
 */
#include "pgpid.h"

#include <dirent.h>
#include <grp.h>
#include <signal.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utmpx.h>


/**
 * Signal every process belonging to this number, and say how many.
 *
 * A signal of 0 asks without sending anything, which is how "is there still
 * something there" is answered without a second walk of /proc.
 */
static unsigned signal_processes(uid_t uid, int sig)
{
    DIR *d = opendir("/proc");
    if (!d)
        return 0;
    unsigned n = 0;
    const struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9')
            continue;
        char path[300];
        snprintf(path, sizeof path, "/proc/%s", e->d_name);
        struct stat st;
        if (stat(path, &st) || st.st_uid != uid)
            continue;
        pid_t pid = (pid_t)strtol(e->d_name, NULL, 10);
        if (pid > 1 && (!sig || !kill(pid, sig)))
            n++;
    }
    closedir(d);
    return n;
}

/**
 * End whatever is left running as this account, and wait for it to be gone.
 *
 * userdel refuses while a process belongs to the account, and one is often
 * left: a login shell leaves systemd a user manager behind, which outlives
 * the session that started it and shows in no utmp record. Somebody actually
 * sitting there was refused several steps ago; this ends the remains.
 *
 * terminate-user asks and returns at once, so asking is not enough -- the
 * first version of this asked and then watched userdel refuse anyway. Two
 * seconds is far longer than a user manager takes to go, and an account with
 * nothing running waits not at all.
 */
static void end_sessions(const char *name, uid_t uid)
{
    const char *argv[] = { "loginctl", "terminate-user", name, NULL };
    pgpid_run_program(argv, NULL, "/dev/null:stderr");
    for (unsigned i = 0; i < 10 && signal_processes(uid, 0); i++)
        usleep(100000);
    if (!signal_processes(uid, 0))
        return;

    /* loginctl reaches what is in the account's own slice, and a daemon
     * started for it from somebody else's session is not in one: the
     * gpg-agent system_confhome leaves in that home sits in the slice of
     * whoever ran it, and loginctl answers that the account is not even
     * logged in. So what is left is asked, then told. Somebody actually
     * sitting in the account was refused several steps ago; this is what
     * remains of it, and closing an account means closing it. */
    unsigned asked = signal_processes(uid, SIGTERM);
    for (unsigned i = 0; i < 20 && signal_processes(uid, 0); i++)
        usleep(100000);
    unsigned told = signal_processes(uid, SIGKILL);
    if (asked || told)
        pgpid_error(_("Notice: %u process of '%s' had to be ended (%u of them the hard way)."),
                    asked > told ? asked : told, name, told);
}

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
        "Remove a local account, and the group of its own. Administrator rights\n"
        "required (sudo).\n"
        "\n"
        "The home directory is kept unless '--remove-home' says otherwise: an\n"
        "account can be opened again from the certificate, what its home held\n"
        "cannot, and a secret key that never left it would go with it.\n"
        "\n"
        "OPTIONS:\n"
        "  -r, --remove-home           Remove the home directory and its contents too\n"
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
    bool remove_home = false;
    const char *who = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-r") || !strcmp(a, "--remove-home")) {
            remove_home = true;
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
    if (geteuid() != 0) {
        pgpid_error(_("Error: Closing an account needs administrator rights (sudo)."));
        return PGPID_FAIL;
    }

    /* USER or EID: the identifier still names an account, through the path of
     * its home, which is the one place it lives now. */
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

    const char *only[] = { named };
    if (anyone_in(only, 1)) {
        pgpid_error(_("Error: '%s' is logged in; an account cannot be closed under its owner."),
                    named);
        return PGPID_FAIL;
    }

    end_sessions(named, uid);
    if (remove_home ? tool("userdel", "--remove", named, NULL)
                    : tool("userdel", named, NULL)) {
        pgpid_error(_("Error: '%s' could not be removed."), named);
        pgpid_error(_("Notice: A process of its own still holds it; 'pkill --uid %lu' ends those."),
                    (unsigned long)uid);
        return PGPID_FAIL;
    }
    pgpid_error(_("Notice: '%s' is no longer an account here."), named);

    /* userdel takes the group with the entry when it is that entry's own; a
     * group made --non-unique is left standing, and leaving it behind is how
     * the next account to take the number inherits a membership nobody
     * granted it. */
    const struct group *g = getgrnam(named);
    if (g && g->gr_gid == uid && tool("groupdel", named, NULL))
        pgpid_error(_("Warning: The group '%s' (%lu) is still there."),
                    named, (unsigned long)uid);

    if (!remove_home)
        pgpid_error(_("Notice: %s is left standing, and still belongs to %lu."),
                    home, (unsigned long)uid);
    return PGPID_OK;
}
