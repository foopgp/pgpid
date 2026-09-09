/* Lay out a home directory for PGP ID use.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Five things, all of them by default, each refusable:
 *
 *   gnupg    the directories and their permissions, the certificate, the
 *            default key, and the credibility that makes it one's own
 *   systemd  the socket unit that points SSH_AUTH_SOCK at gpg-agent
 *   ssh      authorized_keys, from the certificate's authentication subkey --
 *            and only that one. The file is written, not appended to, which is
 *            the point: one identity, one key, nothing left from before that
 *            nobody remembers authorising. It does mean a second key somebody
 *            else relies on goes away, so the help says so.
 *   git      user.signingKey
 *   face     the avatar the certificate wears, as the account's picture
 *
 * For somebody else's home, this re-runs itself as them rather than writing
 * there as root: gpg leaves lock files behind, and a root-owned lock file in
 * another person's .gnupg is their problem for ever after.
 */
#include "pgpid.h"

#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct parts {
    bool gnupg, systemd, ssh, git, face;
};

static int run(const char *fmt, ...)
{
    char cmd[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    return system(cmd);
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " system_confhome [OPTIONS]... [USER|EID]\n"
        "\n"
        "Lay out a home directory for PGP ID use. Without an argument, your own.\n"
        "Somebody else's needs administrator rights, and is done as them rather than\n"
        "as root, so that nothing in their home ends up owned by somebody else.\n"
        "\n"
        "Everything is done unless refused:\n"
        "\n"
        "OPTIONS:\n"
        "      --no-gnupg              Leave ~/.gnupg alone: directories, default key,\n"
        "                              and the credibility that makes it one's own\n"
        "      --no-systemd            Leave the socket that points SSH_AUTH_SOCK at gpg-agent\n"
        "      --no-ssh                Leave ~/.ssh/authorized_keys alone. Otherwise the\n"
        "                              certificate's authentication subkey becomes the ONLY\n"
        "                              key authorised there: anything else is dropped\n"
        "      --no-git                Leave git's user.signingKey alone\n"
        "      --no-face               Leave ~/.face alone\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"),
            PGPID_NAME);
}

/* The certificate that carries this identifier, if the keyring holds one. */
static bool certificate_of_eid(const char *eid, char *fpr, size_t max)
{
    char pattern[128];
    snprintf(pattern, sizeof pattern, "UID:urn:eid:%s", eid);
    const char *pat[] = { pattern };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
    if (!kr)
        return false;
    bool found = false;
    if (pgpid_keys_count(kr)) {
        snprintf(fpr, max, "%s", pgpid_keys_at(kr, 0)->fpr);
        found = *fpr != '\0';
    }
    pgpid_keys_free(kr);
    return found;
}

int pgpid_action_system_confhome(int argc, char **argv)
{
    struct parts do_ = { true, true, true, true, true };
    const char *who = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--no-gnupg"))        do_.gnupg = false;
        else if (!strcmp(a, "--no-systemd")) do_.systemd = false;
        else if (!strcmp(a, "--no-ssh"))     do_.ssh = false;
        else if (!strcmp(a, "--no-git"))     do_.git = false;
        else if (!strcmp(a, "--no-face"))    do_.face = false;
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", PGPID_NAME, PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("system_confhome");
            return PGPID_USAGE;
        } else if (!who) {
            who = a;
        }
    }

    const struct passwd *me = getpwuid(getuid());
    const struct passwd *pw = who ? getpwnam(who) : me;

    /* An identifier names an account too, whether it is the account's name or
     * only the last part of its home. */
    if (!pw && who) {
        setpwent();
        const struct passwd *p;
        while ((p = getpwent())) {
            const char *base = strrchr(p->pw_dir, '/');
            if (!strcmp(p->pw_name, who) || (base && !strcmp(base + 1, who))) {
                pw = p;
                break;
            }
        }
        endpwent();
    }
    if (!pw) {
        pgpid_error(_("Error: No account for '%s' on this system."), who);
        return PGPID_NOTHING;
    }

    /* Somebody else's home: become them. Writing there as root leaves files
     * they do not own, and gpg's lock files are the worst of those. */
    if (me && pw->pw_uid != me->pw_uid) {
        if (geteuid() != 0) {
            pgpid_error(_("Error: Laying out '%s' home needs administrator rights."),
                        pw->pw_name);
            return PGPID_FAIL;
        }
        char flags[256] = "";
        if (!do_.gnupg)   strcat(flags, " --no-gnupg");
        if (!do_.systemd) strcat(flags, " --no-systemd");
        if (!do_.ssh)     strcat(flags, " --no-ssh");
        if (!do_.git)     strcat(flags, " --no-git");
        if (!do_.face)    strcat(flags, " --no-face");
        return run("su - '%s' -c '\"%s\" system_confhome%s'",
                   pw->pw_name, pgpid_self(), flags) ? PGPID_FAIL : PGPID_OK;
    }

    const char *home = pw->pw_dir;
    char eid[64] = "";
    const char *base = strrchr(home, '/');
    if (!pgpid_eid_body_is_sound(pw->pw_name) || !snprintf(eid, sizeof eid, "%s", pw->pw_name))
        if (base)
            snprintf(eid, sizeof eid, "%s", base + 1);
    if (!pgpid_eid_body_is_sound(eid)) {
        pgpid_error(_("Error: '%s' is not a PGP ID account: no identifier in its name"),
                    pw->pw_name);
        pgpid_error(_("Notice: nor in its home. '%s system_adduser --migrate' makes it one."),
                    PGPID_NAME);
        return PGPID_NOTHING;
    }

    char fpr[41];
    if (!certificate_of_eid(eid, fpr, sizeof fpr)) {
        pgpid_error(_("Error: No certificate here carries %s."), eid);
        pgpid_error(_("Notice: '%s cert_get %s' fetches it first."), PGPID_NAME, eid);
        return PGPID_NOTHING;
    }
    pgpid_error(_("Info: Laying out %s for %s."), home, fpr);

    int ret = PGPID_OK;

    if (do_.gnupg) {
        run("mkdir --parents '%s/.gnupg' '%s/.ssh'", home, home);
        run("chmod go-rwx '%s/.gnupg' '%s/.ssh'", home, home);
        if (run("printf 'default-key:0:\"%s\\n' | gpgconf --quiet --change-options gpg", fpr))
            ret = PGPID_FAIL;
        /* One key is one's own; anything else that claimed to be comes down a
         * step rather than being demoted to nothing. */
        run("gpg --export-ownertrust | awk -F: '/:6:/ {print $1}' "
            "| while read k ; do gpg --quiet --quick-set-ownertrust \"$k\" full ; done");
        run("gpg --quiet --quick-set-ownertrust '%s' ultimate", fpr);
    }

    if (do_.systemd) {
        if (access("/usr/lib/systemd/user/gpg-agent.socket", R_OK) == 0) {
            run("mkdir --parents '%s/.config/systemd/user/sockets.target.wants'", home);
            run("cp --force /usr/lib/systemd/user/gpg-agent.socket "
                "'%s/.config/systemd/user/sockets.target.wants/'", home);
        } else {
            pgpid_error(_("Notice: No gpg-agent.socket unit here; SSH_AUTH_SOCK is yours to set."));
        }
    }

    if (do_.ssh) {
        char stamp[16];
        time_t now = time(NULL);
        struct tm tm;
        gmtime_r(&now, &tm);
        strftime(stamp, sizeof stamp, "%Y-%m-%d", &tm);
        if (run("gpg --export-ssh-key '%s' | sed 's,$, %s pgpid %s,' > '%s/.ssh/authorized_keys'",
                fpr, stamp, fpr, home))
            ret = PGPID_FAIL;
        run("chmod go-rwx '%s/.ssh/authorized_keys'", home);
    }

    if (do_.git)
        if (run("git config --global user.signingKey '%s'", fpr))
            ret = PGPID_FAIL;

    if (do_.face) {
        /* cert_avatar writes the image into its working directory and prints
         * where. My first pass threw that away and copied nothing, then
         * announced there was no picture -- on a certificate that carries one.
         * The previous face is kept beside it: a portrait somebody chose is
         * not ours to drop silently. */
        char work[512], face[512];
        snprintf(work, sizeof work, "%s/.cache/pgpid", home);
        snprintf(face, sizeof face, "%s/.face", home);
        run("mkdir --parents '%s'", work);
        char cmd[1024];
        snprintf(cmd, sizeof cmd, "'%s' cert_avatar --workdir '%s' '%s' 2>/dev/null",
                 pgpid_self(), work, fpr);
        FILE *pipe = popen(cmd, "r");
        char path[512] = "";
        if (pipe) {
            if (fgets(path, sizeof path, pipe))
                path[strcspn(path, "\n")] = '\0';
            pclose(pipe);
        }
        if (*path && access(path, R_OK) == 0) {
            if (access(face, R_OK) == 0)
                run("cp --force '%s' '%s.previous'", face, face);
            if (run("cp --force '%s' '%s'", path, face))
                ret = PGPID_FAIL;
            else
                pgpid_error(_("Info: The certificate's picture is now %s."), face);
        } else {
            pgpid_error(_("Notice: The certificate wears no picture; %s left alone."), face);
        }
    }

    return ret;
}
