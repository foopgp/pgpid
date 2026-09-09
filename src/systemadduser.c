/* Open a local account for a PGP ID entity.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * A certificate settles what a Unix account needs: the identifier names it,
 * the identifier gives its number, and the vCard properties it carries fill
 * the GECOS fields. Nothing here is invented, which is what lets the same
 * account be opened again on another machine from the certificate alone.
 *
 * An entity may hold two entries: one named by its identifier -- that one is
 * the account -- and one shorter alias beside it, same numbers, same home,
 * differing only in the first field. The alias is a convenience for typing,
 * never an identity.
 *
 * The home is left as the system made it. Laying it out for PGP ID use is
 * 'system_confhome', and the two stay separate on purpose: whoever opens an
 * account is not always whoever furnishes it.
 *
 * What shadow allows shapes all of this, and it was measured rather than
 * assumed (Debian 13, shadow 4.17.4):
 *
 *   - a name has to match [a-z_][a-z0-9_.-]*, and an identifier is base64url,
 *     so it holds capitals. useradd and usermod take --badname and accept it;
 *     groupadd and groupmod have no such option and refuse outright. So the
 *     group of a new account is made by useradd itself and renumbered after,
 *     and a group being moved keeps the name it had.
 *   - --badname prints "deprecated and will be removed". The day it goes,
 *     naming an account by its identifier goes with it.
 *   - Debian's adduser refuses a name over 32 bytes. A u4 is 38, so adduser
 *     is out of the question here and useradd is called directly -- which is
 *     also what the shell libraries ended up doing, for their own reasons.
 *
 * Every one of these tools is driven through its argument list and never
 * through a shell line: the name, the address and the GECOS fields all come
 * out of somebody else's certificate, and a shell would read what is in them.
 */
#include "pgpid.h"

#include <grp.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utmpx.h>

/* What a desktop account needs to reach the hardware in front of it. Only the
 * ones this system actually has are handed out -- a server has few of them. */
static const char *const EXTRA_GROUPS[] = {
    "cdrom", "floppy", "audio", "dip", "video", "plugdev",
    "netdev", "scanner", "bluetooth", "lpadmin", "crontab",
};

/* Where a file owned by the old account is likely to sit, outside its home.
 * Not a guess at everything -- '--sweep' is for that. */
static const char *const KNOWN_PLACES[] = {
    "/var/mail", "/var/spool/cron", "/var/spool/mail", "/tmp", "/var/tmp",
};

struct entity {
    char eid[64];
    char fpr[41];
    char name[256];
    char email[256];
    char phone[128];
    char address[256];
    uid_t uid;
};

/* A shell line, for the few commands whose every word is ours: no value read
 * from a certificate ever reaches this one. */
static int run(const char *fmt, ...)
{
    char cmd[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    return system(cmd);
}

/** An account tool, by argument list. No argument may be NULL but the last. */
static int tool(const char *stdin_text, ...)
{
    const char *argv[24];
    size_t n = 0;
    va_list ap;
    va_start(ap, stdin_text);
    const char *a;
    while ((a = va_arg(ap, const char *)) && n < 23)
        argv[n++] = a;
    va_end(ap);
    argv[n] = NULL;
    return pgpid_run_program(argv, stdin_text, NULL);
}

/**
 * Does this tool take '--badname'?
 *
 * Asked rather than assumed: shadow before 4.13 only warned about a name it
 * disliked and has no such option, and passing it there would turn a working
 * call into a usage error. Only useradd and usermod answer yes.
 */
static bool takes_badname(const char *program)
{
    static const char *asked[4];
    static bool answer[4];
    static size_t n = 0;
    for (size_t i = 0; i < n; i++)
        if (!strcmp(asked[i], program))
            return answer[i];
    char cmd[128];
    snprintf(cmd, sizeof cmd, "%s --badname --help >/dev/null 2>&1", program);
    bool takes = system(cmd) == 0;
    if (n < 4) {
        asked[n] = program;
        answer[n] = takes;
        n++;
    }
    return takes;
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " system_adduser [OPTIONS]... [FILE.asc]\n"
        "\n"
        "Add a PGP ID entity as a user of this system. Administrator rights required (sudo).\n"
        "Needs a PGP ID certificate, as an argument or on standard input.\n"
        "What is missing is asked for.\n"
        "\n"
        "On a Unix system, PGP ID settles:\n"
        "  - the name of the account (its identifier)\n"
        "  - the GECOS fields (email, phone, address)\n"
        "  - the user and group numbers (UID and GID)\n"
        "  - the path of the home directory (/home/<eid>)\n"
        "\n"
        "The home itself is laid out by '%s system_confhome'.\n"
        "\n"
        "OPTIONS:\n"
        "  -p, --password PASSWORD  User password (for this computer)\n"
        "  -P, --passfrom FILE      Read the user password from the first line of FILE\n"
        "                           (eg: fifo, tmpfs, /dev/stdin, …)\n"
        "  -u, --useralias USER     Give the account this name too, beside its identifier.\n"
        "                           One alias, no more (optional)\n"
        "  -f, --fingerprint FPR    Take the certificate from the local keyring\n"
        "                           (Default: the one of SUDO_USER, else root)\n"
        "  -c, --if-certified       Refuse an entity that is not certified\n"
        "                           (Default: by the local SUDO_USER, else root)\n"
        "  -F, --from USER|EID      Another reference user for --fingerprint and --if-certified\n"
        "  -m, --migrate USER|EID   Move a local account to the PGP ID standard.\n"
        "                           The name given is kept as the alias, unless --useralias\n"
        "                           says otherwise. The user must not be logged in\n"
        "                           (so cannot be SUDO_USER)\n"
        "  -s, --sweep              With --migrate, look through every mounted filesystem\n"
        "                           for files the old account owned, not only its home and\n"
        "                           the usual places\n"
        "  -h, --help               Print this help and exit\n"
        "  -V, --version            Print the version and exit\n"),
            PGPID_NAME, PGPID_NAME);
}

/** A name the account databases will take: IEEE Std 1003.1-2001, and no digit first. */
static bool name_is_usable(const char *s)
{
    if (!*s || (*s >= '0' && *s <= '9') || *s == '-')
        return false;
    for (const char *p = s; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
              || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.'))
            return false;
    return true;
}

/** A GECOS field holds no comma and no colon: those are its separators. */
static void gecos_safe(const char *in, char *out, size_t max)
{
    size_t o = 0;
    bool space = true;                  /* true: swallow a leading space */
    for (const char *p = in; *p && o + 1 < max; p++) {
        char c = (*p == ',' || *p == ':' || *p == ';' || *p == '\n' || *p == '\t') ? ' ' : *p;
        if (c == ' ' && space)
            continue;
        space = (c == ' ');
        out[o++] = c;
    }
    while (o && out[o - 1] == ' ')
        o--;
    out[o] = '\0';
}

/** The name in front of `Name <address>`, without a trailing `(comment)`. */
static void plain_name(const char *uid, char *out, size_t max)
{
    const char *open = strrchr(uid, '<');
    size_t n = open ? (size_t)(open - uid) : strlen(uid);
    while (n && (uid[n - 1] == ' ' || uid[n - 1] == '\t'))
        n--;
    if (n && uid[n - 1] == ')') {
        const char *paren = memrchr(uid, '(', n);
        if (paren && paren > uid) {
            n = (size_t)(paren - uid);
            while (n && (uid[n - 1] == ' ' || uid[n - 1] == '\t'))
                n--;
        }
    }
    char raw[512];
    snprintf(raw, sizeof raw, "%.*s", (int)(n < sizeof raw ? n : sizeof raw - 1), uid);
    gecos_safe(raw, out, max);
}

/**
 * Everything the certificate says about the entity.
 *
 * The address comes from the one rule the whole program uses, so that these
 * fields say the same thing as a card, a signature or a lookup would.
 */
static bool read_entity(const char *pattern, struct entity *e)
{
    /* No pattern: the keyring holds the certificate that was just handed over
     * and nothing else, so everything in it is the answer. */
    const char *pat[] = { pattern };
    struct pgpid_keyring *kr = pgpid_keys_load(pattern ? pat : NULL, pattern ? 1 : 0, 0);
    if (!kr)
        return false;
    if (!pgpid_keys_count(kr)) {
        pgpid_keys_free(kr);
        return false;
    }
    const struct pgpid_key *k = pgpid_keys_at(kr, 0);
    memset(e, 0, sizeof *e);
    snprintf(e->fpr, sizeof e->fpr, "%s", k->fpr);

    unsigned count = 0;
    char *eid = pgpid_eid_of_key(k, &count, false);
    if (eid) {
        snprintf(e->eid, sizeof e->eid, "%s", eid);
        free(eid);
    }
    pgpid_preferred_address(k, e->email, sizeof e->email);

    for (size_t i = 0; i < k->nuid; i++) {
        char prop[32];
        const char *v = pgpid_uid_property(k->uid[i].text, prop, sizeof prop);
        if (!v || !*v)
            continue;
        if (!strcmp(prop, "FN"))
            gecos_safe(v, e->name, sizeof e->name);
        else if (!strcmp(prop, "TEL") && !*e->phone)
            gecos_safe(v, e->phone, sizeof e->phone);
        else if (!strcmp(prop, "ADR") && !*e->address)
            gecos_safe(v, e->address, sizeof e->address);
    }
    /* No FN uid: the name is in front of the address of the uid the address
     * rule picked -- the same uid, so the two agree. */
    if (!*e->name) {
        struct pgpid_uid light[64];
        size_t n = 0;
        for (size_t i = 0; i < k->nuid && n < 64; i++) {
            snprintf(light[n].text, sizeof light[0].text, "%s", k->uid[i].text);
            light[n].validity = k->uid[i].validity;
            light[n].created = k->uid[i].created;
            n++;
        }
        const struct pgpid_uid *pick = pgpid_preferred_uid(light, n);
        if (pick)
            plain_name(pick->text, e->name, sizeof e->name);
    }
    pgpid_keys_free(kr);
    return *e->eid != '\0';
}

/** Does this certificate stand for the reference keyring? */
static bool is_certified(const char *fpr)
{
    const char *pat[] = { fpr };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
    if (!kr)
        return false;
    bool stands = false;
    if (pgpid_keys_count(kr)) {
        const struct pgpid_key *k = pgpid_keys_at(kr, 0);
        for (size_t i = 0; i < k->nuid && !stands; i++)
            if (pgpid_uid_stands(k->uid[i].validity))
                stands = true;
    }
    pgpid_keys_free(kr);
    return stands;
}

/** Is somebody sitting in this account right now? */
static bool is_logged_in(const char *name)
{
    const char *su = getenv("SUDO_USER");
    if (su && !strcmp(su, name))
        return true;
    bool here = false;
    setutxent();
    const struct utmpx *u;
    while ((u = getutxent()))
        if (u->ut_type == USER_PROCESS && !strncmp(u->ut_user, name, sizeof u->ut_user)) {
            here = true;
            break;
        }
    endutxent();
    return here;
}

/** The supplementary groups this system actually has, comma separated. */
static void hardware_groups(char *out, size_t max)
{
    *out = '\0';
    for (size_t i = 0; i < sizeof EXTRA_GROUPS / sizeof *EXTRA_GROUPS; i++) {
        if (!getgrnam(EXTRA_GROUPS[i]))
            continue;
        size_t n = strlen(out);
        snprintf(out + n, max - n, "%s%s", n ? "," : "", EXTRA_GROUPS[i]);
    }
}

/**
 * Put the certificate where its owner will look for it.
 *
 * The account is opened with the certificate in hand; nobody else will have
 * it, and a workshop has no network. system_confhome needs it there.
 */
static void seed_keyring(const char *account, const char *fpr)
{
    size_t len = 0;
    unsigned char *raw = pgpid_export_key(fpr, false, &len);
    if (!raw || !len) {
        free(raw);
        pgpid_error(_("Warning: Could not hand %s its own certificate."), account);
        return;
    }
    char path[] = "/tmp/pgpid-seed-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        free(raw);
        return;
    }
    bool written = write(fd, raw, len) == (ssize_t)len;
    close(fd);
    free(raw);
    chmod(path, 0644);              /* a public certificate, read by another user */
    if (written) {
        run("su - '%s' -c 'gpg --batch --quiet --import %s' >/dev/null 2>&1",
            account, path);
        /* gpg leaves an agent running, and a process belonging to the account
         * is what makes userdel refuse to remove it later -- which is how this
         * was found: the account opened, and would not close. */
        run("su - '%s' -c 'gpgconf --kill all' >/dev/null 2>&1", account);
    }
    unlink(path);
}

/* GECOS holds five comma-separated fields, and finger named them: full name,
 * room, work phone, home phone, and the rest. An address is where somebody is,
 * so it goes where the room did -- and the address rule fills the last. */
static void gecos_line(const struct entity *e, char *out, size_t max)
{
    snprintf(out, max, "%s,%s,,%s,%s", e->name, e->address, e->phone, e->email);
}

/** Give the account a second name: same numbers, same home, first field apart. */
static int add_alias(const struct entity *e, const char *alias, const char *shell)
{
    if (getpwnam(alias)) {
        pgpid_error(_("Warning: '%s' is already an account here; no alias made."), alias);
        return PGPID_OK;
    }
    char gecos[1024], number[24], home[320];
    gecos_line(e, gecos, sizeof gecos);
    snprintf(number, sizeof number, "%lu", (unsigned long)e->uid);
    snprintf(home, sizeof home, "/home/%s", e->eid);
    /* An alias is a name a person types, so it is a name shadow already
     * takes: groupadd needs no talking round for this one. A group of that
     * name already carrying the account's number is the same group, not a
     * clash -- an account closed while something still held it leaves one. */
    const struct group *g = getgrnam(alias);
    bool group_here = g && g->gr_gid == e->uid;
    if ((!group_here && tool(NULL, "groupadd", "--non-unique", "--gid", number, alias, NULL))
     || tool(NULL, "useradd", takes_badname("useradd") ? "--badname" : "--non-unique",
             "--non-unique", "--uid", number, "--gid", number, "--no-create-home",
             "--home-dir", home, "--shell", shell, "--comment", gecos, alias, NULL)) {
        pgpid_error(_("Warning: The account stands, but '%s' could not be added beside it."),
                    alias);
        return PGPID_FAIL;
    }
    return PGPID_OK;
}

/** Hand the files the old account owned to the new number. */
static void sweep_ownership(const char *home, uid_t old, const struct entity *e, bool everywhere)
{
    if (everywhere) {
        pgpid_error(_("Info: Looking through every mounted filesystem for files of %lu."),
                    (unsigned long)old);
        run("find / -xdev -uid %lu -exec chown --no-dereference %lu:%lu {} + 2>/dev/null",
            (unsigned long)old, (unsigned long)e->uid, (unsigned long)e->uid);
        return;
    }
    char places[512] = "";
    for (size_t i = 0; i < sizeof KNOWN_PLACES / sizeof *KNOWN_PLACES; i++) {
        if (access(KNOWN_PLACES[i], F_OK))
            continue;
        size_t n = strlen(places);
        snprintf(places + n, sizeof places - n, " '%s'", KNOWN_PLACES[i]);
    }
    run("find '%s'%s -uid %lu -exec chown --no-dereference %lu:%lu {} + 2>/dev/null",
        home, places, (unsigned long)old, (unsigned long)e->uid, (unsigned long)e->uid);
}

int pgpid_action_system_adduser(int argc, char **argv)
{
    const char *password = NULL, *passfrom = NULL, *alias = NULL;
    const char *want_fpr = NULL, *from = NULL, *migrate = NULL, *file = NULL;
    bool if_certified = false, everywhere = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char **takes = NULL;
        if (!strcmp(a, "-p") || !strcmp(a, "--password"))            takes = &password;
        else if (!strcmp(a, "-P") || !strcmp(a, "--passfrom"))       takes = &passfrom;
        else if (!strcmp(a, "-u") || !strcmp(a, "--useralias"))      takes = &alias;
        else if (!strcmp(a, "-f") || !strcmp(a, "--fingerprint"))    takes = &want_fpr;
        else if (!strcmp(a, "-F") || !strcmp(a, "--from"))           takes = &from;
        else if (!strcmp(a, "-m") || !strcmp(a, "--migrate"))        takes = &migrate;
        else if (!strcmp(a, "-c") || !strcmp(a, "--if-certified"))   { if_certified = true; continue; }
        else if (!strcmp(a, "-s") || !strcmp(a, "--sweep"))          { everywhere = true; continue; }
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
            pgpid_try_help("system_adduser");
            return PGPID_USAGE;
        } else {
            file = a;
            continue;
        }
        if (++i >= argc) {
            pgpid_error(_("Error: '%s' wants a value."), a);
            return PGPID_USAGE;
        }
        *takes = argv[i];
    }

    if (everywhere && !migrate) {
        pgpid_error(_("Error: '--sweep' looks for what an old account owned; there is none without '--migrate'."));
        return PGPID_USAGE;
    }
    if (alias && !name_is_usable(alias)) {
        pgpid_error(_("Error: '%s' is not a usable account name."), alias);
        pgpid_error(_("Notice: Letters, digits, '_', '-' and '.', and not a digit first."));
        return PGPID_USAGE;
    }
    if (geteuid() != 0) {
        pgpid_error(_("Error: Opening an account needs administrator rights (sudo)."));
        return PGPID_FAIL;
    }

    /* The reference keyring: whose trust decides, and where a fingerprint is
     * looked up. Under sudo that is the person who typed it, not root. */
    char ref[64] = "";
    if (from) {
        if (!pgpid_account_name(from, ref, sizeof ref)) {
            pgpid_error(_("Error: No account for '%s' on this system."), from);
            return PGPID_NOTHING;
        }
    } else {
        const char *su = getenv("SUDO_USER");
        snprintf(ref, sizeof ref, "%s", (su && *su) ? su : "root");
    }
    const struct passwd *refpw = getpwnam(ref);
    if (!refpw) {
        pgpid_error(_("Error: No account for '%s' on this system."), ref);
        return PGPID_NOTHING;
    }
    char refring[512];
    snprintf(refring, sizeof refring, "%s/.gnupg", refpw->pw_dir);

    /* The account being moved, if any, settled before anything is read: its
     * own identifier may be where the certificate is found. */
    char oldname[64] = "";
    const struct passwd *oldpw = NULL;
    if (migrate) {
        if (!pgpid_account_name(migrate, oldname, sizeof oldname)
            || !(oldpw = getpwnam(oldname))) {
            pgpid_error(_("Error: No account for '%s' on this system."), migrate);
            return PGPID_NOTHING;
        }
        if (is_logged_in(oldname)) {
            pgpid_error(_("Error: '%s' is logged in; an account cannot be moved under its owner."),
                        oldname);
            return PGPID_FAIL;
        }
    }

    /* The certificate, from wherever it is: a file, the reference keyring, the
     * account being moved, or standard input. */
    char scratch[] = "/tmp/pgpid-adduser-XXXXXX";
    bool scratched = false;
    const char *saved_home = pgpid_homedir;
    char pattern[128] = "";

    if (want_fpr) {
        pgpid_homedir = refring;
        snprintf(pattern, sizeof pattern, "%s", want_fpr);
    } else if (file || !isatty(STDIN_FILENO)) {
        if (!mkdtemp(scratch)) {
            pgpid_error(_("Error: Cannot make a temporary keyring."));
            return PGPID_FAIL;
        }
        scratched = true;
        pgpid_homedir = scratch;
        const char *import[] = { "--batch", "--quiet", "--import", file, NULL };
        int failed = file ? pgpid_run_engine(import)
                          : run("gpg --homedir '%s' --batch --quiet --import", scratch);
        if (failed) {
            pgpid_error(_("Error: No certificate could be read from %s."),
                        file ? file : _("standard input"));
            pgpid_homedir = saved_home;
            run("rm --recursive --force '%s'", scratch);
            return PGPID_FAIL;
        }
    } else if (oldpw) {
        char eid[64];
        if (!pgpid_account_eid(oldpw, eid, sizeof eid)) {
            pgpid_error(_("Error: '%s' carries no identifier, so its certificate is unknown."),
                        oldname);
            pgpid_error(_("Notice: Name it with '--fingerprint', or hand the certificate over."));
            return PGPID_NOTHING;
        }
        pgpid_homedir = refring;
        snprintf(pattern, sizeof pattern, "UID:urn:eid:%s", eid);
    } else {
        pgpid_error(_("Error: Which certificate? A file, '--fingerprint', or standard input."));
        pgpid_try_help("system_adduser");
        return PGPID_USAGE;
    }

    struct entity e;
    bool read = read_entity(*pattern ? pattern : NULL, &e);
    if (scratched && read) {
        /* Read in the scratch keyring, judged in the reference one. */
        pgpid_homedir = refring;
    }
    bool certified = read && if_certified && is_certified(e.fpr);
    pgpid_homedir = saved_home;

    if (!read) {
        pgpid_error(_("Error: No PGP ID certificate there: none found, or none carrying an identifier."));
        if (scratched)
            run("rm --recursive --force '%s'", scratch);
        return PGPID_NOTHING;
    }
    if (if_certified && !certified) {
        pgpid_error(_("Error: %s is not certified for %s."), e.eid, ref);
        pgpid_error(_("Notice: '%s certify %s' says so, once it is true."), PGPID_NAME, e.fpr);
        if (scratched)
            run("rm --recursive --force '%s'", scratch);
        return PGPID_FAIL;
    }
    if (!pgpid_uid_number(e.eid, &e.uid)) {
        pgpid_error(_("Error: No account number comes out of %s."), e.eid);
        if (scratched)
            run("rm --recursive --force '%s'", scratch);
        return PGPID_FAIL;
    }

    /* The certificate has to reach its owner from wherever it was read. */
    const char *seed_from = scratched ? scratch : refring;

    /* A number already handed out elsewhere. Two accounts sharing one is not
     * what keeps them apart -- the encryption does -- so this is said, not
     * refused. Either entity can mint a u5 to step out of the way. */
    const struct passwd *clash = getpwuid(e.uid);
    if (clash && strcmp(clash->pw_name, e.eid)
        && (!oldpw || clash->pw_uid != oldpw->pw_uid)) {
        pgpid_error(_("Warning: %lu is already '%s' here; %s takes the same number."),
                    (unsigned long)e.uid, clash->pw_name, e.eid);
    }

    char pass[256] = "";
    if (passfrom) {
        FILE *f = fopen(passfrom, "r");
        if (!f || !fgets(pass, sizeof pass, f)) {
            pgpid_error(_("Error: Nothing to read in %s."), passfrom);
            if (f)
                fclose(f);
            if (scratched)
                run("rm --recursive --force '%s'", scratch);
            return PGPID_FAIL;
        }
        fclose(f);
        pass[strcspn(pass, "\r\n")] = '\0';
    } else if (password) {
        snprintf(pass, sizeof pass, "%s", password);
    } else if (isatty(STDIN_FILENO)) {
        char again[256] = "";
        if (pgpid_ask_secret(_("Password for this computer: "), pass, sizeof pass)
            && pgpid_ask_secret(_("Once more: "), again, sizeof again)
            && strcmp(pass, again))
            *pass = '\0';
        if (!*pass)
            pgpid_error(_("Notice: No password set; login stays closed until 'passwd %s'."), e.eid);
    } else {
        pgpid_error(_("Notice: No password given and nothing to ask with; login stays closed."));
        pgpid_error(_("Notice: '--password' or '--passfrom FILE' sets one, 'passwd %s' too."), e.eid);
    }

    char home[320];
    snprintf(home, sizeof home, "/home/%s", e.eid);
    char gecos[1024];
    gecos_line(&e, gecos, sizeof gecos);
    const char *shell = "/bin/sh";
    int ret = PGPID_OK;

    char number[24];
    snprintf(number, sizeof number, "%lu", (unsigned long)e.uid);
    const char *bad = takes_badname("usermod") ? "--badname" : "--non-unique";

    if (oldpw) {
        /* Moving an account: it keeps its files, its number changes, and the
         * name it had becomes the alias unless another was asked for. */
        uid_t was = oldpw->pw_uid;
        char oldhome[320], oldgroup[64] = "";
        snprintf(oldhome, sizeof oldhome, "%s", oldpw->pw_dir);
        const struct group *g = getgrgid(oldpw->pw_gid);
        if (g)
            snprintf(oldgroup, sizeof oldgroup, "%s", g->gr_name);
        if (oldpw->pw_shell && *oldpw->pw_shell)
            shell = oldpw->pw_shell;
        if (!alias && strcmp(oldname, e.eid))
            alias = oldname;

        pgpid_error(_("Info: Moving '%s' to %s."), oldname, e.eid);
        if (strcmp(oldname, e.eid)) {
            if (tool(NULL, "usermod", bad, "--login", e.eid,
                     "--home", home, "--move-home", oldname, NULL)) {
                pgpid_error(_("Error: '%s' could not be renamed; nothing was changed."), oldname);
                if (scratched)
                    run("rm --recursive --force '%s'", scratch);
                return PGPID_FAIL;
            }
        } else if (strcmp(oldhome, home)) {
            tool(NULL, "usermod", bad, "--home", home, "--move-home", e.eid, NULL);
        }
        if (was != e.uid) {
            if (*oldgroup)
                tool(NULL, "groupmod", "--non-unique", "--gid", number, oldgroup, NULL);
            tool(NULL, "usermod", bad, "--non-unique",
                 "--uid", number, "--gid", number, e.eid, NULL);
        }
        tool(NULL, "usermod", bad, "--comment", gecos, e.eid, NULL);
        /* groupmod has no --badname and will not rename a group to something
         * holding capitals, so the group an account already had keeps its
         * name. That name is the alias, which is where it belongs anyway. */
        if (*oldgroup && strcmp(oldgroup, e.eid))
            pgpid_error(_("Notice: The group stays '%s' (%lu): shadow names no group after an identifier."),
                        oldgroup, (unsigned long)e.uid);
        /* usermod chowns the home and nothing else; a file the account owns
         * anywhere else would keep a number that is now somebody else's. */
        if (was != e.uid)
            sweep_ownership(home, was, &e, everywhere);
        run("chown --no-dereference --recursive %lu:%lu '%s'",
            (unsigned long)e.uid, (unsigned long)e.uid, home);
    } else if (getpwnam(e.eid)) {
        pgpid_error(_("Error: %s already has an account here."), e.eid);
        pgpid_error(_("Notice: '--migrate %s' brings an existing one up to date."), e.eid);
        if (scratched)
            run("rm --recursive --force '%s'", scratch);
        return PGPID_FAIL;
    } else {
        char groups[256];
        hardware_groups(groups, sizeof groups);
        /* useradd makes the group itself, because groupadd will not: a name
         * with capitals is refused there and there is no telling it otherwise.
         * The number it picks for that group is the next free one rather than
         * the account's, so it is put right on the line after -- and until
         * then the account is the only member, so nothing else sees it. */
        const char *av[24];
        size_t n = 0;
        av[n++] = "useradd";
        if (takes_badname("useradd"))
            av[n++] = "--badname";
        av[n++] = "--user-group";
        av[n++] = "--non-unique";
        av[n++] = "--uid";          av[n++] = number;
        if (*groups) {
            av[n++] = "--groups";   av[n++] = groups;
        }
        av[n++] = "--home-dir";     av[n++] = home;
        av[n++] = "--create-home";
        av[n++] = "--comment";      av[n++] = gecos;
        av[n++] = e.eid;
        av[n] = NULL;
        if (pgpid_run_program(av, NULL, NULL)) {
            pgpid_error(_("Error: No account could be opened for %s."), e.eid);
            if (scratched)
                run("rm --recursive --force '%s'", scratch);
            return PGPID_FAIL;
        }
        if (tool(NULL, "groupmod", "--non-unique", "--gid", number, e.eid, NULL))
            pgpid_error(_("Warning: The group of %s did not take the account's number."), e.eid);
        /* The shell is whatever this system hands out; the alias has to get
         * the same one, so it is read back rather than guessed. */
        const struct passwd *made = getpwnam(e.eid);
        if (made && made->pw_shell && *made->pw_shell)
            shell = made->pw_shell;
        /* usermod does this and useradd does not, which costs an evening the
         * first time: the home is made with the group the system picked. */
        run("chown --no-dereference --recursive %lu:%lu '%s'",
            (unsigned long)e.uid, (unsigned long)e.uid, home);
    }

    if (alias && strcmp(alias, e.eid) && add_alias(&e, alias, shell))
        ret = PGPID_FAIL;

    if (*pass) {
        /* Down chpasswd's standard input: an argument is readable by anybody
         * running ps, and an environment variable by anybody who can read
         * /proc for this user. One password per name in the shadow file, so
         * the alias needs it too or it is a name that cannot log in. */
        char line[512];
        snprintf(line, sizeof line, "%s:%s\n", e.eid, pass);
        if (tool(line, "chpasswd", NULL))
            ret = PGPID_FAIL;
        if (alias && strcmp(alias, e.eid) && getpwnam(alias)) {
            snprintf(line, sizeof line, "%s:%s\n", alias, pass);
            tool(line, "chpasswd", NULL);
        }
        memset(line, 0, sizeof line);
    }
    memset(pass, 0, sizeof pass);

    pgpid_homedir = seed_from;
    seed_keyring(e.eid, e.fpr);
    pgpid_homedir = saved_home;

    if (scratched)
        run("rm --recursive --force '%s'", scratch);

    pgpid_error(_("Notice: %s now has an account here (%lu), home %s."),
                e.eid, (unsigned long)e.uid, home);
    pgpid_error(_("Notice: '%s system_confhome %s' lays that home out for PGP ID use."),
                PGPID_NAME, e.eid);
    return ret;
}
