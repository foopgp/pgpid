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
 * The account is named by the local part of the entity's address -- what
 * people already call each other by -- and the identifier lives in the path of
 * the home, which is where every reader takes it from. Naming the account by
 * the identifier was tried and dropped: it is not a name anybody says out
 * loud, and it dragged in a second entry as an alias, a length limit and two
 * kinds of collision. One entry, one name, one number.
 *
 * The home is left as the system made it. Laying it out for PGP ID use is
 * 'system_confhome', and the two stay separate on purpose: whoever opens an
 * account is not always whoever furnishes it.
 *
 * Debian's adduser has a policy of its own -- NAME_REGEX in adduser.conf,
 * stricter than shadow's and configurable -- and refuses a name over 32 bytes.
 * useradd is called directly, which is also where the shell libraries ended up.
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
    char user[64];     /* the login name: the local part of the address */
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
        "  - the name of the account (the local part of the entity's address)\n"
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
        "  -u, --user USER          Name the account USER instead of the local part\n"
        "                           of its address\n"
        "  -f, --fingerprint FPR    Take the certificate from the local keyring\n"
        "                           (Default: the one of SUDO_USER, else root)\n"
        "  -c, --if-certified       Refuse an entity that is not certified\n"
        "                           (Default: by the local SUDO_USER, else root)\n"
        "  -F, --from USER          Another reference user for --fingerprint and --if-certified\n"
        "  -m, --migrate USER       Move a local account to the PGP ID standard: its home\n"
        "                           becomes /home/<eid> and its numbers come from the\n"
        "                           identifier. The user must not be logged in (so cannot\n"
        "                           be SUDO_USER)\n"
        "  -s, --sweep              With --migrate, look through every mounted filesystem\n"
        "                           for files the old account owned, not only its home and\n"
        "                           the usual places\n"
        "  -h, --help               Print this help and exit\n"
        "  -V, --version            Print the version and exit\n"
        "\n"
        "An account that is already there is answered with 11 rather than a plain\n"
        "failure: a caller wanting to say so needs to tell it apart from the rest.\n"
        "\n"
        "Two people whose addresses share a local part cannot both have an account\n"
        "of that name: the second is refused, and --user gives it another. The\n"
        "identifier still settles the numbers, which do not collide.\n"),
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

/**
 * The login name an address gives.
 *
 * Its local part, which is what people already call each other by. A '+' tag
 * is a routing hint and not part of anybody's name, so it is dropped, and so
 * is anything shadow would refuse -- including a leading digit, dash or dot,
 * which it will not take at all.
 */
static void user_from_address(const char *addr, char *out, size_t max)
{
    size_t n = 0;
    for (const char *p = addr; *p && *p != '@' && *p != '+' && n + 1 < max; p++)
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
            || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.')
            out[n++] = *p;
    out[n] = '\0';
    size_t skip = 0;
    while (out[skip] && (out[skip] == '-' || out[skip] == '.'
                         || (out[skip] >= '0' && out[skip] <= '9')))
        skip++;
    if (skip)
        memmove(out, out + skip, n - skip + 1);
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
    const char *password = NULL, *passfrom = NULL, *wanted_user = NULL;
    const char *want_fpr = NULL, *from = NULL, *migrate = NULL, *file = NULL;
    bool if_certified = false, everywhere = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char **takes = NULL;
        if (!strcmp(a, "-p") || !strcmp(a, "--password"))            takes = &password;
        else if (!strcmp(a, "-P") || !strcmp(a, "--passfrom"))       takes = &passfrom;
        else if (!strcmp(a, "-u") || !strcmp(a, "--user"))           takes = &wanted_user;
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
    if (wanted_user && !name_is_usable(wanted_user)) {
        pgpid_error(_("Error: '%s' is not a usable account name."), wanted_user);
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
        /* A name in the account database, not an identifier: whoever is asked
         * to vouch for this is somebody with a keyring on this machine. */
        if (!getpwnam(from)) {
            pgpid_error(_("Error: No account named '%s' on this system."), from);
            return PGPID_NOTHING;
        }
        snprintf(ref, sizeof ref, "%s", from);
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
        if (!(oldpw = getpwnam(migrate))) {
            pgpid_error(_("Error: No account named '%s' on this system."), migrate);
            return PGPID_NOTHING;
        }
        snprintf(oldname, sizeof oldname, "%s", migrate);
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

    /* The name: what was asked for, or the local part of the address the one
     * rule picked. An entity with no usable address has no name to take, and
     * nobody but the caller can invent one. */
    if (wanted_user)
        snprintf(e.user, sizeof e.user, "%s", wanted_user);
    else
        user_from_address(e.email, e.user, sizeof e.user);
    if (!name_is_usable(e.user)) {
        pgpid_error(_("Error: No account name comes out of '%s'."),
                    *e.email ? e.email : e.eid);
        pgpid_error(_("Notice: '--user NAME' gives one."));
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
    if (clash && strcmp(clash->pw_name, e.user)
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
            pgpid_error(_("Notice: No password set; login stays closed until 'passwd %s'."), e.user);
    } else {
        pgpid_error(_("Notice: No password given and nothing to ask with; login stays closed."));
        pgpid_error(_("Notice: '--password' or '--passfrom FILE' sets one, 'passwd %s' too."), e.user);
    }

    char home[320];
    snprintf(home, sizeof home, "/home/%s", e.eid);
    char gecos[1024];
    gecos_line(&e, gecos, sizeof gecos);
    int ret = PGPID_OK;

    char number[24];
    snprintf(number, sizeof number, "%lu", (unsigned long)e.uid);
    const struct passwd *standing = getpwnam(e.user);
    if (oldpw) {
        /* Moving an account: it keeps its files, its number changes, and it
         * takes the name its address gives -- unless it already had it. */
        uid_t was = oldpw->pw_uid;
        char oldhome[320], oldgroup[64] = "";
        snprintf(oldhome, sizeof oldhome, "%s", oldpw->pw_dir);
        const struct group *g = getgrgid(oldpw->pw_gid);
        if (g)
            snprintf(oldgroup, sizeof oldgroup, "%s", g->gr_name);
        pgpid_error(_("Info: Moving '%s' to %s."), oldname, e.user);
        if (strcmp(oldname, e.user)) {
            if (tool(NULL, "usermod", "--login", e.user,
                     "--home", home, "--move-home", oldname, NULL)) {
                pgpid_error(_("Error: '%s' could not be renamed; nothing was changed."), oldname);
                if (scratched)
                    run("rm --recursive --force '%s'", scratch);
                return PGPID_FAIL;
            }
        } else if (strcmp(oldhome, home)) {
            tool(NULL, "usermod", "--home", home, "--move-home", e.user, NULL);
        }
        if (was != e.uid) {
            if (*oldgroup)
                tool(NULL, "groupmod", "--non-unique", "--gid", number, oldgroup, NULL);
            tool(NULL, "usermod", "--non-unique",
                 "--uid", number, "--gid", number, e.user, NULL);
        }
        tool(NULL, "usermod", "--comment", gecos, e.user, NULL);
        /* The group follows the account: a name short enough to be a login is
         * short enough to be a group. */
        if (*oldgroup && strcmp(oldgroup, e.user))
            tool(NULL, "groupmod", "--new-name", e.user, oldgroup, NULL);
        /* usermod chowns the home and nothing else; a file the account owns
         * anywhere else would keep a number that is now somebody else's. */
        if (was != e.uid)
            sweep_ownership(home, was, &e, everywhere);
        run("chown --no-dereference --recursive %lu:%lu '%s'",
            (unsigned long)e.uid, (unsigned long)e.uid, home);
    } else if (standing) {
        char its[64] = "";
        pgpid_account_eid(standing, its, sizeof its);
        if (strcmp(its, e.eid)) {
            /* Two people whose addresses share a local part. The name is what
             * every other program holds an account by, so the second is
             * refused rather than given a number on the end that nobody could
             * read back to a person -- and the identifier still settles the
             * numbers, which do not collide. */
            pgpid_error(_("Error: '%s' is already the account of %s here."),
                        e.user, *its ? its : standing->pw_name);
            pgpid_error(_("Notice: '--user NAME' gives this one another name."));
            if (scratched)
                run("rm --recursive --force '%s'", scratch);
            return PGPID_FAIL;
        }
        pgpid_error(_("Error: %s already has an account here."), e.eid);
        pgpid_error(_("Notice: '--migrate %s' brings an existing one up to date."), e.user);
        if (scratched)
            run("rm --recursive --force '%s'", scratch);
        return PGPID_EXISTS;
    } else {
        char groups[256];
        hardware_groups(groups, sizeof groups);
        /* A group of its own, named like the account: groupadd takes a login
         * name as it stands. --non-unique on both, because the number comes
         * from the identifier and another account may already hold it. */
        if (tool(NULL, "groupadd", "--non-unique", "--gid", number, e.user, NULL)) {
            pgpid_error(_("Error: No group could be made for %s."), e.user);
            if (scratched)
                run("rm --recursive --force '%s'", scratch);
            return PGPID_FAIL;
        }
        const char *av[24];
        size_t n = 0;
        av[n++] = "useradd";
        av[n++] = "--non-unique";
        av[n++] = "--uid";          av[n++] = number;
        av[n++] = "--gid";          av[n++] = number;
        if (*groups) {
            av[n++] = "--groups";   av[n++] = groups;
        }
        av[n++] = "--home-dir";     av[n++] = home;
        av[n++] = "--create-home";
        av[n++] = "--comment";      av[n++] = gecos;
        av[n++] = e.user;
        av[n] = NULL;
        if (pgpid_run_program(av, NULL, NULL)) {
            tool(NULL, "groupdel", e.user, NULL);
            pgpid_error(_("Error: No account could be opened for %s."), e.user);
            if (scratched)
                run("rm --recursive --force '%s'", scratch);
            return PGPID_FAIL;
        }
        /* usermod does this and useradd does not, which costs an evening the
         * first time: the home is made with the group the system picked. */
        run("chown --no-dereference --recursive %lu:%lu '%s'",
            (unsigned long)e.uid, (unsigned long)e.uid, home);
    }

    if (*pass) {
        /* Down chpasswd's standard input: an argument is readable by anybody
         * running ps, and an environment variable by anybody who can read
         * /proc for this user. */
        char line[512];
        snprintf(line, sizeof line, "%s:%s\n", e.user, pass);
        if (tool(line, "chpasswd", NULL))
            ret = PGPID_FAIL;
        memset(line, 0, sizeof line);
    }
    memset(pass, 0, sizeof pass);

    pgpid_homedir = seed_from;
    seed_keyring(e.user, e.fpr);
    pgpid_homedir = saved_home;

    if (scratched)
        run("rm --recursive --force '%s'", scratch);

    pgpid_error(_("Notice: %s now has an account here as '%s' (%lu), home %s."),
                e.eid, e.user, (unsigned long)e.uid, home);
    pgpid_error(_("Notice: '%s system_confhome %s' lays that home out for PGP ID use."),
                PGPID_NAME, e.user);
    return ret;
}
