/* Recomputing trust, from delegations somebody signed.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * An ownertrust file says "these are the people I would follow". Signed, it
 * says who is saying it, and that is the whole mechanism: trust is extended
 * along a chain of signatures each of which can be checked, rather than
 * handed down by a list somebody has to be trusted to maintain.
 *
 * Two rules make the chain hold rather than merely look like it holds.
 *
 * The order of the files matters, because each one's signer must already be
 * valid when it is applied — file N+1 sees what file N did. Applying them in
 * any other order breaks the chain silently, which is worse than refusing.
 *
 * And the anchor is inviolable: the user's own keys are stripped out of every
 * delegation before it is applied. A referent may extend trust to others; it
 * may not redefine what somebody thinks of themselves. Without that, one
 * signed file could quietly demote the very key the whole chain hangs from.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_FILES 32
#define YEAR_SECONDS 31536000L

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " update_trustdb [OPTIONS]... [OWNERTRUST.GPG]...\n"
        "\n"
        "Recompute GnuPG's trust database, after applying the delegations the\n"
        "given files carry.\n"
        "\n"
        "Every file must be a signed OpenPGP message, and its signer must already\n"
        "be valid when its turn comes — which is why the order of the files is\n"
        "part of what they mean. Whatever they say about your own keys is\n"
        "ignored: somebody may extend trust to others, not redefine yours.\n"
        "\n"
        "OPTIONS:\n"
        "      --batch                 Recompute without asking about the remaining keys\n"
        "  -q, --quiet                 Only errors and warnings\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"),
            PGPID_NAME);
}

struct delegation {
    const char *path;
    char signer[64];
    long signed_at;
    char *content;
};

/** Is this line `FINGERPRINT:TRUST:`, the only thing an ownertrust file holds? */
static bool looks_like_ownertrust(const char *line)
{
    size_t hex = 0;
    const char *p = line;
    for (; *p && *p != ':'; p++, hex++)
        if (!strchr("0123456789ABCDEFabcdef", *p))
            return false;
    if (hex < 16 || *p != ':')
        return false;
    p++;
    size_t digits = 0;
    for (; *p && *p != ':'; p++, digits++)
        if (*p < '0' || *p > '9')
            return false;
    return digits >= 1 && digits <= 3 && *p == ':';
}

/** The current ownertrust, its comments dropped and its lines sorted. */
static char *export_ownertrust(void)
{
    static char raw[1048576];
    const char *argv[] = { "--export-ownertrust", NULL };
    if (pgpid_capture_engine(argv, raw, sizeof raw) < 0)
        return NULL;

    char *lines[8192];
    size_t n = 0;
    for (char *l = raw, *save; (l = strtok_r(l, "\n", &save)) && n < 8192; l = NULL)
        if (*l && *l != '#')
            lines[n++] = l;
    for (size_t i = 1; i < n; i++)          /* small and nearly sorted already */
        for (size_t k = i; k && strcmp(lines[k - 1], lines[k]) > 0; k--) {
            char *t = lines[k - 1];
            lines[k - 1] = lines[k];
            lines[k] = t;
        }
    size_t total = 1;
    for (size_t i = 0; i < n; i++)
        total += strlen(lines[i]) + 1;
    char *out = malloc(total);
    if (!out)
        return NULL;
    *out = '\0';
    for (size_t i = 0; i < n; i++) {
        strcat(out, lines[i]);
        strcat(out, "\n");
    }
    return out;
}

/** Read a signed file: its content, who signed it, and when. */
static bool read_delegation(struct delegation *d, char *const own[], size_t nown)
{
    char status_path[] = "/tmp/pgpid-status-XXXXXX";
    int fd = mkstemp(status_path);
    if (fd < 0) {
        pgpid_error(_("Error: Cannot make a temporary file."));
        return false;
    }
    close(fd);

    static char content[1048576];
    const char *argv[] = { "--status-file", status_path, "--decrypt", d->path, NULL };
    int got = pgpid_capture_engine(argv, content, sizeof content);

    char status[65536] = "";
    FILE *f = fopen(status_path, "r");
    if (f) {
        size_t n = fread(status, 1, sizeof status - 1, f);
        status[n] = '\0';
        fclose(f);
    }
    unlink(status_path);

    if (got < 0) {
        pgpid_error(_("Error: Cannot read or verify %s (missing, not signed, or bad "
                    "signature?)."), d->path);
        return false;
    }

    /* VALIDSIG says the signature checked out; its third word is the signer's
     * fingerprint and its fifth the moment it was made. */
    *d->signer = '\0';
    d->signed_at = 0;
    for (char *line = status, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        const char *at = strstr(line, "VALIDSIG");
        if (!at)
            continue;
        char fpr[128] = "";
        long created = 0;
        if (sscanf(at, "VALIDSIG %127s %*s %ld", fpr, &created) >= 1) {
            snprintf(d->signer, sizeof d->signer, "%s", fpr);
            d->signed_at = created;
        }
        break;
    }
    if (!*d->signer) {
        pgpid_error(_("Error: %s carries no verifiable signature (signer key missing?)."),
                    d->path);
        return false;
    }

    long now = (long)time(NULL);
    if (d->signed_at > now) {
        char when[32];
        struct tm tm;
        time_t t = (time_t)d->signed_at;
        gmtime_r(&t, &tm);
        strftime(when, sizeof when, "%Y-%m-%d", &tm);
        pgpid_error(_("Warning: %s is signed in the future (%s) — is the local clock "
                    "right?"), d->path, when);
    } else if (d->signed_at && d->signed_at < now - YEAR_SECONDS) {
        char when[32];
        struct tm tm;
        time_t t = (time_t)d->signed_at;
        gmtime_r(&t, &tm);
        strftime(when, sizeof when, "%Y-%m-%d", &tm);
        pgpid_error(_("Warning: %s carries a delegation older than a year (%s)."),
                    d->path, when);
    }

    /* Checked before the anchor is stripped, so that a file which only speaks
     * about our own keys — legitimately stripped to nothing — is not mistaken
     * for garbage. */
    bool any = false;
    char copy[1048576];
    snprintf(copy, sizeof copy, "%s", content);
    for (char *line = copy, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        if (!*line || *line == '#')
            continue;
        if (!looks_like_ownertrust(line)) {
            pgpid_error(_("Error: %s is not a valid ownertrust file."), d->path);
            return false;
        }
        any = true;
    }
    if (!any) {
        pgpid_error(_("Error: %s is not a valid ownertrust file."), d->path);
        return false;
    }

    size_t room = strlen(content) + 2;
    d->content = malloc(room);
    if (!d->content)
        return false;
    *d->content = '\0';
    for (char *line = content, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        bool ours = false;
        for (size_t i = 0; i < nown; i++)
            if (!strncmp(line, own[i], strlen(own[i])))
                ours = true;
        if (ours)
            continue;
        strcat(d->content, line);
        strcat(d->content, "\n");
    }
    return true;
}

/** Is this key valid enough for what it signed to be applied? */
static bool signer_is_valid(const char *fpr)
{
    char listing[262144];
    char pattern[80];
    snprintf(pattern, sizeof pattern, "0x%.63s", fpr);
    const char *argv[] = { "--with-colons", "--list-keys", pattern, NULL };
    if (pgpid_capture_engine(argv, listing, sizeof listing) <= 0)
        return false;
    for (char *line = listing, *save; (line = strtok_r(line, "\n", &save)); line = NULL)
        if (!strncmp(line, "uid:", 4) && (line[4] == 'f' || line[4] == 'u'))
            return true;
    return false;
}

/** What changed, as the lines that left and the lines that arrived. */
static void report_change(const char *before, const char *after)
{
    char b[1048576], a[1048576];
    snprintf(b, sizeof b, "%s", before);
    snprintf(a, sizeof a, "%s", after);
    pgpid_error(_("Info: ownertrust changes:"));
    for (char *line = b, *save; (line = strtok_r(line, "\n", &save)); line = NULL)
        if (!strstr(after, line))
            pgpid_error(_("  - %s"), line);
    for (char *line = a, *save; (line = strtok_r(line, "\n", &save)); line = NULL)
        if (!strstr(before, line))
            pgpid_error(_("  + %s"), line);
}

int pgpid_action_update_trustdb(int argc, char **argv)
{
    bool batch = false, quiet = false;
    const char *files[MAX_FILES];
    size_t nfiles = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--batch")) {
            batch = true;
        } else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            quiet = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("update_trustdb");
            return PGPID_USAGE;
        } else if (nfiles < MAX_FILES) {
            files[nfiles++] = a;
        } else {
            pgpid_error(_("Error: Too many files at once."));
            return PGPID_USAGE;
        }
    }

    if (nfiles) {
        /* The anchor: our own keys, whatever any delegation says about them. */
        char ownraw[262144];
        const char *ownargv[] = { "--list-secret-keys", "--with-colons", NULL };
        char *own[512];
        size_t nown = 0;
        if (pgpid_capture_engine(ownargv, ownraw, sizeof ownraw) > 0)
            for (char *line = ownraw, *save; (line = strtok_r(line, "\n", &save)) && nown < 512; line = NULL) {
                if (strncmp(line, "fpr:", 4))
                    continue;
                /* The fingerprint is field 10, so nine colons in. Landing on
                 * the wrong field yields an empty string, and an empty
                 * anchor matches every line there is — which strips each
                 * delegation to nothing and reports it as already applied. */
                char *at = line;
                unsigned field = 1;
                for (; *at && field < 10; at++)
                    if (*at == ':')
                        field++;
                char *endcolon = strchr(at, ':');
                if (endcolon)
                    *endcolon = '\0';
                if (field == 10 && strlen(at) >= 16)
                    own[nown++] = at;
            }

        struct delegation d[MAX_FILES];
        memset(d, 0, sizeof d);
        for (size_t i = 0; i < nfiles; i++) {
            d[i].path = files[i];
            if (!read_delegation(&d[i], own, nown))
                return PGPID_FAIL;
        }

        char *before = export_ownertrust();
        if (!before)
            return PGPID_FAIL;

        /* Would anything change? Later files override earlier ones for the
         * same fingerprint, so the answer is the merged set, not the sum. */
        bool differs = false;
        for (size_t i = 0; i < nfiles && !differs; i++) {
            char *copy = strdup(d[i].content);
            if (!copy)
                continue;
            for (char *line = copy, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
                if (!*line || *line == '#')
                    continue;
                if (!strstr(before, line)) {
                    differs = true;
                    break;
                }
            }
            free(copy);
        }

        if (!differs) {
            if (!quiet)
                pgpid_error(_("Info: The delegations are already applied — ownertrust "
                            "left unchanged."));
        } else {
            char dir[512], path[600];
            const char *home = pgpid_homedir;
            if (!home)
                home = getenv("GNUPGHOME");
            if (!home)
                home = ".";
            snprintf(dir, sizeof dir, "%s/ownertrust-backups", home);
            mkdir(dir, 0700);
            time_t now = time(NULL);
            struct tm tm;
            gmtime_r(&now, &tm);
            char stamp[32];
            strftime(stamp, sizeof stamp, "%Y%m%dT%H%M%SZ", &tm);
            snprintf(path, sizeof path, "%s/ownertrust-%s.txt", dir, stamp);
            FILE *bk = fopen(path, "w");
            if (bk) {
                fputs(before, bk);
                fclose(bk);
                pgpid_error(_("Notice: Current ownertrust backed up in %s."), path);
            } else {
                pgpid_error(_("Warning: Cannot write the backup %s — going ahead "
                            "anyway would leave no way back. Stopping."), path);
                free(before);
                return PGPID_FAIL;
            }

            for (size_t i = 0; i < nfiles; i++) {
                if (!signer_is_valid(d[i].signer)) {
                    pgpid_error(_("Error: Delegation chain broken: the signer of %s is "
                                "not (yet) valid."), d[i].path);
                    free(before);
                    return PGPID_FAIL;
                }
                const char *imp[] = { "--import-ownertrust", NULL };
                if (pgpid_run_engine_input(imp, d[i].content)) {
                    pgpid_error(_("Error: gpg would not import the delegation from %s."),
                                d[i].path);
                    free(before);
                    return PGPID_FAIL;
                }
            }

            if (!quiet) {
                char *after = export_ownertrust();
                if (after) {
                    report_change(before, after);
                    free(after);
                }
            }
            pgpid_error(_("Notice: To restore the previous trust: "
                        "gpg --import-ownertrust %s"), path);
        }
        free(before);
    }

    /* Recompute. --batch takes the answers already on file; without it gpg
     * asks about the keys nobody has said anything about yet, which is the
     * point of running this by hand. */
    const char *interactive[] = { "--update-trustdb", NULL };
    const char *silent[] = { "--batch", "--check-trustdb", NULL };
    return pgpid_run_engine(batch ? silent : interactive) ? PGPID_FAIL : PGPID_OK;
}
