/* Recomputing trust, from delegations somebody signed.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
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
        " trustdb local|export|import [OPTIONS]... [FINGERPRINT|OWNERTRUSTS.GPG]...\n"
        "\n"
        "Read and move the trust you place in others to certify.\n"
        "\n"
        "  local    What this machine says about the given certificates, or about\n"
        "           every one of them when none is named.\n"
        "  export   The same, signed, for others to replay. Writes to stdout.\n"
        "  import   Apply what others signed. Order is part of what it means:\n"
        "           a signer must already be valid when its turn comes.\n"
        "\n"
        "OPTIONS:\n"
        "  -r, --replace-to VALUE      local: set it instead of printing it — needs\n"
        "                              at least one fingerprint\n"
        "      --long                  local: also the identifier and main address\n"
        "      --export-file FILE      export: write there instead of stdout\n"
        "  -u, --use-privkey NAME|KEYID  export: sign with this key\n"
        "      --export-all            export: include ultimate and unknown too\n"
        "      --check                 recompute without asking about the rest\n"
        "      --update                recompute, asking about the rest\n"
        "  -q, --quiet                 Only errors and warnings\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"),
            PGPID_NAME);
}

/** The fingerprints this machine holds at ultimate: its anchors.
 *
 * Not "the keys whose secret we hold". A security key belonging to somebody
 * else, plugged in once, leaves a stub in the secret keyring — so holding a
 * secret says nothing about whose key it is. What says something is having
 * decided, here, that a key is ultimate; and that decision is only ever taken
 * by hand.
 *
 * gpg spells the rungs as digits in --export-ownertrust: 2 unknown, 3 never,
 * 4 marginal, 5 full, 6 ultimate. Measured against `trustdb local`, not
 * guessed from their order. */
static size_t local_anchors(char *raw, size_t rawsize, char *out[], size_t max)
{
    const char *argv[] = { "--export-ownertrust", NULL };
    if (pgpid_capture_engine(argv, raw, rawsize) <= 0)
        return 0;
    size_t n = 0;
    for (char *line = raw, *save; (line = strtok_r(line, "\n", &save)) && n < max;
         line = NULL) {
        if (!*line || *line == '#')
            continue;
        char *colon = strchr(line, ':');
        if (!colon || colon[1] != '6')
            continue;
        *colon = '\0';
        out[n++] = line;
    }
    return n;
}

struct delegation {
    const char *path;
    char signer[64];
    long signed_at;
    char *content;
};

static int one_key(gpgme_ctx_t ctx, const char *pattern, gpgme_key_t *out)
{
    gpgme_error_t err = gpgme_op_keylist_start(ctx, pattern, 0);
    if (err) {
        pgpid_gpgme_error(_("looking the certificate up"), err);
        return PGPID_FAIL;
    }
    gpgme_key_t first = NULL, extra = NULL;
    err = gpgme_op_keylist_next(ctx, &first);
    if (gpg_err_code(err) == GPG_ERR_EOF) {
        gpgme_op_keylist_end(ctx);
        pgpid_error(_("Error: No certificate matching '%s'."), pattern);
        return PGPID_NOTHING;
    }
    if (err) {
        gpgme_op_keylist_end(ctx);
        pgpid_gpgme_error(_("reading the certificate"), err);
        return PGPID_FAIL;
    }
    err = gpgme_op_keylist_next(ctx, &extra);
    gpgme_op_keylist_end(ctx);
    if (gpg_err_code(err) != GPG_ERR_EOF) {
        gpgme_key_unref(first);
        if (extra)
            gpgme_key_unref(extra);
        pgpid_error(_("Error: '%s' matches more than one certificate."), pattern);
        return PGPID_USAGE;
    }
    *out = first;
    return PGPID_OK;
}

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
static bool read_delegation(struct delegation *d, char *const own[], size_t nown,
                            bool quiet)
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
    size_t skipped = 0, capped = 0, nevers = 0;
    for (char *line = content, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        if (!*line || *line == '#')
            continue;

        /* An anchor is what the whole computation stands on. A referent
         * extends trust to others; it never redefines what we hold in
         * ourselves. Said aloud rather than dropped in silence: a file that
         * speaks about our anchors is worth knowing about. */
        bool anchor = false;
        for (size_t i = 0; i < nown; i++)
            if (!strncmp(line, own[i], strlen(own[i])))
                anchor = true;
        if (anchor) {
            skipped++;
            continue;
        }

        char kept[128];
        snprintf(kept, sizeof kept, "%s", line);
        char *colon = strchr(kept, ':');
        if (colon && colon[1]) {
            if (colon[1] == '3')
                nevers++;
            /* Full is as far as a delegation reaches. Ultimate says "this is
             * mine", and that is not something somebody else gets to say. */
            if (colon[1] > '5') {
                colon[1] = '5';
                capped++;
            }
        }
        strcat(d->content, kept);
        strcat(d->content, "\n");
    }

    if (!quiet) {
        if (skipped)
            pgpid_error(_("Info: %s: %zu line(s) about your own anchors, left alone."),
                        d->path, skipped);
        if (capped)
            pgpid_error(_("Info: %s: %zu line(s) beyond full, brought back to it."),
                        d->path, capped);
        if (nevers)
            pgpid_error(_("Info: %s: %zu key(s) it would have you trust for nothing."),
                        d->path, nevers);
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

static int do_local(int argc, char **argv)
{
    const char *value = NULL, *pattern = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-r") || !strcmp(a, "--replace-to")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a value."), a);
                return PGPID_USAGE;
            }
            value = argv[i];
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            if (i + 1 < argc)
                pattern = argv[i + 1];
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("trustdb");
            return PGPID_USAGE;
        } else {
            pattern = a;
            break;
        }
    }

    if (!pattern) {
        pgpid_error(_("Error: A fingerprint is required."));
        return PGPID_USAGE;
    }
    if (value) {
        if (pgpid_validity_from_word(value) < 0) {
            pgpid_error(_("Error: Unknown ownertrust value '%s'."), value);
            pgpid_error(_("Notice: One of undefined, never, marginal, full, ultimate."));
            return PGPID_USAGE;
        }
        /* The engine refuses this one, and it is right to: unknown is the
         * absence of a decision, not one more decision to take. */
        if (!strcmp(value, "unknown")) {
            pgpid_error(_("Error: 'unknown' cannot be set; it is what a certificate"));
            pgpid_error(_("Notice: no one has ruled on already reads as."));
            return PGPID_USAGE;
        }
    }

    gpgme_ctx_t ctx = NULL;
    gpgme_error_t err = pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL);
    if (err) {
        pgpid_gpgme_error(_("opening the engine"), err);
        return PGPID_FAIL;
    }

    gpgme_key_t key = NULL;
    int rc = one_key(ctx, pattern, &key);
    if (rc != PGPID_OK) {
        gpgme_release(ctx);
        return rc;
    }

    if (value) {
        err = gpgme_op_setownertrust(ctx, key, value);
        if (err) {
            pgpid_gpgme_error(_("setting the ownertrust"), err);
            gpgme_key_unref(key);
            gpgme_release(ctx);
            return PGPID_FAIL;
        }
        /* Read it back rather than echo what was asked: the engine is what
         * decides, and a write that did not take should not look like one
         * that did. */
        gpgme_key_unref(key);
        rc = one_key(ctx, pattern, &key);
        if (rc != PGPID_OK) {
            gpgme_release(ctx);
            return rc;
        }
    }

    static const char *const COLUMNS[] = { "credibility" };
    const char *values[] = { pgpid_validity_word(key->owner_trust) };
    pgpid_table_start(COLUMNS, 1);
    pgpid_table_row(values);
    pgpid_table_end();

    gpgme_key_unref(key);
    gpgme_release(ctx);
    return PGPID_OK;
}

static int do_import(int argc, char **argv)
{
    /* Silent by default: this is called from other programs — foodjis shells
     * out to it — and a prompt in a place with no terminal does not ask, it
     * hangs. A human who wants to be asked about the rest says --update. */
    bool interactive = false, quiet = false;
    const char *files[MAX_FILES];
    size_t nfiles = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--check")) {
            interactive = false;
        } else if (!strcmp(a, "--update")) {
            interactive = true;
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
            pgpid_try_help("trustdb");
            return PGPID_USAGE;
        } else if (nfiles < MAX_FILES) {
            files[nfiles++] = a;
        } else {
            pgpid_error(_("Error: Too many files at once."));
            return PGPID_USAGE;
        }
    }

    if (nfiles) {
        /* The anchor: what this machine holds at ultimate, whatever any
         * delegation says about it. */
        char ownraw[262144];
        char *own[512];
        size_t nown = local_anchors(ownraw, sizeof ownraw, own, 512);

        /* Without an anchor there is nothing for the delegations to hang
         * from: gpg would compute validity out of a chain with no first
         * link, and every verdict it returned would be meaningless. */
        if (!nown) {
            pgpid_error(_("Error: No key here is ultimate, so there is no anchor to "
                        "extend from."));
            pgpid_error(_("Notice: Mark your own certificate ultimate first: "
                        "%s trustdb local --replace-to ultimate FINGERPRINT"),
                        PGPID_NAME);
            return PGPID_FAIL;
        }

        struct delegation d[MAX_FILES];
        memset(d, 0, sizeof d);
        for (size_t i = 0; i < nfiles; i++) {
            d[i].path = files[i];
            if (!read_delegation(&d[i], own, nown, quiet))
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

    /* Recompute. --check takes the answers already on file; --update has gpg
     * ask about the keys nobody has ruled on yet. */
    const char *asking[] = { "--update-trustdb", NULL };
    const char *silent[] = { "--batch", "--check-trustdb", NULL };
    return pgpid_run_engine(interactive ? asking : silent) ? PGPID_FAIL : PGPID_OK;
}

/* One action, three verbs: they read and write the same thing, and share the
 * recomputation that has to follow any change to it. Splitting them meant
 * `--quiet` on one and not the other, and no place at all for `export`. */
int pgpid_action_trustdb(int argc, char **argv)
{
    if (argc < 2) {
        pgpid_error(_("Error: One of local, export or import is required."));
        pgpid_try_help("trustdb");
        return PGPID_USAGE;
    }

    const char *verb = argv[1];
    if (!strcmp(verb, "-h") || !strcmp(verb, "--help")) {
        usage(stdout);
        return PGPID_OK;
    }
    if (!strcmp(verb, "-V") || !strcmp(verb, "--version")) {
        printf("%s %s\n", argv[0], PGPID_VERSION);
        return PGPID_OK;
    }

    /* The verb comes first so that an option never has to be read twice to
     * know which one it belongs to. */
    if (!strcmp(verb, "local"))
        return do_local(argc - 1, argv + 1);
    if (!strcmp(verb, "import"))
        return do_import(argc - 1, argv + 1);
    if (!strcmp(verb, "export")) {
        pgpid_error(_("Error: 'export' is not written yet."));
        return PGPID_FAIL;
    }

    pgpid_error(_("Error: '%s' is not one of local, export or import."), verb);
    pgpid_try_help("trustdb");
    return PGPID_USAGE;
}
