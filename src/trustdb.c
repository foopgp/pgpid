/* Recomputing credibility, from delegations somebody signed.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * An ownertrust file says "these are the people I would follow". Signed, it
 * says who is saying it, and that is the whole mechanism: credibility is
 * extended along a chain of signatures each of which can be checked, rather
 * than handed down by a list somebody has to be trusted to maintain.
 *
 * Two rules make the chain hold rather than merely look like it holds.
 *
 * The order of the files matters, because each one's signer must already be
 * valid when it is applied — file N+1 sees what file N did. Applying them in
 * any other order breaks the chain silently, which is worse than refusing.
 *
 * And the anchor is inviolable: whatever is ultimate here is stripped out of
 * every delegation before it is applied. A referent may extend credibility to
 * others; it may not redefine what somebody thinks of themselves. Without
 * that, one signed file could quietly demote the very key the whole chain
 * hangs from. Ultimate, and not "the keys whose secret we hold": somebody
 * else's security key, plugged in once, leaves a stub behind.
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
        "Read and move the credibility you grant others to certify.\n"
        "\n"
        "  local    What this machine says about the given certificates, or about\n"
        "           every one of them when none is named.\n"
        "  export   The same, signed, for others to replay. Writes to stdout.\n"
        "  import   Apply what others signed, fetching the keys it names. Order\n"
        "           is part of what it means: a signer must already be valid when\n"
        "           its turn comes, and each file is weighed against what the\n"
        "           one before it decided.\n"
        "\n"
        "OPTIONS:\n"
        "  -r, --replace-to VALUE      local: set it instead of printing it — needs\n"
        "                              at least one fingerprint\n"
        "      --long                  local: also the identifier and main address\n"
        "      --check                 local, import: work the web of trust out again\n"
        "      --update                the same, asking about the keys nobody has ruled on\n"
        "      --export-file FILE      export: write there instead of stdout\n"
        "  -u, --use-privkey NAME|KEYID  export: sign with this key\n"
        "      --export-all            export: include ultimate and unknown too\n"
        "      --armor                 export: ASCII rather than binary, to commit it\n"
        "      --import-fetch-all      import: fetch or refresh every key it names,\n"
        "                              not only the ones missing here\n"
        "  -K, --keyservers SERVERS    import: ask these, space separated — empty\n"
        "                              for none\n"

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
/*
 * What this machine says about every key it has an opinion on.
 *
 * Read once and then kept in step by hand as the files are weighed, because
 * the order of the files is part of what they mean: file N+1 must be judged
 * against what file N decided, not against the state before either ran.
 */
struct local_table {
    /* Wide enough for a v5 fingerprint, which is sixty-four characters where
     * a v4 one is forty. */
    char (*fpr)[128];
    char *level;
    size_t n, cap;
};

static bool table_room(struct local_table *t, size_t want)
{
    if (want <= t->cap)
        return true;
    size_t cap = t->cap ? t->cap : 256;
    while (cap < want)
        cap *= 2;
    void *f = realloc(t->fpr, cap * sizeof *t->fpr);
    if (!f)
        return false;
    t->fpr = f;
    void *l = realloc(t->level, cap);
    if (!l)
        return false;
    t->level = l;
    t->cap = cap;
    return true;
}

static void table_free(struct local_table *t)
{
    free(t->fpr);
    free(t->level);
    t->fpr = NULL;
    t->level = NULL;
    t->n = t->cap = 0;
}

static bool local_levels(struct local_table *t)
{
    static char raw[1048576];
    const char *argv[] = { "--export-ownertrust", NULL };
    t->n = 0;
    if (pgpid_capture_engine(argv, raw, sizeof raw) <= 0)
        return false;
    for (char *line = raw, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        if (!*line || *line == '#')
            continue;
        char *colon = strchr(line, ':');
        if (!colon || !colon[1])
            continue;
        if (!table_room(t, t->n + 1))
            return false;
        t->level[t->n] = colon[1];
        *colon = '\0';
        snprintf(t->fpr[t->n], sizeof t->fpr[0], "%s", line);
        t->n++;
    }
    return true;
}

/* '2' — no opinion — for a key this machine has never ruled on. */
static char local_level(const struct local_table *t, const char *fpr)
{
    for (size_t i = 0; i < t->n; i++)
        if (!strcmp(t->fpr[i], fpr))
            return t->level[i];
    return '2';
}

static void local_set(struct local_table *t, const char *fpr, char level)
{
    for (size_t i = 0; i < t->n; i++)
        if (!strcmp(t->fpr[i], fpr)) {
            t->level[i] = level;
            return;
        }
    if (table_room(t, t->n + 1)) {
        snprintf(t->fpr[t->n], sizeof t->fpr[0], "%s", fpr);
        t->level[t->n++] = level;
    }
}

/* What becomes of one received line, given what this machine already says.
 * The level is capped in place. */
enum verdict { V_TAKE, V_ANCHOR, V_LOCAL_NEVER, V_NO_OPINION, V_UNDER_LOCAL };

static enum verdict weigh_line(char *level, char local, bool *capped)
{
    /* An anchor is what the whole computation stands on. A referent extends
     * credibility to others; it never redefines what we hold in ourselves. */
    if (local == '6')
        return V_ANCHOR;
    /* Having said never about somebody is a decision, and the strongest one
     * there is. Nobody else's file undoes it. */
    if (local == '3')
        return V_LOCAL_NEVER;
    /* An absence is not a decision. Letting it through would quietly unset
     * what somebody here had ruled. */
    if (*level < '3')
        return V_NO_OPINION;
    /* Full is as far as a delegation reaches. Ultimate says "this is mine",
     * and that is not something somebody else gets to say. */
    if (*level > '5') {
        *level = '5';
        *capped = true;
    }
    /* Downwards only for never, which is a warning worth hearing. Marginal
     * under a local full is a second opinion, not news. */
    if (*level == '4' && local == '5')
        return V_UNDER_LOCAL;
    return V_TAKE;
}

struct delegation {
    const char *path;
    char signer[64];
    long signed_at;
    char *content;
};

static int one_key(const char *pattern, struct pgpid_keyring **out)
{
    const char *pat[] = { pattern };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
    size_t n = pgpid_keys_count(kr);
    if (n == 0) {
        pgpid_keys_free(kr);
        pgpid_error(_("Error: No certificate matching '%s'."), pattern);
        return PGPID_NOTHING;
    }
    if (n > 1) {
        pgpid_keys_free(kr);
        pgpid_error(_("Error: '%s' matches more than one certificate."), pattern);
        return PGPID_USAGE;
    }
    *out = kr;
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

/** The current ownertrust, its comments dropped and its lines sorted. */
static char *export_ownertrust(void)
{
    static char raw[1048576];
    const char *argv[] = { "--export-ownertrust", NULL };
    if (pgpid_capture_engine(argv, raw, sizeof raw) < 0)
        return NULL;

    /* One slot per line of the export. Sized from the text rather than fixed:
     * this snapshot is what the backup is written from, and a backup missing
     * the lines past an arbitrary number is not a way back. */
    size_t room = 1;
    for (const char *c = raw; *c; c++)
        if (*c == '\n')
            room++;
    char **lines = calloc(room, sizeof *lines);
    if (!lines)
        return NULL;
    size_t n = 0;
    for (char *l = raw, *save; (l = strtok_r(l, "\n", &save)); l = NULL)
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
    if (!out) {
        free(lines);
        return NULL;
    }
    *out = '\0';
    for (size_t i = 0; i < n; i++) {
        strcat(out, lines[i]);
        strcat(out, "\n");
    }
    free(lines);
    return out;
}

/** Read a signed file: its content, who signed it, and when. */
static bool read_delegation(struct delegation *d)
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
    snprintf(d->content, room, "%s", content);
    return true;
}

/*
 * Every key the file speaks of, fetched if this keyring has not got it.
 *
 * Whether its line will be taken or left alone does not come into it: the
 * file explains a tree, and a certificate one cannot see is a branch one
 * cannot check. `all` refreshes the ones already here as well.
 */
static void fetch_named(const struct delegation *d, bool all,
                        const char *known, const char *keyservers)
{
    if (!keyservers || !*keyservers)
        return;

    char *copy = strdup(d->content);
    if (!copy)
        return;

    /* Gathered first, then asked for in one go per keyserver. A merged
     * registry names hundreds of keys, and a process apiece would be the
     * slowest part of the import by a long way. */
    /* As many as the file has lines, counted before asking for room: a
     * delegation naming more keys than a fixed array holds must not have the
     * rest quietly dropped. */
    size_t lines = 1;
    for (const char *c = copy; *c; c++)
        if (*c == '\n')
            lines++;
    const char **want = calloc(lines, sizeof *want);
    if (!want) {
        free(copy);
        return;
    }
    size_t n = 0;
    for (char *line = copy, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        if (!*line || *line == '#')
            continue;
        char *colon = strchr(line, ':');
        if (!colon)
            continue;
        *colon = '\0';
        if (!all && known && strstr(known, line))
            continue;
        want[n++] = line;
    }
    if (!n) {
        free(want);
        free(copy);
        return;
    }

    char *servers = strdup(keyservers);
    const char **argv = calloc(n + 5, sizeof *argv);
    if (!servers || !argv) {
        free(servers);
        free(argv);
        free(want);
        free(copy);
        return;
    }
    for (char *save = NULL, *ks = strtok_r(servers, " \t,", &save); ks;
         ks = strtok_r(NULL, " \t,", &save)) {
        size_t k = 0;
        argv[k++] = "--keyserver";
        argv[k++] = ks;
        argv[k++] = "--recv-keys";
        for (size_t i = 0; i < n; i++)
            argv[k++] = want[i];
        argv[k] = NULL;
        /* Failure is ordinary — a server down, a key absent — and it must not
         * stop the import: what the file says still stands. */
        pgpid_run_engine(argv);
    }
    free(argv);
    free(servers);
    free(want);
    free(copy);
}

/*
 * Weigh every line against what this machine already says, and keep what
 * survives. The table is moved on as we go, so the next file is judged
 * against this one's decisions rather than against the state before it.
 */
static void filter_delegation(struct delegation *d, struct local_table *table,
                              bool quiet)
{
    char *kept = malloc(strlen(d->content) + 2);
    if (!kept)
        return;
    *kept = '\0';

    size_t anchors = 0, refused = 0, capped = 0, nevers = 0, undercut = 0;
    char *copy = strdup(d->content);
    if (!copy) {
        free(kept);
        return;
    }
    for (char *line = copy, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        if (!*line || *line == '#')
            continue;
        char one[128];
        snprintf(one, sizeof one, "%s", line);
        char *colon = strchr(one, ':');
        if (!colon || !colon[1])
            continue;
        *colon = '\0';

        bool was_capped = false;
        char level = colon[1];
        switch (weigh_line(&level, local_level(table, one), &was_capped)) {
        case V_ANCHOR:       anchors++;  continue;
        case V_LOCAL_NEVER:  refused++;  continue;
        case V_NO_OPINION:              continue;
        case V_UNDER_LOCAL:  undercut++; continue;
        case V_TAKE:         break;
        }
        if (was_capped)
            capped++;
        if (level == '3')
            nevers++;

        colon[1] = level;
        *colon = ':';
        strcat(kept, one);
        strcat(kept, "\n");
        *colon = '\0';
        local_set(table, one, level);
    }
    free(copy);
    free(d->content);
    d->content = kept;

    if (quiet)
        return;
    if (anchors)
        pgpid_error(_("Info: %s: %zu line(s) about your own anchors, left alone."),
                    d->path, anchors);
    if (refused)
        pgpid_error(_("Info: %s: %zu key(s) you have ruled never on, left alone."),
                    d->path, refused);
    if (undercut)
        pgpid_error(_("Info: %s: %zu key(s) it credits less than you already do, "
                    "left alone."), d->path, undercut);
    if (capped)
        pgpid_error(_("Info: %s: %zu line(s) beyond full, brought back to it."),
                    d->path, capped);
    if (nevers)
        pgpid_error(_("Info: %s: %zu key(s) it would have you credit with nothing."),
                    d->path, nevers);
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
    pgpid_error(_("Info: credibility changes:"));
    for (char *line = b, *save; (line = strtok_r(line, "\n", &save)); line = NULL)
        if (!strstr(after, line))
            pgpid_error(_("  - %s"), line);
    for (char *line = a, *save; (line = strtok_r(line, "\n", &save)); line = NULL)
        if (!strstr(before, line))
            pgpid_error(_("  + %s"), line);
}

/* One line of the answer. `--long` adds columns rather than moving them, so
 * whatever a script already reads at $2 stays at $2. */
static void local_row(const struct pgpid_key *key, bool long_form)
{
    const char *fpr = *key->fpr ? key->fpr : "-";
    const char *word = pgpid_validity_word(key->ownertrust);

    if (!long_form) {
        const char *values[] = { fpr, word };
        pgpid_table_row(values);
        return;
    }

    unsigned neids = 0;
    char *eid = pgpid_eid_of_key(key, &neids, true);
    const char *mbox = pgpid_first_mbox(key);
    const char *values[] = { fpr, word, neids == 1 ? eid : "-", mbox ? mbox : "-" };
    pgpid_table_row(values);
    free(eid);
}

/* Every certificate this keyring holds, in the engine's own order. */
static int local_all(bool long_form)
{
    struct pgpid_keyring *kr = pgpid_keys_load(NULL, 0, 0);
    if (!kr) {
        pgpid_error(_("Error: Cannot read the keyring."));
        return PGPID_FAIL;
    }
    for (size_t n = 0; n < pgpid_keys_count(kr); n++)
        local_row(pgpid_keys_at(kr, n), long_form);
    pgpid_keys_free(kr);
    return PGPID_OK;
}

static int do_local(int argc, char **argv)
{
    const char *value = NULL;
    bool long_form = false, recompute = false, interactive = false;
    const char **patterns = NULL;
    size_t npatterns = 0;
    int i = 1;

    patterns = calloc((size_t)argc, sizeof *patterns);
    if (!patterns) {
        pgpid_error(_("Error: Out of memory."));
        return PGPID_FAIL;
    }

    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-r") || !strcmp(a, "--replace-to")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a value."), a);
                free(patterns);
                return PGPID_USAGE;
            }
            value = argv[i];
        } else if (!strcmp(a, "--long")) {
            long_form = true;
        } else if (!strcmp(a, "--check")) {
            recompute = true;
            interactive = false;
        } else if (!strcmp(a, "--update")) {
            recompute = true;
            interactive = true;
        } else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            /* Taken for symmetry with the other two verbs. `local` says
             * nothing but its table and its errors, so there is nothing here
             * to silence. */
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            free(patterns);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            i++;
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("trustdb");
            free(patterns);
            return PGPID_USAGE;
        } else {
            patterns[npatterns++] = a;
        }
    }
    for (; i < argc; i++)
        patterns[npatterns++] = argv[i];

    if (value) {
        /* Setting is a decision about a named certificate. Without a name
         * there is nothing to decide about, and "the whole keyring, full"
         * would be a decision nobody meant to take. */
        if (!npatterns) {
            pgpid_error(_("Error: A fingerprint is required to set a credibility."));
            free(patterns);
            return PGPID_USAGE;
        }
        if (pgpid_validity_from_word(value) < 0) {
            pgpid_error(_("Error: Unknown credibility value '%s'."), value);
            pgpid_error(_("Notice: One of undefined, never, marginal, full, ultimate."));
            free(patterns);
            return PGPID_USAGE;
        }
        /* The engine refuses this one, and it is right to: unknown is the
         * absence of a decision, not one more decision to take. */
        if (!strcmp(value, "unknown")) {
            pgpid_error(_("Error: 'unknown' cannot be set; it is what a certificate"));
            pgpid_error(_("Notice: no one has ruled on already reads as."));
            free(patterns);
            return PGPID_USAGE;
        }
    }

    static const char *const SHORT_COLUMNS[] = { "fingerprint", "credibility" };
    static const char *const LONG_COLUMNS[] = {
        "fingerprint", "credibility", "eid", "email",
    };
    pgpid_table_start(long_form ? LONG_COLUMNS : SHORT_COLUMNS, long_form ? 4 : 2);

    int rc = PGPID_OK;
    if (!npatterns) {
        rc = local_all(long_form);
    } else {
        for (size_t n = 0; n < npatterns && rc == PGPID_OK; n++) {
            struct pgpid_keyring *kr = NULL;
            rc = one_key(patterns[n], &kr);
            if (rc != PGPID_OK)
                break;

            if (value) {
                /* One line of the ownertrust file: the fingerprint, the
                 * number that stands for the word, and a trailing colon. */
                char line[64];
                snprintf(line, sizeof line, "%s:%d:\n",
                         pgpid_keys_at(kr, 0)->fpr,
                         pgpid_ownertrust_code((char)pgpid_validity_from_word(value)));
                const char *args[] = { "--batch", "--import-ownertrust", NULL };
                int status = pgpid_run_engine_input(args, line);
                pgpid_keys_free(kr);
                kr = NULL;
                if (status != 0) {
                    pgpid_error(_("Error: The engine refused to set the credibility."));
                    rc = PGPID_FAIL;
                    break;
                }
                /* Read it back rather than echo what was asked: the engine is
                 * what decides, and a write that did not take should not look
                 * like one that did. */
                rc = one_key(patterns[n], &kr);
                if (rc != PGPID_OK)
                    break;
            }

            local_row(pgpid_keys_at(kr, 0), long_form);
            pgpid_keys_free(kr);
        }
    }

    if (rc == PGPID_OK)
        pgpid_table_end();
    free(patterns);

    /*
     * Setting a credibility only marks gpg's database stale; every validity
     * it has already worked out stays as it was until somebody asks again.
     * Asked here, after the answer is printed, so that what one reads is the
     * value and what one gets afterwards is a keyring that agrees with it.
     */
    if (rc == PGPID_OK && recompute) {
        const char *asking[] = { "--update-trustdb", NULL };
        const char *silent[] = { "--batch", "--check-trustdb", NULL };
        if (pgpid_run_engine(interactive ? asking : silent))
            rc = PGPID_FAIL;
    }
    return rc;
}

/* What we would have others replay: our own decisions, signed.
 *
 * Armored rather than binary: these files are meant to be committed next to
 * the tree they justify, and a git history that cannot diff its own contents
 * explains nothing. gpg reads either on the way back in.
 *
 * Ultimate and unknown are left out by default. Ultimate says "this key is
 * mine", which means nothing to anybody else and is refused on import anyway;
 * unknown is the absence of a decision, and there is no point signing one. */
static int do_export(int argc, char **argv)
{
    const char *file = NULL, *user = NULL;
    bool all = false, armor = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--export-file")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a path."), a);
                return PGPID_USAGE;
            }
            file = argv[i];
        } else if (!strcmp(a, "-u") || !strcmp(a, "--use-privkey")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a key."), a);
                return PGPID_USAGE;
            }
            user = argv[i];
        } else if (!strcmp(a, "--export-all")) {
            all = true;
        } else if (!strcmp(a, "--armor")) {
            armor = true;
        } else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            /* accepted everywhere, nothing to say here */
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("trustdb");
            return PGPID_USAGE;
        } else {
            pgpid_error(_("Error: 'export' takes no argument; the path goes to "
                        "--export-file."));
            return PGPID_USAGE;
        }
    }

    char *raw = export_ownertrust();
    if (!raw)
        return PGPID_FAIL;

    char *kept = malloc(strlen(raw) + 1);
    if (!kept) {
        free(raw);
        return PGPID_FAIL;
    }
    *kept = '\0';
    size_t n = 0;
    for (char *line = raw, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        if (!*line || *line == '#')
            continue;
        const char *colon = strchr(line, ':');
        if (!colon || !colon[1])
            continue;
        if (!all && (colon[1] < '3' || colon[1] > '5'))
            continue;
        strcat(kept, line);
        strcat(kept, "\n");
        n++;
    }
    free(raw);

    if (!n) {
        pgpid_error(_("Error: Nothing to export: no decision worth signing."));
        free(kept);
        return PGPID_NOTHING;
    }

    const char *a[8];
    size_t k = 0;
    /* Binary unless asked, as gpg itself does. --armor is for the file one
     * commits: a git history that cannot diff its own contents explains
     * nothing. Either reads back the same. */
    if (armor)
        a[k++] = "--armor";
    a[k++] = "--sign";
    if (user) {
        a[k++] = "--local-user";
        a[k++] = user;
    }
    a[k] = NULL;

    int rc = pgpid_run_engine_io(a, kept, file);
    free(kept);
    if (rc) {
        /* A signature that failed half-way leaves a file that looks like one
         * and is not. Better nothing than something to be trusted by mistake. */
        if (file)
            unlink(file);
        pgpid_error(_("Error: gpg would not sign the export."));
        return PGPID_FAIL;
    }
    pgpid_error(_("Notice: %zu delegation(s) signed. Publish it beside the tree "
                "it explains, so that anyone can replay it."), n);
    return PGPID_OK;
}

/*
 * Read the files, weigh them, and apply what survives — in that order and in
 * the order they were given, since a delegation is judged against what the
 * one before it decided.
 *
 * The table is the caller's so that it is freed once, whichever way this
 * returns.
 */
static int weigh_and_apply(const char *files[], size_t nfiles, bool quiet,
                           bool fetch_all, const char *servers,
                           struct local_table *table)
{
    if (!local_levels(table)) {
        pgpid_error(_("Error: Cannot read what this machine already says."));
        return PGPID_FAIL;
    }

    /* Without an anchor there is nothing for the delegations to hang
     * from: gpg would compute validity out of a chain with no first
     * link, and every verdict it returned would be meaningless. */
    bool anchored = false;
    for (size_t i = 0; i < table->n && !anchored; i++)
        anchored = table->level[i] == '6';
    if (!anchored) {
        pgpid_error(_("Error: No key here is ultimate, so there is no anchor to "
                    "extend from."));
        pgpid_error(_("Notice: Mark your own certificate ultimate first: "
                    "%s trustdb local --replace-to ultimate FINGERPRINT"),
                    PGPID_NAME);
        return PGPID_FAIL;
    }

    /* One listing rather than one question per key. */
    static char known[1048576];
    if (*servers && !fetch_all) {
        const char *listing[] = { "--with-colons", "--list-keys", NULL };
        if (pgpid_capture_engine(listing, known, sizeof known) <= 0)
            *known = '\0';
    }

    struct delegation d[MAX_FILES];
    memset(d, 0, sizeof d);
    for (size_t i = 0; i < nfiles; i++) {
        d[i].path = files[i];
        if (!read_delegation(&d[i]))
            return PGPID_FAIL;
        /* Between reading and weighing, so that a key this file names may
         * be the one signing the next. An empty server list asks nobody, and
         * that is the whole of not fetching. */
        fetch_named(&d[i], fetch_all, fetch_all ? NULL : known, servers);
        filter_delegation(&d[i], table, quiet);
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
            pgpid_error(_("Info: The delegations are already applied — credibility "
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
            pgpid_error(_("Notice: Current credibility backed up in %s."), path);
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
        pgpid_error(_("Notice: To restore the previous credibility: "
                    "gpg --import-ownertrust %s"), path);
    }
    free(before);

    return PGPID_OK;
}

static int do_import(int argc, char **argv)
{
    /* Silent by default: this is called from other programs — foodjis shells
     * out to it — and a prompt in a place with no terminal does not ask, it
     * hangs. A human who wants to be asked about the rest says --update. */
    bool interactive = false, quiet = false;
    /* Fetching what a delegation names is the default: a file explaining a
     * tree is worth little beside a keyring that has not got the branches.
     * `--keyservers ''` is how one asks nobody — the same empty list that
     * means the same thing in every other action here. */
    bool fetch_all = false;
    const char *keyservers = NULL;
    const char *files[MAX_FILES];
    size_t nfiles = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--check")) {
            interactive = false;
        } else if (!strcmp(a, "--update")) {
            interactive = true;
        } else if (!strcmp(a, "--import-fetch-all")) {
            fetch_all = true;
        } else if (!strcmp(a, "-K") || !strcmp(a, "--keyservers")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a list, empty for none."), a);
                return PGPID_USAGE;
            }
            keyservers = argv[i];
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
        struct local_table table = { NULL, NULL, 0, 0 };
        int rc = weigh_and_apply(files, nfiles, quiet, fetch_all,
                                 keyservers ? keyservers : PGPID_KEYSERVERS,
                                 &table);
        table_free(&table);
        if (rc != PGPID_OK)
            return rc;
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
    if (!strcmp(verb, "export"))
        return do_export(argc - 1, argv + 1);

    pgpid_error(_("Error: '%s' is not one of local, export or import."), verb);
    pgpid_try_help("trustdb");
    return PGPID_USAGE;
}
