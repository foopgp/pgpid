/* One pass over the keyring, everything a contact card needs.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This is the one that had to be rewritten. The shell walk spawns a gpg per
 * key and pays a process for every row; here a single engine streams the
 * whole keyring, and every column comes out of the same record.
 *
 * Two words that look alike and are not:
 *
 *   validity     what the web of trust concludes about this certificate
 *   credibility  what *you* decided about its holder's ability to certify
 *
 * GnuPG prints both with the same letters, which is a fine way to lose an
 * afternoon. Here they are words, and different ones.
 */
#include "pgpid.h"

#include <ctype.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* The best validity any surviving uid reaches — validity is carried per uid,
 * and it takes one good uid to answer yes. */
static char best_uid_validity(const struct pgpid_key *key)
{
    char best = '-';
    for (size_t i = 0; i < key->nuid; i++) {
        const struct pgpid_keyuid *u = &key->uid[i];
        if (u->revoked || u->invalid)
            continue;
        if (pgpid_validity_rank(u->validity) > pgpid_validity_rank(best))
            best = u->validity;
    }
    return best;
}

/* How many distinct other certificates have signed a uid of this one.
 * Self-signatures do not count: a certificate vouching for itself says
 * nothing. Needs GPGME_KEYLIST_MODE_SIGS, which costs a second pass in gpg. */
static unsigned count_certifiers(const struct pgpid_key *key)
{
    const char *own = *key->keyid ? key->keyid : NULL;
    unsigned n = 0;
    /* Small and quadratic on purpose: a certificate with enough signatures
     * for this to matter does not exist in a personal keyring, and a hash
     * table here would be more code than the thing it saves. */
    const char *seen[256];
    unsigned nseen = 0;

    for (size_t ui = 0; ui < key->nuid; ui++) {
        const struct pgpid_keyuid *u = &key->uid[ui];
        if (u->revoked || u->invalid)
            continue;
        for (size_t si = 0; si < u->nsig; si++) {
            const struct pgpid_keysig *s = &u->sig[si];
            if (!*s->keyid)
                continue;
            if (own && !strcmp(s->keyid, own))
                continue;
            bool dup = false;
            for (unsigned i = 0; i < nseen; i++)
                if (!strcmp(seen[i], s->keyid)) {
                    dup = true;
                    break;
                }
            if (dup)
                continue;
            if (nseen < sizeof seen / sizeof *seen)
                seen[nseen++] = s->keyid;
            n++;
        }
    }
    return n;
}

/* ISO 8601, the way onak-foopgp writes a date; or the seconds themselves
 * under --machine-readable. A dash when there is nothing to say. */
static void put_date(char *out, size_t n, long t, bool machine)
{
    if (t <= 0) {
        snprintf(out, n, "-");
        return;
    }
    if (machine) {
        snprintf(out, n, "%ld", t);
        return;
    }
    struct tm tm;
    time_t tt = (time_t)t;
    if (gmtime_r(&tt, &tm))
        strftime(out, n, "%Y-%m-%d", &tm);
    else
        snprintf(out, n, "-");
}

/* --short collects before it prints, because the shell it must match pipes
 * its lines through `sort -u`.
 *
 * What is sorted and deduplicated is the pair "fingerprint address", *before*
 * any column is dropped — so `--email` comes out in fingerprint order rather
 * than alphabetical order, and the same address on two certificates appears
 * twice. Sorting what is displayed instead would be right-looking and wrong.
 */
struct short_row {
    char *key;      /* "fingerprint address", what the shell sorts on */
    char *fpr;
    char *email;
    char *eid;      /* borrowed from the caller for the length of the walk */
};

struct short_lines {
    struct short_row *row;
    size_t n, cap;
};

static void short_add(struct short_lines *s, const char *fpr,
                      const char *email, const char *eid)
{
    char lowered[320], key[512];
    /* gpg lowercases the address it reports, and the shell prints what gpg
     * reports. Strictly an address's local part is case-sensitive, but the
     * question here is what the certificate can be found by, and that is the
     * normalised form. */
    size_t i = 0;
    for (; email[i] && i + 1 < sizeof lowered; i++)
        lowered[i] = (char)tolower((unsigned char)email[i]);
    lowered[i] = '\0';
    snprintf(key, sizeof key, "%s %s", fpr, lowered);

    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 64;
        struct short_row *grown = realloc(s->row, cap * sizeof *grown);
        if (!grown)
            return;
        s->row = grown;
        s->cap = cap;
    }
    struct short_row *r = &s->row[s->n];
    r->key = strdup(key);
    r->fpr = strdup(fpr);
    r->email = strdup(lowered);
    r->eid = eid ? strdup(eid) : NULL;
    if (r->key && r->fpr && r->email)
        s->n++;
}

/* strcoll and not strcmp: the shell sorts with `sort`, which collates in the
 * caller's locale. Byte order and French collation disagree on case and on
 * punctuation, and the disagreement is visible on any keyring holding more
 * than a handful of certificates. */
static int by_key(const void *a, const void *b)
{
    return strcoll(((const struct short_row *)a)->key,
                   ((const struct short_row *)b)->key);
}

/* The columns the short listing shows, for the formats that name them.
 *
 * Opened by the caller and not by the walk: `get` runs the walk once per
 * pattern, and several patterns are one answer rather than several tables.
 * Raw stays hand-printed below — its column at 80 is what the shell has
 * always printed, and `get` must keep answering to the column.
 */
void pgpid_list_short_start(bool only_fpr, bool only_mbox)
{
    static const char *const FPR_ONLY[] = { "fingerprint" };
    static const char *const MBOX_ONLY[] = { "email" };
    static const char *const BOTH[] = { "fingerprint", "eid", "email" };

    if (pgpid_format == PGPID_FMT_RAW)
        return;
    if (only_fpr)
        pgpid_table_start(FPR_ONLY, 1);
    else if (only_mbox)
        pgpid_table_start(MBOX_ONLY, 1);
    else
        pgpid_table_start(BOTH, 3);
}

void pgpid_list_short_end(void)
{
    if (pgpid_format != PGPID_FMT_RAW)
        pgpid_table_end();
}

static void short_flush(struct short_lines *s, bool only_fpr, bool only_mbox)
{
    const bool raw = pgpid_format == PGPID_FMT_RAW;

    qsort(s->row, s->n, sizeof *s->row, by_key);
    const char *previous = NULL;
    for (size_t i = 0; i < s->n; i++) {
        const struct short_row *r = &s->row[i];
        /* Deduplicated on the pair, as the shell does. Dropping a column
         * afterwards may therefore leave what looks like a repeat — and it
         * is one, on purpose: two certificates can carry one address. */
        bool same = previous && !strcmp(r->key, previous);
        previous = r->key;
        if (same && !only_fpr)
            continue;
        if (only_fpr) {
            /* Fingerprints repeat once per address, so this column alone is
             * deduplicated in its own right — which is what the shell does
             * with a second `sort -u`. */
            if (i > 0 && !strcmp(r->fpr, s->row[i - 1].fpr))
                continue;
            if (raw) {
                puts(r->fpr);
            } else {
                const char *values[] = { r->fpr };
                pgpid_table_row(values);
            }
        } else if (only_mbox) {
            if (raw) {
                puts(r->email);
            } else {
                const char *values[] = { r->email };
                pgpid_table_row(values);
            }
        } else if (raw) {
            /* The identifier comes before the address, as everywhere else
             * in this tool: what a certificate *is* reads before how one
             * writes to it. */
            char left[512];
            snprintf(left, sizeof left, "%s %s", r->fpr, r->eid ? r->eid : "-");
            if (r->email)
                printf("%-80s %s\n", left, r->email);
            else
                printf("%-80s\n", left);
        } else {
            const char *values[] = {
                r->fpr, r->eid ? r->eid : "-", r->email ? r->email : "-",
            };
            pgpid_table_row(values);
        }
    }
    for (size_t i = 0; i < s->n; i++) {
        free(s->row[i].key);
        free(s->row[i].fpr);
        free(s->row[i].email);
        free(s->row[i].eid);
    }
    free(s->row);
    s->row = NULL;
    s->n = s->cap = 0;
}

/* The short listing, shared with `get`.
 *
 * Its own walk of the keyring rather than a branch inside the long one: the
 * two answer different questions — one address per line against one
 * certificate per line — and the only thing they have in common is where the
 * data comes from. Sharing the loop would mean a function that is half
 * disabled whichever way it is called.
 */
int pgpid_list_short(const char *pattern, bool only_fpr, bool only_mbox,
                     size_t *certificates)
{
    const char *pat[1];
    size_t npat = 0;
    if (pattern)
        pat[npat++] = pattern;
    struct pgpid_keyring *kr = pgpid_keys_load(pat, npat, 0);
    if (!kr) {
        pgpid_error(_("Error: Cannot read the keyring."));
        return PGPID_FAIL;
    }

    struct short_lines lines = { NULL, 0, 0 };
    size_t rows = 0;
    for (size_t n = 0; n < pgpid_keys_count(kr); n++) {
        const struct pgpid_key *key = pgpid_keys_at(kr, n);
        if (!*key->fpr)
            continue;
        const char *fpr = key->fpr;
        unsigned neids = 0;
        char *eid = pgpid_eid_of_key(key, &neids, false);
        if (neids > 1)
            pgpid_error(_("Warning: Certificate %s carries more than one identifier."), fpr);
        for (size_t i = 0; i < key->nuid; i++) {
            const struct pgpid_keyuid *u = &key->uid[i];
            if (!*u->address || !strchr(u->address, '@'))
                continue;
            if ((u->revoked || u->invalid) && !key->revoked)
                continue;
            short_add(&lines, fpr, u->address, neids == 1 ? eid : "-");
        }
        free(eid);
        rows++;
    }
    pgpid_keys_free(kr);
    short_flush(&lines, only_fpr, only_mbox);
    if (certificates)
        *certificates = rows;
    return rows ? PGPID_OK : PGPID_NOTHING;
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " cert_list [OPTIONS]... [SEARCH]\n"
        "\n"
        "List the certificates of the keyring, one per line.\n"
        "\n"
        "Columns:\n"
        "fingerprint, entity identifier, email (primary), certifications\n"
        "(optional), validity, credibility, creation_date, expiration_date,\n"
        "revocation_date\n"
        "\n"
        "Single dash '-' means hidden or unknown value.\n"
        "\n"
        "Values for validity: certified|uncertified|expired|revoked|broken|-\n"
        "Order of importance for unusable certificates: broken>revoked>expired\n"
        "\n"
        "Values for credibility: never|undefined|marginal|full|ultimate|-\n"
        "\n"
        "SEARCH, when given, is passed to the engine as a pattern; without it\n"
        "the whole keyring is listed.\n"
        "\n"
        "OPTIONS:\n"
        "  -S, --short                 One line per address: fingerprint, identifier, address\n"
        "                              What 'pgpid get --no-fetch' answers, to the column\n"
        "  -L, --no-check-eid          Legacy: don't consider certificate as 'broken' if there is no consistent eid inside\n"
        "      --count-certs           Count the distinct certifiers of each certificates and fill *certifications* column (may take time !)\n"
        "      --hide-trust            Credibility (aka ownertrust) is a sensible information used to calculate validity — sometimes both need to stay private\n"
        "      --machine-readable      Output time (seconds since epoch) instead of date (iso-8601) and flags instead of human-readable validity and credibility\n"
        "  -h, --help                  Print this help and exit\n"),
            PGPID_NAME);
}

int pgpid_action_cert_list(int argc, char **argv)
{
    bool check_eid = true, count_certs = false, hide_trust = false, machine = false;
    bool short_form = false;
    const char *pattern = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-S") || !strcmp(a, "--short")) {
            short_form = true;
        } else if (!strcmp(a, "-L") || !strcmp(a, "--no-check-eid")) {
            check_eid = false;
        } else if (!strcmp(a, "--count-certs")) {
            count_certs = true;
        } else if (!strcmp(a, "--hide-trust")) {
            hide_trust = true;
        } else if (!strcmp(a, "--machine-readable")) {
            machine = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            if (i + 1 < argc)
                pattern = argv[i + 1];
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("cert_list");
            return PGPID_USAGE;
        } else {
            pattern = a;
            break;
        }
    }

    if (short_form) {
        pgpid_list_short_start(false, false);
        int rc = pgpid_list_short(pattern, false, false, NULL);
        pgpid_list_short_end();
        return rc;
    }

    /* Signatures are what a certifier count and a revocation date are made
     * of, and they are what makes a listing slow — 6 s against 140 ms on a
     * keyring of 128. Asked for only when one of the two is wanted. */
    unsigned flags = count_certs ? PGPID_KEYS_SIGS : 0;
    const char *pat[1];
    size_t npat = 0;
    if (pattern)
        pat[npat++] = pattern;
    struct pgpid_keyring *kr = pgpid_keys_load(pat, npat, flags);
    if (!kr) {
        pgpid_error(_("Error: Cannot read the keyring."));
        return PGPID_FAIL;
    }

    static const char *const COLUMNS[] = {
        "fingerprint", "eid", "email", "certifications",
        "validity", "credibility",
        "creation_date", "expiration_date", "revocation_date",
    };
    pgpid_table_start(COLUMNS, sizeof COLUMNS / sizeof *COLUMNS);

    unsigned rows = 0;
    for (size_t n = 0; n < pgpid_keys_count(kr); n++) {
        const struct pgpid_key *key = pgpid_keys_at(kr, n);
        if (!*key->fpr)
            continue;
        const char *fpr = key->fpr;

        unsigned neids = 0;
        char *eid = pgpid_eid_of_key(key, &neids, true);

        /* --short answers what `pgpid get --no-fetch` answers: one line
         * per address rather than per certificate, fingerprint and address
         * inside eighty columns, then the identifier. The shell pads exactly
         * so, and callers have been reading those columns for a year — the
         * point of this option is to be indistinguishable, not similar. */
        const char *mbox = pgpid_first_mbox(key);
        char uidv = best_uid_validity(key);

        /* Order of importance, as agreed: broken beats revoked beats
         * expired. A certificate that says two things about whose it is, or
         * nothing at all, is broken whatever else is true of it. */
        char vflag[2] = { uidv, '\0' };
        const char *validity;
        if (check_eid && neids != 1)
            validity = machine ? "b" : "broken";
        else if (key->revoked)
            validity = machine ? "r" : "revoked";
        else if (key->expired)
            validity = machine ? "e" : "expired";
        else if (pgpid_validity_rank(uidv) >= pgpid_validity_rank('f'))
            validity = machine ? vflag : "certified";
        else
            validity = machine ? vflag : "uncertified";

        char credflag[2] = { key->ownertrust, '\0' };
        const char *credibility = hide_trust
            ? "-"
            : machine ? credflag : pgpid_validity_word(key->ownertrust);

        char certs[16] = "-";
        if (count_certs)
            snprintf(certs, sizeof certs, "%u", count_certifiers(key));

        char created[24], expires[24], revoked[24];
        put_date(created, sizeof created, key->created, machine);
        put_date(expires, sizeof expires, key->expires, machine);
        /* Paid for only when a revoked certificate actually turns up: the
         * date lives in a gpg record the listing does not carry. */
        put_date(revoked, sizeof revoked,
                 key->revoked ? pgpid_revocation_time(fpr, pattern) : 0, machine);

        const char *values[] = {
            fpr, eid ? eid : "-", mbox ? mbox : "-", certs,
            validity, credibility, created, expires, revoked,
        };
        pgpid_table_row(values);
        free(eid);
        rows++;
    }

    pgpid_table_end();
    pgpid_keys_free(kr);
    return rows ? PGPID_OK : PGPID_NOTHING;
}
