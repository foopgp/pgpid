/* Finding a certificate, locally or in the world.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * `get` and `list --short` print the same thing; they differ in what they
 * are for. `list` shows what is at hand, so a missing pattern means the whole
 * keyring. `get` looks something up, so it wants to be told what — a search
 * with no term is almost always a caller that lost its variable, and `'*'`
 * is there for the rare occasion when everything really is meant.
 *
 * The other difference is the network: `get` refreshes before it answers,
 * unless told not to. A certificate is a claim other people update, and
 * answering from a stale copy is how one certifies a key whose owner revoked
 * it last week.
 */
#include "pgpid.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " cert_get [OPTIONS]... NAME|U4|U5|EMAIL...\n"
        "\n"
        "Output fingerprints, emails and eid of certificates matching NAME|U4|U5|EMAIL.\n"
        "May also get or refresh certificates from keyservers.\n"
        "'*' matches the whole keyring; `list` is the one that shows everything\n"
        "when asked nothing.\n"
        "\n"
        "OPTIONS:\n"
        "  -F, --fingerprint           Output only fingerprints\n"
        "  -E, --email                 Output only emails\n"
        "  -f, --no-fetch              Don't refresh certificates from keyservers or Web Key Directories\n"
        "      --import-from FILE      Take the certificate from a file rather than a keyserver\n"
        "  -r, --recurse[=NUM]         Also fetch the certificates signing the target, NUM\n"
        "                              levels deep (0..6) - Default with -r: 1\n"
        "  -m, --errexit-g=1           Return an error if there is more than one (1) entry - You may replace '1' by an other number\n"
        "  -K, --keyservers KEYSERVERS Search and refresh certificates from this keyservers - Default: "
        "%s"
        "\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "There is no 'cert_check': `list` answers what it answered, for less.\n"),
            PGPID_NAME, PGPID_KEYSERVERS);
}

/**
 * What actually goes to a keyserver.
 *
 * HKP is one request — `op=get&search=…` — and `search` takes whatever one
 * has: a fingerprint, a key identifier, an address, a name. The C used to
 * refuse everything but the first three, on the grounds that a name search
 * was "rare and ambiguous". That was wrong twice over: it is neither rare
 * (it is how one finds somebody one has only been told about) nor a reason
 * to refuse (an imprecise search returns several certificates, which is an
 * answer, not a failure).
 *
 * **An entity identifier is searched by its body** — what follows the `u4`,
 * `u5` or `=` — because that is the one string both spellings share. A
 * certificate minted before the separator went away carries
 * `udid4=sRyU…`; one minted after carries `u4sRyU…`; searching either
 * spelling whole finds only its own generation, and there were forty-two
 * legacy-only certificates in one ordinary keyring on the day this was
 * written. The body finds both.
 */
static char *eid_body(const char *term)
{
    /* Written bare and glued — `u4-zTIla…` — which is how a person types one
     * off a screen and how the card's Login data holds it. pgpid_eid_of_uid
     * does not see these: it looks for a *uid*, so it wants either the `UID`
     * that opens the standard one or the `=` of the old one. Asked for the
     * modern spelling alone it answered nothing, and the search went out
     * verbatim — finding only certificates of that same generation, which is
     * the whole bug this is here to close. */
    if (pgpid_eid_body_is_sound(term))
        return strdup(term + 2);

    /* Otherwise a uid, in either spelling: `u4=…`, `udid4=…`, or the whole
     * `UID:urn:eid:u4…`. What comes back is glued, so the body follows its
     * first two characters. */
    char *eid = pgpid_eid_of_uid(term);
    if (!eid)
        return NULL;
    char *body = strlen(eid) > 2 ? strdup(eid + 2) : NULL;
    free(eid);
    return body;
}

/* Percent-encode everything a query string does not take unescaped. The
 * unreserved set of RFC 3986, and nothing else: an eid carries '.' and '-'
 * and '_', which are in it, and a name carries spaces and accents, which
 * are not. */
static char *url_encode(const char *s)
{
    static const char *HEX = "0123456789ABCDEF";
    size_t n = strlen(s);
    char *out = malloc(n * 3 + 1);
    if (!out)
        return NULL;
    char *w = out;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if ((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z')
            || (*p >= '0' && *p <= '9') || *p == '-' || *p == '.'
            || *p == '_' || *p == '~') {
            *w++ = (char)*p;
        } else {
            *w++ = '%';
            *w++ = HEX[*p >> 4];
            *w++ = HEX[*p & 0x0F];
        }
    }
    *w = '\0';
    return out;
}

/**
 * Ask every keyserver for [term], and the Web Key Directory too when it is
 * an address.
 *
 * Both, and not one or the other. WKD says which certificate an address's own
 * domain stands behind, which is the only authority on the question when one
 * address sits on several certificates — but today more than ninety-nine
 * addresses in a hundred have no WKD at all, so a lookup that stopped there
 * would find nothing for almost everybody.
 *
 * The request goes through `gpg --fetch-keys`, which takes a URL and imports
 * what comes back. No HTTP client of our own: gpg is already required, and
 * asking it is what this program does everywhere else.
 *
 * Failure is ordinary — a server may be down, a key absent — and must not
 * stop the answer: what is already local is still worth printing.
 */
void pgpid_refresh(const char *term, const char *keyservers)
{
    if (!keyservers || !*keyservers)
        return;

    bool is_address = strchr(term, '@') != NULL;

    /* Two searches at most, and usually one: the body of an identifier, which
     * both spellings share, and the term as it was given. The second is not
     * redundant — this was measured against our own keyserver, where every
     * spelling answers, and against keys.openpgp.org, which refuses them all
     * with a 400; a server we have not met may sit between the two. A lookup
     * happens because somebody asked for it, so a second request costs
     * nothing anybody notices. */
    char *body = eid_body(term);
    /* A key id or a fingerprint as it is read off a screen, with no "0x": a
     * keyserver takes that for a name. keys.foopgp.org answered "Key not
     * found" to every fingerprint sent this way, and only keys.openpgp.org,
     * which serves a certificate stripped of what it has not verified,
     * answered at all. HKP wants the prefix; bl-pgpid always gave it. */
    char *hex = NULL;
    if (!body && (strlen(term) == 16 || pgpid_is_fingerprint(term))) {
        bool all_hex = true;
        for (const char *p = term; *p; p++)
            all_hex = all_hex && isxdigit((unsigned char)*p);
        if (all_hex && asprintf(&hex, "0x%s", term) < 0)
            hex = NULL;
    }
    const char *wanted[2] = { body ? body : hex ? hex : term, NULL };
    if (body && strcmp(body, term) != 0)
        wanted[1] = term;

    char *copy = strdup(keyservers);
    if (!copy) {
        free(body);
        free(hex);
        return;
    }
    for (char *save = NULL, *ks = strtok_r(copy, " \t,", &save); ks;
         ks = strtok_r(NULL, " \t,", &save)) {
        if (is_address) {
            /* The domain's own word on which certificate is its address's —
             * the only authority when one address sits on several. */
            const char *locate[] = {
                "--keyserver", ks, "--auto-key-locate", "clear,wkd",
                "--locate-external-keys", term, NULL,
            };
            pgpid_run_engine(locate);
        }
        for (size_t i = 0; i < 2 && wanted[i]; i++) {
            char *escaped = url_encode(wanted[i]);
            if (!escaped)
                continue;
            /* `options=mr` asks for the machine-readable answer: the armoured
             * certificates and nothing around them. */
            char url[1024];
            size_t len = strlen(ks);
            int trim = (len && ks[len - 1] == '/') ? 1 : 0;
            snprintf(url, sizeof url, "%.*s/pks/lookup?op=get&options=mr&search=%s",
                     (int)(len - trim), ks, escaped);
            const char *fetch[] = { "--fetch-keys", url, NULL };
            pgpid_run_engine(fetch);
            free(escaped);
        }
    }
    free(copy);
    free(body);
    free(hex);
}

/* Fetch the certificates that signed these, then the ones that signed those,
 * up to depth levels. A worklist rather than recursion, and a set of the
 * key identifiers already visited -- the web of trust has cycles, and two
 * people who certified each other would otherwise be fetched for ever.
 */
static void fetch_certifiers(char **terms, int nterms, int depth,
                             const char *keyservers)
{
    static char seen[512][17];
    size_t nseen = 0;
    /* Wide enough for a fingerprint: the first level is whatever the caller
     * asked for, and truncating that to a short key identifier left gpg with
     * nothing to list. */
    char level[64][64];
    size_t nlevel = 0;

    for (int i = 0; i < nterms && nlevel < 64; i++)
        snprintf(level[nlevel++], sizeof level[0], "%.63s", terms[i]);

    while (depth-- > 0 && nlevel) {
        char args[80][64];
        const char *argv2[84];
        size_t n = 0;
        argv2[n++] = "--with-colons";
        argv2[n++] = "--list-sigs";
        for (size_t i = 0; i < nlevel && n < 82; i++) {
            /* Bounded explicitly: level[] holds "0x" plus sixteen hex
             * characters, but the compiler cannot see that from here. */
            snprintf(args[i], sizeof args[0], "%.63s", level[i]);
            argv2[n++] = args[i];
        }
        argv2[n] = NULL;

        char listing[262144] = "";
        if (pgpid_capture_engine(argv2, listing, sizeof listing) <= 0)
            return;

        nlevel = 0;
        for (char *line = strtok(listing, "\n"); line; line = strtok(NULL, "\n")) {
            if (strncmp(line, "sig:", 4))
                continue;
            /* Field 5 of a sig record is the signer's key identifier. */
            char *f = line;
            for (int c = 0; c < 4 && f; c++)
                f = strchr(f + 1, ':');
            if (!f)
                continue;
            char kid[17] = "";
            snprintf(kid, sizeof kid, "%.16s", f + 1);
            if (strlen(kid) != 16)
                continue;
            bool known = false;
            for (size_t i = 0; i < nseen && !known; i++)
                known = !strcmp(seen[i], kid);
            if (known || nseen >= 512)
                continue;
            snprintf(seen[nseen++], sizeof seen[0], "%s", kid);
            char term[19];
            snprintf(term, sizeof term, "0x%s", kid);
            pgpid_refresh(term, keyservers);
            if (nlevel < 64)
                snprintf(level[nlevel++], sizeof level[0], "%s", term);
        }
    }
}

int pgpid_action_cert_get(int argc, char **argv)
{
    bool only_fpr = false, only_mbox = false, fetch = true;
    const char *import_from = NULL;
    int recurse = 0;
    const char *keyservers = NULL;
    long errexit = -1;
    int first = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-r") || !strcmp(a, "--recurse")) {
            recurse = 1;
        } else if (!strncmp(a, "--recurse=", 10)) {
            recurse = atoi(a + 10);
            if (recurse < 0 || recurse > 6) {
                pgpid_error(_("Error: --recurse takes a number in 0..6."));
                return PGPID_USAGE;
            }
        } else if (!strcmp(a, "--import-from") || !strcmp(a, "--importfrom")) {
            if (i + 1 >= argc) {
                pgpid_error(_("Error: --import-from wants a file."));
                return PGPID_USAGE;
            }
            import_from = argv[++i];
        } else if (!strcmp(a, "-F") || !strcmp(a, "--fpr") || !strcmp(a, "--fingerprint")) {
            only_fpr = true;
            only_mbox = false;
        } else if (!strcmp(a, "-E") || !strcmp(a, "--mbox") || !strcmp(a, "--email")) {
            only_mbox = true;
            only_fpr = false;
        } else if (!strcmp(a, "-f") || !strcmp(a, "--no-fetch")) {
            fetch = false;
        } else if (!strcmp(a, "-K") || !strcmp(a, "--keyservers")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a list of servers, empty for none."), a);
                return PGPID_USAGE;
            }
            keyservers = argv[i];
        } else if (!strncmp(a, "--errexit-g=", 12) || !strcmp(a, "-m")) {
            const char *v = a[1] == 'm' ? "1" : a + 12;
            char *end = NULL;
            errexit = strtol(v, &end, 10);
            if (!*v || (end && *end) || errexit < 1) {
                pgpid_error(_("Error: '%s' wants a number of one or more."), a);
                return PGPID_USAGE;
            }
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            first = i + 1;
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("cert_get");
            return PGPID_USAGE;
        } else {
            first = i;
            break;
        }
    }

    if (!first || first >= argc) {
        pgpid_error(_("Error: What are you looking for? '*' for everything."));
        usage(stderr);
        return PGPID_USAGE;
    }

    /* '*' is the whole keyring, which is what an empty pattern means to the
     * engine — and nothing to fetch, since there is no one thing to ask for. */
    bool everything = argc - first == 1 && !strcmp(argv[first], "*");

    /* A file where the keyservers would have been: the certificate arrives from
     * somewhere else, and what follows -- the lookup, the output -- is the same
     * whichever door it came through. */
    if (import_from) {
        const char *imp[] = { "--batch", "--import", import_from, NULL };
        if (pgpid_run_engine(imp)) {
            pgpid_error(_("Error: Nothing could be imported from '%s'."), import_from);
            return PGPID_FAIL;
        }
    } else if (fetch && !everything) {
        for (int i = first; i < argc; i++)
            pgpid_refresh(argv[i], keyservers ? keyservers : PGPID_KEYSERVERS);
        if (recurse)
            fetch_certifiers(argv + first, argc - first, recurse,
                             keyservers ? keyservers : PGPID_KEYSERVERS);
    }

    /* One pattern at a time, as the engine takes them; several terms are
     * several searches whose answers meet in the output. */
    int ret = PGPID_NOTHING;
    size_t matched = 0;
    pgpid_list_short_start(only_fpr, only_mbox);
    for (int i = first; i < argc; i++) {
        size_t n = 0;
        /* Locally as remotely: an identifier is looked up by its body, the
         * one string `u4=sRyU…` and `u4sRyU…` share. gpg matches a pattern
         * as a substring of the uid, so asking for one spelling whole finds
         * only certificates of that generation. */
        char *body = everything ? NULL : eid_body(argv[i]);
        int r = pgpid_list_short(everything ? NULL : (body ? body : argv[i]),
                                 only_fpr, only_mbox, &n);
        free(body);
        if (r == PGPID_FAIL)
            return PGPID_FAIL;
        if (r == PGPID_OK)
            ret = PGPID_OK;
        matched += n;
    }
    pgpid_list_short_end();

    if (ret == PGPID_NOTHING) {
        pgpid_error(_("Error: No certificate for what was asked."));
        return ret;
    }

    /* The answer is printed first and judged after, deliberately: a caller
     * who asked for one certificate and got three wants to see which three,
     * not just to be told the count was wrong. */
    if (errexit > 0 && matched > (size_t)errexit) {
        pgpid_error(_("Error: %zu certificates matched, more than the %ld asked for."),
                    matched, errexit);
        return PGPID_FAIL;
    }
    return ret;
}
