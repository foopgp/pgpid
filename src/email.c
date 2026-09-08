/* The addresses a certificate answers to.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * An address is not a vCard property uid. It keeps the `Name <addr>` shape
 * every mail client has read for thirty years, and that is why it is handled
 * here rather than with the others.
 *
 * A certificate never loses its last address. Not out of caution: an OpenPGP
 * certificate with no address is one no mail client will offer to anybody,
 * and the person who revoked their way there has no way back — the revoked
 * uids stay revoked forever.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_UIDS  256
#define MAX_LIST   64

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " cert_email [OPTIONS]... [NAME|EMAIL|KEYID|U4|U5]\n"
        "\n"
        "Display and add or revoke emails inside OpenPGP certificate.\n"
        "Missing NAME|EMAIL|KEYID|U4|U5 => the certificate the connected security\n"
        "token belongs to.\n"
        "Output usable emails (non-revoked and non-expired).\n"
        "\n"
        "OPTIONS:\n"
        "  -R, --revoke EMAIL          Revoke existing EMAIL (may be used more than once)\n"
        "      --revoke-all            Revoke every usable email uid but the newest\n"
        "  -A, --add EMAIL             Add EMAIL as a 'Name <EMAIL>' uid. Enable the --name option\n"
        "  -N, --name NAME             The name in front of an added address\n"
        "                              Default: the certificate's own FN:, else the local part\n"
        "  -y, --yes                   Assume yes: skip the irreversible-revocation confirmation\n"
        "  -c, --certs-count           Also output the count of external valid certifications per email (tab-separated)\n"
        "      --show-unusable         Also display the uids that no longer stand: revoked, expired, or without a valid self-signature\n"
        "      --info                  Output the emails as pairs key=value ready to be evaluated in bash\n"
        "  -K, --keyservers KEYSERVERS If non-empty, send updated certificate to this keyservers - Default: "
        "%s"
        "\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "Revoking is irreversible: OpenPGP keeps the address on the certificate\n"
        "forever, marked revoked, and an identical one can never be added again.\n"),
            PGPID_NAME, PGPID_KEYSERVERS);
}

/* Enough of a check to catch a typo, not a parser for RFC 5322. */
static bool looks_like_address(const char *s)
{
    const char *at = strchr(s, '@');
    if (!at || at == s || !at[1])
        return false;
    if (strchr(at + 1, '@'))
        return false;
    if (!strchr(at + 1, '.'))
        return false;
    for (const char *p = s; *p; p++)
        if (*p <= ' ' || *p == '<' || *p == '>' || *p == ',')
            return false;
    return true;
}

/** `<addr>` and `addr` both name the same thing on a command line. */
static void unbracket(const char *in, char *out, size_t max)
{
    if (*in == '<')
        in++;
    snprintf(out, max, "%s", in);
    size_t n = strlen(out);
    if (n && out[n - 1] == '>')
        out[n - 1] = '\0';
}

/** The address a vCard EMAIL uid carries, bracketed or not. */
static const char *vcard_email(const char *uid, size_t *len)
{
    if (strncmp(uid, "EMAIL", 5))
        return NULL;
    const char *p = uid + 5;
    if (*p == ';') {
        p = strchr(p, ':');
        if (!p)
            return NULL;
    } else if (*p != ':') {
        return NULL;
    }
    p++;
    if (*p == ' ')
        p++;
    const char *end = p + strlen(p);
    if (*p == '<' && end > p + 1 && end[-1] == '>') {
        p++;
        end--;
    }
    if (end <= p)
        return NULL;
    for (const char *q = p; q < end; q++)
        if (*q == '<' || *q == '>')
            return NULL;
    *len = (size_t)(end - p);
    return p;
}

/** Either shape, for the operations that treat both as an address. */
static bool uid_carries(const char *uid, const char *addr)
{
    size_t len = 0;
    const char *at = vcard_email(uid, &len);
    if (!at)
        at = pgpid_uid_address(uid, &len);
    return at && len == strlen(addr) && !memcmp(at, addr, len);
}

static bool uid_is_email(const char *uid)
{
    size_t len = 0;
    return vcard_email(uid, &len) || pgpid_uid_has_address(uid);
}

/**
 * Which certificate to work on.
 *
 * Named, or the one the connected card belongs to. One and only one: a
 * pattern that matches two certificates is a question, and answering it by
 * taking the first would write to whichever gpg happened to list first.
 */
static int resolve_target(const char *given, char *out, size_t max)
{
    if (!given) {
        if (pgpid_card_certification_key(out, max))
            return PGPID_OK;
        pgpid_error(_("Error: No card answered, so there is no certificate to work on."));
        pgpid_error(_("Name one, or plug the card in."));
        return PGPID_FAIL;
    }

    char found[41] = "";
    unsigned n = 0;
    const char *pat[] = { given };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
    for (size_t i = 0; i < pgpid_keys_count(kr); i++) {
        const struct pgpid_key *key = pgpid_keys_at(kr, i);
        if (!*key->fpr)
            continue;
        if (!n)
            snprintf(found, sizeof found, "%s", key->fpr);
        n++;
    }
    pgpid_keys_free(kr);

    if (!n) {
        pgpid_error(_("Error: No certificate here matches '%s'."), given);
        return PGPID_FAIL;
    }
    if (n > 1) {
        pgpid_error(_("Error: '%s' matches %u certificates. Name one."), given, n);
        return PGPID_FAIL;
    }
    snprintf(out, max, "%s", found);
    return PGPID_OK;
}

/** The name to put in front of an added address: the certificate's own FN:. */
static void own_name(const struct pgpid_uid *uids, size_t n, char *out, size_t max)
{
    *out = '\0';
    for (size_t i = 0; i < n; i++) {
        if (!pgpid_uid_stands(uids[i].validity))
            continue;
        if (strncmp(uids[i].text, "FN", 2))
            continue;
        const char *p = uids[i].text + 2;
        if (*p == ';') {
            p = strchr(p, ':');
            if (!p)
                continue;
        } else if (*p != ':') {
            continue;
        }
        p++;
        if (*p == ' ')
            p++;
        snprintf(out, max, "%s", p);
        return;
    }
}

/**
 * How many other people vouch for each address.
 *
 * --check-sigs rather than --list-sigs, so gpg verifies each signature and
 * marks it '!'. A local certification is not a public statement and does not
 * count; neither does the certificate signing itself.
 */
static int show_certs_count(const char *user)
{
    char listing[1048576];
    const char *argv[] = { "--with-colons", "--check-sigs", user, NULL };
    if (pgpid_capture_engine(argv, listing, sizeof listing) <= 0) {
        pgpid_error(_("Error: Cannot check the signatures of %s."), user);
        return PGPID_FAIL;
    }
    const char *owner = user + (strlen(user) > 16 ? strlen(user) - 16 : 0);

    struct { char addr[320]; int count; } best[MAX_UIDS];
    size_t nbest = 0;
    char cur[320] = "";
    int count = 0;

    for (char *line = listing, *save; ; line = NULL) {
        char *at = strtok_r(line, "\n", &save);
        bool last = !at;

        bool boundary = last || !strncmp(at, "uid:", 4) || !strncmp(at, "uat:", 4);
        if (boundary && *cur) {
            size_t k = 0;
            for (; k < nbest; k++)
                if (!strcmp(best[k].addr, cur))
                    break;
            if (k == nbest && nbest < MAX_UIDS) {
                snprintf(best[nbest].addr, sizeof best[0].addr, "%s", cur);
                best[nbest++].count = count;
            } else if (k < nbest && count > best[k].count) {
                best[k].count = count;
            }
        }
        if (last)
            break;
        if (boundary) {
            *cur = '\0';
            count = 0;
            /* Only a uid that still stands collects a count; a revoked one
             * carries certifications that no longer say anything. */
            if (!strncmp(at, "uid:", 4) && at[4] != 'r' && at[4] != 'e') {
                char text[512] = "";
                unsigned nf = 0;
                char *start = at;
                for (char *p = at; nf < 12; p++) {
                    if (*p == ':' || !*p) {
                        if (nf == 9)
                            snprintf(text, sizeof text, "%.*s", (int)(p - start), start);
                        nf++;
                        if (!*p)
                            break;
                        start = p + 1;
                    }
                }
                size_t len = 0;
                const char *addr = pgpid_uid_address(text, &len);
                if (addr && len < sizeof cur)
                    snprintf(cur, sizeof cur, "%.*s", (int)len, addr);
            }
            continue;
        }
        if (strncmp(at, "sig:!::", 7) || !*cur)
            continue;
        /* Fields: 5 is who signed, 11 the signature class. */
        char *field[13] = { NULL };
        unsigned nf = 0;
        char *start = at;
        for (char *p = at; nf < 13; p++) {
            if (*p == ':' || !*p) {
                field[nf++] = start;
                if (!*p)
                    break;
                *p = '\0';
                start = p + 1;
            }
        }
        if (nf < 12)
            continue;
        const char *by = field[4] ? field[4] : "";
        const char *class = field[10] ? field[10] : "";
        size_t cl = strlen(class);
        if (strcmp(by, owner) && !(cl && class[cl - 1] == 'l'))
            count++;
    }

    for (size_t i = 0; i < nbest; i++)
        printf("%s\t%d\n", best[i].addr, best[i].count);
    return PGPID_OK;
}

int pgpid_action_cert_email(int argc, char **argv)
{
    const char *keyservers = NULL, *pseudo = NULL, *target = NULL;
    char toadd[MAX_LIST][320], torev[MAX_LIST][320];
    size_t nadd = 0, nrev = 0;
    bool revoke_all = false, assume_yes = false, show_unusable = false;
    bool info = false, certs_count = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-A") || !strcmp(a, "--add")
            || !strcmp(a, "-R") || !strcmp(a, "--rev") || !strcmp(a, "--revoke")) {
            bool adding = (a[1] == 'A' || !strcmp(a, "--add"));
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants an address."), a);
                return PGPID_USAGE;
            }
            char addr[320];
            unbracket(argv[i], addr, sizeof addr);
            if (!looks_like_address(addr)) {
                pgpid_error(_("Error: Invalid email '%s'."), argv[i]);
                return PGPID_USAGE;
            }
            if ((adding ? nadd : nrev) >= MAX_LIST) {
                pgpid_error(_("Error: Too many addresses at once."));
                return PGPID_USAGE;
            }
            snprintf(adding ? toadd[nadd++] : torev[nrev++], 320, "%s", addr);
        } else if (!strcmp(a, "--revoke-all") || !strcmp(a, "--revokeall")) {
            revoke_all = true;
        } else if (!strcmp(a, "-y") || !strcmp(a, "--yes")) {
            assume_yes = true;
        } else if (!strcmp(a, "-N") || !strcmp(a, "--name")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a name."), a);
                return PGPID_USAGE;
            }
            pseudo = argv[i];
        } else if (!strcmp(a, "-C") || !strcmp(a, "--extra-comment")
                   || !strcmp(a, "--extracomment")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a note."), a);
                return PGPID_USAGE;
            }
            pgpid_error(_("Notice: --extra-comment is ignored: a note is carried by "
                        "its own NOTE: uid."));
        } else if (!strcmp(a, "-c") || !strcmp(a, "--certs-count")
                   || !strcmp(a, "--certscount")) {
            certs_count = true;
        } else if (!strcmp(a, "--show-unusable") || !strcmp(a, "--showunusable")) {
            show_unusable = true;
        } else if (!strcmp(a, "--info")) {
            info = true;
        } else if (!strcmp(a, "-K") || !strcmp(a, "--keyservers")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a list, empty for none."), a);
                return PGPID_USAGE;
            }
            keyservers = argv[i];
        } else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
            /* Accepted and ignored: gpg's own noise goes to stderr either way. */
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
            pgpid_try_help("email");
            return PGPID_USAGE;
        } else if (!target) {
            target = a;
        }
    }

    char user[41];
    int ret = resolve_target(target, user, sizeof user);
    if (ret)
        return ret;

    struct pgpid_uid uids[MAX_UIDS];
    size_t nuids = 0;
    bool changed = false;

    if (nadd) {
        if (!pgpid_upgrade_uids(user, keyservers))
            return PGPID_FAIL;
        nuids = pgpid_list_uids(user, true, uids, MAX_UIDS);
        if (!nuids) {
            pgpid_error(_("Error: No editable certificate %s here."), user);
            return PGPID_FAIL;
        }
        char name[512] = "";
        if (pseudo)
            snprintf(name, sizeof name, "%s", pseudo);
        else
            own_name(uids, nuids, name, sizeof name);

        for (size_t a = 0; a < nadd; a++) {
            char want[900];
            /* Bounded explicitly: the compiler cannot see that a name is
             * 511 characters at most and an address 319. */
            if (*name)
                snprintf(want, sizeof want, "%.511s <%.319s>", name, toadd[a]);
            else
                snprintf(want, sizeof want, "%.*s <%.319s>",
                         (int)(strchr(toadd[a], '@') - toadd[a]), toadd[a], toadd[a]);

            bool here = false, struck = false;
            for (size_t i = 0; i < nuids; i++) {
                if (strcmp(uids[i].text, want))
                    continue;
                if (pgpid_uid_stands(uids[i].validity))
                    here = true;
                else
                    struck = true;
            }
            if (here) {
                pgpid_error(_("Notice: Certificate %s already carries '%s'."), user, want);
                continue;
            }
            if (struck) {
                pgpid_error(_("Notice: '%s' was revoked earlier and cannot be added "
                            "again — OpenPGP keeps revoked User IDs on the "
                            "certificate forever."), want);
                continue;
            }
            pgpid_error(_("Notice: Adding '%s' into certificate %s…"), want, user);
            const char *add[] = { "--batch", "--quick-add-uid", user, want, NULL };
            if (pgpid_run_engine(add)) {
                pgpid_error(_("Error: gpg would not add '%s'."), want);
                return PGPID_FAIL;
            }
            changed = true;
        }
    }

    bool revoked = false;
    for (size_t r = 0; r < nrev; r++) {
        nuids = pgpid_list_uids(user, true, uids, MAX_UIDS);
        const char *victim = NULL;
        size_t addresses = 0;
        /* The vCard shape first, the legacy one after: peeling one per call
         * means the caller sees each removal, and re-runs for the next. */
        for (int pass = 0; pass < 2 && !victim; pass++) {
            for (size_t i = 0; i < nuids; i++) {
                if (!pgpid_uid_stands(uids[i].validity))
                    continue;
                size_t len = 0;
                bool is_vcard = vcard_email(uids[i].text, &len) != NULL;
                if (pass == 0 ? !is_vcard : is_vcard)
                    continue;
                if (uid_carries(uids[i].text, torev[r])) {
                    victim = uids[i].text;
                    break;
                }
            }
        }
        for (size_t i = 0; i < nuids; i++)
            if (pgpid_uid_stands(uids[i].validity) && uid_is_email(uids[i].text))
                addresses++;

        if (!victim) {
            pgpid_error(_("Error: No revokable email '%s' inside certificate %s."),
                        torev[r], user);
            return PGPID_FAIL;
        }
        if (addresses < 2) {
            pgpid_error(_("Error: At least one email must be retained."));
            return PGPID_FAIL;
        }
        if (!pgpid_revoke_uid(user, victim, assume_yes))
            return PGPID_FAIL;
        revoked = changed = true;
    }

    if (revoke_all) {
        nuids = pgpid_list_uids(user, true, uids, MAX_UIDS);
        long newest = -1;
        size_t keep = 0, n = 0;
        for (size_t i = 0; i < nuids; i++) {
            if (!pgpid_uid_stands(uids[i].validity) || !uid_is_email(uids[i].text))
                continue;
            n++;
            if (uids[i].created >= newest) {
                newest = uids[i].created;
                keep = i;
            }
        }
        if (n < 2) {
            pgpid_error(_("Warning: Nothing to revoke."));
        } else {
            for (size_t i = 0; i < nuids; i++) {
                if (i == keep)
                    continue;
                if (!pgpid_uid_stands(uids[i].validity) || !uid_is_email(uids[i].text))
                    continue;
                if (!pgpid_revoke_uid(user, uids[i].text, assume_yes))
                    return PGPID_FAIL;
                revoked = changed = true;
            }
        }
    }

    if (revoked && !pgpid_fix_primary(user))
        return PGPID_FAIL;

    ret = PGPID_OK;
    if (changed)
        ret = pgpid_send_to_keyservers(user, keyservers ? keyservers : PGPID_KEYSERVERS);

    if (certs_count)
        return show_certs_count(user) ? PGPID_FAIL : ret;

    /* The colon listing, not show-only-fpr-mbox: that one cannot tell an
     * address that still stands from one that does not, and drops the second
     * silently — which left --show-unusable with nothing to show. */
    nuids = pgpid_list_uids(user, false, uids, MAX_UIDS);
    char seen[MAX_UIDS][330];
    size_t nseen = 0;
    unsigned idx[2] = { 0, 0 };
    for (size_t i = 0; i < nuids; i++) {
        bool stands = pgpid_uid_stands(uids[i].validity);
        if (!stands && !show_unusable)
            continue;
        size_t len = 0;
        const char *addr = pgpid_uid_address(uids[i].text, &len);
        if (!addr)
            continue;
        char bucket[330];
        snprintf(bucket, sizeof bucket, "%s%.*s", stands ? "" : "_UNUSABLE:",
                 (int)len, addr);
        bool already = false;
        for (size_t k = 0; k < nseen; k++)
            if (!strcmp(seen[k], bucket))
                already = true;
        if (already)
            continue;
        if (nseen < MAX_UIDS)
            snprintf(seen[nseen++], sizeof seen[0], "%s", bucket);
        if (!info) {
            printf("%.*s\n", (int)len, addr);
            continue;
        }
        printf("pgpid_EMAIL%s[%u]='%.*s'\n", stands ? "" : "_UNUSABLE",
               idx[stands ? 0 : 1]++, (int)len, addr);
    }
    return ret;
}

/* The first address on a uid that still stands. A certificate carries its
 * name and its identifier on uids of their own, so the first uid is rarely
 * the one with an address on it. */
const char *pgpid_first_mbox(const struct pgpid_key *key)
{
    for (size_t i = 0; i < key->nuid; i++) {
        const struct pgpid_keyuid *u = &key->uid[i];
        if (u->revoked || u->invalid)
            continue;
        if (*u->address)
            return u->address;
    }
    return NULL;
}
