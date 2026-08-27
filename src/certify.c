/* Vouching for somebody else.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * A certification says one thing: I have checked that this certificate
 * belongs to this person. It cannot be withdrawn — revoking adds a later
 * statement, it does not erase the first — so the fingerprint is required
 * here and a search pattern is never accepted. `del` and `push` refuse for
 * the same reason.
 *
 * What gets signed is the identity uid, the one carrying the entity
 * identifier, and nothing else unless `--all-emails` asks. Signing every uid
 * would vouch for things nobody checked: an address, a phone number, a note.
 *
 * The identifier is matched on its head only. A u4's last fourteen characters
 * say roughly where somebody was born, and "roughly" is the point — they
 * separate two people who would otherwise collide, they are not part of what
 * the certification is about.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_UIDS 128
#define UID_MAX  512

/* What the shell answers, kept because foodjis switches on these. */
#define CERT_NO_PRIVKEY   140
#define CERT_NO_CERT      141
#define CERT_SELF         142
#define CERT_NO_MATCH     143

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " certify [OPTIONS]... KEYFPR [U4|U5]\n"
        "\n"
        "Vouch for somebody else: state that this certificate is theirs.\n"
        "\n"
        "KEYFPR is the whole forty-character fingerprint, read off the other\n"
        "person's card and checked against it — never a search pattern, because\n"
        "a certification cannot be taken back. Giving the identifier as well\n"
        "asks that the certificate carry it, and refuses otherwise.\n"
        "\n"
        "Certifying is a commitment. It builds your standing, and spends it if\n"
        "you do it without looking.\n"
        "\n"
        "OPTIONS:\n"
        "  -u, --use-privkey NAME|KEYID  Certify with this key\n"
        "                                Default: the one the connected card belongs to\n"
        "  -E, --all-emails              Also certify every uid carrying an email,\n"
        "                                for software that expects it there\n"
        "  -R, --revoke                  Revoke your earlier certifications on it\n"
        "  -o, --credibility VALUE       How well they certify others, in turn\n"
        "      --ownertrust VALUE        The same, under the name gpg gives it\n"
        "                                {undefined,marginal,full,never} - Default: marginal\n"
        "  -l, --local                   Certify without exporting — useful for testing\n"
        "  -K, --keyservers SERVERS      Send the result to these, space separated\n"
        "                                Empty for none. Default: "
        "%s"
        "\n"
        "  -h, --help                    Print this help and exit\n"
        "  -V, --version                 Print the version and exit\n"
        "\n"
        "Return value:\n"
        "-   0 No error\n"
        "-   2 Input/Usage error\n"
        "- %d Nothing to certify with — say which key with --use-privkey\n"
        "- %d No certificate carries that fingerprint\n"
        "- %d Self-certification is not innovative! ;-)\n"
        "- %d That certificate does not carry that identifier\n"),
            PGPID_NAME, PGPID_KEYSERVERS, CERT_NO_PRIVKEY, CERT_NO_CERT, CERT_SELF, CERT_NO_MATCH);
}

/**
 * The head of an identifier — what a uid must contain to be the right one.
 *
 * A u4 ends in fourteen characters of coordinates that are deliberately
 * fuzzy: they exist to tell apart two people born the same day with the same
 * name, not to be exact. Matching on them would refuse a certificate that
 * spells the same birthplace slightly differently. One character of them is
 * kept — enough to keep the shapes apart, loose enough to be true.
 *
 * A u5 is a timestamp, exact by construction, and is matched whole.
 */
static void match_head(const char *eid, char *out, size_t max)
{
    if (eid[0] == 'u' && eid[1] == '4' && pgpid_eid_body_is_sound(eid)) {
        size_t n = 2 + 22 + 1;
        if (n < max) {
            memcpy(out, eid, n);
            out[n] = '\0';
            return;
        }
    }
    snprintf(out, max, "%s", eid);
}

/**
 * The fingerprint of the key that will sign.
 *
 * Named, or the one the connected card belongs to. Nothing else: the shell
 * asks at this point, and asking is what a precise command exists to avoid.
 */
static int signing_key(const char *given, char *out, size_t max)
{
    if (!given) {
        if (pgpid_card_certification_key(out, max))
            return PGPID_OK;
        pgpid_error(_("Error: No card answered, so there is nothing to certify with."));
        pgpid_error(_("Say which key with --use-privkey."));
        return CERT_NO_PRIVKEY;
    }

    char listing[8192];
    const char *argv[] = { "--list-options", "show-only-fpr-mbox",
                           "--list-secret-keys", given, NULL };
    if (pgpid_capture_engine(argv, listing, sizeof listing) < 0) {
        pgpid_error(_("Error: Cannot list the secret keys."));
        return PGPID_FAIL;
    }

    /* One fingerprint, or the choice was not made. Two different keys behind
     * one name is exactly the case where guessing signs with the wrong one. */
    char found[41] = "";
    bool several = false;
    for (char *line = listing, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        char fpr[41] = "";
        sscanf(line, "%40s", fpr);
        if (!pgpid_is_fingerprint(fpr))
            continue;
        if (*found && strcmp(found, fpr))
            several = true;
        snprintf(found, sizeof found, "%s", fpr);
    }
    if (!*found || several) {
        pgpid_error(_("Error: '%s' names %s secret key."), given,
                    several ? "more than one" : "no");
        return PGPID_FAIL;
    }
    snprintf(out, max, "%s", found);
    return PGPID_OK;
}

/**
 * The uids that should carry the signature.
 *
 * The identity uid first — that is what a certification is about. Older
 * certificates, minted before the shape existed, have their identifier
 * somewhere else, and those are taken instead rather than refused. Email
 * uids come last and only when asked.
 *
 * Revoked and expired uids are left alone: signing them would state
 * something about a name its owner has withdrawn.
 */
static size_t collect_uids(const char *fpr, const char *head, bool all_emails,
                           char out[][UID_MAX], size_t max)
{
    gpgme_ctx_t ctx;
    if (pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL))
        return 0;

    gpgme_key_t key = NULL;
    if (gpgme_op_keylist_start(ctx, fpr, 0) || gpgme_op_keylist_next(ctx, &key)) {
        gpgme_op_keylist_end(ctx);
        gpgme_release(ctx);
        return 0;
    }
    gpgme_op_keylist_end(ctx);

    /* gpgme cannot say "expired" about a uid — it arrives as unknown, which
     * is also what an uncertified one looks like. The letters gpg prints
     * carry the distinction, in the same order. */
    char letters[MAX_UIDS + 1];
    size_t nletters = pgpid_uid_validities(fpr, letters, sizeof letters);

    size_t n = 0;
    unsigned i = 0;
    for (gpgme_user_id_t u = key->uids; u && n < max; u = u->next, i++) {
        if (!u->uid || u->revoked || u->invalid)
            continue;
        if (i < nletters && (letters[i] == 'r' || letters[i] == 'e'))
            continue;
        if (!strstr(u->uid, "UID:urn:eid:"))
            continue;
        if (head && !strstr(u->uid, head))
            continue;
        snprintf(out[n++], UID_MAX, "%s", u->uid);
    }

    if (!n && head) {
        i = 0;
        for (gpgme_user_id_t u = key->uids; u && n < max; u = u->next, i++) {
            if (!u->uid || u->revoked || u->invalid)
                continue;
            if (i < nletters && (letters[i] == 'r' || letters[i] == 'e'))
                continue;
            if (strstr(u->uid, head))
                snprintf(out[n++], UID_MAX, "%s", u->uid);
        }
    }

    if (all_emails) {
        i = 0;
        for (gpgme_user_id_t u = key->uids; u && n < max; u = u->next, i++) {
            if (!u->uid || u->revoked || u->invalid)
                continue;
            if (i < nletters && (letters[i] == 'r' || letters[i] == 'e'))
                continue;
            if (!u->email || !*u->email)
                continue;
            bool already = false;
            for (size_t k = 0; k < n; k++)
                if (!strcmp(out[k], u->uid))
                    already = true;
            if (!already)
                snprintf(out[n++], UID_MAX, "%s", u->uid);
        }
    }

    gpgme_key_unref(key);
    gpgme_release(ctx);
    return n;
}

/**
 * The certificates carrying this identity.
 *
 * The order of the two questions decides which sentence the operator reads.
 * Asking "does this fingerprint exist" first turns a mistyped fingerprint
 * into "no such certificate", which sends them looking for the wrong problem.
 * Asking "who carries this identity" first lets the answer be the true one:
 * somebody carries it, and what you typed is not them.
 */
/*
 * How many certificates carry this identifier, and whether the one we mean is
 * among them.
 *
 * Counted as the keyring is walked rather than collected into an array: the
 * caller only ever asks those two things, and an array would need a size
 * nobody can choose — a keyserver can hand out as many certificates claiming
 * one identifier as it likes.
 */
static size_t candidates_for(const char *head, const char *target, bool *among)
{
    *among = false;
    gpgme_ctx_t ctx;
    if (pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL))
        return 0;
    size_t n = 0;
    if (!gpgme_op_keylist_start(ctx, head, 0)) {
        gpgme_key_t key = NULL;
        while (!gpgme_op_keylist_next(ctx, &key)) {
            if (key->subkeys && key->subkeys->fpr) {
                n++;
                if (!strcmp(key->subkeys->fpr, target))
                    *among = true;
            }
            gpgme_key_unref(key);
        }
    }
    gpgme_op_keylist_end(ctx);
    gpgme_release(ctx);
    return n;
}

/** Does this certificate exist here at all? */
static bool key_is_here(const char *fpr)
{
    gpgme_ctx_t ctx;
    if (pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL))
        return false;
    gpgme_key_t key = NULL;
    bool here = !gpgme_op_keylist_start(ctx, fpr, 0)
             && !gpgme_op_keylist_next(ctx, &key);
    if (key)
        gpgme_key_unref(key);
    gpgme_op_keylist_end(ctx);
    gpgme_release(ctx);
    return here;
}

int pgpid_action_certify(int argc, char **argv)
{
    const char *privkey = NULL, *keyservers = NULL, *credibility = NULL;
    bool revoke = false, all_emails = false, local = false;
    char target[41] = "", eid[64] = "";

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-u") || !strcmp(a, "--use-privkey")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a key."), a);
                return PGPID_USAGE;
            }
            privkey = argv[i];
        } else if (!strcmp(a, "-R") || !strcmp(a, "--revoke")) {
            revoke = true;
        } else if (!strcmp(a, "-E") || !strcmp(a, "--all-emails")
                   || !strcmp(a, "--allemails")) {
            all_emails = true;
        } else if (!strcmp(a, "-l") || !strcmp(a, "--local")) {
            local = true;
        } else if (!strcmp(a, "-o") || !strcmp(a, "--credibility")
                   || !strcmp(a, "--ownertrust")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a value."), a);
                return PGPID_USAGE;
            }
            credibility = argv[i];
            if (strcmp(credibility, "undefined") && strcmp(credibility, "marginal")
                && strcmp(credibility, "full") && strcmp(credibility, "never")) {
                pgpid_error(_("Error: Unknown credibility value '%s'."), credibility);
                return PGPID_USAGE;
            }
        } else if (!strcmp(a, "-K") || !strcmp(a, "--keyservers")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a list, empty for none."), a);
                return PGPID_USAGE;
            }
            keyservers = argv[i];
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
            pgpid_try_help("certify");
            return PGPID_USAGE;
        } else if (pgpid_is_fingerprint(a)) {
            for (size_t k = 0; a[k] && k < 40; k++)
                target[k] = (a[k] >= 'a' && a[k] <= 'f') ? a[k] - 32 : a[k];
            target[40] = '\0';
        } else if (pgpid_eid_body_is_sound(a)) {
            snprintf(eid, sizeof eid, "%s", a);
        } else {
            pgpid_error(_("Error: '%s' is neither a fingerprint nor an identifier."), a);
            return PGPID_USAGE;
        }
    }

    if (!*target) {
        pgpid_error(_("Error: Which certificate? A whole fingerprint is required —"));
        pgpid_error(_("a certification cannot be taken back, so it is never guessed."));
        usage(stderr);
        return PGPID_USAGE;
    }

    char mine[41];
    int ret = signing_key(privkey, mine, sizeof mine);
    if (ret)
        return ret;

    const char *list = keyservers ? keyservers : PGPID_KEYSERVERS;

    /* Certify what stands now, not a copy that may be months behind. A server
     * that will not answer is not a reason to stop: the certificate is here. */
    if (*list) {
        for (char *copy = strdup(list), *save = NULL,
             *ks = copy ? strtok_r(copy, " \t,", &save) : NULL; ks;
             ks = strtok_r(NULL, " \t,", &save)) {
            const char *recv[] = { "--quiet", "--keyserver", ks, "--recv-keys", target, NULL };
            pgpid_run_engine(recv);
        }
    }

    char head[64];
    if (*eid)
        match_head(eid, head, sizeof head);

    if (*eid) {
        bool among = false;
        size_t n = candidates_for(head, target, &among);
        if (!n) {
            pgpid_error(_("Error: Nobody here carries '%s'."), eid);
            return CERT_NO_CERT;
        }
        if (!among) {
            pgpid_error(_("Error: %s carries '%s', and %s does not."),
                        n == 1 ? "One certificate" : "Several certificates",
                        eid, target);
            return CERT_NO_MATCH;
        }
    } else if (!key_is_here(target)) {
        pgpid_error(_("Error: No certificate here carries %s."), target);
        return CERT_NO_CERT;
    }

    if (!strcmp(target, mine)) {
        pgpid_error(_("Warning: Self-certification is not innovative! ;-)"));
        return CERT_SELF;
    }

    static char uids[MAX_UIDS][UID_MAX];
    size_t nuids = collect_uids(target, *eid ? head : NULL, all_emails,
                                uids, MAX_UIDS);
    if (!nuids) {
        if (*eid) {
            pgpid_error(_("Error: %s carries no usable uid for '%s'."), target, eid);
            return CERT_NO_MATCH;
        }
        pgpid_error(_("Crit: %s carries no identity uid — the certificate looks broken."),
                    target);
        return PGPID_FAIL;
    }

    /* gpg matches a uid exactly when it is given a leading '='. Without it the
     * string is a search, and a search that hits two uids signs both. */
    const char *args[MAX_UIDS + 8];
    char marked[MAX_UIDS][UID_MAX + 2];   /* the '=', the uid, the NUL */
    size_t at = 0;

    if (revoke) {
        if (credibility)
            pgpid_error(_("Info: --credibility means nothing when revoking; ignored."));
        args[at++] = "--quick-revoke-sig";
        args[at++] = target;
        args[at++] = mine;
    } else {
        args[at++] = "--local-user";
        args[at++] = mine;
        args[at++] = local ? "--quick-lsign-key" : "--quick-sign-key";
        args[at++] = target;
    }
    for (size_t i = 0; i < nuids; i++) {
        snprintf(marked[i], sizeof marked[0], "=%.*s", UID_MAX - 1, uids[i]);
        args[at++] = marked[i];
    }
    args[at] = NULL;

    if (pgpid_run_engine(args))
        return PGPID_FAIL;

    if (revoke)
        pgpid_error(_("Notice: gpg reported no error, which does not mean it found "
                    "a certification to revoke."));
    else
        pgpid_error(_("Notice: Signed %zu uid(s) of certificate %s."), nuids, target);

    /* Ownertrust answers a different question — how well this one certifies
     * others — and is set alongside because nobody remembers to do it after. */
    if (!revoke) {
        const char *ot[] = { "--quick-set-ownertrust", target,
                             credibility ? credibility : "marginal", NULL };
        pgpid_run_engine(ot);
    }

    return pgpid_send_to_keyservers(target, list);
}
