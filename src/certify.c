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
#include <sys/random.h>

#define MAX_UIDS 128
#define UID_MAX PGPID_UID_MAX

/* What the shell answers, kept because foodjis switches on these. */
#define CERT_NO_PRIVKEY   140
#define CERT_NO_CERT      141
#define CERT_SELF         142
#define CERT_NO_MATCH     143

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " certify [OPTIONS]... [TARGET_KEYFPR] [TARGET_U4|TARGET_U5]\n"
        "\n"
        "Certify somebody else. Both operands are optional and may come in either\n"
        "order — they are recognised by their shape, not by their place. What is\n"
        "missing is asked for, unless --batch says there is nobody to ask.\n"
        "\n"
        "TARGET_KEYFPR is the whole forty characters, read off the other person's\n"
        "card — never a search pattern, because a certification cannot be taken\n"
        "back. Without it, whoever carries TARGET_U4 is looked up here and on the\n"
        "keyservers, and eight characters of the fingerprint are asked for, taken\n"
        "at a place drawn at random: enough to prove the card is in your hand.\n"
        "\n"
        "TARGET_U4 may be written u4VALUE, the deprecated u4=VALUE, or bare.\n"
        "Given together with a fingerprint, it asks that the certificate carry it,\n"
        "and refuses otherwise.\n"
        "\n"
        "Certification means : I know this other certificate belongs to this real person.\n"
        "This implies verifying the civil status and the public key fingerprint of the TARGET.\n"
        "This allows you to expand and strengthen your web of trust and those of your close ones.\n"
        "This is a commitment: the more you certify, the more you increase your reputation,\n"
        "but if you do it wrong, you will ruin your credibility.\n"
        "\n"
        "OPTIONS:\n"
        "  -u, --use-privkey NAME|KEYID Select private key to use. Default: Guess it from connected token\n"
        "  -E, --all-emails             Also certify every PGP uid containing an email. For compatibility with some legacy software.\n"
        "  -R, --revoke                 Revoke your previous certifications on someone else's certificate\n"
        "  -o, --credibility VALUE      What credibility do you assign to the target to correctly certify others {undefined,marginal,full,never}\n"
        "      --ownertrust VALUE       The same, under the name gpg gives it - Default: marginal\n"
        "  -l, --local                  « Non-exportable » certification. Pretty useless, except for testing\n"
        "  -K, --keyservers KEYSERVERS  If non-empty, receive and send updated certificate from and to this keyservers - Default: "
        "%s"
        "\n"
        "  -h, --help                   Print this help and exit\n"
        "  -V, --version                Print the version and exit\n"
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
 * The same head, spelled the deprecated way: the tag, a '=', then the body.
 *
 * Ours write the eid glued to its tag; certificates already in the wild
 * separate the two. A uid is matched by substring, so one spelling never finds
 * the other, and a certificate that carries only the old one would be reported
 * as carrying no identifier at all. Both are offered until every certificate
 * has migrated — gpg lists a key matching several patterns once, so offering
 * two costs nothing but the asking. Empty when the head is not an eid.
 */
static void match_head_deprecated(const char *head, char *out, size_t max)
{
    if ((head[0] == 'u') && (head[1] == '4' || head[1] == '5'))
        snprintf(out, max, "u%c=%s", head[1], head + 2);
    else
        *out = '\0';
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
#define MAX_CANDIDATES 32
#define WINDOW 8                      /* two groups of four, as a card prints them */

/**
 * Accept an identifier however it was written.
 *
 * Glued to its tag, which is what we write; behind the deprecated separator,
 * which certificates in the wild still carry; or bare, which is how a value
 * read aloud off a card or copied from a sticker arrives. Bare is tried as a
 * u4 then as a u5 — the two shapes cannot be mistaken for one another.
 */
static bool eid_operand(const char *a, char *out, size_t max)
{
    /* Longer than the longest eid: not one, and not worth glueing tags onto. */
    if (strlen(a) > 48)
        return false;
    if (pgpid_eid_body_is_sound(a)) {
        snprintf(out, max, "%s", a);
        return true;
    }
    char glued[64];
    /* u4=…, u4:…, udid4=… and their u5 counterparts. */
    if (a[0] == 'u') {
        const char *p = a + 1;
        if (!strncmp(p, "did", 3))
            p += 3;
        if ((*p == '4' || *p == '5') && (p[1] == '=' || p[1] == ':')) {
            snprintf(glued, sizeof glued, "u%c%s", *p, p + 2);
            if (pgpid_eid_body_is_sound(glued)) {
                snprintf(out, max, "%s", glued);
                return true;
            }
        }
    }
    for (char digit = '4'; digit <= '5'; digit++) {
        snprintf(glued, sizeof glued, "u%c%s", digit, a);
        if (pgpid_eid_body_is_sound(glued)) {
            snprintf(out, max, "%s", glued);
            return true;
        }
    }
    return false;
}

/**
 * Ask the keyservers who carries this identifier, and bring them here.
 *
 * gpg cannot locate a key by anything but an address, so the index is asked
 * for directly: --search-keys in colon mode answers with whole fingerprints,
 * which --recv-keys then fetches by name. Both spellings, for as long as both
 * exist. A server that will not answer is not a reason to stop.
 */
static void fetch_by_eid(const char *eid, const char *list)
{
    if (!*list || !*eid)
        return;
    char spellings[2][80];
    snprintf(spellings[0], sizeof spellings[0], "%s", eid);
    snprintf(spellings[1], sizeof spellings[1], "u%c=%s", eid[1], eid + 2);

    for (char *copy = strdup(list), *save = NULL,
         *ks = copy ? strtok_r(copy, " \t,", &save) : NULL; ks;
         ks = strtok_r(NULL, " \t,", &save)) {
        for (unsigned s = 0; s < 2; s++) {
            char found[8192];
            const char *search[] = { "--batch", "--with-colons", "--keyserver", ks,
                                     "--search-keys", spellings[s], NULL };
            if (pgpid_capture_engine(search, found, sizeof found) < 0)
                continue;
            for (char *line = found, *lsave; (line = strtok_r(line, "\n", &lsave));
                 line = NULL) {
                if (strncmp(line, "pub:", 4))
                    continue;
                char fpr[41] = "";
                if (sscanf(line + 4, "%40[0-9A-Fa-f]", fpr) != 1
                    || !pgpid_is_fingerprint(fpr))
                    continue;
                const char *recv[] = { "--quiet", "--keyserver", ks,
                                       "--recv-keys", fpr, NULL };
                pgpid_run_engine(recv);
            }
        }
    }
}

/**
 * The certificates carrying this identifier, by fingerprint.
 *
 * Capped, and a keyring holding more than the cap is refused rather than
 * silently truncated: choosing among candidates one cannot see is not a
 * choice. Nobody legitimately carries thirty-two certificates for one
 * identity — such a keyring has been fed something.
 */
static size_t collect_candidates(const char *pats[],
                                 char out[][41], size_t max, bool *overflow)
{
    *overflow = false;
    size_t npat = 0;
    while (pats[npat])
        npat++;
    struct pgpid_keyring *kr = pgpid_keys_load(pats, npat, 0);
    size_t n = 0;
    for (size_t i = 0; i < pgpid_keys_count(kr); i++) {
        const struct pgpid_key *key = pgpid_keys_at(kr, i);
        if (!*key->fpr)
            continue;
        if (n >= max)
            *overflow = true;
        else
            snprintf(out[n++], 41, "%s", key->fpr);
    }
    pgpid_keys_free(kr);
    return n;
}

/**
 * Which certificate, confirmed against the card in the certifier's hand.
 *
 * Eight hexadecimal characters, not forty: enough to prove they are holding
 * the object, short enough to read aloud without losing one's place. Which
 * eight is drawn at random, so that nobody learns to copy the same corner of
 * every card, and so that a shoulder-surfer learns nothing reusable.
 *
 * Exactly one candidate may match. Eight characters could in principle land
 * on two of them, and signing "the first that fits" is not a check.
 */
static int confirm_fingerprint(char cands[][41], size_t n, char *out, size_t max)
{
    /* Drawn from the kernel, not from a seeded generator: the point of moving
     * the window is that it cannot be anticipated. */
    unsigned char byte = 0;
    if (getrandom(&byte, 1, 0) != 1)
        return PGPID_FAIL;
    unsigned at = (unsigned)((byte % (40 / WINDOW)) * WINDOW);

    pgpid_error(_("Notice: %zu certificate(s) carry this identifier:"), n);
    for (size_t i = 0; i < n; i++) {
        char shown[64];
        size_t k = 0;
        for (unsigned c = 0; c < 40; c++) {
            if (c && !(c % 4))
                shown[k++] = ' ';
            shown[k++] = (c >= at && c < at + WINDOW) ? '.' : cands[i][c];
        }
        shown[k] = '\0';
        pgpid_error("  %s", shown);
    }

    char prompt[256];
    snprintf(prompt, sizeof prompt,
             _("Characters %u to %u of the fingerprint on the card: "),
             at + 1, at + WINDOW);
    char typed[WINDOW + 1];
    if (!pgpid_ask_hex(prompt, WINDOW, typed, sizeof typed))
        return CERT_NO_MATCH;

    const char *hit = NULL;
    for (size_t i = 0; i < n; i++) {
        if (!strncmp(cands[i] + at, typed, WINDOW)) {
            if (hit) {
                pgpid_error(_("Error: Those eight characters fit more than one certificate."));
                return CERT_NO_MATCH;
            }
            hit = cands[i];
        }
    }
    if (!hit) {
        pgpid_error(_("Error: No certificate here has those characters there."));
        return CERT_NO_MATCH;
    }
    snprintf(out, max, "%.40s", hit);
    return PGPID_OK;
}

/** Does this uid carry the identifier, in either spelling? */
static bool uid_carries(const char *uid, const char *head, const char *old)
{
    if (head && strstr(uid, head))
        return true;
    return old && *old && strstr(uid, old);
}

static size_t collect_uids(const char *fpr, const char *head, const char *old,
                           bool all_emails, char out[][UID_MAX], size_t max)
{
    const char *pat[] = { fpr };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
    const struct pgpid_key *key = pgpid_keys_at(kr, 0);
    if (!key) {
        pgpid_keys_free(kr);
        return 0;
    }

    /* The uid validity letters, which carry a distinction the record's own
     * flags do not: expired and uncertified look alike otherwise. Same
     * order as the uids. */
    char letters[MAX_UIDS + 1];
    size_t nletters = pgpid_uid_validities(fpr, letters, sizeof letters);

    size_t n = 0;
    for (size_t i = 0; i < key->nuid && n < max; i++) {
        const struct pgpid_keyuid *u = &key->uid[i];
        if (u->revoked || u->invalid)
            continue;
        if (i < nletters && (letters[i] == 'r' || letters[i] == 'e'))
            continue;
        if (!strstr(u->text, "UID:urn:eid:"))
            continue;
        if (head && !uid_carries(u->text, head, old))
            continue;
        snprintf(out[n++], UID_MAX, "%s", u->text);
    }

    if (!n && head) {
        for (size_t i = 0; i < key->nuid && n < max; i++) {
            const struct pgpid_keyuid *u = &key->uid[i];
            if (u->revoked || u->invalid)
                continue;
            if (i < nletters && (letters[i] == 'r' || letters[i] == 'e'))
                continue;
            if (uid_carries(u->text, head, old))
                snprintf(out[n++], UID_MAX, "%s", u->text);
        }
    }

    if (all_emails) {
        for (size_t i = 0; i < key->nuid && n < max; i++) {
            const struct pgpid_keyuid *u = &key->uid[i];
            if (u->revoked || u->invalid)
                continue;
            if (i < nletters && (letters[i] == 'r' || letters[i] == 'e'))
                continue;
            if (!*u->address)
                continue;
            bool already = false;
            for (size_t k = 0; k < n; k++)
                if (!strcmp(out[k], u->text))
                    already = true;
            if (!already)
                snprintf(out[n++], UID_MAX, "%s", u->text);
        }
    }

    pgpid_keys_free(kr);
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
static size_t candidates_for(const char *pats[], const char *target, bool *among)
{
    *among = false;
    size_t npat = 0;
    while (pats[npat])
        npat++;
    struct pgpid_keyring *kr = pgpid_keys_load(pats, npat, 0);
    size_t n = 0;
    for (size_t i = 0; i < pgpid_keys_count(kr); i++) {
        const struct pgpid_key *key = pgpid_keys_at(kr, i);
        if (!*key->fpr)
            continue;
        n++;
        if (!strcmp(key->fpr, target))
            *among = true;
    }
    pgpid_keys_free(kr);
    return n;
}

/** Does this certificate exist here at all? */
static bool key_is_here(const char *fpr)
{
    const char *pat[] = { fpr };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
    bool here = pgpid_keys_count(kr) > 0;
    pgpid_keys_free(kr);
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
        } else if (eid_operand(a, eid, sizeof eid)) {
            /* Whichever way it was written, and whichever order it came in. */
        } else {
            pgpid_error(_("Error: '%s' is neither a fingerprint nor an identifier."), a);
            return PGPID_USAGE;
        }
    }

    /* Neither given: ask. The shell asks for whatever it is missing, and a
     * caller that cannot be asked says so with --batch. */
    if (!*target && !*eid) {
        char line[128];
        if (!pgpid_ask(_("Whom are you certifying? A fingerprint or an identifier: "),
                       line, sizeof line))
            return PGPID_USAGE;
        if (pgpid_is_fingerprint(line)) {
            for (size_t k = 0; line[k] && k < 40; k++)
                target[k] = (line[k] >= 'a' && line[k] <= 'f') ? line[k] - 32 : line[k];
            target[40] = '\0';
        } else if (!eid_operand(line, eid, sizeof eid)) {
            pgpid_error(_("Error: '%s' is neither a fingerprint nor an identifier."), line);
            return PGPID_USAGE;
        }
    }

    char mine[41];
    int ret = signing_key(privkey, mine, sizeof mine);
    if (ret)
        return ret;

    const char *list = keyservers ? keyservers : PGPID_KEYSERVERS;

    /* Certify what stands now, not a copy that may be months behind. A server
     * that will not answer is not a reason to stop: the certificate is here. */
    if (*list && *target) {
        for (char *copy = strdup(list), *save = NULL,
             *ks = copy ? strtok_r(copy, " \t,", &save) : NULL; ks;
             ks = strtok_r(NULL, " \t,", &save)) {
            const char *recv[] = { "--quiet", "--keyserver", ks, "--recv-keys", target, NULL };
            pgpid_run_engine(recv);
        }
    }

    char head[64], old[sizeof head + 2] = "";
    const char *pats[3] = { NULL, NULL, NULL };
    if (*eid) {
        match_head(eid, head, sizeof head);
        match_head_deprecated(head, old, sizeof old);
        pats[0] = head;
        pats[1] = *old ? old : NULL;
    }

    /* An identifier and no fingerprint: find who carries it — here, then on
     * the keyservers — and have the certifier confirm which one against the
     * card in their hand. That confirmation is the certification's whole
     * substance, so it is asked for even when only one candidate turned up. */
    if (*eid && !*target) {
        char cands[MAX_CANDIDATES][41];
        bool over = false;
        size_t n = collect_candidates(pats, cands, MAX_CANDIDATES, &over);
        if (!n) {
            fetch_by_eid(eid, list);
            n = collect_candidates(pats, cands, MAX_CANDIDATES, &over);
        }
        if (over) {
            pgpid_error(_("Error: More than %d certificates carry '%s'."),
                        MAX_CANDIDATES, eid);
            pgpid_error(_("Notice: Name the fingerprint to say which one."));
            return CERT_NO_MATCH;
        }
        if (!n) {
            pgpid_error(_("Error: Nobody here or on the keyservers carries '%s'."), eid);
            return CERT_NO_CERT;
        }
        ret = confirm_fingerprint(cands, n, target, sizeof target);
        if (ret)
            return ret;
    }

    if (*eid) {
        bool among = false;
        size_t n = candidates_for(pats, target, &among);
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
    size_t nuids = collect_uids(target, *eid ? head : NULL, *eid ? old : NULL, all_emails,
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
