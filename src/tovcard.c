/* A certificate, written as a contact card.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * vCard 4.0, RFC 6350. The point is that an address book already knows how to
 * read one — so a certificate stops being something only a cryptography tool
 * can open, and becomes a contact with a face, a telephone and a key.
 *
 * Most of the card is already there: our certificates carry their name, note,
 * telephone and the rest on uids shaped like vCard lines, so those pass
 * through as they stand. What has to be built is the rest — the address from
 * an ordinary `Name <addr>` uid, the key itself, and the photograph, which
 * a listing cannot see and packets.c reads.
 */
#include "pgpid.h"

#include <ctype.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * One content line, folded as RFC 6350 §3.2 wants it.
 *
 * Seventy-five octets, then CRLF and a single space starting each
 * continuation. Not a nicety: a key or a photograph inlined as base64 makes a
 * line thousands of characters long, and readers do reject those.
 */
static size_t fold_point(const char *line, size_t from, size_t budget)
{
    size_t n = strlen(line);
    if (n - from <= budget)
        return n;
    size_t at = from + budget;
    /* Never inside a multi-octet sequence — RFC 6350 §3.2 asks for both
     * "at most 75 octets" and "not in the middle of a UTF-8 character", and
     * a reader given half a character shows a broken glyph rather than a
     * name. Continuation bytes are 10xxxxxx; step back off them. */
    while (at > from && ((unsigned char)line[at] & 0xC0) == 0x80)
        at--;
    return at > from ? at : from + budget;
}

static void fold(const char *line)
{
    size_t n = strlen(line);
    size_t cut = fold_point(line, 0, 75);
    printf("%.*s\r\n", (int)cut, line);
    for (size_t at = cut; at < n; ) {
        size_t next = fold_point(line, at, 74);
        printf(" %.*s\r\n", (int)(next - at), line + at);
        at = next;
    }
}

/** Is this uid one of ours, `PROPERTY:value` or `PROPERTY;PARAM:value`? */
static const char *vcard_property(const char *uid, char *name, size_t max)
{
    size_t i = 0;
    while (uid[i] >= 'A' && uid[i] <= 'Z' && i < max - 1)
        i++;
    if (!i)
        return NULL;
    const char *p = uid + i;
    if (*p == ';')
        p = strchr(p, ':');
    if (!p || *p != ':')
        return NULL;
    memcpy(name, uid, i);
    name[i] = '\0';
    /* One optional space after the colon, which the vCard-uid experiment
     * used and which is not part of the value. */
    return p[1] == ' ' ? p + 2 : p + 1;
}

/** The address inside the angle brackets of a `Name <addr>` uid, or NULL. */
static const char *bracketed_address(const char *uid, char *out, size_t max)
{
    const char *close = strrchr(uid, '>');
    if (!close)
        return NULL;
    const char *open = strrchr(uid, '<');
    if (!open || open > close)
        return NULL;
    /* Nothing but spaces may follow, or it is a name that happens to
     * contain brackets rather than an address at the end. */
    for (const char *p = close + 1; *p; p++)
        if (*p != ' ' && *p != '\t')
            return NULL;
    size_t n = (size_t)(close - open - 1);
    if (!n || n >= max)
        return NULL;
    /* A mailbox, not any string between brackets: 'Frre U4 <a.com>' names
     * nowhere, and a card carrying it as EMAIL would be lying quietly. */
    bool has_at = false;
    for (const char *q = open + 1; q < close; q++)
        has_at = has_at || *q == '@';
    if (!has_at)
        return NULL;
    memcpy(out, open + 1, n);
    out[n] = '\0';
    return out;
}

/**
 * The URL a keyserver would answer with for this certificate.
 *
 * Built rather than stored, from the keyserver the certificate names as its
 * own when it names one, and from ours when it does not.
 */
static bool key_url(const char *keyserver, const char *fpr, char *out, size_t max)
{
    const char *host = strstr(keyserver, "://");
    if (!host)
        return false;
    size_t scheme_len = (size_t)(host - keyserver);
    char scheme[8];
    if (scheme_len >= sizeof scheme)
        return false;
    for (size_t i = 0; i < scheme_len; i++)
        scheme[i] = (char)tolower((unsigned char)keyserver[i]);
    scheme[scheme_len] = '\0';
    host += 3;

    char hostport[256];
    size_t n = 0;
    for (; host[n] && host[n] != '/' && n < sizeof hostport - 8; n++)
        hostport[n] = host[n];
    hostport[n] = '\0';
    if (!n)
        return false;

    bool secure = !strcmp(scheme, "hkps") || !strcmp(scheme, "https");
    if (!secure && !strcmp(scheme, "hkp") && !strchr(hostport, ':'))
        strcat(hostport, ":11371");
    else if (!secure && strcmp(scheme, "hkp") && strcmp(scheme, "http"))
        return false;

    /* Lowercase fingerprint, matching what the web page of the same name
     * produces — two tools writing the same card must write it the same. */
    char lower[80];
    size_t f = 0;
    for (; fpr[f] && f < sizeof lower - 1; f++)
        lower[f] = (char)tolower((unsigned char)fpr[f]);
    lower[f] = '\0';

    snprintf(out, max, "%s://%s/pks/lookup?op=get&search=0x%s",
             secure ? "https" : "http", hostport, lower);
    return true;
}

/**
 * The keyserver the certificate names as its own — subpacket 24.
 *
 * Not simply the first one found: that picks up a value from any signature,
 * including one a subkey binding carries or one an old uid still holds, and
 * it demonstrably answers with a different server than the shell.
 *
 * The rule, which is the shell's: for each user id, take its newest binding
 * self-signature; ignore it if a revocation on that uid is newer still; and
 * among the uids that survive, prefer the one flagged primary, failing that
 * the last. A certificate saying two different things is worth a word,
 * because it means somebody set it twice and one of the two is stale.
 */
char *pgpid_preferred_keyserver(const unsigned char *buf, size_t len,
                                const char *fpr)
{
    static char chosen[256];
    char from_primary[256] = "", from_last[256] = "", seen_other[256] = "";
    const char *keyid = strlen(fpr) >= 16 ? fpr + strlen(fpr) - 16 : fpr;

    const unsigned char *p = buf, *end = buf + len;
    struct pgpid_packet pkt;
    bool in_uid = false;
    unsigned long newest_binding = 0, newest_revocation = 0;
    char uid_keyserver[256] = "";
    bool uid_primary = false;

    /* Closes the uid just walked past, keeping what it said. */
    #define FLUSH()                                                          \
        do {                                                                 \
            if (in_uid && newest_binding && newest_binding > newest_revocation \
                && *uid_keyserver) {                                         \
                if (uid_primary)                                             \
                    snprintf(from_primary, sizeof from_primary, "%s", uid_keyserver); \
                if (*from_last && strcmp(from_last, uid_keyserver))          \
                    snprintf(seen_other, sizeof seen_other, "%s", from_last); \
                snprintf(from_last, sizeof from_last, "%s", uid_keyserver);  \
            }                                                                \
        } while (0)

    while (pgpid_packet_next(p, end, &pkt)) {
        p = pkt.next;
        if (pkt.tag == TAG_USER_ID) {
            FLUSH();
            in_uid = true;
            newest_binding = newest_revocation = 0;
            uid_keyserver[0] = '\0';
            uid_primary = false;
            continue;
        }
        if (pkt.tag != TAG_SIGNATURE) {
            /* A key or subkey packet ends the run of certifications. */
            FLUSH();
            in_uid = false;
            continue;
        }
        if (!in_uid)
            continue;

        unsigned type;
        unsigned long created;
        const char *issuer;
        if (!pgpid_signature_read(&pkt, &type, &created, &issuer))
            continue;
        /* Only what the certificate says about itself: a third party may
         * suggest a keyserver, and it is not theirs to say. */
        if (!issuer || strcasecmp(issuer, keyid))
            continue;

        if (type == SIG_CERT_REVOKE) {
            if (created > newest_revocation)
                newest_revocation = created;
            continue;
        }
        if (type < SIG_CERT_LOWEST || type > SIG_CERT_HIGHEST)
            continue;
        if (created <= newest_binding)
            continue;

        newest_binding = created;
        uid_keyserver[0] = '\0';
        uid_primary = false;
        const unsigned char *value;
        size_t vlen;
        if (pgpid_signature_subpacket(&pkt, 24, &value, &vlen)
            && vlen && vlen < sizeof uid_keyserver) {
            memcpy(uid_keyserver, value, vlen);
            uid_keyserver[vlen] = '\0';
        }
        if (pgpid_signature_subpacket(&pkt, 25, &value, &vlen) && vlen && value[0])
            uid_primary = true;
    }
    FLUSH();
    #undef FLUSH

    const char *pick = *from_primary ? from_primary : from_last;
    if (!*pick)
        return NULL;
    if (*seen_other && strcmp(seen_other, pick))
        pgpid_error(_("Warning: Several preferred keyservers across uids — kept '%s'."), pick);
    snprintf(chosen, sizeof chosen, "%s", pick);
    return chosen;
}

/**
 * The certificate without its attribute packets.
 *
 * A card already carries the photograph as PHOTO; carrying it a second time
 * inside the inlined key doubles the size of the file for nothing — nine
 * kilobytes of the fourteen, measured. gpg has `no-export-attributes` for
 * this and no listing has a flag for it, so the packets are dropped here.
 *
 * An attribute's certifications go with it: a signature over a packet that is
 * no longer there is not a signature, and leaving it would make the key look
 * damaged to anything that checks.
 */
static size_t strip_attributes(const unsigned char *in, size_t len,
                               unsigned char *out)
{
    const unsigned char *p = in, *end = in + len;
    struct pgpid_packet pkt;
    size_t o = 0;
    bool dropping = false;

    while (pgpid_packet_next(p, end, &pkt)) {
        size_t whole = (size_t)(pkt.next - p);
        if (pkt.tag == TAG_USER_ATTR) {
            dropping = true;
        } else if (pkt.tag == TAG_SIGNATURE && dropping) {
            /* still the dropped attribute's certifications */
        } else {
            dropping = false;
            memcpy(out + o, p, whole);
            o += whole;
        }
        p = pkt.next;
    }
    return o;
}

/**
 * The display name a uid carries, for certificates that have no FN uid.
 *
 * RFC 6350 makes FN required: a card without one is not a card. Ours carry
 * it as a uid of its own, but a certificate from anywhere else does not —
 * measured 2026-08-22, 117 of the 122 cards the shell produces have no FN
 * at all, which means it has been emitting files no reader should accept.
 *
 * The name is there all the same: `Name <address>` has a name in front. A
 * trailing parenthesis is dropped — an identifier in a comment is not what
 * somebody is called — and what is left is escaped as a vCard value.
 */
static bool display_name(const char *uid, char *out, size_t max)
{
    const char *open = strrchr(uid, '<');
    size_t n = open ? (size_t)(open - uid) : strlen(uid);
    while (n && (uid[n - 1] == ' ' || uid[n - 1] == '\t'))
        n--;
    /* A comment at the end carries the entity identifier, not the name. */
    if (n && uid[n - 1] == ')') {
        const char *paren = memrchr(uid, '(', n);
        if (paren && paren > uid) {
            n = (size_t)(paren - uid);
            while (n && (uid[n - 1] == ' ' || uid[n - 1] == '\t'))
                n--;
        }
    }
    if (!n)
        return false;

    size_t o = 0;
    for (size_t i = 0; i < n && o + 2 < max; i++) {
        /* RFC 6350 §3.4: these four have to be escaped in a value. */
        if (uid[i] == '\\' || uid[i] == ',' || uid[i] == ';')
            out[o++] = '\\';
        if (uid[i] == '\n') {
            out[o++] = '\\';
            out[o++] = 'n';
            continue;
        }
        out[o++] = uid[i];
    }
    out[o] = '\0';
    return o > 0;
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " cert_tovcard [OPTIONS]... [NAME|EMAIL|KEYID|U4|U5]\n"
        "\n"
        "Convert OpenPGP certificate to vCard (format 4.0).\n"
        "Missing NAME|EMAIL|KEYID|U4|U5 => the certificate whose secret key is at\n"
        "hand.\n"
        "\n"
        "OPTIONS:\n"
        "  -o, --output FILE           Write into given FILE instead of standard output\n"
        "      --raw                   Don't convert, but raw output all OpenPGP uids strings, separated by empty lines\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"),
            PGPID_NAME);
}

int pgpid_action_cert_tovcard(int argc, char **argv)
{
    const char *selector = NULL, *output = NULL;
    bool raw = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-o") || !strcmp(a, "--output")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a file."), a);
                return PGPID_USAGE;
            }
            output = argv[i];
        } else if (!strcmp(a, "--raw")) {
            raw = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            if (++i < argc)
                selector = argv[i];
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("cert_tovcard");
            return PGPID_USAGE;
        } else {
            selector = a;
            break;
        }
    }

    const char *pat[1] = { NULL };
    size_t npat = 0;
    if (selector)
        pat[npat++] = selector;
    struct pgpid_keyring *kr =
        pgpid_keys_load(pat, npat, selector ? 0 : PGPID_KEYS_SECRET);
    const struct pgpid_key *key = pgpid_keys_at(kr, 0);
    if (!key) {
        pgpid_keys_free(kr);
        pgpid_error(_("Error: No certificate for what was asked."));
        return PGPID_NOTHING;
    }
    const char *fpr = key->fpr;

    FILE *out = stdout;
    if (output && !(out = freopen(output, "w", stdout))) {
        pgpid_error(_("Error: Cannot write '%s'."), output);
        pgpid_keys_free(kr);
        return PGPID_FAIL;
    }

    if (raw) {
        for (size_t i = 0; i < key->nuid; i++)
            printf("%s\n\n", key->uid[i].text);
        pgpid_keys_free(kr);
        return PGPID_OK;
    }

    /* Which uids count: the shell keeps validities [ounmfqws-] and drops
     * revoked, expired, invalid and disabled. The letters come from the
     * engine's own listing, in step with the uids. */
    char line[4096];
    char validity[256];
    size_t nvalid = pgpid_uid_validities(fpr, validity, sizeof validity);

    /* FN is required and singular (RFC 6350 §6.2.1), so it is settled before
     * a single byte is written: either a uid provides one, or one is read off
     * the name a uid carries, or there is no card to write and saying so is
     * the only honest answer. */
    char fn[512] = "";
    {
        unsigned k = 0;
        char nm[64];
        for (size_t i = 0; i < key->nuid; i++, k++) {
            const struct pgpid_keyuid *u = &key->uid[i];
            char l = (k < nvalid) ? validity[k] : '-';
            if (!strchr("ounmfqws-", l))
                continue;
            const char *v = vcard_property(u->text, nm, sizeof nm);
            if (v && !strcmp(nm, "FN")) {
                fn[0] = '\0';   /* the certificate says it itself */
                break;
            }
            if (!v && !*fn)
                display_name(u->text, fn, sizeof fn);
        }
        if (*fn) {
            /* Nothing to derive it from either: no name, no card. */
        } else {
            bool has_own_fn = false;
            k = 0;
            for (size_t i = 0; i < key->nuid; i++, k++) {
                const struct pgpid_keyuid *u = &key->uid[i];
                char l = (k < nvalid) ? validity[k] : '-';
                if (!strchr("ounmfqws-", l))
                    continue;
                if (vcard_property(u->text, nm, sizeof nm) && !strcmp(nm, "FN"))
                    has_own_fn = true;
            }
            if (!has_own_fn) {
                pgpid_error(_("Error: This certificate carries no name."));
                pgpid_error(_("Notice: A vCard needs FN; there is no card to write."));
                pgpid_keys_free(kr);
                return PGPID_NOTHING;
            }
        }
    }

    printf("BEGIN:VCARD\r\nVERSION:4.0\r\n");
    if (*fn) {
        snprintf(line, sizeof line, "FN:%s", fn);
        fold(line);
    }

    unsigned pref = 0, at = 0;
    char name[64], value[512];
    for (size_t i = 0; i < key->nuid; i++, at++) {
        const struct pgpid_keyuid *u = &key->uid[i];
        char letter = (at < nvalid) ? validity[at] : '-';
        if (!strchr("ounmfqws-", letter))
            continue;
        const char *v = vcard_property(u->text, name, sizeof name);
        if (v) {
            if (!strcmp(name, "EMAIL")) {
                /* The 'EMAIL: <addr>' shape the vCard-uid experiment used.
                 * Still rendered, so certificates minted then keep working. */
                const char *a = v;
                size_t n = strlen(a);
                char stripped[320];
                if (n >= 2 && a[0] == '<' && a[n - 1] == '>') {
                    n -= 2;
                    if (n >= sizeof stripped)
                        continue;
                    memcpy(stripped, a + 1, n);
                    stripped[n] = '\0';
                    a = stripped;
                }
                snprintf(line, sizeof line, "EMAIL;PREF=%u:%s", ++pref, a);
                fold(line);
            } else {
                fold(u->text);  /* already a valid, escaped vCard line */
            }
        } else if (bracketed_address(u->text, value, sizeof value)) {
            /* A plain 'Name <addr>' uid: only its address becomes a line.
             * The name is carried by FN:, the identifier by UID:urn:eid:. */
            snprintf(line, sizeof line, "EMAIL;PREF=%u:%s", ++pref, value);
            fold(line);
        }
    }

    /* The certificate itself, twice: where to fetch it, and inline. The URL
     * is worth having because a card outlives the bytes in it — a key gains
     * signatures, an address is revoked. */
    size_t raw_len = 0;
    unsigned char *raw_key = pgpid_export_key(fpr, true, &raw_len);

    char url[512];
    const char *ks = raw_key ? pgpid_preferred_keyserver(raw_key, raw_len, fpr) : NULL;
    if (key_url(ks ? ks : PGPID_FIRST_KEYSERVER, fpr, url, sizeof url)) {
        snprintf(line, sizeof line, "KEY;MEDIATYPE=application/pgp-keys:%s", url);
        fold(line);
    }

    if (raw_key && raw_len) {
        unsigned char *lean = malloc(raw_len);
        size_t lean_len = lean ? strip_attributes(raw_key, raw_len, lean) : 0;
        size_t need = 4 * ((lean_len + 2) / 3) + 64;
        char *b64 = lean_len ? malloc(need) : NULL;
        if (b64) {
            pgpid_base64(lean, lean_len, b64);
            char *whole = malloc(need + 64);
            if (whole) {
                snprintf(whole, need + 64, "KEY:data:application/pgp-keys;base64,%s", b64);
                fold(whole);
                free(whole);
            }
            free(b64);
        }
        free(lean);
        /* The photograph, which no listing carries — and the one that
         * stands, not the first in packet order. The shell takes the first,
         * which on a certificate carrying several is the oldest: the card
         * would then show a face its owner replaced. */
        const unsigned char *img;
        size_t ilen;
        const char *keyid = strlen(fpr) >= 16 ? fpr + strlen(fpr) - 16 : fpr;
        if (pgpid_current_image(raw_key, raw_len, keyid, &img, &ilen)) {
            size_t need2 = 4 * ((ilen + 2) / 3) + 64;
            char *b = malloc(need2);
            if (b) {
                pgpid_base64(img, ilen, b);
                char *whole = malloc(need2 + 64);
                if (whole) {
                    snprintf(whole, need2 + 64, "PHOTO:data:image/jpeg;base64,%s", b);
                    fold(whole);
                    free(whole);
                }
                free(b);
            }
        }
        free(raw_key);
    }

    printf("END:VCARD\r\n");
    if (output) {
        fflush(out);
        pgpid_error(_("Notice: Written into '%s'."), output);
    }
    pgpid_keys_free(kr);
    return PGPID_OK;
}
