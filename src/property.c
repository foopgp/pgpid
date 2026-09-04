/* The vCard properties a certificate carries on uids of its own.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * A pgpid certificate carries its name, its note, its telephone and the rest
 * on uids shaped like vCard lines — `FN:Mnêmê`, `URL:https://…`, `NOTE:…` —
 * so that a certificate is a business card and not only a key.
 *
 * Reading them was `bl-pgpid property`, and that is the call foodjis makes
 * six times per card refresh. It moves here for two reasons. It spawned a gpg
 * per property; and it went through an interactive helper that, run with no
 * terminal, could not stop asking — 35 orphaned processes at 40% CPU, the
 * oldest two days old, all of them this call. The shell fix exists; this
 * removes the trigger rather than waiting for the fix to be packaged.
 *
 * Reading only. Writing a property revokes a uid and adds another, needs the
 * card and its PIN, and stays with bl-pgpid until it is worth moving.
 */
#include "pgpid.h"

#include <regex.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What the application asks for, and the vCard name it means. Singular ones
 * hold one value which may itself contain newlines; the others repeat. */
static const struct {
    const char *name;
    const char *vcard;
    bool singular;    /* one at a time: adding revokes the one before */
    bool keepone;     /* and the certificate never ends up without one */
    bool free_text;   /* escaped per RFC 6350 §3.4 on the way in */
    bool structural;  /* ... except for the ';' that carry its structure */
} PROPERTIES[] = {
    { "name",    "FN",   true,  true,  true,  false },
    { "note",    "NOTE", true,  false, true,  false },
    { "phone",   "TEL",  false, false, false, false },
    { "address", "ADR",  false, false, true,  true  },
    { "url",     "URL",  false, false, false, false },
    { "lang",    "LANG", false, false, false, false },
    { "geo",     "GEO",  false, false, false, false },
};

/* Not a vCard uid at all: the preferred keyserver is a subpacket of the
 * primary uid's self-signature. It sits here because that is where somebody
 * looks for it, and it is spelled out wherever it behaves differently. */
#define KSPREFRD "ksprefrd"

/* RFC 6350 §3.4 in reverse: the escapes a value may carry. Caller frees. */
static char *unescape(const char *v)
{
    char *out = malloc(strlen(v) + 1);
    if (!out)
        return NULL;
    char *w = out;
    for (; *v; v++) {
        if (*v != '\\') {
            *w++ = *v;
            continue;
        }
        switch (*++v) {
        case 'n': case 'N': *w++ = '\n'; break;
        case '\\': *w++ = '\\'; break;
        case ',': *w++ = ','; break;
        case ';': *w++ = ';'; break;
        case '\0': *w++ = '\\'; *w = '\0'; return out;
        default: *w++ = '\\'; *w++ = *v; break;
        }
    }
    *w = '\0';
    return out;
}

/* RFC 6350 §3.4 forwards. The order matters: backslashes first, or the
 * escapes added afterwards would be escaped in turn. A carriage return is
 * dropped rather than escaped — it is line ending, not content. */
static void escape(const char *v, bool structural, char *out, size_t max)
{
    size_t n = 0;
    for (; *v && n + 2 < max; v++) {
        switch (*v) {
        case '\\': out[n++] = '\\'; out[n++] = '\\'; break;
        case '\r': break;
        case ',':  out[n++] = '\\'; out[n++] = ','; break;
        case ';':
            if (structural)
                out[n++] = ';';
            else {
                out[n++] = '\\';
                out[n++] = ';';
            }
            break;
        case '\n': out[n++] = '\\'; out[n++] = 'n'; break;
        default:  out[n++] = *v; break;
        }
    }
    out[n] = '\0';
}

/* The value of `uid` if it is a line of that property, else NULL.
 * `FN:value` and `FN;TYPE=x:value` both count; the parameters are dropped,
 * which is what every caller does with them today. */
static const char *value_of(const char *uid, const char *vcard)
{
    size_t n = strlen(vcard);
    if (strncmp(uid, vcard, n))
        return NULL;
    const char *p = uid + n;
    if (*p == ';') {
        p = strchr(p, ':');
        if (!p)
            return NULL;
    } else if (*p != ':') {
        return NULL;   /* NOTES: is not NOTE: */
    }
    return p + 1;
}

/**
 * Is this a value of that property, or a typo?
 *
 * Strict where a machine reads it — a phone number, a URL, a language tag, a
 * geographic point all have a shape something downstream depends on. Light on
 * the free text: a name and a note are whatever their owner says, minus the
 * control characters that would break the uid carrying them.
 */
static bool value_is_sound(const char *vcard, const char *val)
{
    if (!*val)
        return false;
    for (const char *p = val; *p; p++)
        if ((unsigned char)*p < 0x20 && *p != '\n')
            return false;

    static const struct { const char *vcard; const char *re; } SHAPES[] = {
        { "TEL",  "^(tel:)?\\+[0-9][0-9 ./()-]{3,22}[0-9]$" },
        { "URL",  "^[a-zA-Z][a-zA-Z0-9+.-]*://[^[:space:]]+$" },
        { "LANG", "^[a-zA-Z]{2,8}(-[a-zA-Z0-9]{1,8})*$" },
        { "GEO",  "^geo:-?[0-9]{1,2}(\\.[0-9]+)?,-?[0-9]{1,3}(\\.[0-9]+)?"
                  "(,-?[0-9]+(\\.[0-9]+)?)?(;(u|crs)=[a-zA-Z0-9.-]+)*$" },
    };
    for (size_t i = 0; i < sizeof SHAPES / sizeof *SHAPES; i++) {
        if (strcmp(vcard, SHAPES[i].vcard))
            continue;
        regex_t re;
        if (regcomp(&re, SHAPES[i].re, REG_EXTENDED | REG_NOSUB))
            return true;   /* our own regex is broken: do not blame the value */
        bool ok = regexec(&re, val, 0, NULL, 0) == 0;
        regfree(&re);
        return ok;
    }
    return true;
}

/**
 * Which certificate to work on.
 *
 * Values from two certificates in one listing would be a lie about a single
 * card, so exactly one has to come out. With no pattern, the one whose secret
 * key is at hand; when several answer, the one held on a card wins — that is
 * what "the plugged key" means.
 */
static int resolve_key(const char *pattern, char *out, size_t max)
{
    const char *pat[1];
    size_t npat = 0;
    if (pattern)
        pat[npat++] = pattern;
    /* No pattern means "the key at hand", which is a secret key. */
    struct pgpid_keyring *kr =
        pgpid_keys_load(pat, npat, pattern ? 0 : PGPID_KEYS_SECRET);
    if (!kr) {
        pgpid_error(_("Error: Cannot read the keyring."));
        return PGPID_FAIL;
    }

    const struct pgpid_key *candidate = NULL;
    unsigned matches = 0, on_card = 0;
    for (size_t n = 0; n < pgpid_keys_count(kr); n++) {
        const struct pgpid_key *k = pgpid_keys_at(kr, n);
        matches++;
        bool carded = false;
        if (!pattern)
            for (size_t i = 0; i < k->nsub; i++)
                if (*k->sub[i].card)
                    carded = true;
        if (carded)
            on_card++;
        if (!candidate || (carded && on_card == 1))
            candidate = k;
    }

    int ret = PGPID_OK;
    if (!matches) {
        pgpid_error(_("Error: No certificate %s."),
                    pattern ? "matching that search" : "with a secret key at hand");
        ret = PGPID_NOTHING;
    } else if (matches > 1 && on_card != 1) {
        pgpid_error(_("Error: %u certificates match; name one."), matches);
        ret = PGPID_USAGE;
    } else if (*candidate->fpr) {
        snprintf(out, max, "%s", candidate->fpr);
    } else {
        ret = PGPID_FAIL;
    }
    pgpid_keys_free(kr);
    return ret;
}

/**
 * The preferred keyserver: read from the packets, written by re-signing.
 *
 * Written on the primary uid and nowhere else, by index — `uid 1` is a
 * position, never a string, because a string that matches nothing would let
 * the keyserver spill onto every uid at once. The primary flag has to be
 * re-asserted in the same self-signature: re-signing drops it otherwise, and
 * the certificate would come back announcing a different main identity than
 * the one it went in with.
 */
static int do_ksprefrd(const char *fpr, const char *add, bool revoking,
                       const char *keyservers)
{
    if (revoking) {
        pgpid_error(_("Error: 'ksprefrd' cannot be revoked — it is a subpacket of a "
                    "signature, not a uid. Set another value instead."));
        return PGPID_USAGE;
    }

    if (add) {
        if (strncmp(add, "hkp://", 6) && strncmp(add, "hkps://", 7)) {
            pgpid_error(_("Error: 'ksprefrd' must start with hkp:// or hkps:// (%s)."), add);
            return PGPID_USAGE;
        }
        char script[1200];
        snprintf(script, sizeof script, "uid 1\nkeyserver\n%.1023s\ny\nprimary\nsave\n", add);
        const char *argv[] = { "--batch", "--command-fd", "0", "--edit-key", fpr, NULL };
        if (pgpid_run_engine_input(argv, script)) {
            pgpid_error(_("Error: Cannot set the preferred keyserver — right PIN?"));
            return PGPID_FAIL;
        }
        return pgpid_send_to_keyservers(fpr, keyservers ? keyservers : PGPID_KEYSERVERS);
    }

    size_t len = 0;
    unsigned char *raw = pgpid_export_key(fpr, true, &len);
    if (!raw) {
        pgpid_error(_("Error: Cannot export %s."), fpr);
        return PGPID_FAIL;
    }
    char *ks = pgpid_preferred_keyserver(raw, len, fpr);
    free(raw);
    if (!ks || !*ks)
        return PGPID_NOTHING;

    const char *const columns[] = { KSPREFRD };
    const char *values[] = { ks };
    pgpid_table_start(columns, 1);
    pgpid_table_row(values);
    pgpid_table_end();
    return PGPID_OK;
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " property PROPERTY [OPTIONS]... [NAME|EMAIL|KEYID|U4|U5]\n"
        "\n"
        "Display and add or revoke vCard-property uids inside OpenPGP certificate.\n"
        "PROPERTY is one of: { name, note, address, phone, url, lang, geo, ksprefrd }.\n"
        "Email addresses are not vCard-property uids (they keep the 'Name <addr>' shape\n"
        "every mail client understands): manage them with '"
        "%s"
        " email'.\n"
        "'ksprefrd' is preferred certificate server. This is not stored as a\n"
        "vCard-property uid, but used when generating vCard: it can be replaced,\n"
        "never revoked.\n"
        "Missing NAME|EMAIL|KEYID|U4|U5 => the certificate whose secret key is at hand.\n"
        "Free-text values (name, note) with , ; \\ or newlines are stored RFC 6350-escaped\n"
        "and decoded back on display (address keeps its structural ';')\n"
        "\n"
        "OPTIONS:\n"
        "  -A, --add VALUE             Add ({name,note,ksprefrd} ⇒ replace) a PROPERTY uid (may be used more than once)\n"
        "      --replace-to VALUE      Exact synonym of --add — terminology is just more relevant for {name,note,ksprefrd}\n"
        "  -R, --revoke VALUE          Revoke the PROPERTY uid carrying VALUE (may be used more than once)\n"
        "      --revoke-all            Revoke every usable PROPERTY uid — all but the newest for {name,email}\n"
        "  -y, --yes                   Assume yes: skip the irreversible-revocation confirmation\n"
        "      --show-unusable         Also display the uids that no longer stand: revoked, expired, or without a valid self-signature\n"
        "  -K, --keyservers KEYSERVERS If non-empty, send updated certificate to this keyservers - Default: "
        "%s"
        "\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "Revoking is irreversible: OpenPGP keeps the uid on the certificate\n"
        "forever, marked revoked, and an identical one can never be added again.\n"),
            PGPID_NAME, PGPID_NAME, PGPID_KEYSERVERS);
}

int pgpid_action_property(int argc, char **argv)
{
    const char *name = NULL, *pattern = NULL, *keyservers = NULL;
    char toadd[16][1024], torev[16][1024];
    size_t nadd = 0, nrev = 0;
    bool revoke_all = false, assume_yes = false, show_unusable = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-A") || !strcmp(a, "--add") || !strcmp(a, "--replace-to")
            || !strcmp(a, "-R") || !strcmp(a, "--rev") || !strcmp(a, "--revoke")) {
            bool adding = strcmp(a, "-R") && strcmp(a, "--rev") && strcmp(a, "--revoke");
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a value."), a);
                return PGPID_USAGE;
            }
            if ((adding ? nadd : nrev) >= 16) {
                pgpid_error(_("Error: Too many values at once."));
                return PGPID_USAGE;
            }
            snprintf(adding ? toadd[nadd++] : torev[nrev++], 1024, "%s", argv[i]);
        } else if (!strcmp(a, "--revoke-all") || !strcmp(a, "--revokeall")) {
            revoke_all = true;
        } else if (!strcmp(a, "-y") || !strcmp(a, "--yes")) {
            assume_yes = true;
        } else if (!strcmp(a, "--show-unusable") || !strcmp(a, "--showunusable")) {
            show_unusable = true;
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
            pgpid_try_help("property");
            return PGPID_USAGE;
        } else if (!name) {
            name = a;
        } else if (!pattern) {
            pattern = a;
        } else {
            pgpid_error(_("Warning: Ignoring extra argument '%s'."), a);
        }
    }

    if (!name) {
        pgpid_error(_("Error: A property name is required."));
        usage(stderr);
        return PGPID_USAGE;
    }

    const char *vcard = NULL;
    bool singular = false, keepone = false, free_text = false, structural = false;
    bool is_ks = !strcmp(name, KSPREFRD);
    if (!is_ks) {
        for (size_t i = 0; i < sizeof PROPERTIES / sizeof *PROPERTIES; i++) {
            if (strcmp(name, PROPERTIES[i].name))
                continue;
            vcard      = PROPERTIES[i].vcard;
            singular   = PROPERTIES[i].singular;
            keepone    = PROPERTIES[i].keepone;
            free_text  = PROPERTIES[i].free_text;
            structural = PROPERTIES[i].structural;
            break;
        }
        if (!vcard) {
            pgpid_error(_("Error: Unknown property '%s'."), name);
            pgpid_error(_("Notice: One of name, note, phone, address, url, lang, geo, %s."),
                        KSPREFRD);
            return PGPID_USAGE;
        }
    }

    if (singular && nadd > 1) {
        pgpid_error(_("Error: Only one --add at a time for '%s' — the new value "
                    "replaces the one before, and two would race."), name);
        return PGPID_USAGE;
    }

    char fpr[41];
    int ret = resolve_key(pattern, fpr, sizeof fpr);
    if (ret)
        return ret;

    if (is_ks) {
        if (nadd > 1) {
            pgpid_error(_("Error: Only one --add at a time for '%s'."), KSPREFRD);
            return PGPID_USAGE;
        }
        return do_ksprefrd(fpr, nadd ? toadd[0] : NULL, nrev || revoke_all, keyservers);
    }

    /* Free text is stored escaped, so what is asked for has to be escaped too
     * — otherwise a note with a comma in it would never match itself. */
    if (free_text) {
        char buf[1024];
        for (size_t i = 0; i < nadd; i++) {
            escape(toadd[i], structural, buf, sizeof buf);
            snprintf(toadd[i], sizeof toadd[0], "%s", buf);
        }
        for (size_t i = 0; i < nrev; i++) {
            escape(torev[i], structural, buf, sizeof buf);
            snprintf(torev[i], sizeof torev[0], "%s", buf);
        }
    }
    for (size_t i = 0; i < nadd; i++) {
        if (!value_is_sound(vcard, toadd[i])) {
            pgpid_error(_("Error: Invalid %s value '%s'."), vcard, toadd[i]);
            return PGPID_USAGE;
        }
    }

    struct pgpid_uid uids[256];
    size_t nuids = 0;
    bool modified = false;

    if (nadd || nrev || revoke_all) {
        if (!pgpid_upgrade_uids(fpr, keyservers))
            return PGPID_FAIL;
        nuids = pgpid_list_uids(fpr, true, uids, 256);
        if (!nuids) {
            pgpid_error(_("Error: No editable certificate %s here."), fpr);
            return PGPID_FAIL;
        }
    }

    /* Add first, revoke after: the property is never left with no value at
     * all, not even for the moment between the two calls. */
    size_t nbefore = 0;
    char before[256][512];
    for (size_t i = 0; i < nuids && nadd; i++)
        if (pgpid_uid_stands(uids[i].validity) && value_of(uids[i].text, vcard))
            snprintf(before[nbefore++], sizeof before[0], "%.511s", uids[i].text);

    for (size_t a = 0; a < nadd; a++) {
        char want[1100];
        snprintf(want, sizeof want, "%s:%.1023s", vcard, toadd[a]);
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
            pgpid_error(_("Notice: Certificate %s already carries '%s'."), fpr, want);
            continue;
        }
        if (struck) {
            pgpid_error(_("Notice: '%s' was revoked earlier and cannot be added again "
                        "— OpenPGP keeps revoked User IDs on the certificate "
                        "forever."), want);
            continue;
        }
        pgpid_error(_("Notice: Adding '%s' into certificate %s…"), want, fpr);
        const char *add[] = { "--batch", "--quick-add-uid", fpr, want, NULL };
        if (pgpid_run_engine(add)) {
            pgpid_error(_("Error: gpg would not add '%s'."), want);
            return PGPID_FAIL;
        }
        modified = true;
    }

    if (modified && singular) {
        for (size_t i = 0; i < nbefore; i++)
            if (!pgpid_revoke_uid(fpr, before[i], assume_yes))
                return PGPID_FAIL;
    }

    for (size_t r = 0; r < nrev; r++) {
        nuids = pgpid_list_uids(fpr, true, uids, 256);
        size_t current = 0, matched = 0;
        char victims[256][512];
        for (size_t i = 0; i < nuids; i++) {
            if (!pgpid_uid_stands(uids[i].validity))
                continue;
            const char *v = value_of(uids[i].text, vcard);
            if (!v)
                continue;
            current++;
            if (!strcmp(v, torev[r]) && matched < 256)
                snprintf(victims[matched++], sizeof victims[0], "%.511s", uids[i].text);
        }
        if (!matched) {
            pgpid_error(_("Error: No revokable '%s:%s' inside certificate %s."),
                        vcard, torev[r], fpr);
            return PGPID_FAIL;
        }
        if (keepone && current - matched < 1) {
            pgpid_error(_("Error: At least one %s must be retained."), vcard);
            return PGPID_FAIL;
        }
        for (size_t i = 0; i < matched; i++)
            if (!pgpid_revoke_uid(fpr, victims[i], assume_yes))
                return PGPID_FAIL;
        modified = true;
    }

    if (revoke_all) {
        nuids = pgpid_list_uids(fpr, true, uids, 256);
        long newest = -1;
        size_t keep = (size_t)-1, n = 0;
        for (size_t i = 0; i < nuids; i++) {
            if (!pgpid_uid_stands(uids[i].validity) || !value_of(uids[i].text, vcard))
                continue;
            n++;
            if (keepone && uids[i].created >= newest) {
                newest = uids[i].created;
                keep = i;
            }
        }
        if (n - (keep != (size_t)-1 ? 1 : 0) < 1) {
            pgpid_error(_("Warning: Nothing to revoke."));
        } else {
            for (size_t i = 0; i < nuids; i++) {
                if (i == keep)
                    continue;
                if (!pgpid_uid_stands(uids[i].validity) || !value_of(uids[i].text, vcard))
                    continue;
                if (!pgpid_revoke_uid(fpr, uids[i].text, assume_yes))
                    return PGPID_FAIL;
                modified = true;
            }
        }
    }

    ret = PGPID_OK;
    if (modified) {
        /* The primary flag is left strictly alone. It is the holder's main
         * address by convention, not an identity anchor, and a property has
         * no business moving it. */
        ret = pgpid_send_to_keyservers(fpr, keyservers ? keyservers : PGPID_KEYSERVERS);
    }

    /* From the colon listing's own letters: an expired uid would otherwise read as
     * unknown, indistinguishable from one nobody has vouched for, and
     * --show-unusable would then have nothing to show. */
    nuids = pgpid_list_uids(fpr, false, uids, 256);
    const char *const columns[] = { name };
    pgpid_table_start(columns, 1);
    unsigned found = 0;
    for (size_t i = 0; i < nuids; i++) {
        if (!pgpid_uid_stands(uids[i].validity) && !show_unusable)
            continue;
        const char *v = value_of(uids[i].text, vcard);
        if (!v)
            continue;
        char *plain = unescape(v);
        const char *values[] = { plain ? plain : v };
        pgpid_table_row(values);
        free(plain);
        found++;
    }
    pgpid_table_end();

    /* An empty property is an answer, not a failure: this certificate has no
     * phone number, and saying so with a non-zero code turns an ordinary fact
     * into an error for every caller that checks. "Nothing found" is reserved
     * for the search that matched no certificate at all, above. */
    (void)found;
    return ret;
}
