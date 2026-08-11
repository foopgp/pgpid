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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* What the application asks for, and the vCard name it means. Singular ones
 * hold one value which may itself contain newlines; the others repeat. */
static const struct {
    const char *name;
    const char *vcard;
    bool singular;
} PROPERTIES[] = {
    { "name",    "FN",   true  },
    { "note",    "NOTE", true  },
    { "phone",   "TEL",  false },
    { "address", "ADR",  false },
    { "url",     "URL",  false },
    { "lang",    "LANG", false },
    { "geo",     "GEO",  false },
};

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

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: " PGPID_MIP_NAME " property [OPTIONS]... NAME [SEARCH]\n"
        "\n"
        "Print the values of one vCard property carried by a certificate, one per\n"
        "line. Without SEARCH, the certificate is the one whose secret key is at\n"
        "hand — the plugged security key.\n"
        "\n"
        "NAME is one of: name, note, phone, address, url, lang, geo.\n"
        "name and note hold a single value, which may run over several lines and\n"
        "is then printed whole.\n"
        "\n"
        "OPTIONS:\n"
        "  -h, --help                  Print this help and exit\n");
}

int pgpid_action_property(int argc, char **argv)
{
    const char *name = NULL, *pattern = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            if (i + 1 < argc)
                name = argv[++i];
            if (i + 1 < argc)
                pattern = argv[i + 1];
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error("Error: Unrecognized option '%s'.", a);
            pgpid_error("Try '" PGPID_MIP_NAME " property --help' for more information.");
            return PGPID_USAGE;
        } else if (!name) {
            name = a;
        } else {
            pattern = a;
            break;
        }
    }

    if (!name) {
        pgpid_error("Error: A property name is required.");
        return PGPID_USAGE;
    }

    const char *vcard = NULL;
    bool singular = false;
    for (size_t i = 0; i < sizeof PROPERTIES / sizeof *PROPERTIES; i++) {
        if (!strcmp(name, PROPERTIES[i].name)) {
            vcard = PROPERTIES[i].vcard;
            singular = PROPERTIES[i].singular;
            break;
        }
    }
    if (!vcard) {
        pgpid_error("Error: Unknown property '%s'.", name);
        pgpid_error("Notice: One of name, note, phone, address, url, lang, geo.");
        return PGPID_USAGE;
    }

    gpgme_ctx_t ctx = NULL;
    gpgme_error_t err = pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL);
    if (err) {
        pgpid_gpgme_error("opening the engine", err);
        return PGPID_FAIL;
    }

    /* No pattern means the key we hold the secret of, which is what "the
     * plugged one" comes down to — and it costs no round trip to the card. */
    err = gpgme_op_keylist_start(ctx, pattern, pattern ? 0 : 1);
    if (err) {
        pgpid_gpgme_error("looking the certificate up", err);
        gpgme_release(ctx);
        return PGPID_FAIL;
    }
    /* Values from two certificates in one listing would be a lie about a
     * single card, so exactly one has to come out. When no pattern was given
     * and several secret keys answer, the one held on a card wins: that is
     * what "the plugged key" means, and it costs no round trip to ask the
     * card itself. */
    gpgme_key_t key = NULL, candidate = NULL;
    unsigned matches = 0, on_card = 0;
    for (;;) {
        gpgme_key_t k = NULL;
        err = gpgme_op_keylist_next(ctx, &k);
        if (gpg_err_code(err) == GPG_ERR_EOF)
            break;
        if (err) {
            gpgme_op_keylist_end(ctx);
            if (candidate)
                gpgme_key_unref(candidate);
            gpgme_release(ctx);
            pgpid_gpgme_error("reading the certificate", err);
            return PGPID_FAIL;
        }
        matches++;
        bool carded = false;
        for (gpgme_subkey_t sk = k->subkeys; sk && !pattern; sk = sk->next)
            if (sk->is_cardkey)
                carded = true;
        if (carded)
            on_card++;
        /* Keep the first, then let a card-held one take its place. */
        if (!candidate || (carded && on_card == 1)) {
            if (candidate)
                gpgme_key_unref(candidate);
            candidate = k;
        } else {
            gpgme_key_unref(k);
        }
    }
    gpgme_op_keylist_end(ctx);

    if (!matches) {
        gpgme_release(ctx);
        pgpid_error("Error: No certificate %s.",
                    pattern ? "matching that search" : "with a secret key at hand");
        return PGPID_NOTHING;
    }
    if (matches > 1 && on_card != 1) {
        gpgme_key_unref(candidate);
        gpgme_release(ctx);
        pgpid_error("Error: %u certificates match; name one.", matches);
        return PGPID_USAGE;
    }
    key = candidate;

    /* A property is one column, and a single column is a value: nothing is
     * padded, so the caller reads exactly what the certificate carries. */
    const char *const columns[] = { name };
    pgpid_table_start(columns, 1);
    unsigned found = 0;
    for (gpgme_user_id_t u = key->uids; u; u = u->next) {
        if (u->revoked || u->invalid)
            continue;
        const char *v = value_of(u->uid, vcard);
        if (!v)
            continue;
        char *plain = unescape(v);
        const char *values[] = { plain ? plain : v };
        pgpid_table_row(values);
        free(plain);
        found++;
        if (singular)
            break;
    }
    pgpid_table_end();

    gpgme_key_unref(key);
    gpgme_release(ctx);
    return found ? PGPID_OK : PGPID_NOTHING;
}
