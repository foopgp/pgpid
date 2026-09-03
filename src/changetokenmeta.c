/* What the card says about its holder.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Three fields, and each is checked against something outside the card before
 * it is written, because a card is read by people who cannot check it
 * themselves. An address that the certificate does not carry, or a URL that
 * serves a different certificate, would be a card that lies — and it lies to
 * whoever plugs it in, not to whoever set it.
 *
 * Which field is meant is read off the value: an address is a cardholder
 * name, an http URL is where the certificate lives, two letters are a
 * language. Guessing here rather than asking is what makes the command
 * usable without a dialogue.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " change_token_meta [OPTIONS]... NEW_METADATA\n"
        "\n"
        "Change a textual metadata of a security token (OpenPGP smartcard).\n"
        "Detect if NEW_METADATA is an email, a certurl or a lang:\n"
        "\n"
        "  an address        the cardholder name (DO 5B)\n"
        "  an http(s) URL    where the public certificate lives (DO 5F50)\n"
        "  two letters       the language preference, ISO 639-1 (DO 5F2D)\n"
        "\n"
        "Each is checked before it is written: the address must be one the\n"
        "certificate still stands by, and the URL must serve a certificate\n"
        "carrying this key's three subkeys.\n"
        "\n"
        "OPTIONS:\n"
        "  -A, --admincode CODE         Admin code (usually 8 digits) protecting writes to security token metadata\n"
        "  -p, --admincodefrom FILE     Get admin code from first line of FILE (eg: fifo, tmpfs, /dev/stdin)\n"
        "  -h, --help                   Print this help and exit\n"
        "  -V, --version                Print the version and exit\n"),
            PGPID_NAME);
}

static bool first_line_of(const char *path, char *out, size_t max)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        pgpid_error(_("Error: Cannot read %s."), path);
        return false;
    }
    if (!fgets(out, (int)max, f))
        *out = '\0';
    fclose(f);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return true;
}

static bool looks_like_address(const char *s)
{
    const char *at = strchr(s, '@');
    if (!at || at == s || !at[1])
        return false;
    if (strchr(at + 1, '@') || !strchr(at + 1, '.'))
        return false;
    for (const char *p = s; *p; p++)
        if (*p <= ' ' || *p == '<' || *p == '>' || *p == ',')
            return false;
    return true;
}

static bool looks_like_url(const char *s)
{
    if (!isalpha((unsigned char)s[0]))
        return false;
    const char *p = s;
    while (*p && (isalnum((unsigned char)*p) || *p == '.' || *p == '+' || *p == '-'))
        p++;
    return p[0] == ':' && p[1] == '/';
}

static bool looks_like_language(const char *s)
{
    return strlen(s) == 2 && isalpha((unsigned char)s[0]) && isalpha((unsigned char)s[1]);
}

/** The three subkey fingerprints the connected card carries. */
static bool card_subkeys(char s[41], char e[41], char a[41], char serial[64])
{
    char status[16384];
    if (pgpid_capture_card_status(status, sizeof status) <= 0)
        return false;

    static const char *const WANTED[] = {
        "Signature key", "Encryption key", "Authentication key", "Serial number",
    };
    char *into[] = { s, e, a, serial };
    for (unsigned w = 0; w < 4; w++) {
        *into[w] = '\0';
        const char *at = strstr(status, WANTED[w]);
        if (!at)
            continue;
        const char *colon = strchr(at, ':');
        if (!colon)
            continue;
        size_t n = 0;
        size_t room = (w == 3) ? 63 : 40;
        for (const char *p = colon + 1; *p && *p != '\n' && n < room; p++)
            if (isxdigit((unsigned char)*p))
                into[w][n++] = (char)toupper((unsigned char)*p);
        into[w][n] = '\0';
    }
    return *serial || *s;
}

int pgpid_action_change_token_meta(int argc, char **argv)
{
    char admincode[128] = "";
    bool admin_given = false;
    const char *value = NULL;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-A") || !strcmp(a, "--admincode")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a code."), a); return PGPID_USAGE; }
            snprintf(admincode, sizeof admincode, "%s", argv[i]);
            admin_given = true;
        } else if (!strcmp(a, "-p") || !strcmp(a, "--admincodefrom")
                   || !strcmp(a, "--admincode-from")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a file."), a); return PGPID_USAGE; }
            if (!first_line_of(argv[i], admincode, sizeof admincode))
                return PGPID_FAIL;
            admin_given = true;
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
            pgpid_try_help("change_token_meta");
            return PGPID_USAGE;
        } else if (!value) {
            value = a;
        }
    }

    static char typed[256];
    if (!value) {
        /* Asked for rather than refused, as the shell does. What it should
         * hold is said in the question, so nobody has to go back to the help
         * to learn what shape is expected. */
        if (!pgpid_ask(_("What should the card say? An address, an http URL, "
                       "or a two-letter language code: "), typed, sizeof typed)
            || !*typed) {
            pgpid_error(_("Error: Nothing to write."));
            return PGPID_USAGE;
        }
        value = typed;
    }

    char lowered[512];
    snprintf(lowered, sizeof lowered, "%s", value);
    for (char *p = lowered; *p; p++)
        *p = (char)tolower((unsigned char)*p);

    const char *field;
    if (looks_like_language(lowered))
        field = "lang";
    else if (looks_like_address(value))
        field = "name";
    else if (looks_like_url(lowered))
        field = "url";
    else {
        pgpid_error(_("Error: '%s' is neither an email, a certurl, nor a 2-letter "
                    "language code."), value);
        return PGPID_USAGE;
    }

    char skey[41], ekey[41], akey[41], serial[64];
    if (!card_subkeys(skey, ekey, akey, serial) || !*serial) {
        pgpid_error(_("Error: No security token detected."));
        return PGPID_FAIL;
    }

    if (!strcmp(field, "name")) {
        /* GnuPG caps DO 5B at 38 characters in card-edit — the spec allows 39.
         * Saying so here beats letting card-edit fail without a reason. */
        if (strlen(value) > 38) {
            pgpid_error(_("Error: Email '%s' exceeds 38 bytes (OpenPGP smartcard cap)."),
                        value);
            return PGPID_FAIL;
        }
        if (!*skey) {
            pgpid_error(_("Error: The card names no signing key, so its certificate "
                        "cannot be found."));
            return PGPID_FAIL;
        }
        /* The address has to be one the certificate still stands by: a card
         * saying otherwise misleads whoever reads it, not whoever set it. */
        struct pgpid_uid uids[256];
        char owner[41] = "";
        const char *pat[] = { skey };
        struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
        const struct pgpid_key *key = pgpid_keys_at(kr, 0);
        if (key && *key->fpr)
            snprintf(owner, sizeof owner, "%s", key->fpr);
        pgpid_keys_free(kr);
        if (!*owner) {
            pgpid_error(_("Error: Can't find the token's certificate here."));
            return PGPID_FAIL;
        }
        size_t n = pgpid_list_uids(owner, false, uids, 256);
        bool carried = false;
        for (size_t i = 0; i < n && !carried; i++) {
            if (!pgpid_uid_stands(uids[i].validity))
                continue;
            size_t len = 0;
            const char *addr = pgpid_uid_address(uids[i].text, &len);
            if (addr && len == strlen(value) && !memcmp(addr, value, len))
                carried = true;
        }
        if (!carried) {
            pgpid_error(_("Error: %s is not a usable email of the token's certificate."),
                        value);
            return PGPID_FAIL;
        }
    } else if (!strcmp(field, "url")) {
        /* Fetched into a throwaway keyring, and checked for the card's own
         * subkeys: a URL serving somebody else's certificate would send every
         * reader of this card to the wrong person. Revoked subkeys count —
         * pointing at an archived certificate is a legitimate thing to do. */
        char ring[] = "/tmp/pgpid-url-XXXXXX";
        if (!mkdtemp(ring)) {
            pgpid_error(_("Error: Cannot make a temporary keyring."));
            return PGPID_FAIL;
        }
        char fetched[600];
        snprintf(fetched, sizeof fetched, "%s/cert.gpg", ring);
        const char *curl[] = { "curl", "--fail", "--silent", "--show-error",
                               "--location", value, NULL };
        if (pgpid_run_program(curl, NULL, fetched)) {
            pgpid_error(_("Error: Can't fetch a usable certificate from %s."), value);
            return PGPID_FAIL;
        }
        const char *saved = pgpid_homedir;
        pgpid_homedir = ring;
        const char *import[] = { "--batch", "--quiet", "--import", fetched, NULL };
        int imported = pgpid_run_engine(import);
        char listing[262144] = "";
        if (!imported) {
            const char *list[] = { "--with-colons", "--with-fingerprint",
                                   "--list-keys", NULL };
            pgpid_capture_engine(list, listing, sizeof listing);
        }
        pgpid_homedir = saved;
        if (imported) {
            pgpid_error(_("Error: Can't fetch a usable certificate from %s."), value);
            return PGPID_FAIL;
        }
        char missing[256] = "";
        const char *kinds[] = { "S", "E", "A" };
        const char *fprs[] = { skey, ekey, akey };
        for (unsigned k = 0; k < 3; k++) {
            if (!*fprs[k])
                continue;
            if (strstr(listing, fprs[k]))
                continue;
            snprintf(missing + strlen(missing), sizeof missing - strlen(missing),
                     "%s%s=%s", *missing ? " " : "", kinds[k], fprs[k]);
        }
        if (*missing) {
            pgpid_error(_("Error: Certificate at %s doesn't hold the token's subkeys: %s."),
                        value, missing);
            return PGPID_FAIL;
        }
    } else {
        snprintf(lowered, sizeof lowered, "%s", value);
        for (char *p = lowered; *p; p++)
            *p = (char)tolower((unsigned char)*p);
        value = lowered;
    }

    if (!admin_given) {
        /* Without echo: a code the terminal showed stays in the scrollback
         * for the rest of the session. */
        if (!pgpid_ask_secret(_("Admin code (8 digits): "),
                              admincode, sizeof admincode)) {
            pgpid_error(_("Notice: Give --admincode, or --admincodefrom to "
                        "keep it off the process list."));
            return PGPID_USAGE;
        }
    }
    if (strlen(admincode) < 8)
        pgpid_error(_("Warning: Admin code shorter than 8 digits."));

    /* card-edit, because gpg has no --quick- form for these. For the name it
     * asks for the surname and then the given names: the whole value goes in
     * the first answer and the second is left empty. */
    char script[700];
    if (!strcmp(field, "name"))
        snprintf(script, sizeof script, "admin\nname\n%.500s\n\nquit\n", value);
    else
        snprintf(script, sizeof script, "admin\n%s\n%.500s\nquit\n", field, value);

    const char *edit[] = { "--command-fd", "0", "--batch", "--pinentry-mode",
                           "loopback", "--passphrase", admincode, "--card-edit", NULL };
    if (pgpid_run_engine_input(edit, script)) {
        pgpid_error(_("Error: gpg --card-edit failed — wrong Admin code?"));
        return PGPID_FAIL;
    }
    pgpid_error(_("Notice: Wrote new value '%s' into the security token."), value);
    return PGPID_OK;
}
