/* Is the security key configured to carry an identity?
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The hottest path there is: the application asks this every time a key is
 * plugged in, and twice — once without the network to answer at once, once
 * with it to be right.
 *
 * The answer is a set of fields and, more importantly, *which of them are
 * missing*. A key with no identifier is not broken, it is blank; a key whose
 * certificate is not at hand is not blank, it is unfetched. The return code
 * carries that distinction — 100 plus the number of missing fields — and the
 * application shows the reasons rather than the word "invalid".
 */
#include "pgpid.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* The fields, in the order they are reported. */
enum {
    F_NAME, F_ID, F_EMAIL, F_SKEY, F_EKEY, F_AKEY, F_CERTURL,
    F_CKEY, F_TOKEN_ID, F_AVERSION, F_MSN, F_COUNT,
};

static const char *const FIELD_NAME[F_COUNT] = {
    "pgpid_name", "pgpid_id", "pgpid_email", "pgpid_Skeyfpr", "pgpid_Ekeyfpr",
    "pgpid_Akeyfpr", "pgpid_certurl", "pgpid_Ckeyfpr", "token_ID",
    "token_AVersion", "token_MSN",
};

/* The seven a PGP ID needs. The other four are description, not identity:
 * a card can say which model it is and still carry nobody. */
static const int REQUIRED[] = {
    F_NAME, F_ID, F_EMAIL, F_SKEY, F_EKEY, F_AKEY, F_CERTURL,
};

struct fields {
    char v[F_COUNT][512];
};

/** The text after the first ": ", or "" for gpg's "[not set]". */
static void take_value(const char *line, char *out, size_t max)
{
    const char *colon = strchr(line, ':');
    if (!colon) {
        out[0] = '\0';
        return;
    }
    colon++;
    while (*colon == ' ')
        colon++;
    snprintf(out, max, "%s", colon);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\r' || out[n - 1] == ' '))
        out[--n] = '\0';
    if (!strcmp(out, "[not set]"))
        out[0] = '\0';
}

/** The forty hexadecimal characters in a line, spaces removed. */
static bool take_fingerprint(const char *line, char *out, size_t max)
{
    char packed[256];
    size_t n = 0;
    for (const char *p = line; *p && n < sizeof packed - 1; p++)
        if (isxdigit((unsigned char)*p))
            packed[n++] = (char)toupper((unsigned char)*p);
    packed[n] = '\0';
    /* A short line means the slot is empty, not that the card lied. */
    if (n < 40)
        return false;
    snprintf(out, max, "%.40s", packed + n - 40);
    return true;
}

/** The first address in a line, or false. */
static bool take_email(const char *line, char *out, size_t max)
{
    for (const char *at = strchr(line, '@'); at; at = strchr(at + 1, '@')) {
        const char *start = at;
        while (start > line && (isalnum((unsigned char)start[-1])
               || strchr("_.%+-", start[-1])))
            start--;
        const char *end = at + 1;
        while (*end && (isalnum((unsigned char)*end) || *end == '.' || *end == '-'))
            end++;
        /* A sentence's full stop is not part of the address it ends. */
        while (end > at + 1 && end[-1] == '.')
            end--;
        /* A domain needs a dot, and its *last* label must be letters -- the
         * first dot is the wrong one to look at, and looking there is how
         * "a@mail.example.org" and "a@example.co.uk" were both thrown away:
         * anything with more than two labels failed. Two letters at least,
         * since no top-level domain is shorter. */
        const char *dot = NULL;
        for (const char *p = at + 1; p < end; p++)
            if (*p == '.')
                dot = p;
        if (start == at || !dot || end - dot < 3)
            continue;
        bool tail_alpha = true;
        for (const char *p = dot + 1; p < end; p++)
            tail_alpha = tail_alpha && isalpha((unsigned char)*p);
        if (!tail_alpha)
            continue;
        size_t n = (size_t)(end - start);
        if (n >= max)
            continue;
        memcpy(out, start, n);
        out[n] = '\0';
        return true;
    }
    return false;
}

/**
 * An identifier written bare, as the card writes it.
 *
 * `pgpid_eid_of_uid` reads the shapes a *uid* uses; the card's "Login data"
 * field holds the identifier on its own, with nothing around it. Same value,
 * different surroundings — and looking for it with the wrong reader is how
 * the field came back empty while sitting in plain sight.
 */
/* Three spellings have existed for one identifier: the current glued form, a
 * deprecated "u4=" separator, and an older "udid4=" still. A card written years
 * ago carries what it carried then, and an identifier is for life -- so all
 * three are read, and the glued form is what comes back. */
static bool take_bare_eid(const char *line, char *out, size_t max)
{
    for (const char *p = line; *p; p++) {
        const char *q = p;
        if (!strncmp(q, "udid", 4))
            q += 4;
        else if (*q == 'u')
            q += 1;
        else
            continue;
        if (*q != '4' && *q != '5')
            continue;
        char digit = *q++;
        if (*q == '=')
            q++;

        size_t body = (digit == '4') ? 22 + 14 : 16 + 14;
        char glued[64];
        if (2 + body + 1 > sizeof glued || 2 + body >= max)
            continue;
        if (strlen(q) < body)
            continue;
        glued[0] = 'u';
        glued[1] = digit;
        memcpy(glued + 2, q, body);
        glued[2 + body] = '\0';
        if (!pgpid_eid_body_is_sound(glued))
            continue;
        memcpy(out, glued, 2 + body + 1);
        return true;
    }
    return false;
}

/**
 * The cardholder name, as a name rather than as a field.
 *
 * The card's own field is short and people put whatever fits in it. When it
 * holds an address, only what comes before the '@' is a name; when it holds a
 * name *and* an address, the address is removed. Either way what is left is
 * later superseded by the certificate's own FN, which has room.
 */
static void clean_name(char *name, size_t max)
{
    char address[320];
    if (!take_email(name, address, sizeof address))
        return;
    if (!strcmp(name, address)) {
        const char *at = strchr(name, '@');
        size_t n = (size_t)(at - name);
        if (n < max)
            name[n] = '\0';
        return;
    }
    char *found = strstr(name, address);
    if (!found)
        return;
    memmove(found, found + strlen(address), strlen(found + strlen(address)) + 1);
    size_t n = strlen(name);
    while (n && name[n - 1] == ' ')
        name[--n] = '\0';
    size_t lead = 0;
    while (name[lead] == ' ')
        lead++;
    if (lead)
        memmove(name, name + lead, strlen(name + lead) + 1);
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " token_check [OPTIONS]...\n"
        "\n"
        "Check if security token is correctly configured for PGP ID ; may output informations.\n"
        "Will try to import cleaned certificate indicated in 'URL of public key' field.\n"
        "\n"
        "OPTIONS:\n"
        "  -f, --no-fetch              Don't try to fetch public certificate (from URL indicated in token metadata)\n"
        "  -q, --quiet                 Don't errput 'Info' or 'Notice' messages\n"
        "  -p, --cert-fpr              Output certificate fingerprint (Certification key fpr)\n"
        "  -i, --info                  Output the metadata as pairs key='value' ready to be evaluated in bash\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "Return value:\n"
        "-   0 if no error and security token is correctly configured for PGP ID.\n"
        "- 100 + number of missing PGP ID data fields.\n"
        "- then 107 if all required data are missing (OpenPGP card is probably empty).\n"
        "- Other non-zero on other errors.\n"),
            PGPID_NAME);
}

/**
 * The certificate's own FN, which has room where the card's field has not.
 *
 * The reading itself lives in common.c, so that a certificate is called the
 * same thing here, on a vCard, and in a list of certifiers.
 */
static bool certificate_name(const char *fpr, char *out, size_t max)
{
    const char *pat[] = { fpr };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
    bool found = pgpid_key_name(pgpid_keys_at(kr, 0), out, max);
    pgpid_keys_free(kr);
    return found;
}

int pgpid_action_token_check(int argc, char **argv)
{
    bool fetch = true, info = false, quiet = false, print_fpr = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-f") || !strcmp(a, "--no-fetch")) fetch = false;
        else if (!strcmp(a, "-p") || !strcmp(a, "--cert-fpr")) print_fpr = true;
        else if (!strcmp(a, "-i") || !strcmp(a, "--info")) info = true;
        else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) quiet = true;
        else if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout); return PGPID_OK; }
        else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("token_check");
            return PGPID_USAGE;
        }
    }

    struct fields f;
    memset(&f, 0, sizeof f);

    char status[16384];
    if (pgpid_capture_card_status(status, sizeof status) < 0 || !*status) {
        pgpid_error(_("Error: No security key answered."));
        return PGPID_FAIL;
    }

    /* The certificate may be fetched before anything is read from it, since
     * the address often lives only in the certificate and not on the card. */
    char url[512] = "";
    {
        /* On a copy: strtok_r writes NULs where the newlines were, and the
         * answer is needed whole afterwards. Scanning in place here cost an
         * hour and read as "the card says nothing". */
        char scan[16384];
        snprintf(scan, sizeof scan, "%s", status);
        for (char *line = scan, *save; (line = strtok_r(line, "\n", &save)); line = NULL)
            if (!strncmp(line, "URL", 3)) {
                take_value(line, url, sizeof url);
                break;
            }
    }
    if (*url && fetch) {
        if (!quiet)
            pgpid_error(_("Notice: Fetching the certificate from %s…"), url);
        char fetched[1 << 20];
        const char *curl[] = { "curl", "--no-progress-meter", "--location", url, NULL };
        int n = pgpid_capture(curl, fetched, sizeof fetched);
        if (n > 0) {
            /* Written where gpg can import it: a pipe would need a second
             * process and this is already the slow path. */
            char path[] = "/tmp/pgpid-fetch.XXXXXX";
            int fd = mkstemp(path);
            if (fd >= 0) {
                if (write(fd, fetched, (size_t)n) == n) {
                    close(fd);
                    const char *import[] = { "--import", path, NULL };
                    pgpid_run_engine(import);
                    /* Read the card again: what it says may now resolve.
                     * Through the engine -- this called pgpid_capture with
                     * gpg's arguments but no gpg, so it execed "--card-status"
                     * as a program, failed, and emptied what it meant to
                     * refresh. */
                    pgpid_capture_card_status(status, sizeof status);
                } else {
                    close(fd);
                }
                unlink(path);
            }
        }
    }

    /* One pass over the card's answer. Addresses and identifiers are looked
     * for on every line, because the card puts them wherever it likes. */
    char emails[8][320];
    unsigned nemails = 0;
    char ids[4][64];
    unsigned nids = 0;
    char ttype[128] = "", tversion[128] = "", manufacturer[128] = "", serial[128] = "";

    char copy[16384];
    snprintf(copy, sizeof copy, "%s", status);
    for (char *line = copy, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        if (!strncmp(line, "Application ID", 14))
            take_value(line, f.v[F_TOKEN_ID], sizeof f.v[0]);
        else if (!strncmp(line, "Application type", 16))
            take_value(line, ttype, sizeof ttype);
        else if (!strncmp(line, "Version", 7))
            take_value(line, tversion, sizeof tversion);
        else if (!strncmp(line, "Manufacturer", 12))
            take_value(line, manufacturer, sizeof manufacturer);
        else if (!strncmp(line, "Serial number", 13))
            take_value(line, serial, sizeof serial);
        else if (!strncmp(line, "URL", 3))
            take_value(line, f.v[F_CERTURL], sizeof f.v[0]);
        else if (!strncmp(line, "Name of cardholder", 18)) {
            take_value(line, f.v[F_NAME], sizeof f.v[0]);
            clean_name(f.v[F_NAME], sizeof f.v[0]);
        }
        else if (!strncmp(line, "Signature key", 13))
            take_fingerprint(line, f.v[F_SKEY], sizeof f.v[0]);
        else if (!strncmp(line, "Encryption key", 14))
            take_fingerprint(line, f.v[F_EKEY], sizeof f.v[0]);
        else if (!strncmp(line, "Authentication key", 18))
            take_fingerprint(line, f.v[F_AKEY], sizeof f.v[0]);

        char address[320];
        if (nemails < 8 && take_email(line, address, sizeof address)) {
            bool known = false;
            for (unsigned i = 0; i < nemails; i++)
                known = known || !strcmp(emails[i], address);
            if (!known)
                snprintf(emails[nemails++], sizeof emails[0], "%s", address);
        }
        char bare[64];
        char *eid = pgpid_eid_of_uid(line);
        if (!eid && take_bare_eid(line, bare, sizeof bare))
            eid = strdup(bare);
        if (eid) {
            bool known = false;
            for (unsigned i = 0; i < nids; i++)
                known = known || !strcmp(ids[i], eid);
            if (!known && nids < 4)
                snprintf(ids[nids++], sizeof ids[0], "%s", eid);
            free(eid);
        }
    }

    if (nemails)
        snprintf(f.v[F_EMAIL], sizeof f.v[0], "%s", emails[0]);
    if (nemails > 1 && !quiet)
        pgpid_error(_("Notice: The key names %u addresses; keeping the first."), nemails);
    if (nids > 1) {
        pgpid_error(_("Error: The key names %u identifiers, which cannot both be its."), nids);
        return PGPID_FAIL;
    }
    if (nids)
        snprintf(f.v[F_ID], sizeof f.v[0], "%s", ids[0]);
    snprintf(f.v[F_AVERSION], sizeof f.v[0], "%s %s", ttype, tversion);
    snprintf(f.v[F_MSN], sizeof f.v[0], "%s %s", manufacturer, serial);

    /* The key that certifies may not be the one that signs — a card carries
     * subkeys, and the certification key stays off it. */
    const char *anchor = *f.v[F_SKEY] ? f.v[F_SKEY]
                       : *f.v[F_EKEY] ? f.v[F_EKEY] : f.v[F_AKEY];
    if (*anchor) {
        const char *pat[] = { anchor };
        struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
        const struct pgpid_key *key = pgpid_keys_at(kr, 0);
        if (key && *key->fpr)
            snprintf(f.v[F_CKEY], sizeof f.v[0], "%s", key->fpr);
        pgpid_keys_free(kr);
    }
    if (!*f.v[F_CKEY] && !quiet)
        pgpid_error(_("Warning: No certification key known. Share or fetch the certificate."));

    /* The certificate's name wins over the card's: the card's field is short
     * and was filled once, the certificate's is the one kept up to date. */
    if (*f.v[F_CKEY]) {
        char fn[512];
        if (certificate_name(f.v[F_CKEY], fn, sizeof fn))
            snprintf(f.v[F_NAME], sizeof f.v[0], "%s", fn);
    }

    if (print_fpr)
        printf("%s\n", f.v[F_CKEY]);

    if (info)
        for (unsigned i = 0; i < F_COUNT; i++)
            printf("%s='%s'\n", FIELD_NAME[i], f.v[i]);

    /* What is missing, and how much of it. A key missing everything is blank;
     * a key missing one thing needs that one thing. The count says which. */
    int missing = 0;
    for (unsigned i = 0; i < sizeof REQUIRED / sizeof *REQUIRED; i++) {
        if (*f.v[REQUIRED[i]])
            continue;
        missing++;
        if (!quiet)
            pgpid_error(_("Notice: Not a PGP ID key yet, missing: '%s'."),
                        FIELD_NAME[REQUIRED[i]]);
    }
    if (missing)
        return 100 + missing;

    if (!quiet)
        pgpid_error(_("Info: A PGP ID key, certified by %s, carrying %s."),
                    f.v[F_CKEY], f.v[F_ID]);

    /* Valid, so it gets remembered -- beside GnuPG's stub, which says only
     * which card holds the secret and has no room for the rest. Written here
     * and only here: a key that fails the check is not one we want to answer
     * questions about later. */
    if (*f.v[F_TOKEN_ID]) {
        char note[4096] = "";
        for (unsigned i = 0; i < F_COUNT; i++) {
            char line[640];
            snprintf(line, sizeof line, "%s='%s'\n", FIELD_NAME[i], f.v[i]);
            if (strlen(note) + strlen(line) < sizeof note)
                strcat(note, line);
        }
        pgpid_token_remember(f.v[F_TOKEN_ID], note);
    }
    return PGPID_OK;
}
