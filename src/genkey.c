/* Making a certificate that is a PGP ID from birth.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The certificate is born with one uid and one only: the identity, written
 * `UID:urn:eid:<eid>`. Everything else — the name, the note, the address — is
 * added afterwards as its own uid, because each is a separate claim that can
 * be revoked separately. A certificate whose name and address are welded into
 * one string cannot drop the address without dropping the name.
 *
 * The primary flag then goes on the *address*, never on the identity anchor.
 * That looks backwards and is not: the primary uid is what mail clients show
 * and what a keyserver search leads with, so it has to be the thing people
 * recognise. The anchor does not need to be first; it needs to be signed.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " gen_key [OPTIONS]... EMAIL\n"
        "\n"
        "Generate a PGP key pair (public and secret) according to PGP ID standards.\n"
        "Output 3 lines for each fingerprints:\n"
        "* main key (Sign Certify)\n"
        "* decryption key (Encrypt)\n"
        "* authentication key (Auth)\n"
        "\n"
        "OPTIONS:\n"
        "  -N, --name PSEUDONYM             Common name or pseudonym. Default: first part of email\n"
        "  -c, --eid U4|U5                  Entity ID. Worldwide and decentralised entity identifier. Required here\n"
        "  -C, --extra-comment NOTE         Supplemental information or comment associated with the entity\n"
        "  -p, --passphrase PASSPHRASE      Passphrase to (symetric) encrypt secret part of PGP key. CAN'T BE EMPTY (at this stage)\n"
        "  -P, --passfrom FILE              Get passphrase from first line of FILE (eg: fifo, tmpfs, /dev/stdin …)\n"
        "  -e, --expiration YEARS           Number of years before certificate expiration. Default: 11\n"
        "  -k, --keyserver KEYSERVER        Prefered PGP certificate server. Default: "
        "%s"
        "\n"
        "  -h, --help                       Print this help and exit\n"
        "  -V, --version                    Print the version and exit\n"
        "\n"
        "Both ways of giving the passphrase have their drawback, and the second has\n"
        "fewer: an argument is visible to every process on the machine for as long\n"
        "as this one runs.\n"),
            PGPID_NAME, PGPID_KEYSERVERS_FIRST);
}

/* Enough of a check to catch a typo, not a parser for RFC 5322. */
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

/**
 * The identifier out of what was typed.
 *
 * Written whole (`u4…`) or as the body alone: both are in use, one comes off
 * a certificate and the other out of `gen_u4`, and refusing either would only
 * teach people to paste more carefully.
 */
static bool read_eid(const char *given, char *out, size_t max)
{
    for (const char *p = given; *p; p++)
        if (pgpid_eid_body_is_sound(p)) {
            size_t n = (p[1] == '4') ? 2 + 22 + 14 : 2 + 16 + 14;
            if (n >= max)
                return false;
            memcpy(out, p, n);
            out[n] = '\0';
            return true;
        }
    for (unsigned kind = 4; kind <= 5; kind++) {
        char tried[128];
        snprintf(tried, sizeof tried, "u%u%.100s", kind, given);
        if (pgpid_eid_body_is_sound(tried)) {
            size_t n = (kind == 4) ? 2 + 22 + 14 : 2 + 16 + 14;
            if (n >= max)
                return false;
            memcpy(out, tried, n);
            out[n] = '\0';
            return true;
        }
    }
    return false;
}

/** RFC 6350 §3.4, for the note — the only free text minted here. */
static void escape(const char *v, char *out, size_t max)
{
    size_t n = 0;
    for (; *v && n + 2 < max; v++) {
        switch (*v) {
        case '\\': out[n++] = '\\'; out[n++] = '\\'; break;
        case '\r': break;
        case ',':  out[n++] = '\\'; out[n++] = ','; break;
        case ';':  out[n++] = '\\'; out[n++] = ';'; break;
        case '\n': out[n++] = '\\'; out[n++] = 'n'; break;
        default:   out[n++] = *v; break;
        }
    }
    out[n] = '\0';
}

int pgpid_action_gen_key(int argc, char **argv)
{
    const char *email = NULL, *pseudo = NULL, *given_eid = NULL;
    const char *note = NULL, *keyserver = NULL;
    char passphrase[512] = "";
    int expire = 11;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-n") || !strcmp(a, "-N") || !strncmp(a, "--name", 6)) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a name."), a);
                return PGPID_USAGE;
            }
            pseudo = argv[i];
        } else if (!strcmp(a, "-c") || !strcmp(a, "--eid") || !strcmp(a, "--comment")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants an identifier."), a);
                return PGPID_USAGE;
            }
            given_eid = argv[i];
        } else if (!strcmp(a, "-C") || !strcmp(a, "--extra-comment")
                   || !strcmp(a, "--extracomment")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a note."), a);
                return PGPID_USAGE;
            }
            note = argv[i];
        } else if (!strcmp(a, "-p") || !strcmp(a, "--passphrase")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a passphrase."), a);
                return PGPID_USAGE;
            }
            snprintf(passphrase, sizeof passphrase, "%s", argv[i]);
        } else if (!strcmp(a, "-P") || !strcmp(a, "--passfrom")
                   || !strcmp(a, "--pass-from")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a file."), a);
                return PGPID_USAGE;
            }
            FILE *f = fopen(argv[i], "r");
            if (!f) {
                pgpid_error(_("Error: Cannot read %s."), argv[i]);
                return PGPID_FAIL;
            }
            if (!fgets(passphrase, sizeof passphrase, f))
                *passphrase = '\0';
            fclose(f);
            size_t n = strlen(passphrase);
            while (n && (passphrase[n - 1] == '\n' || passphrase[n - 1] == '\r'))
                passphrase[--n] = '\0';
        } else if (!strcmp(a, "-e") || !strncmp(a, "--expir", 7)) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a number of years."), a);
                return PGPID_USAGE;
            }
            char *end = NULL;
            long v = strtol(argv[i], &end, 10);
            if (!end || *end || v < 1) {
                pgpid_error(_("Error: Given parameter '%s' is not a valid number."), argv[i]);
                return PGPID_USAGE;
            }
            expire = (int)v;
        } else if (!strcmp(a, "-k") || !strcmp(a, "--keyserver")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a keyserver."), a);
                return PGPID_USAGE;
            }
            if (strncmp(argv[i], "hkp://", 6) && strncmp(argv[i], "hkps://", 7)) {
                pgpid_error(_("Error: keyserver MUST be hkp(s)://…"));
                return PGPID_USAGE;
            }
            keyserver = argv[i];
        } else if (!strcmp(a, "-v") || !strcmp(a, "--verify")) {
            /* Accepted since the shell accepts it; it checks nothing there
             * either, and inventing checks here would be a difference. */
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
            pgpid_try_help("gen_key");
            return PGPID_USAGE;
        } else if (!email) {
            email = a;
        }
    }

    if (!email || !looks_like_address(email)) {
        usage(stderr);
        return PGPID_USAGE;
    }

    char eid[64];
    if (!given_eid) {
        pgpid_error(_("Error: Which entity is this key for? Give --eid."));
        pgpid_error(_("Deriving one needs a civil status, which is somebody's to give:"));
        pgpid_error(_("  %s gen_u4 --surname … --given-names … --birth-date … --birth-country …"),
                    PGPID_NAME);
        return PGPID_USAGE;
    }
    if (!read_eid(given_eid, eid, sizeof eid)) {
        pgpid_error(_("Error: No eid in given '%s'."), given_eid);
        return PGPID_USAGE;
    }
    if (!*passphrase) {
        pgpid_error(_("Error: A passphrase is needed, and asking for one is not this "
                    "program's job. Give --passphrase, or --passfrom to keep it off"));
        pgpid_error(_("the process list."));
        return PGPID_USAGE;
    }

    char name[512];
    if (pseudo)
        snprintf(name, sizeof name, "%s", pseudo);
    else
        snprintf(name, sizeof name, "%.*s", (int)(strchr(email, '@') - email), email);

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    tm.tm_year += expire;
    char until[16];
    strftime(until, sizeof until, "%Y-%m-%d", &tm);

    /* One self-certified identity uid, and nothing else yet. */
    char params[2048];
    snprintf(params, sizeof params,
             "%%echo Generating PGP key for %s\n"
             "Key-Type: eddsa\n"
             "Key-Curve: Ed25519\n"
             "Key-Usage: cert sign\n"
             "Subkey-Type: ecdh\n"
             "Subkey-Curve: Curve25519\n"
             "Subkey-Usage: encrypt\n"
             "Name-Real: UID:urn:eid:%s\n"
             "Expire-Date: %s\n"
             "Passphrase: %s\n"
             "Keyserver: %s\n"
             "%%commit\n",
             email, eid, until, passphrase,
             keyserver ? keyserver : PGPID_KEYSERVERS_FIRST);

    const char *gen[] = { "--batch", "--generate-key", "--allow-freeform-uid", NULL };
    if (pgpid_run_engine_input(gen, params)) {
        pgpid_error(_("Error: gpg would not generate the key."));
        return PGPID_FAIL;
    }

    /* Found by its exact identity uid — the '=' makes gpg match the whole
     * string rather than search for it, and at this point it is the only uid
     * the key has. */
    char selector[128], listing[8192];
    snprintf(selector, sizeof selector, "=UID:urn:eid:%s", eid);
    const char *find[] = { "--list-secret-keys", "--with-colons", selector, NULL };
    char fpr[41] = "";
    if (pgpid_capture_engine(find, listing, sizeof listing) > 0)
        for (char *line = listing, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
            if (strncmp(line, "fpr:", 4))
                continue;
            unsigned field = 1;
            char *at = line;
            for (; *at && field < 10; at++)
                if (*at == ':')
                    field++;
            char *end = strchr(at, ':');
            if (end)
                *end = '\0';
            if (pgpid_is_fingerprint(at))
                snprintf(fpr, sizeof fpr, "%s", at);
            break;
        }
    if (!*fpr) {
        pgpid_error(_("Error: Freshly generated key not found by its eid UID (%s)."), eid);
        return PGPID_FAIL;
    }

    /* The rest of what the certificate says about its holder, each claim its
     * own uid. Signing them needs the secret key, so the passphrase goes
     * straight to gpg rather than through an agent that would ask for it. */
    char fn[600], addr[900], years[16];
    snprintf(fn, sizeof fn, "FN:%.511s", name);
    snprintf(addr, sizeof addr, "%.511s <%.319s>", name, email);
    snprintf(years, sizeof years, "%dy", expire);

    const char *quick[] = { "--batch", "--pinentry-mode", "loopback",
                            "--passphrase", passphrase, NULL, NULL, NULL, NULL, NULL, NULL };
    #define QUICK(...)                                                    \
        do {                                                              \
            const char *rest[] = { __VA_ARGS__, NULL };                   \
            size_t at = 5;                                                \
            for (size_t k = 0; rest[k]; k++)                              \
                quick[at++] = rest[k];                                    \
            quick[at] = NULL;                                             \
        } while (0)

    QUICK("--quick-add-uid", fpr, fn);
    if (pgpid_run_engine(quick)) {
        pgpid_error(_("Error: gpg would not add '%s'."), fn);
        return PGPID_FAIL;
    }
    QUICK("--quick-add-uid", fpr, addr);
    if (pgpid_run_engine(quick)) {
        pgpid_error(_("Error: gpg would not add '%s'."), addr);
        return PGPID_FAIL;
    }
    if (note && *note) {
        char noteuid[1100], escaped[1024];
        escape(note, escaped, sizeof escaped);
        snprintf(noteuid, sizeof noteuid, "NOTE:%.1023s", escaped);
        QUICK("--quick-add-uid", fpr, noteuid);
        if (pgpid_run_engine(quick)) {
            pgpid_error(_("Error: gpg would not add '%s'."), noteuid);
            return PGPID_FAIL;
        }
    }
    QUICK("--quick-set-primary-uid", fpr, addr);
    if (pgpid_run_engine(quick))
        pgpid_error(_("Warning: Can't set the primary uid to %s."), addr);

    QUICK("--quick-add-key", fpr, "ed25519", "auth", years);
    if (pgpid_run_engine(quick)) {
        pgpid_error(_("Error: gpg would not add the authentication key."));
        return PGPID_FAIL;
    }
    #undef QUICK

    /* All three fingerprints, the main key first. */
    const char *all[] = { "--list-secret-keys", "--with-colons", email, NULL };
    if (pgpid_capture_engine(all, listing, sizeof listing) > 0)
        for (char *line = listing, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
            if (strncmp(line, "fpr:", 4))
                continue;
            unsigned field = 1;
            char *at = line;
            for (; *at && field < 10; at++)
                if (*at == ':')
                    field++;
            char *end = strchr(at, ':');
            if (end)
                *end = '\0';
            if (pgpid_is_fingerprint(at))
                printf("%s\n", at);
        }
    return PGPID_OK;
}
