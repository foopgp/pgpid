/* Moving the secrets onto a card.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Moving, not copying: `keytocard` takes the secret parts off this machine
 * and leaves a stub pointing at the card. There is no undo and no second
 * copy — whoever runs this without having printed the key first has one
 * object in the world holding their identity, and it fits in a pocket.
 *
 * The card is wiped first, which is the other irreversible half: anything
 * already on it goes. The shell asks before doing that unless the card is
 * blank; this refuses instead, because a question nobody is there to answer
 * is not a safeguard.
 *
 * The passphrase has to come off the key beforehand — gpg will not move a
 * protected key to a card — and the card leaves the factory with 123456 and
 * 12345678, which is why new codes are drawn and printed at the end. They are
 * printed once. Nothing else knows them.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/random.h>
#include <unistd.h>

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: " PGPID_MIP_NAME " totoken [OPTIONS]... KEY\n"
        "\n"
        "Move an OpenPGP secret key onto the connected security key, and print the\n"
        "certificate, the new PIN and the new Admin code.\n"
        "\n"
        "This wipes the card and takes the secret parts off this machine. Both are\n"
        "final. Print the key first if it is not printed: " PGPID_MIP_NAME
        " print_secret.\n"
        "\n"
        "OPTIONS:\n"
        "  -p, --passphrase PASSPHRASE  The passphrase protecting the secret parts\n"
        "  -P, --passfrom FILE          Read it from the first line of FILE instead\n"
        "  -U, --certurl URL            Where the certificate can be fetched\n"
        "                               Default: the keyserver's lookup for this key\n"
        "  -L, --lang LANG              The card's language preference - Default: the locale's\n"
        "  -k, --keyserver KEYSERVER    Send the certificate there, and build the\n"
        "                               default URL from it\n"
        "  -K, --pubkey FILE            Also write the armored certificate to FILE\n"
        "      --force                  Wipe a card that is not blank\n"
        "  -h, --help                   Print this help and exit\n"
        "  -V, --version                Print the version and exit\n");
}

static bool first_line_of(const char *path, char *out, size_t max)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        pgpid_error("Error: Cannot read %s.", path);
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

/**
 * A code of N digits, drawn without bias.
 *
 * The obvious `random % 10` is not uniform when the range does not divide the
 * generator's; on a six-digit PIN it is a small bias, and a small bias in a
 * secret is the kind of thing that gets published about later. Rejecting the
 * tail costs nothing here.
 */
static bool draw_code(char *out, size_t digits)
{
    for (size_t i = 0; i < digits; i++) {
        unsigned char byte;
        for (;;) {
            if (getrandom(&byte, 1, 0) != 1)
                return false;
            if (byte < 250)          /* 250 = 25 × 10: the tail is thrown away */
                break;
        }
        out[i] = (char)('0' + byte % 10);
    }
    out[digits] = '\0';
    return true;
}

int pgpid_action_totoken(int argc, char **argv)
{
    char passphrase[512] = "";
    const char *certurl = NULL, *keyserver = NULL, *pubkeyfile = NULL, *keyid = NULL;
    char lang[8] = "";
    bool force = false;

    const char *locale = getenv("LANG");
    if (locale && isalpha((unsigned char)locale[0]) && isalpha((unsigned char)locale[1]))
        snprintf(lang, sizeof lang, "%c%c",
                 tolower((unsigned char)locale[0]), tolower((unsigned char)locale[1]));

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-p") || !strcmp(a, "--passphrase")) {
            if (++i >= argc) { pgpid_error("Error: '%s' wants a passphrase.", a); return PGPID_USAGE; }
            snprintf(passphrase, sizeof passphrase, "%s", argv[i]);
        } else if (!strcmp(a, "-P") || !strcmp(a, "--passfrom") || !strcmp(a, "--pass-from")) {
            if (++i >= argc) { pgpid_error("Error: '%s' wants a file.", a); return PGPID_USAGE; }
            if (!first_line_of(argv[i], passphrase, sizeof passphrase))
                return PGPID_FAIL;
        } else if (!strcmp(a, "-U") || !strcmp(a, "--certurl")) {
            if (++i >= argc) { pgpid_error("Error: '%s' wants a URL.", a); return PGPID_USAGE; }
            certurl = argv[i];
        } else if (!strcmp(a, "-k") || !strcmp(a, "--keyserver")) {
            if (++i >= argc) { pgpid_error("Error: '%s' wants a keyserver.", a); return PGPID_USAGE; }
            keyserver = argv[i];
        } else if (!strcmp(a, "-L") || !strcmp(a, "--lang")) {
            if (++i >= argc) { pgpid_error("Error: '%s' wants a language.", a); return PGPID_USAGE; }
            snprintf(lang, sizeof lang, "%.2s", argv[i]);
            for (char *p = lang; *p; p++)
                *p = (char)tolower((unsigned char)*p);
        } else if (!strcmp(a, "-K") || !strcmp(a, "--pubkey")) {
            if (++i >= argc) { pgpid_error("Error: '%s' wants a file.", a); return PGPID_USAGE; }
            pubkeyfile = argv[i];
        } else if (!strcmp(a, "--force")) {
            force = true;
        } else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
            /* Accepted: gpg's noise goes to stderr either way. */
        } else if (!strcmp(a, "--no-send")) {
            pgpid_error("Warning: Deprecated option %s.", a);
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_MIP_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error("Error: Unrecognized option '%s'.", a);
            pgpid_error("Try '" PGPID_MIP_NAME " totoken --help' for more information.");
            return PGPID_USAGE;
        } else if (!keyid) {
            keyid = a;
        }
    }

    if (strlen(lang) != 2)
        pgpid_error("Warning: Only 2 lower case ASCII letters can define a preferred "
                    "language; leaving it out.");
    if (!keyid) {
        pgpid_error("Error: Which secret key should move onto the card?");
        usage(stderr);
        return PGPID_USAGE;
    }

    char listing[16384], fpr[41] = "";
    const char *find[] = { "--list-secret-keys", "--with-colons", keyid, NULL };
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
        pgpid_error("Error: No secret for '%s' here.", keyid);
        return PGPID_FAIL;
    }

    const char *host = keyserver ? keyserver : PGPID_KEYSERVERS_FIRST;
    const char *bare = strstr(host, "//");
    bare = bare ? bare + 2 : host;
    char url[512];
    if (certurl)
        snprintf(url, sizeof url, "%.500s", certurl);
    else
        snprintf(url, sizeof url, "https://%.200s/pks/lookup?op=get&search=0x%s", bare, fpr);

    if (pubkeyfile) {
        const char *ex[] = { "--export", "--armor", fpr, NULL };
        if (pgpid_run_engine_io(ex, NULL, pubkeyfile)) {
            pgpid_error("Error: Cannot write the certificate to %s.", pubkeyfile);
            return PGPID_FAIL;
        }
    }

    /* What goes on the card: its holder's identifier if the certificate has
     * one, else the first address. Both are read from the uids rather than
     * asked for. */
    struct pgpid_uid uids[256];
    size_t nuids = pgpid_list_uids(fpr, true, uids, 256);
    char email[320] = "", eid[64] = "";
    for (size_t i = 0; i < nuids; i++) {
        if (!pgpid_uid_stands(uids[i].validity))
            continue;
        if (!*email) {
            size_t len = 0;
            const char *addr = pgpid_uid_address(uids[i].text, &len);
            if (addr && len < sizeof email)
                snprintf(email, sizeof email, "%.*s", (int)len, addr);
        }
        if (!*eid) {
            char *found = pgpid_eid_of_uid(uids[i].text);
            if (found) {
                snprintf(eid, sizeof eid, "%s", found);
                free(found);
            }
        }
    }
    if (!*email) {
        pgpid_error("Error: No email for OpenPGP key '%s'.", fpr);
        return PGPID_FAIL;
    }

    char skey[41], ekey[41], akey[41], serial[64];
    (void)skey; (void)ekey; (void)akey;
    {
        char status[16384];
        const char *argv2[] = { "gpg", "--card-status", NULL };
        *serial = '\0';
        if (pgpid_capture(argv2, status, sizeof status) > 0) {
            const char *at = strstr(status, "Serial number");
            const char *colon = at ? strchr(at, ':') : NULL;
            size_t n = 0;
            for (const char *p = colon ? colon + 1 : ""; *p && *p != '\n' && n < 63; p++)
                if (isxdigit((unsigned char)*p))
                    serial[n++] = (char)toupper((unsigned char)*p);
            serial[n] = '\0';
        }
    }
    if (!*serial) {
        pgpid_error("Error: No security token detected.");
        return PGPID_FAIL;
    }
    pgpid_error("Notice: Detected OpenPGP security token: %s.", serial);

    /* Wiping the card is the point of no return for whatever is on it. */
    if (!force) {
        pgpid_error("Error: This wipes card %s and everything on it, then takes the", serial);
        pgpid_error("secret parts of %s off this machine. Neither can be undone.", fpr);
        pgpid_error("Pass --force when that is what you mean.");
        return PGPID_USAGE;
    }

    /* Only now: gpg will not move a protected key to a card, so the
     * passphrase has to come off. That is itself irreversible, and doing it
     * before the --force check meant a refused command still changed the key
     * on disk — found by running the refusal and reading what gpg said. */
    char answer[600];
    snprintf(answer, sizeof answer, "\n");
    const char *dry[] = { "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                          "--dry-run", "--change-passphrase", fpr, NULL };
    if (pgpid_run_engine(dry)) {
        if (!*passphrase) {
            pgpid_error("Error: The key is protected by a passphrase, which has to "
                        "come off before it can move to a card.");
            pgpid_error("Give --passphrase, or --passfrom to keep it off the process list.");
            return PGPID_USAGE;
        }
        char script[1200];
        snprintf(script, sizeof script, "%.500s\n\n\n\n", passphrase);
        const char *strip[] = { "--command-fd", "0", "--batch", "--pinentry-mode",
                                "loopback", "--change-passphrase", fpr, NULL };
        if (pgpid_run_engine_input(strip, script)) {
            pgpid_error("Error: Cannot take the passphrase off '%s' — right passphrase?", fpr);
            return PGPID_FAIL;
        }
    }

    pgpid_error("Notice: Resetting OpenPGP security token…");
    const char *reset[] = { "--command-fd", "0", "--batch", "--card-edit", NULL };
    if (pgpid_run_engine_input(reset, "admin\nfactory-reset\ny\nyes\nquit\n")) {
        pgpid_error("Error: Factory reset of the OpenPGP card failed.");
        return PGPID_FAIL;
    }

    pgpid_error("Notice: Configuring OpenPGP security token…");
    char config[1400];
    snprintf(config, sizeof config,
             "admin\nlogin\n%.100s\nurl\n%.500s\n%s%.2s%s"
             "name\n%.300s\n\n",
             *eid ? eid : email, url,
             strlen(lang) == 2 ? "lang\n" : "", lang, strlen(lang) == 2 ? "\n" : "",
             email);
    const char *setup[] = { "--command-fd", "0", "--batch", "--pinentry-mode",
                            "loopback", "--passphrase", "12345678", "--card-edit", NULL };
    if (pgpid_run_engine_input(setup, config)) {
        pgpid_error("Error: Configuring the OpenPGP card failed.");
        return PGPID_FAIL;
    }

    /* The card is told to hold elliptic-curve keys before the keys arrive:
     * changing that afterwards would wipe them again. */
    if (pgpid_run_engine_input(setup, "admin\nkey-attr\n2\n1\n2\n1\n2\n1\nquit\n")) {
        pgpid_error("Error: Setting the card's key attributes failed.");
        return PGPID_FAIL;
    }

    pgpid_error("Notice: Moving OpenPGP secrets to security token…");
    const char *move[] = { "--command-fd", "0", "--batch", "--pinentry-mode",
                           "loopback", "--passphrase", "12345678", "--edit-key", fpr, NULL };
    if (pgpid_run_engine_input(move,
            "keytocard\ny\n1\nkey 1\nkeytocard\n2\nkey 1\nkey 2\nkeytocard\n3\nsave\n")) {
        pgpid_error("Error: Moving the secrets to the card failed.");
        return PGPID_FAIL;
    }

    /* The factory codes are printed on the internet; new ones are drawn here
     * and printed once. */
    char pin[8], admin[16];
    if (!draw_code(pin, 6) || !draw_code(admin, 8)) {
        pgpid_error("Error: Cannot draw new codes — the card is left on its "
                    "factory PIN 123456 and Admin 12345678. Change them now.");
        return PGPID_FAIL;
    }
    char pinfile[] = "/tmp/pgpid-mip-pin-XXXXXX";
    int fd = mkstemp(pinfile);
    if (fd < 0) {
        pgpid_error("Error: Cannot make a temporary file for the new codes.");
        return PGPID_FAIL;
    }
    close(fd);

    struct { const char *current; const char *fresh; bool admin; const char *what; } codes[] = {
        { "123456",   pin,   false, "PIN" },
        { "12345678", admin, true,  "Admin" },
    };
    for (unsigned i = 0; i < 2; i++) {
        FILE *f = fopen(pinfile, "w");
        if (!f) {
            pgpid_error("Error: Cannot write the new %s code out.", codes[i].what);
            return PGPID_FAIL;
        }
        fprintf(f, "%s\n", codes[i].fresh);
        fclose(f);
        char *sub[8];
        int n = 0;
        sub[n++] = (char *)"change_token_code";
        sub[n++] = (char *)"--code";
        sub[n++] = (char *)codes[i].current;
        sub[n++] = (char *)"--newcodefrom";
        sub[n++] = pinfile;
        if (codes[i].admin)
            sub[n++] = (char *)"--admin";
        sub[n] = NULL;
        int ret = pgpid_action_change_token_code(n, sub);
        if (ret) {
            unlink(pinfile);
            pgpid_error("Error: Changing the %s code failed (%d). The card is left "
                        "on its factory code — change it now.", codes[i].what, ret);
            return ret;
        }
    }
    unlink(pinfile);

    printf("\n");
    const char *ex[] = { "--export", "--armor", fpr, NULL };
    if (pgpid_run_engine(ex))
        return PGPID_FAIL;
    if (pgpid_send_to_keyservers(fpr, host))
        pgpid_error("Warning: Please publish this certificate on the Internet "
                    "(a keyserver will do).");

    printf("\nADMIN_CODE=%s\nPIN_CODE=%s\n", admin, pin);
    pgpid_error("Notice: Write these down. Nothing else knows them. They can be "
                "changed with '" PGPID_MIP_NAME " change_token_code'.");
    return PGPID_OK;
}
