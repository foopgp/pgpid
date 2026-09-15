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

/* Two ways the passphrase can stop this, told apart because a caller that
 * drives pgpid has to know which one to act on: ask for a passphrase, or say
 * the one it was given is wrong. 41 and 42 read together — something is
 * missing, or the holder refused. */
#define TOTOKEN_BAD_PASS  40
#define TOTOKEN_NEED_PASS 41

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " secret_totoken [OPTIONS]... KEY_ID|FPR\n"
        "\n"
        "Move PGP secrets to security token (OpenPGP smartcard).\n"
        "Security token (OpenPGP smartcard) must be connected.\n"
        "Output ASCII armored PGP certificate, PIN code and admin code.\n"
        "\n"
        "This wipes the card and takes the secret parts off this machine. Both are\n"
        "final. Print the key first if it is not printed: "
        "%s"
        " secret_print.\n"
        "\n"
        "OPTIONS:\n"
        "  -p, --passphrase PASSPHRASE  Passphrase to access secret parts of PGP key\n"
        "  -P, --passfrom FILE          Get passphrase from first line of FILE (eg: fifo, tmpfs, /dev/stdin ...)\n"
        "  -U, --certurl URL            URL to retrieve your PGP certificate\n"
        "                               Default: https://%s/pks/lookup?op=get&search=0x<FPR>\n"
        "  -L, --lang LANG              Security token (OpenPGP smartcard) prefered language (default: the locale's)\n"
        "  -k, --keyserver KEYSERVER    Send PGP certificate to this public keys server\n"
        "                               Empty to send it nowhere. Does not change --certurl\n"
        "                               Default: %s\n"
        "  -K, --pubkey FILE            Also write armored PGP certificate to given FILE\n"
        "      --force                  Don't ask before resetting unempty security token (OpenPGP smartcard)\n"
        "  -h, --help                   Print this help and exit\n"
        "  -V, --version                Print the version and exit\n"
        "\n"
        "Return value:\n"
        "-   0 No error\n"
        "-   2 Input/Usage error\n"
        "- %d The passphrase given does not open the secret key\n"
        "- %d The key is protected and no passphrase was given\n"),
            PGPID_NAME, PGPID_NAME, PGPID_KEYSERVERS_HOST, PGPID_KEYSERVERS_FIRST,
            TOTOKEN_BAD_PASS, TOTOKEN_NEED_PASS);
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

/** One field of the card status, trimmed. Empty when gpg wrote none. */
static void card_field(const char *status, const char *label, char *out, size_t max)
{
    *out = '\0';
    const char *at = strstr(status, label);
    const char *colon = at ? strchr(at, ':') : NULL;
    if (!colon)
        return;
    const char *end = strchr(colon, '\n');
    size_t len = end ? (size_t)(end - colon - 1) : strlen(colon + 1);
    if (len >= max)
        len = max - 1;
    snprintf(out, max, "%.*s", (int)len, colon + 1);
    char *v = out;
    while (*v == ' ')
        v++;
    memmove(out, v, strlen(v) + 1);
    for (char *p = out + strlen(out); p > out && p[-1] == ' '; p--)
        p[-1] = '\0';
    /* What gpg writes for a field nobody filled, and for a slot with no key.
     * Both read as empty here, so that a caller never has to know them. */
    if (!strcmp(out, "[not set]") || !strcmp(out, "[none]"))
        *out = '\0';
}

/**
 * Does this card carry anything at all?
 *
 * The question somebody is owed before it is wiped, and the one the shell
 * asked by reading token_check's count: 107 meant every field missing, which
 * meant blank. Answered here off the status gpg has already printed rather
 * than by reading the card a second time.
 *
 * gpg writes "[none]" for a key slot with no key and "[not set]" for a field
 * nobody filled. Both are English whatever the locale, because
 * pgpid_capture_card_status forces one -- a value is translated too, and a
 * field that fails to read as empty reads as filled.
 */
static bool card_is_blank(const char *status)
{
    static const char *const FIELDS[] = {
        "Name of cardholder", "Login data", "URL of public key",
        "Signature key", "Encryption key", "Authentication key",
    };
    for (size_t i = 0; i < sizeof FIELDS / sizeof *FIELDS; i++) {
        char value[256];
        card_field(status, FIELDS[i], value, sizeof value);
        if (*value)
            return false;
    }
    return true;
}

int pgpid_action_secret_totoken(int argc, char **argv)
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
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a passphrase."), a); return PGPID_USAGE; }
            snprintf(passphrase, sizeof passphrase, "%s", argv[i]);
        } else if (!strcmp(a, "-P") || !strcmp(a, "--passfrom") || !strcmp(a, "--pass-from")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a file."), a); return PGPID_USAGE; }
            if (!first_line_of(argv[i], passphrase, sizeof passphrase))
                return PGPID_FAIL;
        } else if (!strcmp(a, "-U") || !strcmp(a, "--certurl")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a URL."), a); return PGPID_USAGE; }
            certurl = argv[i];
        } else if (!strcmp(a, "-k") || !strcmp(a, "--keyserver")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a keyserver."), a); return PGPID_USAGE; }
            keyserver = argv[i];
        } else if (!strcmp(a, "-L") || !strcmp(a, "--lang")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a language."), a); return PGPID_USAGE; }
            snprintf(lang, sizeof lang, "%.2s", argv[i]);
            for (char *p = lang; *p; p++)
                *p = (char)tolower((unsigned char)*p);
        } else if (!strcmp(a, "-K") || !strcmp(a, "--pubkey")) {
            if (++i >= argc) { pgpid_error(_("Error: '%s' wants a file."), a); return PGPID_USAGE; }
            pubkeyfile = argv[i];
        } else if (!strcmp(a, "--force")) {
            force = true;
        } else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
            /* Accepted: gpg's noise goes to stderr either way. */
        } else if (!strcmp(a, "--no-send")) {
            pgpid_error(_("Warning: Deprecated option %s."), a);
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
            pgpid_try_help("secret_totoken");
            return PGPID_USAGE;
        } else if (!keyid) {
            keyid = a;
        }
    }

    if (strlen(lang) != 2)
        pgpid_error(_("Warning: Only 2 lower case ASCII letters can define a preferred "
                    "language; leaving it out."));
    if (!keyid) {
        /* Same question the shell puts through a radiolist: moving the wrong
         * secret key onto a card is not a small mistake. --batch refuses. */
        static char picked[41];
        if (!pgpid_choose_secret_key(_("Which secret key? Its number: "),
                                     picked, sizeof picked)) {
            pgpid_error(_("Error: Which secret key should move onto the card?"));
            return PGPID_USAGE;
        }
        keyid = picked;
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
        pgpid_error(_("Error: No secret for '%s' here."), keyid);
        return PGPID_FAIL;
    }

    /* Where to send and what URL to write down are two questions, and only
       --certurl answers the second. --keyserver used to move the card's URL
       as well, which reads as one option quietly editing another: sending a
       copy somewhere for today's convenience would have engraved that
       somewhere on the card for the life of the key. An empty --keyserver
       answers the first with "nowhere" -- the escape hatch bl-pgpid spells
       --keyservers '' -- and the card still says where the certificate will
       be findable once somebody publishes it. */
    const char *host = keyserver ? keyserver : PGPID_KEYSERVERS_FIRST;
    const char *bare = PGPID_KEYSERVERS_HOST;
    char url[512];
    if (certurl)
        snprintf(url, sizeof url, "%.500s", certurl);
    else
        snprintf(url, sizeof url, "https://%.200s/pks/lookup?op=get&search=0x%s", bare, fpr);

    if (pubkeyfile) {
        const char *ex[] = { "--export", "--armor", fpr, NULL };
        if (pgpid_run_engine_io(ex, NULL, pubkeyfile)) {
            pgpid_error(_("Error: Cannot write the certificate to %s."), pubkeyfile);
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
        pgpid_error(_("Error: No email for PGP key '%s'."), fpr);
        return PGPID_FAIL;
    }

    char skey[41], ekey[41], akey[41], serial[64];
    (void)skey; (void)ekey; (void)akey;
    static char card[16384];
    {
        char *status = card;
        *status = '\0';
        *serial = '\0';
        if (pgpid_capture_card_status(status, sizeof card) > 0) {
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
        pgpid_error(_("Error: No security token detected."));
        return PGPID_FAIL;
    }
    /* Who it says it belongs to, when it says anything: the serial alone
     * names a card, and the question below is about whose card it is. The
     * shell printed the holder here for the same reason. */
    char holder[256], login[256];
    card_field(card, "Name of cardholder", holder, sizeof holder);
    card_field(card, "Login data", login, sizeof login);
    if (*holder || *login)
        pgpid_error(_("Notice: Detected OpenPGP security token: %s — holder: %s %s."),
                    serial, *holder ? holder : "-", *login ? login : "-");
    else
        pgpid_error(_("Notice: Detected OpenPGP security token: %s."), serial);

    /* Wiping the card is the point of no return for whatever is on it -- so
     * the question is asked where there is something to lose, and not asked
     * where there is not. A blank card is the ordinary case of step II: a
     * secret has just come back off paper and the card was reset for it.
     *
     * Refusing outright is what this did, and it stopped the terminal dead in
     * front of a card that merely had something on it. The shell said what
     * was there and asked; --force still skips the question, and --batch
     * still refuses, having nobody to ask. */
    if (!force && !card_is_blank(card)) {
        pgpid_error(_("Warning: Card %s is not empty: it already carries keys or a"), serial);
        pgpid_error(_("holder. This wipes all of it, and takes the secret parts of"));
        pgpid_error(_("%s off this machine. Neither can be undone."), fpr);
        if (pgpid_batch) {
            pgpid_error(_("Error: --batch was given, so nothing is asked. Add --force."));
            return PGPID_USAGE;
        }
        char answer[8];
        if (!pgpid_ask(_("Type yes to wipe it: "), answer, sizeof answer)
            || strcmp(answer, "yes")) {
            pgpid_error(_("Notice: Nothing done."));
            return PGPID_CANCEL;
        }
    }

    /* Only now: gpg will not move a protected key to a card, so the
     * passphrase has to come off. That is itself irreversible, and doing it
     * before the --force check meant a refused command still changed the key
     * on disk — found by running the refusal and reading what gpg said. */
    char answer[600];
    snprintf(answer, sizeof answer, "\n");
    const char *dry[] = { "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                          "--dry-run", "--change-passphrase", fpr, NULL };
    if (pgpid_run_engine_quiet(dry)) {
        /* Asked for when there is somebody to ask, and three tries because a
         * fourth is no longer a typo. Under --batch nobody is there: the
         * caller is told which of the two things went wrong, so it can ask
         * for the passphrase itself rather than guess from a usage error. */
        for (unsigned tries = 0; ; tries++) {
            if (!*passphrase
                && !pgpid_ask_secret(_("Passphrase protecting the secret key: "),
                                     passphrase, sizeof passphrase)) {
                pgpid_error(_("Error: The key is protected by a passphrase, which has "
                            "to come off before it can move to a card."));
                pgpid_error(_("Notice: Give --passphrase, or --passfrom to keep it off "
                            "the process list."));
                return TOTOKEN_NEED_PASS;
            }
            char script[1200];
            snprintf(script, sizeof script, "%.500s\n\n\n\n", passphrase);
            const char *strip[] = { "--command-fd", "0", "--batch", "--pinentry-mode",
                                    "loopback", "--change-passphrase", fpr, NULL };
            if (!pgpid_run_engine_input(strip, script))
                break;
            pgpid_error(_("Error: That passphrase does not open '%s'."), fpr);
            if (pgpid_batch || tries >= 2)
                return TOTOKEN_BAD_PASS;
            *passphrase = '\0';
        }
    }

    pgpid_error(_("Notice: Resetting OpenPGP security token…"));
    const char *reset[] = { "--command-fd", "0", "--batch", "--card-edit", NULL };
    if (pgpid_run_engine_input(reset, "admin\nfactory-reset\ny\nyes\nquit\n")) {
        pgpid_error(_("Error: Factory reset of the OpenPGP card failed."));
        return PGPID_FAIL;
    }

    pgpid_error(_("Notice: Configuring OpenPGP security token…"));
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
        pgpid_error(_("Error: Configuring the OpenPGP card failed."));
        return PGPID_FAIL;
    }

    /* The card is told to hold elliptic-curve keys before the keys arrive:
     * changing that afterwards would wipe them again. */
    if (pgpid_run_engine_input(setup, "admin\nkey-attr\n2\n1\n2\n1\n2\n1\nquit\n")) {
        pgpid_error(_("Error: Setting the card's key attributes failed."));
        return PGPID_FAIL;
    }

    pgpid_error(_("Notice: Moving PGP secrets to security token…"));
    const char *move[] = { "--command-fd", "0", "--batch", "--pinentry-mode",
                           "loopback", "--passphrase", "12345678", "--edit-key", fpr, NULL };
    if (pgpid_run_engine_input(move,
            "keytocard\ny\n1\nkey 1\nkeytocard\n2\nkey 1\nkey 2\nkeytocard\n3\nsave\n")) {
        pgpid_error(_("Error: Moving the secrets to the card failed."));
        return PGPID_FAIL;
    }

    /* The factory codes are printed on the internet; new ones are drawn here
     * and printed once. */
    char pin[8], admin[16];
    if (!draw_code(pin, 6) || !draw_code(admin, 8)) {
        pgpid_error(_("Error: Cannot draw new codes — the card is left on its "
                    "factory PIN 123456 and Admin 12345678. Change them now."));
        return PGPID_FAIL;
    }
    char pinfile[] = "/tmp/pgpid-pin-XXXXXX";
    int fd = mkstemp(pinfile);
    if (fd < 0) {
        pgpid_error(_("Error: Cannot make a temporary file for the new codes."));
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
            pgpid_error(_("Error: Cannot write the new %s code out."), codes[i].what);
            return PGPID_FAIL;
        }
        fprintf(f, "%s\n", codes[i].fresh);
        fclose(f);
        char *sub[9];
        int n = 0;
        sub[n++] = (char *)"token_code";
        /* --replace, or the card keeps its factory code while this prints a
         * random one. token_code without it only *verifies*, and verifying
         * 123456 on a card that has just been reset succeeds — so every check
         * passed, the codes were announced, and the card stayed open to
         * anybody who picked it up. Found by writing a real key to a real
         * card and then failing to use it. */
        sub[n++] = (char *)"--replace";
        sub[n++] = (char *)"--code";
        sub[n++] = (char *)codes[i].current;
        sub[n++] = (char *)"--newcodefrom";
        sub[n++] = pinfile;
        if (codes[i].admin)
            sub[n++] = (char *)"--admin";
        sub[n] = NULL;
        int ret = pgpid_action_token_code(n, sub);
        if (ret) {
            unlink(pinfile);
            pgpid_error(_("Error: Changing the %s code failed (%d). The card is left "
                        "on its factory code — change it now."), codes[i].what, ret);
            return ret;
        }
    }
    unlink(pinfile);

    printf("\n");
    const char *ex[] = { "--export", "--armor", fpr, NULL };
    if (pgpid_run_engine(ex))
        return PGPID_FAIL;
    if (pgpid_send_to_keyservers(fpr, host))
        pgpid_error(_("Warning: Please publish this certificate on the Internet "
                    "(a keyserver will do)."));

    printf("\nADMIN_CODE=%s\nPIN_CODE=%s\n", admin, pin);
    pgpid_error(_("Notice: Write these down. Nothing else knows them. They can be "
                  "changed with '%s token_code --replace'."), PGPID_NAME);
    return PGPID_OK;
}
