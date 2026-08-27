/* pgpid — the pgpid API, while it migrates out of the shell libraries.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The name says what it is: migration in progress. Actions land here as they
 * are rewritten — the ones bl-pgpid never had, and the ones whose shell
 * implementation pays a process per certificate. When the last one has moved,
 * the name goes.
 *
 * The shape follows bl-*: an action, then its options, human output by
 * default and key=value under --info, long options everywhere, and 0 / 1 / 2
 * meaning fine / failed / the caller is wrong.
 */
#include "pgpid.h"

#include <locale.h>
#include <stdio.h>
#include <string.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " [OPTIONS]... ACTION [ARGS]...\n"
        "\n"
        "Read and act on OpenPGP certificates through the pgpid model: entity\n"
        "identifiers, validity, credibility.\n"
        "\n"
        "ACTIONS:\n"
        "  list                        List the certificates of the keyring\n"
        "  get                         Look a certificate up, refreshing it first\n"
        "  property                    Print a vCard property of one certificate\n"
        "  sigs                        List who has certified one certificate\n"
        "  del                         Delete certificates, by fingerprint only\n"
        "  avatar                      Extract the image a certificate wears\n"
        "  push                        Send certificates to the keyservers\n"
        "  gen_u4                      Print the identifier a civil status or a passport gives\n"
        "  gen_uid                     Print the Unix account number an identifier gives\n"
        "  to_vcard                    Print a certificate as a vCard\n"
        "  email                       Show, add or revoke the addresses a certificate carries\n"
        "  certify                     Vouch for somebody else\n"
        "  trustdb                     Read, publish and apply the credibility of others\n"
        "  gen_key                     Generate a key pair the PGP ID way\n"
        "  change_passphrase           Change what protects a secret key here\n"
        "  token_check                 Check what the connected security key carries\n"
        "  token_retries               Attempts left on the key's codes\n"
        "  totoken                     Move a secret key onto a security key\n"
        "  change_token_code           Check or change its PIN or Admin code\n"
        "  change_token_meta           Write what it says about its holder\n"
        "  print_secret                Put a secret key on paper, in fragments\n"
        "  scan                        Put it back together from the fragments\n"
        "  print_card                  Produce or print a sticker or business card\n"
        "\n"
        "OPTIONS:\n"
        "  -H, --homedir DIR           GnuPG home directory - Environment variable: GNUPGHOME\n"
        "      --output-format=FORMAT  Specify output format between {raw, info, md} - Default: 'raw'\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "Every action takes --help of its own.\n"),
            PGPID_NAME);
}

int main(int argc, char **argv)
{
    setlocale(LC_ALL, "");
    bindtextdomain(PGPID_TEXTDOMAIN, PGPID_LOCALEDIR);
    textdomain(PGPID_TEXTDOMAIN);
    /* Required before anything else in gpgme, and it also selects the
     * gettext domain the engine speaks. */
    gpgme_check_version(NULL);
    gpgme_set_locale(NULL, LC_ALL, setlocale(LC_ALL, NULL));

    int i = 1;
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-H") || !strcmp(a, "--homedir")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a directory."), a);
                return PGPID_USAGE;
            }
            pgpid_homedir = argv[i];
        } else if (!strncmp(a, "--output-format=", 16)) {
            const char *f = a + 16;
            if (!strcmp(f, "raw")) {
                pgpid_format = PGPID_FMT_RAW;
            } else if (!strcmp(f, "info")) {
                pgpid_format = PGPID_FMT_INFO;
            } else if (!strcmp(f, "md")) {
                pgpid_format = PGPID_FMT_MD;
            } else {
                pgpid_error(_("Error: Unknown output format '%s'."), f);
                pgpid_error(_("Notice: One of raw, info, md."));
                return PGPID_USAGE;
            }
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s (gpgme %s)\n", PGPID_NAME, PGPID_VERSION,
                   gpgme_check_version(NULL));
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            i++;
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help(NULL);
            return PGPID_USAGE;
        } else {
            break;
        }
    }

    if (i >= argc) {
        usage(stderr);
        return PGPID_USAGE;
    }

    const char *action = argv[i];
    int sub_argc = argc - i;
    char **sub_argv = argv + i;

    if (!strcmp(action, "list"))
        return pgpid_action_list(sub_argc, sub_argv);
    if (!strcmp(action, "property"))
        return pgpid_action_property(sub_argc, sub_argv);
    if (!strcmp(action, "sigs"))
        return pgpid_action_sigs(sub_argc, sub_argv);
    if (!strcmp(action, "del"))
        return pgpid_action_del(sub_argc, sub_argv);
    if (!strcmp(action, "avatar"))
        return pgpid_action_avatar(sub_argc, sub_argv);
    if (!strcmp(action, "push"))
        return pgpid_action_push(sub_argc, sub_argv);
    if (!strcmp(action, "get"))
        return pgpid_action_get(sub_argc, sub_argv);
    if (!strcmp(action, "gen_uid"))
        return pgpid_action_gen_uid(sub_argc, sub_argv);
    if (!strcmp(action, "gen_u4"))
        return pgpid_action_gen_u4(sub_argc, sub_argv);
    if (!strcmp(action, "to_vcard"))
        return pgpid_action_to_vcard(sub_argc, sub_argv);
    if (!strcmp(action, "token_retries"))
        return pgpid_action_token_retries(sub_argc, sub_argv);
    if (!strcmp(action, "token_check"))
        return pgpid_action_token_check(sub_argc, sub_argv);
    if (!strcmp(action, "certify"))
        return pgpid_action_certify(sub_argc, sub_argv);
    if (!strcmp(action, "email"))
        return pgpid_action_email(sub_argc, sub_argv);
    if (!strcmp(action, "trustdb"))
        return pgpid_action_trustdb(sub_argc, sub_argv);
    if (!strcmp(action, "gen_key"))
        return pgpid_action_gen_key(sub_argc, sub_argv);
    if (!strcmp(action, "change_passphrase"))
        return pgpid_action_change_passphrase(sub_argc, sub_argv);
    if (!strcmp(action, "print_secret"))
        return pgpid_action_print_secret(sub_argc, sub_argv);
    if (!strcmp(action, "scan"))
        return pgpid_action_scan(sub_argc, sub_argv);
    if (!strcmp(action, "print_card"))
        return pgpid_action_print_card(sub_argc, sub_argv);
    if (!strcmp(action, "change_token_code"))
        return pgpid_action_change_token_code(sub_argc, sub_argv);
    if (!strcmp(action, "change_token_meta"))
        return pgpid_action_change_token_meta(sub_argc, sub_argv);
    if (!strcmp(action, "totoken"))
        return pgpid_action_totoken(sub_argc, sub_argv);

    pgpid_error(_("Error: Unknown action '%s'."), action);
    pgpid_try_help(NULL);
    return PGPID_USAGE;
}
