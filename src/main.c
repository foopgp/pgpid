/* pgpid-mip — the pgpid API, while it migrates out of the shell libraries.
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
    fprintf(out,
        "Usage: " PGPID_MIP_NAME " [OPTIONS]... ACTION [ARGS]...\n"
        "\n"
        "Read and act on OpenPGP certificates through the pgpid model: entity\n"
        "identifiers, validity, ownertrust.\n"
        "\n"
        "ACTIONS:\n"
        "  list                        List the certificates of the keyring\n"
        "  get                         Look a certificate up, refreshing it first\n"
        "  property                    Print a vCard property of one certificate\n"
        "  sigs                        List who has certified one certificate\n"
        "  ownertrust                  Print or set how far one is trusted to certify\n"
        "  del                         Delete certificates, by fingerprint only\n"
        "  avatar                      Extract the image a certificate wears\n"
        "  push                        Send certificates to the keyservers\n"
        "  gen_u4                      Print the identifier a civil status gives\n"
        "  mrz_to_u4                   Print the identifier a passport's machine zone gives\n"
        "  gen_uid                     Print the Unix account number an identifier gives\n"
        "\n"
        "OPTIONS:\n"
        "  -H, --homedir DIR           GnuPG home directory - Environment variable: GNUPGHOME\n"
        "      --output-format=FORMAT  Specify output format between {raw, info, md} - Default: 'raw'\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "Every action takes --help of its own.\n");
}

int main(int argc, char **argv)
{
    setlocale(LC_ALL, "");
    /* Required before anything else in gpgme, and it also selects the
     * gettext domain the engine speaks. */
    gpgme_check_version(NULL);
    gpgme_set_locale(NULL, LC_ALL, setlocale(LC_ALL, NULL));

    int i = 1;
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-H") || !strcmp(a, "--homedir")) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants a directory.", a);
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
                pgpid_error("Error: Unknown output format '%s'.", f);
                pgpid_error("Notice: One of raw, info, md.");
                return PGPID_USAGE;
            }
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s (gpgme %s)\n", PGPID_MIP_NAME, PGPID_MIP_VERSION,
                   gpgme_check_version(NULL));
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            i++;
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error("Error: Unrecognized option '%s'.", a);
            pgpid_error("Try '" PGPID_MIP_NAME " --help' for more information.");
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
    if (!strcmp(action, "ownertrust"))
        return pgpid_action_ownertrust(sub_argc, sub_argv);
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
    if (!strcmp(action, "mrz_to_u4"))
        return pgpid_action_mrz_to_u4(sub_argc, sub_argv);
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

    pgpid_error("Error: Unknown action '%s'.", action);
    pgpid_error("Try '" PGPID_MIP_NAME " --help' for more information.");
    return PGPID_USAGE;
}
