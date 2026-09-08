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


/* Every action, once. The dispatch reads it, and so does the completion:
 * a list of actions kept in two places is a list that disagrees with
 * itself the day one is added. */
/* Every action, once: its name, the group it belongs to, what it does, and
 * what runs it. The dispatch reads this, the completion reads this, and so
 * does the help -- which used to keep a second list of its own, three lines
 * under a comment saying a list kept twice is a list that disagrees with
 * itself. It did. */
static const struct {
    const char *name;
    const char *section;   /* NULL: continues the previous one */
    const char *desc;
    int (*run)(int, char **);
} ACTIONS[] = {
    { "cert_list",         N_("Certificates"),
      N_("List the certificates of the keyring"),            pgpid_action_cert_list },
    { "cert_get",          NULL,
      N_("Look a certificate up, refreshing it first"),      pgpid_action_cert_get },
    { "cert_property",     NULL,
      N_("Show, add or revoke a vCard property it carries"), pgpid_action_cert_property },
    { "cert_email",        NULL,
      N_("Show, add or revoke the addresses it carries"),    pgpid_action_cert_email },
    { "cert_avatar",       NULL,
      N_("Extract the image it wears"),                      pgpid_action_cert_avatar },
    { "cert_sigs",         NULL,
      N_("List who has certified it"),                       pgpid_action_cert_sigs },
    { "cert_tovcard",      NULL,
      N_("Write it out as a vCard document"),                pgpid_action_cert_tovcard },
    { "cert_tobizcard",    NULL,
      N_("Produce or print a sticker or business card"),     pgpid_action_cert_tobizcard },
    { "cert_push",         NULL,
      N_("Send certificates to the keyservers"),             pgpid_action_cert_push },
    { "cert_del",          NULL,
      N_("Delete certificates, by fingerprint only"),        pgpid_action_cert_del },

    { "secret_list",       N_("Secret keys held on this machine"),
      N_("List the secret keys that are really here"),       pgpid_action_secret_list },
    { "secret_passphrase", NULL,
      N_("Check, or --replace, what protects one"),          pgpid_action_secret_passphrase },
    { "secret_print",      NULL,
      N_("Put one on paper, in fragments"),                  pgpid_action_secret_print },
    { "secret_scan",       NULL,
      N_("Put it back together from the fragments"),         pgpid_action_secret_scan },
    { "secret_totoken",    NULL,
      N_("Move one onto a security key"),                    pgpid_action_secret_totoken },

    { "token_list",        N_("Security keys"),
      N_("List the security keys this system knows"),        pgpid_action_token_list },
    { "token_check",       NULL,
      N_("Check what the connected one carries"),            pgpid_action_token_check },
    { "token_retries",     NULL,
      N_("Attempts left on its codes"),                      pgpid_action_token_retries },
    { "token_code",        NULL,
      N_("Check, or --replace, its PIN or Admin code"),      pgpid_action_token_code },
    { "token_meta",        NULL,
      N_("Show, or --replace, what it says about its holder"), pgpid_action_token_meta },

    { "gen_key",           N_("Generators"),
      N_("Generate a key pair the PGP ID way"),              pgpid_action_gen_key },
    { "gen_u4",            NULL,
      N_("Print the identifier a civil status or a passport gives"), pgpid_action_gen_u4 },
    { "gen_uid",           NULL,
      N_("Print the Unix account number an identifier gives"), pgpid_action_gen_uid },

    { "certify",           N_("Other people"),
      N_("Vouch for somebody else"),                         pgpid_action_certify },
    { "trustdb",           NULL,
      N_("Read, publish and apply the credibility of others"), pgpid_action_trustdb },
};

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " [OPTIONS]... ACTION [ARGS]...\n"
        "\n"
        "Read and act on OpenPGP certificates through the pgpid model: entity\n"
        "identifiers, validity, credibility.\n"
        "\n"
        "ACTIONS:\n"),
            PGPID_NAME);

    /* Straight off the dispatch table, so an action cannot be listed here and
     * missing there, or the other way round. A section header is printed
     * whenever it changes. */
    for (size_t k = 0; k < sizeof ACTIONS / sizeof ACTIONS[0]; k++) {
        if (ACTIONS[k].section)
            fprintf(out, "\n %s:\n", _(ACTIONS[k].section));
        fprintf(out, "  %-22s%s\n", ACTIONS[k].name, _(ACTIONS[k].desc));
    }

    fprintf(out, _("\n"
        "OPTIONS:\n"
        "  -H, --homedir DIR           GnuPG home directory - Environment variable: GNUPGHOME\n"
        "      --output-format=FORMAT  Specify output format between {raw, info, md} - Default: 'raw'\n"
        "  -B, --batch                 Never ask: fail instead of prompting for what is missing\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"
        "\n"
        "Every action takes --help of its own.\n"));
}

int main(int argc, char **argv)
{
    setlocale(LC_ALL, "");
    bindtextdomain(PGPID_TEXTDOMAIN, PGPID_LOCALEDIR);
    textdomain(PGPID_TEXTDOMAIN);
    /* The locale still has to be set before anything else -- it selects the
     * gettext domain the engine speaks. */
    setlocale(LC_ALL, "");

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
        } else if (!strcmp(a, "--bash-completion")) {
            const char *names[sizeof ACTIONS / sizeof ACTIONS[0]];
            for (size_t k = 0; k < sizeof names / sizeof names[0]; k++)
                names[k] = ACTIONS[k].name;
            pgpid_emit_completion(names, sizeof names / sizeof names[0]);
            return PGPID_OK;
        } else if (!strcmp(a, "-B") || !strcmp(a, "--batch")) {
            pgpid_batch = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", PGPID_NAME, PGPID_VERSION);
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

    for (size_t k = 0; k < sizeof ACTIONS / sizeof ACTIONS[0]; k++)
        if (!strcmp(action, ACTIONS[k].name))
            return ACTIONS[k].run(sub_argc, sub_argv);

    pgpid_error(_("Error: Unknown action '%s'."), action);
    pgpid_try_help(NULL);
    return PGPID_USAGE;
}
