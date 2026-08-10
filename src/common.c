/* The bits every action needs: a context, an error, a vocabulary.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */
#include "pgpid.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

const char *pgpid_homedir = NULL;

gpgme_error_t pgpid_ctx_new(gpgme_ctx_t *ctx, gpgme_keylist_mode_t mode)
{
    gpgme_error_t err = gpgme_new(ctx);
    if (err)
        return err;
    err = gpgme_set_protocol(*ctx, GPGME_PROTOCOL_OpenPGP);
    if (err)
        goto fail;
    /* NULL file_name keeps the engine gpgme found; only the home moves. */
    err = gpgme_ctx_set_engine_info(*ctx, GPGME_PROTOCOL_OpenPGP, NULL, pgpid_homedir);
    if (err)
        goto fail;
    if (mode) {
        err = gpgme_set_keylist_mode(*ctx, mode);
        if (err)
            goto fail;
    }
    return 0;
fail:
    gpgme_release(*ctx);
    *ctx = NULL;
    return err;
}

void pgpid_error(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "%s: ", PGPID_MIP_NAME);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void pgpid_gpgme_error(const char *what, gpgme_error_t err)
{
    pgpid_error("Error: %s: %s (%s)", what,
                gpgme_strerror(err), gpgme_strsource(err));
}

/* gpg writes one letter for a validity and the same letter for an ownertrust,
 * and the trustdb stores the same enum for both. One table, therefore. */
char pgpid_validity_letter(gpgme_validity_t v)
{
    switch (v) {
    case GPGME_VALIDITY_UNKNOWN:   return '-';
    case GPGME_VALIDITY_UNDEFINED: return 'q';
    case GPGME_VALIDITY_NEVER:     return 'n';
    case GPGME_VALIDITY_MARGINAL:  return 'm';
    case GPGME_VALIDITY_FULL:      return 'f';
    case GPGME_VALIDITY_ULTIMATE:  return 'u';
    }
    return '-';
}

const char *pgpid_validity_word(gpgme_validity_t v)
{
    switch (v) {
    case GPGME_VALIDITY_UNKNOWN:   return "unknown";
    case GPGME_VALIDITY_UNDEFINED: return "undefined";
    case GPGME_VALIDITY_NEVER:     return "never";
    case GPGME_VALIDITY_MARGINAL:  return "marginal";
    case GPGME_VALIDITY_FULL:      return "full";
    case GPGME_VALIDITY_ULTIMATE:  return "ultimate";
    }
    return "unknown";
}

int pgpid_validity_from_word(const char *word)
{
    static const struct { const char *word; gpgme_validity_t v; } words[] = {
        { "unknown",   GPGME_VALIDITY_UNKNOWN   },
        { "undefined", GPGME_VALIDITY_UNDEFINED },
        { "never",     GPGME_VALIDITY_NEVER     },
        { "marginal",  GPGME_VALIDITY_MARGINAL  },
        { "full",      GPGME_VALIDITY_FULL      },
        { "ultimate",  GPGME_VALIDITY_ULTIMATE  },
    };
    for (size_t i = 0; i < sizeof words / sizeof *words; i++)
        if (!strcmp(word, words[i].word))
            return (int)words[i].v;
    return -1;
}
