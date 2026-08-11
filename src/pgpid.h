/* Shared declarations for pgpid-mip.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef PGPID_MIP_H
#define PGPID_MIP_H

#include <gpgme.h>
#include <stdbool.h>

#define PGPID_MIP_NAME    "pgpid-mip"
#define PGPID_MIP_VERSION "0.1.0"

/* Return codes, as bl-* uses them: 0 fine, 1 failed, 2 the caller is wrong. */
#define PGPID_OK      0
#define PGPID_FAIL    1
#define PGPID_USAGE   2
/* Nothing matched — distinct from a failure, because an empty answer to a
 * search is an answer. bl-pgpid says 141 here and so do we. */
#define PGPID_NOTHING 141

/* Set once from the global --homedir, NULL for the user's own. */
extern const char *pgpid_homedir;

/* An engine bound to pgpid_homedir. Callers release it with gpgme_release. */
gpgme_error_t pgpid_ctx_new(gpgme_ctx_t *ctx, gpgme_keylist_mode_t mode);

/* Error/Warning/Notice/Info on stderr, prefixed like the shell libraries. */
void pgpid_error(const char *fmt, ...);
void pgpid_gpgme_error(const char *what, gpgme_error_t err);

/* The single letter gpg prints in colon field 2 or 9, for a validity or an
 * ownertrust: o i n m f u q -.  Never NUL. */
char pgpid_validity_letter(gpgme_validity_t v);

/* The word the same value is written with — the vocabulary --replace-to takes
 * and the one a human reads. NULL for a value with no word (never happens for
 * an ownertrust read back from gpg). */
const char *pgpid_validity_word(gpgme_validity_t v);

/* The reverse: a word to a validity, or -1 when the word is not one of ours. */
int pgpid_validity_from_word(const char *word);

/* The entity identifier a uid carries, u4… or u5…, or NULL.
 * Caller frees. Both shapes are recognised — see eid.c. */
char *pgpid_eid_of_uid(const char *uid);

/* Run the engine with these arguments, wait, and give back its exit status.
 * No shell: the arguments go to execv as they are. -1 if it could not run. */
int pgpid_run_engine(const char *const *argv);

/* Is this a fingerprint and nothing else? 40 or 64 hexadecimal characters.
 * What the destructive actions accept, so that a search pattern can never
 * become a target. */
bool pgpid_is_fingerprint(const char *s);

/* Actions. argv[0] is the action name, as main leaves it. */
int pgpid_action_list(int argc, char **argv);
int pgpid_action_ownertrust(int argc, char **argv);
int pgpid_action_sigs(int argc, char **argv);
int pgpid_action_del(int argc, char **argv);
int pgpid_action_property(int argc, char **argv);

#endif /* PGPID_MIP_H */
