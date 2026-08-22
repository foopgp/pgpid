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
#include <stddef.h>
#include <stdint.h>

#define PGPID_MIP_NAME    "pgpid-mip"

/* Given by the Makefile, which reads it from the application this ships
 * inside. Defined here only so the file compiles on its own. */
#ifndef PGPID_MIP_VERSION
#define PGPID_MIP_VERSION "0.0.0-standalone"
#endif

/* Return codes, as bl-* uses them: 0 fine, 1 failed, 2 the caller is wrong. */
#define PGPID_OK      0
#define PGPID_FAIL    1
#define PGPID_USAGE   2
/* Nothing matched — distinct from a failure, because an empty answer to a
 * search is an answer. bl-pgpid says 141 here and so do we. */
#define PGPID_NOTHING 141

/* Where a certificate goes when nobody says otherwise, first one hkp(s).
 *
 * Compiled in, as bl-pgpid and bl-pgpkey carry theirs: this tool answers
 * about certificates and does not read a configuration file. Whoever needs
 * to configure — a different server, a delayed publication, none at all —
 * does it above, by passing --keyservers, and an empty list means nothing
 * is sent. */
#define PGPID_KEYSERVERS "hkps://keys.foopgp.org hkps://keys.openpgp.org"

/* Set once from the global --homedir, NULL for the user's own. */
extern const char *pgpid_homedir;

/* How every action answers. Said once, globally, next to --homedir: an
 * action's business is what it says, not the shape it says it in. */
typedef enum { PGPID_FMT_RAW, PGPID_FMT_INFO, PGPID_FMT_MD } pgpid_format_t;
extern pgpid_format_t pgpid_format;

/* Rows of named values. Held until the end, because column widths are not
 * known before the last row is in — see output.c. */
void pgpid_table_start(const char *const *keys, size_t ncols);
void pgpid_table_row(const char *const *values);
void pgpid_table_end(void);

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
/* Same, but replacing this process — the child side of a pipe. */
void pgpid_exec_engine(const char *const *argv);
/* When that certificate was revoked, 0 when it was not or is not known.
 * PATTERN is the listing's own, so the lookup costs what the listing does. */
long pgpid_revocation_time(const char *fpr, const char *pattern);

/* Hand a certificate to each server in LIST, space or comma separated, and
 * name the ones that refuse. An empty list sends nothing and says so by
 * returning PGPID_OK: asking for nowhere is not a failure. */
int pgpid_send_to_keyservers(const char *fpr, const char *list);

/* MD5 and base64url — what an entity identifier is made of. Written here
 * rather than linked: see md5.c for why, and why that is not the usual
 * "don't write your own crypto" mistake. */
void pgpid_md5(const void *data, size_t len, unsigned char out[16]);
void pgpid_base64url(const unsigned char *in, size_t len, char *out);
int pgpid_base64url_decode(const char *in, unsigned char *out, size_t max);

/* A name, reduced to the letters an identifier is derived from: separators
 * become '<', everything else goes through the reference transliteration —
 * `iconv //TRANSLIT` under C.utf8 — and comes out uppercased.
 *
 * What survives as a non-letter stays: it has to break a run of letters, as
 * it does in the shell, or two name components would silently become one.
 * Returns the length written, or -1 on input that is not valid UTF-8.
 */
int pgpid_transliterate(const char *in, char *out, size_t max);

/* The surname and given names, matched out of a string already reduced to
 * the format's alphabet: the first run that satisfies
 * `[A-Z]{1,32}<<[A-Z]{1,32}<[A-Z]{0,32}<`. False when there is none. */
bool pgpid_extract_names(const char *composed, char *out, size_t max);

/* An ICAO 9303 passport zone, and whether its check digits agree. */
struct pgpid_mrz {
    char line[512];
    size_t length;
    bool is_passport, right_length;
    bool bad[5];        /* number, birth, expiry, personal, composite */
    char country[4], names[40], birth[7];
};
bool pgpid_mrz_parse(const char *raw, struct pgpid_mrz *out);
int pgpid_mrz_check_digit(const char *s, size_t len);

/* Where a country is, as the last fourteen characters of an identifier.
 * NULL for a code that is not one of the 231 — refused rather than guessed. */
const char *pgpid_country_coordinates(const char *code);

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
int pgpid_action_avatar(int argc, char **argv);
int pgpid_action_push(int argc, char **argv);
int pgpid_action_get(int argc, char **argv);
int pgpid_action_gen_uid(int argc, char **argv);
int pgpid_action_gen_u4(int argc, char **argv);
int pgpid_action_mrz_to_u4(int argc, char **argv);

/* The short listing — one line per address — shared by `list --short` and
 * `get`, so that the two cannot drift apart. */
int pgpid_list_short(const char *pattern, bool only_fpr, bool only_mbox,
                     size_t *certificates);

#endif /* PGPID_MIP_H */
