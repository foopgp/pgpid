/* Shared declarations for pgpid.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef PGPID_H
#define PGPID_H

#include <pwd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PGPID_NAME    "pgpid"

/* What the Makefile decides: the version and where the catalogues live. Both
 * come through a generated header rather than -D, so that changing either
 * rebuilds what depends on it. The fallbacks below are for building without
 * the Makefile, and must come after the include or they win. */
#if __has_include("version.h")
#include "version.h"
#endif

#define PGPID_TEXTDOMAIN "pgpid"
#ifndef PGPID_LOCALEDIR
#define PGPID_LOCALEDIR "/usr/share/locale"
#endif

/* Every sentence a person reads goes through this. What does not: the
 * Error:/Warning:/Notice:/Info: prefixes, which say the level rather than
 * anything in a language, and the key=value names, which callers parse. */
#include <libintl.h>
#define _(s)  gettext(s)
#define N_(s) (s)

/* From `git describe` — the same answer bl-pgpid and bl-pgpkey give, so that a
 * bug report names a commit rather than a release nobody can place. */
#ifndef PGPID_VERSION
#define PGPID_VERSION "unknown"
#endif

/* Return codes, as bl-* uses them: 0 fine, 1 failed, 2 the caller is wrong. */
#define PGPID_OK      0
#define PGPID_FAIL    1
#define PGPID_USAGE   2
/* Nothing matched — distinct from a failure, because an empty answer to a
 * search is an answer. bl-pgpid says 141 here and so do we. */
/* The shell libraries answer 42 when the person said no; a caller that
 * drives both should not have to learn two vocabularies. */
#define PGPID_EXISTS  11   /* what was asked for is already there */
#define PGPID_CANCEL  42
#define PGPID_NOTHING 141

/* Where a certificate goes when nobody says otherwise, first one hkp(s).
 *
 * Compiled in, as bl-pgpid and bl-pgpkey carry theirs: this tool answers
 * about certificates and does not read a configuration file. Whoever needs
 * to configure — a different server, a delayed publication, none at all —
 * does it above, by passing --keyservers, and an empty list means nothing
 * is sent. */
/* How far --split may go.
 *
 * Not a buffer size: the QR header is four characters — '~', the version, the
 * threshold less one, and the fragment's number — so the number and the
 * threshold each get exactly one digit. `print_secret` writes it and `scan`
 * reads it back that way, and a sheet nobody can read is discovered on paper. */
#define PGPID_SPLIT_MAX 10

/* Where a name in the account databases stops.
 *
 * shadow's GROUP_NAME_MAX_LENGTH is the size of utmpx's ut_user, and the same
 * 32 is written into more places than anyone could find and fix. So our own
 * identifiers are cut to it rather than being carried past it and refused
 * somewhere we did not look: a u5 is exactly this long and loses nothing, a u4
 * is 38 and loses the tail of its coordinates -- never a character of its
 * hash, which is the whole of what tells two entities apart.
 *
 * The full identifier stays in the path of the home, which has no such limit,
 * so nothing is lost, only shortened where it has to be. */
#define PGPID_ACCOUNT_NAME_MAX 32

/* Three shapes of one fact, derived so they cannot drift: the bare host
 * composes the certurl engraved on a card, one server is what an action
 * that must pick exactly one uses, and the list is where a certificate
 * gets published. Moving where we publish is editing the first line. */
#define PGPID_KEYSERVERS_HOST  "keys.foopgp.org"
#define PGPID_KEYSERVERS_FIRST "hkps://" PGPID_KEYSERVERS_HOST
#define PGPID_KEYSERVERS       PGPID_KEYSERVERS_FIRST " hkps://keys.openpgp.org"

/* The first of them, which is the one a card points at. */
#define PGPID_FIRST_KEYSERVER "hkps://keys.foopgp.org"

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


/* Error/Warning/Notice/Info on stderr, prefixed like the shell libraries. */
void pgpid_error(const char *fmt, ...);

/* Asking the person in front of the terminal — command line only, and never
 * when --batch says the caller is not one. See interactive.c. */
extern bool pgpid_batch;
bool pgpid_ask(const char *prompt, char *out, size_t max);
bool pgpid_ask_hex(const char *prompt, size_t want, char *out, size_t max);
bool pgpid_ask_secret(const char *prompt, char *out, size_t max);
bool pgpid_choose(const char *prompt, const char *const *items, size_t n, size_t *picked);
/* Which secret key, when nobody said. See seckeys.c. */
bool pgpid_choose_secret_key(const char *prompt, char *out, size_t max);
/* The bash completion, emitted by the program it completes. See completion.c. */
void pgpid_emit_completion(const char *const *actions, size_t n);

/* "Try 'pgpid certify --help' for more information." — the same sentence in
 * twenty-six places, so it is written once and translated once. ACTION is
 * NULL for the program itself. */
void pgpid_try_help(const char *action);

/* Reading the keyring without gpgme -- see keyring.c for why. The fields
 * are the ones the actions actually read; the record and field numbers they
 * come from are gpg's doc/DETAILS. */
#define PGPID_KEYS_SECRET  (1u << 0)   /* --list-secret-keys */
#define PGPID_KEYS_SIGS    (1u << 1)   /* --with-sig-list */

struct pgpid_keysig {
    char keyid[17];
    char text[512];      /* the signer's uid, as gpg reports it */
    char address[256];   /* the mail address inside it, or "" */
    long created;
};

struct pgpid_keyuid {
    char text[512];      /* as its owner wrote it, escapes undone */
    char address[256];   /* the mail address it carries, or "" */
    char validity;       /* field 2 */
    bool revoked, expired, invalid;
    long created;
    struct pgpid_keysig *sig;
    size_t nsig;
};

struct pgpid_subkey {
    char fpr[41];
    char keyid[17];
    char card[33];       /* field 15: the card holding the secret, or "" */
    char caps[8];        /* field 12: e s c a, upper case when the key has it */
    char validity;
    bool revoked, expired, invalid;
    long created, expires;
};

struct pgpid_key {
    char fpr[41];
    char keyid[17];
    char caps[8];
    char validity;
    char ownertrust;     /* field 9 */
    char card[64];       /* field 15: the serial of the card the secret sits on,
                          * empty when the material is really on this machine */
    bool secret, revoked, expired, invalid;
    long created, expires;
    struct pgpid_keyuid *uid;
    size_t nuid;
    size_t nuat;         /* attribute packets, which gpg counts as user ids */
    struct pgpid_subkey *sub;
    size_t nsub;
};

struct pgpid_keyring;
struct pgpid_keyring *pgpid_keys_load(const char *const *patterns, size_t npat,
                                      unsigned flags);
size_t pgpid_keys_count(const struct pgpid_keyring *kr);
const struct pgpid_key *pgpid_keys_at(const struct pgpid_keyring *kr, size_t i);

/** True when some part of the secret is really on this machine, rather than
 *  a stub pointing at a security key. */
bool pgpid_secret_is_local(const struct pgpid_key *k);

/** The same rule, taken straight off a keyring entry: writes the bare address.
 *  False when the certificate carries no address that stands. */
bool pgpid_preferred_address(const struct pgpid_key *key, char *out, size_t max);
void pgpid_keys_free(struct pgpid_keyring *kr);

/* The certificate's bytes, caller frees. NULL when gpg exported nothing. */
unsigned char *pgpid_export_key(const char *fpr, bool minimal, size_t *len);

/* Driving `gpg --edit-key`. `fn` is handed the status word ("GET_LINE") and
 * the question's name ("keyedit.prompt"), and answers with the line to send;
 * NULL sends an empty one. Returns gpg's exit status. */
typedef const char *(*pgpid_edit_fn)(void *opaque, const char *keyword,
                                     const char *ask);
int pgpid_edit_key(const char *fpr, pgpid_edit_fn fn, void *opaque);

/* Undo the \x3a and friends gpg writes in a colon field. */
void pgpid_colon_unescape(const char *in, char *out, size_t max);

/* Comparing two validity letters, weakest to strongest. */
int pgpid_validity_rank(char v);

/* The number --import-ownertrust takes, 0 for a letter it will not write. */
int pgpid_ownertrust_code(char v);

/* The word the same value is written with — the vocabulary --replace-to takes
 * and the one a human reads. NULL for a value with no word (never happens for
 * an ownertrust read back from gpg). */
const char *pgpid_validity_word(char v);

/* The reverse: a word to a validity letter, or -1 when it is not one of ours. */
int pgpid_validity_from_word(const char *word);

/* The entity identifier a uid carries, u4… or u5…, or NULL.
 * Caller frees. Both shapes are recognised — see eid.c. */
char *pgpid_eid_of_uid(const char *uid);

/* The identifier a certificate carries, and how many distinct ones it claims.
 * `standing_only` ignores revoked uids: what it asserts today, not ever.
 * Caller frees. */
char *pgpid_eid_of_key(const struct pgpid_key *key, unsigned *count, bool standing_only);

/* The first address on a uid that still stands, or NULL. Borrowed from the
 * key. */
const char *pgpid_first_mbox(const struct pgpid_key *key);

/* Does an identifier written bare — as the card's "Login data" holds it —
 * start at this position? */
bool pgpid_eid_body_is_sound(const char *at);

/* Run the engine with these arguments, wait, and give back its exit status.
 * No shell: the arguments go to execv as they are. -1 if it could not run. */
int pgpid_run_engine(const char *const *argv);

/* The same, with TEXT handed to the engine on its standard input — for the
 * edit-key conversation, which has no --quick- equivalent. */
int pgpid_run_engine_input(const char *const *argv, const char *text);

/* The same, with the engine's complaints thrown away — for probes, where the
 * failure is the answer and gpg's account of it reads as a bug. */
int pgpid_run_engine_quiet(const char *const *argv);

/* And the same again, keeping the engine's output in a file — for the bytes
 * a buffer has no business holding. Either of TEXT and OUT_PATH may be NULL. */
int pgpid_run_engine_io(const char *const *argv, const char *text, const char *out_path);

/* Run any program, not just the engine: printing a secret is a pipeline of
 * other people's tools, and calling them is the work. */
int pgpid_run_program(const char *const *argv, const char *text, const char *out_path);
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
void pgpid_base64(const unsigned char *in, size_t len, char *out);
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

/* Packet tags, RFC 9580 §5.  */
#define TAG_SIGNATURE      2
#define TAG_USER_ID       13
#define TAG_USER_ATTR     17
/* Signature types, §5.2.1: certifying a user id, and taking it back. */
#define SIG_CERT_LOWEST   0x10
#define SIG_CERT_HIGHEST  0x13
#define SIG_CERT_REVOKE   0x30
/* Attribute subpacket types, §5.12: one is defined, and it is the image. */
#define ATTR_IMAGE         1
/* How many images one certificate may carry before we stop reading. Ours
 * revoke as they replace, so a long history is normal and a thousand is not.
 */

/* Walking an OpenPGP packet stream — what a colon listing does not surface.
 * See packets.c: the image a certificate wears and the keyserver it names
 * both live in packets its user id chain never mentions. */
struct pgpid_packet {
    unsigned tag;
    const unsigned char *body;
    size_t len;
    const unsigned char *next;
};
bool pgpid_packet_next(const unsigned char *p, const unsigned char *end,
                       struct pgpid_packet *out);
bool pgpid_sub_length(const unsigned char **p, const unsigned char *end,
                      size_t *len);
bool pgpid_attribute_image(const struct pgpid_packet *pkt,
                           const unsigned char **data, size_t *len);
bool pgpid_signature_read(const struct pgpid_packet *pkt, unsigned *type,
                          unsigned long *created, const char **issuer_hex);
bool pgpid_signature_subpacket(const struct pgpid_packet *pkt, unsigned want,
                               const unsigned char **data, size_t *len);

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

/* YYMMDD to YYYY-MM-DD, pivoting at sixty-eight as POSIX does — which is
 * why anyone born before 1969 has to give their date themselves. */
void pgpid_mrz_expand_year(const char *yymmdd, char *out, size_t max);

/* Where a country is, as the last fourteen characters of an identifier.
 * NULL for a code that is not one of the 231 — refused rather than guessed. */
const char *pgpid_country_coordinates(const char *code);

/* The image a certificate wears today, out of its exported packets — the
 * standing one, newest when several stand. Shared so that a card and an
 * avatar cannot show two different faces. */
bool pgpid_current_image(const unsigned char *buf, size_t len, const char *keyid,
                         const unsigned char **data, size_t *ilen);

/* Run a program and keep its output — for the card, which is reached through
 * gpg-connect-agent and scdaemon rather than through a key listing. */
int pgpid_capture(const char *const *argv, char *out, size_t max);

/* Same, with the engine and the home directory already in front. */
int pgpid_capture_engine(const char *const *argv, char *out, size_t max);
int pgpid_capture_card_status(char *out, size_t max);

/* Send one ISO 7816 command to the card and keep its status word — for what
 * a listing has no opinion about and gpg will only ask questions about. */
bool pgpid_card_apdu(const char *apdu, char *sw, size_t max);

/* What that status word means: 0 when the card agreed, 192 to 194 when a
 * code has that many attempts left, else the class of the problem. */
int pgpid_sw_analyse(const char *sw);

/* How many attempts remain on each of the three codes. Needed outside
 * token_retries because some cards answer a wrong VERIFY with 6982 instead
 * of 63CX, and the count has to be fetched to say anything useful. */
bool pgpid_card_retries(int *pin, int *rc, int *admin);

/* Put the OpenPGP application in front before asking it anything. */
bool pgpid_card_select_openpgp(int *ret);

/* A string as the card wants it: its bytes in hexadecimal, space separated. */
void pgpid_to_hex(const char *in, char *out, size_t max);

/* The certification key of whoever holds the connected card — the card
 * carries subkeys, the certifying key stays off it. False when no card
 * answered, or when its subkeys belong to no certificate we hold. */
bool pgpid_card_certification_key(char *out, size_t max);

/* One uid of a certificate, as the colon listing describes it. */
struct pgpid_uid {
    char text[512];    /* as its owner wrote it, escapes undone */
    char validity;     /* field 2 — see pgpid_uid_stands */
    long created;      /* when its self-signature was made */
};

/* The uids of a certificate. Returns how many were written. */
size_t pgpid_list_uids(const char *user, bool secret,
                       struct pgpid_uid *out, size_t max);

/* Does this uid still stand — not revoked, not expired, not disabled? */
/** The path of the running binary, for the parts that call other parts. */
const char *pgpid_self(void);
bool pgpid_uid_stands(char validity);
/** The user id the certificate flags as primary, from its packets. */
bool pgpid_primary_uid(const char *user, char *out, size_t max);
/** The number gpg's --edit-key menu gives this user id, attributes counted. */
unsigned pgpid_uid_index(const char *user, const char *text);
/** Is this uid one of ours, `PROPERTY:value` or `PROPERTY;PARAM:value`? */
const char *pgpid_uid_property(const char *uid, char *name, size_t max);
/** The account named USER, or the one whose identifier is EID. */
bool pgpid_account_name(const char *who, char *out, size_t max);
/** The name an identifier takes in /etc/passwd and /etc/group. */
void pgpid_account_of_eid(const char *eid, char *out, size_t max);
/** The identifier an account carries: in its name, or in the path of its home. */
bool pgpid_account_eid(const struct passwd *pw, char *out, size_t max);
/** The account number an identifier stands for, the same on every machine. */
bool pgpid_uid_number(const char *identifier, uid_t *out);
/** The address an entity is written to: the primary uid when it carries one,
 *  else the most recent standing uid that does. One rule for the listing, the
 *  business card, the paper backup and anything else that has to pick. */
const struct pgpid_uid *pgpid_preferred_uid(const struct pgpid_uid *uids, size_t n);

/* Does this uid end in an address, the shape every mail client reads? */
bool pgpid_uid_has_address(const char *uid);

/* The address inside such a uid, pointing into it, or NULL. */
const char *pgpid_uid_address(const char *uid, size_t *len);

/* Revoke one uid. Irreversible: OpenPGP keeps it on the certificate forever
 * and gpg then refuses an identical one, which is what the confirmation is
 * there to say. */
bool pgpid_revoke_uid(const char *user, const char *uid, bool assume_yes);

/* Put the primary flag back on an address after a revocation moved it. */
bool pgpid_fix_primary(const char *user);

/* Mint the identity uid of a certificate made before the shape existed. */
bool pgpid_upgrade_uids(const char *user, const char *keyservers);

/* The keyserver a certificate names as its own — subpacket 24, taken from
 * the uid flagged primary, failing that the last one that still stands.
 * Points at static storage. */
char *pgpid_preferred_keyserver(const unsigned char *buf, size_t len,
                                const char *fpr);

/* The validity letter gpg gives each uid, in listing order — because a key
 * cannot say "expired": such a uid arrives as unknown, indistinguishable
 * from one nobody vouched for. Returns how many were written. */
size_t pgpid_uid_validities(const char *fpr, char *out, size_t max);

/* Is this a fingerprint and nothing else? 40 or 64 hexadecimal characters.
 * What the destructive actions accept, so that a search pattern can never
 * become a target. */
bool pgpid_is_fingerprint(const char *s);

/* Actions. argv[0] is the action name, as main leaves it. */
int pgpid_action_cert_list(int argc, char **argv);
int pgpid_action_cert_sigs(int argc, char **argv);
int pgpid_action_cert_del(int argc, char **argv);
int pgpid_action_cert_property(int argc, char **argv);
int pgpid_action_cert_avatar(int argc, char **argv);
int pgpid_action_cert_push(int argc, char **argv);
int pgpid_action_cert_get(int argc, char **argv);
int pgpid_action_gen_uid(int argc, char **argv);
int pgpid_action_gen_u4(int argc, char **argv);
int pgpid_action_cert_tovcard(int argc, char **argv);
int pgpid_action_token_retries(int argc, char **argv);
int pgpid_action_token_check(int argc, char **argv);
int pgpid_action_token_list(int argc, char **argv);
int pgpid_action_token_del(int argc, char **argv);

/* What pgpid remembers of the security keys it has met, beside GnuPG's stub:
 * one note per card under $GNUPGHOME/pgpid/tokens, made at the first write. */
const char *pgpid_home(void);
bool pgpid_token_remember(const char *serial, const char *info);
bool pgpid_token_forget(const char *serial);
bool pgpid_token_recall(const char *serial, char *out, size_t max);
size_t pgpid_token_known(char serials[][64], size_t max);
/** The signing fingerprint of the security key seen most recently, which is
 *  the connected one whenever there is one: token_check writes its note as it
 *  checks. */
bool pgpid_token_last_signing_key(char *out, size_t max);
int pgpid_action_secret_list(int argc, char **argv);
int pgpid_action_secret_del(int argc, char **argv);
int pgpid_action_cert_revoke(int argc, char **argv);
int pgpid_action_system_users(int argc, char **argv);
int pgpid_action_system_adduser(int argc, char **argv);
int pgpid_action_system_deluser(int argc, char **argv);
int pgpid_action_system_admins(int argc, char **argv);
int pgpid_action_system_confhome(int argc, char **argv);
int pgpid_action_certify(int argc, char **argv);
int pgpid_action_cert_email(int argc, char **argv);
int pgpid_action_trustdb(int argc, char **argv);
int pgpid_action_gen_key(int argc, char **argv);
int pgpid_action_secret_passphrase(int argc, char **argv);
int pgpid_action_secret_print(int argc, char **argv);
int pgpid_action_secret_scan(int argc, char **argv);
int pgpid_action_cert_tobizcard(int argc, char **argv);
int pgpid_action_token_code(int argc, char **argv);
int pgpid_action_token_meta(int argc, char **argv);
int pgpid_action_secret_totoken(int argc, char **argv);

/* The short listing — one line per address — shared by `list --short` and
 * `get`, so that the two cannot drift apart. */
/* The short listing's table, opened and closed around the walk — `get` runs
 * the walk once per pattern and prints one answer. No-ops in raw. */
void pgpid_list_short_start(bool only_fpr, bool only_mbox);
void pgpid_list_short_end(void);

/* Ask the keyservers about one term — an address, a key id, a fingerprint.
 * Failure is ordinary and silent-ish: a server may be down, a key absent, and
 * neither must stop the caller from working with what is already local. */
void pgpid_refresh(const char *term, const char *keyservers);

int pgpid_list_short(const char *pattern, bool only_fpr, bool only_mbox,
                     size_t *certificates);

#endif /* PGPID_H */
