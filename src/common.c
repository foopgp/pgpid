/* The bits every action needs: a context, an error, a vocabulary.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */
#include "pgpid.h"

#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <pwd.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

const char *pgpid_homedir = NULL;


void pgpid_try_help(const char *action)
{
    if (action)
        pgpid_error(_("Try '%s %s --help' for more information."),
                    PGPID_NAME, action);
    else
        pgpid_error(_("Try '%s --help' for more information."), PGPID_NAME);
}

void pgpid_error(const char *fmt, ...)
{
    va_list ap;
    fprintf(stderr, "%s: ", PGPID_NAME);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}


/* gpg writes one letter for a validity and the same letter for an ownertrust,
 * and the trustdb stores the same enum for both. One table, therefore. */

const char *pgpid_validity_word(char v)
{
    switch (v) {
    case 'q': return "undefined";
    case 'n': return "never";
    case 'm': return "marginal";
    case 'f': return "full";
    case 'u': return "ultimate";
    default:  return "unknown";
    }
}

/* What --import-ownertrust reads, from the letter --list-keys prints. Three
 * vocabularies say the same thing here: a word is written, a letter is read
 * back in colon field 9, and a number is what the ownertrust file carries.
 * 'unknown' has no number: it is the absence of a decision, not a value, and
 * gpg answers "Invalid argument" to anyone who tries to write it. */
int pgpid_ownertrust_code(char v)
{
    switch (v) {
    case 'q': return 2;
    case 'n': return 3;
    case 'm': return 4;
    case 'f': return 5;
    case 'u': return 6;
    default:  return 0;
    }
}

/* An order over the validity letters, because callers compare validities
 * to find the best one a key reaches. */
int pgpid_validity_rank(char v)
{
    switch (v) {
    case 'q': return 1;
    case 'n': return 2;
    case 'm': return 3;
    case 'f': return 4;
    case 'u': return 5;
    default:  return 0;
    }
}

int pgpid_validity_from_word(const char *word)
{
    static const struct { const char *word; char v; } words[] = {
        { "unknown",   '-' }, { "undefined", 'q' }, { "never",    'n' },
        { "marginal",  'm' }, { "full",      'f' }, { "ultimate", 'u' },
    };
    for (size_t i = 0; i < sizeof words / sizeof *words; i++)
        if (!strcmp(word, words[i].word))
            return words[i].v;
    return -1;
}


/* The child side of a pipe: replace this process with the engine. Never
 * returns on success. Used where the output has to be read back. */
void pgpid_exec_engine(const char *const *argv)
{
    size_t n = 0;
    while (argv[n])
        n++;
    const char **full = calloc(n + 4, sizeof *full);
    if (!full)
        return;
    size_t at = 0;
    full[at++] = "gpg";
    if (pgpid_homedir) {
        full[at++] = "--homedir";
        full[at++] = pgpid_homedir;
    }
    for (size_t i = 0; i < n; i++)
        full[at++] = argv[i];
    full[at] = NULL;
    /* execvp, not execv: the engine is found on PATH, and not through
     * a shell -- --homedir and the fingerprints go through untouched. */
    execvp(full[0], (char *const *)full);
    free(full);
}

/* Running the engine directly. execvp, not a shell: --homedir and
 * the fingerprints go through as they are, with nothing to quote and nothing
 * to get wrong. argv is NULL-terminated and starts after the program name;
 * --homedir is prepended here when one was given. */
/**
 * Run a program, optionally speaking to it and optionally keeping what it says.
 *
 * One primitive rather than three near-copies: the differences between
 * "run it", "tell it something" and "keep its output" are two redirections,
 * and three functions that each set up a fork were three places for the same
 * mistake.
 *
 * A closed pipe is ignored rather than fatal — a program that gives up before
 * reading everything says so with its exit status, which is more use than a
 * signal that kills us instead.
 */
int pgpid_run_program(const char *const *argv, const char *text, const char *out_path)
{
    int fds[2] = { -1, -1 };
    if (text && pipe(fds))
        return -1;

    pid_t pid = fork();
    if (pid < 0) {
        if (text) {
            close(fds[0]);
            close(fds[1]);
        }
        return -1;
    }
    if (pid == 0) {
        if (text) {
            close(fds[1]);
            dup2(fds[0], STDIN_FILENO);
            close(fds[0]);
        }
        if (out_path) {
            /* The one magic name: "/dev/null:stderr" silences complaints
             * rather than capturing output. Probes need that and nothing
             * else, so it is a special case rather than a second parameter
             * every caller would have to pass NULL for. */
            bool silence = !strcmp(out_path, "/dev/null:stderr");
            int out = open(silence ? "/dev/null" : out_path,
                           O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (out < 0)
                _exit(126);
            dup2(out, silence ? STDERR_FILENO : STDOUT_FILENO);
            close(out);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    if (text) {
        close(fds[0]);
        signal(SIGPIPE, SIG_IGN);
        size_t len = strlen(text), written = 0;
        while (written < len) {
            ssize_t got = write(fds[1], text + written, len - written);
            if (got <= 0)
                break;
            written += (size_t)got;
        }
        close(fds[1]);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* The engine and the home directory in front of what the caller asked for. */
static const char **with_engine(const char *const *argv)
{
    size_t n = 0;
    while (argv[n])
        n++;
    const char **full = calloc(n + 4, sizeof *full);
    if (!full)
        return NULL;
    size_t at = 0;
    full[at++] = "gpg";
    if (pgpid_homedir) {
        full[at++] = "--homedir";
        full[at++] = pgpid_homedir;
    }
    for (size_t i = 0; i < n; i++)
        full[at++] = argv[i];
    full[at] = NULL;
    return full;
}

int pgpid_run_engine(const char *const *argv)
{
    const char **full = with_engine(argv);
    if (!full)
        return -1;
    int ret = pgpid_run_program(full, NULL, NULL);
    free(full);
    return ret;
}

/**
 * The same, with the engine's complaints thrown away.
 *
 * For probes — asking "is this key protected?" by trying to open it with
 * nothing. The failure is the answer, and printing gpg's account of it makes
 * a working program look like a broken one, which cost an hour of reading a
 * log backwards.
 */
int pgpid_run_engine_quiet(const char *const *argv)
{
    const char **full = with_engine(argv);
    if (!full)
        return -1;
    int ret = pgpid_run_program(full, NULL, "/dev/null:stderr");
    free(full);
    return ret;
}

int pgpid_run_engine_io(const char *const *argv, const char *text, const char *out_path)
{
    const char **full = with_engine(argv);
    if (!full)
        return -1;
    int ret = pgpid_run_program(full, text, out_path);
    free(full);
    return ret;
}

bool pgpid_is_fingerprint(const char *s)
{
    if (!s)
        return false;
    size_t n = strlen(s);
    /* v4 is 40, v6 is 64. Nothing else is a fingerprint. */
    if (n != 40 && n != 64)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]))
            return false;
    return true;
}

/* Hand a certificate to each server named, and say which ones refused.
 * An empty list is a deliberate "nowhere" and not a failure. */
int pgpid_send_to_keyservers(const char *fpr, const char *list)
{
    if (!list || !*list)
        return PGPID_OK;
    char *copy = strdup(list);
    if (!copy)
        return PGPID_FAIL;
    int ret = PGPID_OK;
    for (char *save = NULL, *ks = strtok_r(copy, " \t,", &save); ks;
         ks = strtok_r(NULL, " \t,", &save)) {
        const char *argv[] = { "--keyserver", ks, "--send-keys", fpr, NULL };
        pgpid_error(_("Info: Sending %s to %s…"), fpr, ks);
        if (pgpid_run_engine(argv)) {
            pgpid_error(_("Warning: %s would not take it."), ks);
            ret = PGPID_FAIL;
        }
    }
    free(copy);
    return ret;
}

/**
 * The validity letter gpg gives each uid, in the order it lists them.
 *
 * Needed because the record's own flags cannot say "expired": a uid gpg marks 'e' arrives
 * here as revoked=0, invalid=0, validity=unknown — indistinguishable from
 * one nobody has vouched for. Measured 2026-08-22; the third thing a plain
 * will not tell us, after attribute packets and their images.
 *
 * Zipping by position is sound here and only here: the reader walks this very
 * output, so the two lists are the same list.
 */
size_t pgpid_uid_validities(const char *fpr, char *out, size_t max)
{
    int fds[2];
    if (pipe(fds))
        return 0;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return 0;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, STDERR_FILENO);
            close(null);
        }
        const char *argv[] = { "--with-colons", "--list-key", fpr, NULL };
        pgpid_exec_engine(argv);
        _exit(127);
    }
    close(fds[1]);
    FILE *f = fdopen(fds[0], "r");
    size_t n = 0;
    char line[8192];
    while (f && fgets(line, sizeof line, f)) {
        if (strncmp(line, "uid:", 4))
            continue;
        if (n + 1 < max)
            out[n++] = line[4] ? line[4] : '-';
    }
    if (f)
        fclose(f);
    int st;
    waitpid(pid, &st, 0);
    out[n] = '\0';
    return n;
}

/**
 * Run a program and keep what it writes, up to `max` bytes.
 *
 * Not the engine: the card is reached through gpg-connect-agent, which
 * speaks to scdaemon. A key listing has nothing for it — its business is keys and
 * data, and a smartcard's remaining attempts are neither.
 *
 * Returns the number of bytes captured, or -1 if the program could not run.
 * Its exit status is deliberately not the answer: a program can fail and
 * still have said something worth reading.
 */
int pgpid_capture(const char *const *argv, char *out, size_t max)
{
    int fds[2];
    if (pipe(fds))
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], STDOUT_FILENO);
        close(fds[1]);
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, STDERR_FILENO);
            close(null);
        }
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(fds[1]);
    size_t n = 0;
    ssize_t got;
    while (n + 1 < max && (got = read(fds[0], out + n, max - n - 1)) > 0)
        n += (size_t)got;
    out[n] = '\0';
    close(fds[0]);
    int st;
    waitpid(pid, &st, 0);
    return (int)n;
}

/**
 * Run the engine and keep what it said.
 *
 * `pgpid_capture` takes a whole command line; this one prepends the engine
 * and the home directory, so that a caller asking gpg a question cannot
 * forget which keyring the answer is about.
 */
int pgpid_capture_engine(const char *const *argv, char *out, size_t max)
{
    size_t n = 0;
    while (argv[n])
        n++;

    const char **full = calloc(n + 4, sizeof *full);
    if (!full)
        return -1;
    size_t at = 0;
    full[at++] = "gpg";
    if (pgpid_homedir) {
        full[at++] = "--homedir";
        full[at++] = pgpid_homedir;
    }
    for (size_t i = 0; i < n; i++)
        full[at++] = argv[i];
    full[at] = NULL;

    int got = pgpid_capture(full, out, max);
    free(full);
    return got;
}

/**
 * The certification key of whoever holds the connected card.
 *
 * The card carries subkeys; the key that certifies stays off it, in a safe
 * place. So the card is asked for a subkey it does have, and the keyring is
 * asked which certificate that subkey belongs to.
 */
/**
 * gpg's card status, read in a locale that will not translate it.
 *
 * Everything this feeds is parsed against English: the labels ("URL", "Name
 * of cardholder", "Signature key") and, worse, the value gpg writes for an
 * empty field -- "[not set]", which becomes "[non positionne]" in French. A
 * field that fails to read as empty reads as filled, so the count of what is
 * missing drops and token_check returns 102 where it owes 103.
 *
 * The shell guards the same read with `LANG=C.UTF-8`. LC_ALL is used here
 * because it also wins when LC_ALL is what the environment sets, which LANG
 * does not -- the shell is wrong in that case and this is not. C.UTF-8 and
 * not C: a cardholder name may carry accents, and they must stay characters.
 */
int pgpid_capture_card_status(char *out, size_t max)
{
    const char *argv[] = { "--card-status", NULL };
    const char *had = getenv("LC_ALL");
    char saved[128] = "";
    if (had)
        snprintf(saved, sizeof saved, "%s", had);
    setenv("LC_ALL", "C.UTF-8", 1);
    int got = pgpid_capture_engine(argv, out, max);
    if (had)
        setenv("LC_ALL", saved, 1);
    else
        unsetenv("LC_ALL");
    return got;
}

bool pgpid_card_certification_key(char *out, size_t max)
{
    char status[16384];
    if (pgpid_capture_card_status(status, sizeof status) <= 0)
        return false;

    /* Whichever of the three the card holds: any of them names the same
     * certificate, and a card missing one is not a card missing all. */
    static const char *const WANTED[] = {
        "Signature key", "Encryption key", "Authentication key",
    };
    char anchor[64] = "";
    for (unsigned w = 0; w < 3 && !*anchor; w++) {
        const char *at = strstr(status, WANTED[w]);
        if (!at)
            continue;
        const char *colon = strchr(at, ':');
        if (!colon)
            continue;
        size_t n = 0;
        for (const char *p = colon + 1; *p && *p != '\n' && n < sizeof anchor - 1; p++)
            if ((*p >= '0' && *p <= '9') || (*p >= 'A' && *p <= 'F')
                || (*p >= 'a' && *p <= 'f'))
                anchor[n++] = *p;
        anchor[n] = '\0';
        if (n != 40)
            *anchor = '\0';
    }
    if (!*anchor)
        return false;

    const char *pat[] = { anchor };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
    const struct pgpid_key *k = pgpid_keys_at(kr, 0);
    bool got = false;
    if (k && *k->fpr) {
        snprintf(out, max, "%s", k->fpr);
        got = true;
    }
    pgpid_keys_free(kr);
    return got;
}

/* gpg's colon listing escapes ':' and '\' and every control byte as \xNN.
 * What the caller wants back is the uid as its owner wrote it — gpg's own
 * --quick-*-uid will not match anything else. */
void pgpid_colon_unescape(const char *in, char *out, size_t max)
{
    size_t n = 0;
    for (; *in && n + 1 < max; in++) {
        if (in[0] == '\\' && in[1] == 'x' && in[2] && in[3]) {
            char hex[3] = { in[2], in[3], '\0' };
            char *end = NULL;
            long v = strtol(hex, &end, 16);
            if (end && !*end) {
                out[n++] = (char)v;
                in += 3;
                continue;
            }
        }
        out[n++] = *in;
    }
    out[n] = '\0';
}

/**
 * Does this uid still stand?
 *
 * Field 2 of the colon listing mixes two things: how far the web of trust
 * vouches for the uid (o i n m f u q -) and whether it is still alive
 * (r e d). This asks the second, as an allow list — a letter gpg has yet to
 * invent counts as unusable, because defaulting to "usable" is the dangerous
 * side to be wrong on.
 *
 * 'm' belongs in the list. Marginal says the web of trust vouches weakly, not
 * that the address is dead; leaving it out hid a third of the addresses on a
 * real certificate.
 */
/* The address an entity is written to — one rule, in one place.
 *
 * The primary uid when it carries an address, which is where this project puts
 * it; failing that the most recent standing uid that does. gpg lists the
 * primary first, so the first address seen is the primary's when the primary
 * is one.
 *
 * It was written three times before, and the copies disagreed: the business
 * card took the most recent and ignored the primary, the paper backup
 * preferred the primary, the listing had its own. Three answers to the same
 * question about the same certificate.
 */
const struct pgpid_uid *pgpid_preferred_uid(const struct pgpid_uid *uids, size_t n)
{
    const struct pgpid_uid *pick = NULL;
    long newest = -1;

    for (size_t i = 0; i < n; i++) {
        if (!pgpid_uid_stands(uids[i].validity))
            continue;
        if (!pgpid_uid_has_address(uids[i].text))
            continue;
        if (!pick) {
            pick = &uids[i];
            /* The primary outranks any date; anything later wins only on
             * being newer than the last one taken. */
            newest = (i == 0) ? LONG_MAX : uids[i].created;
        } else if (uids[i].created > newest) {
            pick = &uids[i];
            newest = uids[i].created;
        }
    }
    return pick;
}

/**
 * The user id the certificate flags as its primary — subpacket 25.
 *
 * Walked from the packets rather than read off the colon listing, which does
 * not say: gpg happens to list the primary first today, and a program that
 * relies on that is relying on an ordering nobody promised.
 *
 * For each uid, its newest binding self-signature counts, unless a revocation
 * on that uid is newer still. The last one flagged primary wins, which is what
 * gpg does when two signatures disagree.
 */
bool pgpid_primary_uid(const char *user, char *out, size_t max)
{
    *out = '\0';
    char fpr[41] = "";
    const char *pat[] = { user };
    struct pgpid_keyring *kr = pgpid_keys_load(pat, 1, 0);
    if (kr && pgpid_keys_count(kr))
        snprintf(fpr, sizeof fpr, "%s", pgpid_keys_at(kr, 0)->fpr);
    pgpid_keys_free(kr);
    if (!*fpr)
        return false;

    size_t len = 0;
    unsigned char *raw = pgpid_export_key(fpr, true, &len);
    if (!raw)
        return false;

    const char *keyid = strlen(fpr) >= 16 ? fpr + strlen(fpr) - 16 : fpr;
    const unsigned char *p = raw, *end = raw + len;
    struct pgpid_packet pkt;
    char current[512] = "";
    unsigned long newest_binding = 0, newest_revocation = 0;
    bool uid_primary = false;

    while (pgpid_packet_next(p, end, &pkt)) {
        p = pkt.next;
        if (pkt.tag == TAG_USER_ID) {
            if (*current && uid_primary && newest_binding > newest_revocation)
                snprintf(out, max, "%s", current);
            snprintf(current, sizeof current, "%.*s",
                     (int)(pkt.len < sizeof current ? pkt.len : sizeof current - 1),
                     (const char *)pkt.body);
            newest_binding = newest_revocation = 0;
            uid_primary = false;
            continue;
        }
        if (pkt.tag != TAG_SIGNATURE) {
            if (*current && uid_primary && newest_binding > newest_revocation)
                snprintf(out, max, "%s", current);
            *current = '\0';
            continue;
        }
        if (!*current)
            continue;

        unsigned type;
        unsigned long created;
        const char *issuer;
        if (!pgpid_signature_read(&pkt, &type, &created, &issuer))
            continue;
        /* Only what the certificate says about itself. */
        if (!issuer || strcasecmp(issuer, keyid))
            continue;
        if (type == SIG_CERT_REVOKE) {
            if (created > newest_revocation)
                newest_revocation = created;
            continue;
        }
        if (type < SIG_CERT_LOWEST || type > SIG_CERT_HIGHEST)
            continue;
        if (created < newest_binding)
            continue;
        newest_binding = created;
        const unsigned char *flag;
        size_t flen = 0;
        uid_primary = pgpid_signature_subpacket(&pkt, 25, &flag, &flen)
                      && flen >= 1 && flag[0];
    }
    if (*current && uid_primary && newest_binding > newest_revocation)
        snprintf(out, max, "%s", current);

    free(raw);
    return *out != '\0';
}

/**
 * The number gpg's --edit-key menu gives this user id.
 *
 * Its place among the uid *and* attribute lines, counted from one: a photo
 * takes a number in that menu just as a name does, so a certificate carrying
 * one shifts every uid after it. Counting only the uids -- which is what a
 * listing of them gives -- names the wrong one on exactly the certificates
 * that carry an avatar, which is most of ours.
 */
unsigned pgpid_uid_index(const char *user, const char *text)
{
    char listing[262144];
    const char *argv[] = { "--with-colons", "--list-key", user, NULL };
    if (pgpid_capture_engine(argv, listing, sizeof listing) <= 0)
        return 0;

    unsigned index = 0, keys = 0;
    for (char *line = listing, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        if (!strncmp(line, "pub:", 4) && ++keys > 1)
            break;
        bool is_uid = !strncmp(line, "uid:", 4);
        if (!is_uid && strncmp(line, "uat:", 4))
            continue;
        index++;
        if (!is_uid)
            continue;
        /* Field 10 is the uid itself, colon-escaped. */
        unsigned field = 1;
        char *start = line;
        for (char *q = line; ; q++) {
            if (*q != ':' && *q)
                continue;
            if (field == 10) {
                char plain[512];
                char saved = *q;
                *q = '\0';
                pgpid_colon_unescape(start, plain, sizeof plain);
                *q = saved;
                if (!strcmp(plain, text))
                    return index;
                break;
            }
            if (!*q)
                break;
            field++;
            start = q + 1;
        }
    }
    return 0;
}

/**
 * Is this uid one of ours, `PROPERTY:value` or `PROPERTY;PARAM:value`?
 *
 * The vCard properties an entity publishes live in uids of their own, and
 * three actions now read them -- the card writer, the account opener, and
 * the address rule. One reading, so that a uid means the same thing to all.
 */
const char *pgpid_uid_property(const char *uid, char *name, size_t max)
{
    size_t i = 0;
    while (uid[i] >= 'A' && uid[i] <= 'Z' && i < max - 1)
        i++;
    if (!i)
        return NULL;
    const char *p = uid + i;
    if (*p == ';')
        p = strchr(p, ':');
    if (!p || *p != ':')
        return NULL;
    memcpy(name, uid, i);
    name[i] = '\0';
    /* One optional space after the colon, which the vCard-uid experiment
     * used and which is not part of the value. */
    return p[1] == ' ' ? p + 2 : p + 1;
}

/**
 * What a certificate is called: the FN it carries, or nothing.
 *
 * FN is the field made to hold a name, and the only one that is a name: an
 * address is where to write, an identifier is who, a comment is whatever
 * somebody typed. Read here rather than in each caller, so that a certificate
 * is called the same thing by the card writer, the key page and the list of
 * certifiers.
 *
 * Revoked and unusable uids are passed over: a name its owner has taken back
 * is not what they are called.
 */
bool pgpid_key_name(const struct pgpid_key *key, char *out, size_t max)
{
    if (!key || !out || !max)
        return false;
    for (size_t k = 0; k < key->nuid; k++) {
        const struct pgpid_keyuid *u = &key->uid[k];
        if (u->revoked || u->invalid)
            continue;
        char name[64];
        const char *value = pgpid_uid_property(u->text, name, sizeof name);
        if (!value || strcmp(name, "FN") || !*value)
            continue;
        snprintf(out, max, "%s", value);
        return true;
    }
    return false;
}

/**
 * The account named USER, or the one whose identifier is EID.
 *
 * The two name the same thing: an entity holds an entry under its identifier
 * and, usually, a shorter one beside it. An account laid out before this tool
 * has only the short name and carries the identifier in the path of its home,
 * so that counts as naming it too.
 */
bool pgpid_account_name(const char *who, char *out, size_t max)
{
    if (!who || !*who)
        return false;
    if (getpwnam(who)) {
        snprintf(out, max, "%s", who);
        return true;
    }
    bool found = false;
    setpwent();
    const struct passwd *p;
    while ((p = getpwent())) {
        const char *base = strrchr(p->pw_dir, '/');
        if (base && !strcmp(base + 1, who)) {
            snprintf(out, max, "%s", p->pw_name);
            found = true;
            break;
        }
    }
    endpwent();
    return found;
}

/** The identifier an account carries: in its name, or in the path of its home. */
bool pgpid_account_eid(const struct passwd *pw, char *out, size_t max)
{
    *out = '\0';
    if (!pw)
        return false;
    /* The home first: it holds the identifier whole, and the name may be it
     * cut to what shadow allows -- which no longer reads as one. */
    const char *base = strrchr(pw->pw_dir, '/');
    if (base && pgpid_eid_body_is_sound(base + 1)) {
        snprintf(out, max, "%s", base + 1);
        return true;
    }
    if (pgpid_eid_body_is_sound(pw->pw_name)) {
        snprintf(out, max, "%s", pw->pw_name);
        return true;
    }
    return false;
}

bool pgpid_preferred_address(const struct pgpid_key *key, char *out, size_t max)
{
    struct pgpid_uid light[64];
    size_t n = 0;
    *out = '\0';
    for (size_t i = 0; i < key->nuid && n < 64; i++) {
        snprintf(light[n].text, sizeof light[0].text, "%s", key->uid[i].text);
        light[n].validity = key->uid[i].validity;
        light[n].created = key->uid[i].created;
        n++;
    }
    const struct pgpid_uid *pick = pgpid_preferred_uid(light, n);
    if (!pick)
        return false;
    size_t len = 0;
    const char *at = pgpid_uid_address(pick->text, &len);
    if (!at || !len || len >= max)
        return false;
    snprintf(out, max, "%.*s", (int)len, at);
    return true;
}

/* Our own path, so that a part of this program calling another part reaches
 * the binary that is running rather than whatever "pgpid" resolves to -- or
 * fails to resolve to, which is what happens on a machine where it is built
 * but not installed. */
const char *pgpid_self(void)
{
    static char path[512];
    if (*path)
        return path;
    ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1);
    if (n > 0)
        path[n] = '\0';
    else
        snprintf(path, sizeof path, "%s", PGPID_NAME);
    return path;
}

bool pgpid_uid_stands(char validity)
{
    return strchr("ounmfqws-", validity) != NULL;
}

/**
 * The uids of a certificate, with what gpg knows about each.
 *
 * Read straight from the colon listing, for two things a key record does not
 * carry: the letter that tells an expired uid from an uncertified one, and
 * the date the uid's self-signature was made — which is how "the newest
 * address" gets decided when one has to be kept.
 */
size_t pgpid_list_uids(const char *user, bool secret,
                       struct pgpid_uid *out, size_t max)
{
    char listing[262144];
    const char *argv[] = { "--with-colons",
                           secret ? "--list-secret-key" : "--list-key",
                           user, NULL };
    if (pgpid_capture_engine(argv, listing, sizeof listing) <= 0)
        return 0;

    size_t n = 0;
    unsigned keys = 0;
    for (char *line = listing, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        if (!strncmp(line, "pub:", 4) || !strncmp(line, "sec:", 4)) {
            /* The first keyring only: a second certificate in the same
             * listing is a different key that happens to match too. */
            if (++keys > 1)
                break;
            continue;
        }
        if (strncmp(line, "uid:", 4) || n >= max)
            continue;

        /* Split by hand: strtok_r folds empty fields together, and a uid
         * line with a blank validity would shift every field after it. */
        char *field[12] = { NULL };
        unsigned nf = 0;
        char *start = line;
        for (char *p = line; nf < 12; p++) {
            if (*p == ':' || !*p) {
                field[nf++] = start;
                if (!*p)
                    break;
                *p = '\0';
                start = p + 1;
            }
        }
        if (nf < 10)
            continue;
        out[n].validity = field[1] && *field[1] ? field[1][0] : '-';
        out[n].created = field[5] && *field[5] ? strtol(field[5], NULL, 10) : 0;
        pgpid_colon_unescape(field[9] ? field[9] : "", out[n].text, sizeof out[n].text);
        n++;
    }
    return n;
}

/**
 * Run the engine with something to say to it.
 *
 * `--quick-*` covers most of what gpg can be told; the preferred keyserver is
 * one of the things it does not, and that one is reached by holding an
 * edit-key conversation. The answers are written to the engine's standard
 * input, in order, and the pipe is closed so gpg knows the conversation ended
 * rather than waiting for a line that never comes.
 */
int pgpid_run_engine_input(const char *const *argv, const char *text)
{
    return pgpid_run_engine_io(argv, text, NULL);
}
