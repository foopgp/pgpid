/* Which secret key, when nobody said.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The shell puts this question through a radiolist; here the keys are printed
 * and a number is read. Same question either way, and the same refusal to
 * answer it on the user's behalf: a machine holding several secret keys is
 * exactly where guessing signs, moves or re-locks the wrong one.
 */
#include "pgpid.h"

#include <stdio.h>
#include <string.h>

#define MAX_SECKEYS 32

/* Field 15 is not "empty or a serial". gpg writes "+" there when the secret
 * material is really at hand, the card's serial when the entry is only a stub
 * pointing at one, and "#" when the secret is not available at all. */
#define ON_DISK "+"

bool pgpid_secret_is_local(const struct pgpid_key *k)
{
    if (!strcmp(k->card, ON_DISK))
        return true;
    for (size_t i = 0; i < k->nsub; i++)
        if (!strcmp(k->sub[i].card, ON_DISK))
            return true;
    return false;
}

/**
 * Ask which secret key, and return its fingerprint.
 *
 * A single key is taken without asking — there is no choice to make, and a
 * question with one answer is a question not worth putting. More than
 * MAX_SECKEYS is refused rather than truncated: choosing among keys one
 * cannot see is not choosing.
 */
bool pgpid_choose_secret_key(const char *prompt, char *out, size_t max)
{
    static char fprs[MAX_SECKEYS][41];
    static char shown[MAX_SECKEYS][128];
    const char *items[MAX_SECKEYS];
    size_t n = 0;
    bool over = false;

    struct pgpid_keyring *kr = pgpid_keys_load(NULL, 0, PGPID_KEYS_SECRET);
    for (size_t i = 0; i < pgpid_keys_count(kr); i++) {
        const struct pgpid_key *key = pgpid_keys_at(kr, i);
        if (!*key->fpr || key->revoked || key->expired)
            continue;
        /* Stubs pointing at a security key are not answers to this question:
         * none of the three callers can act on one. Offering them is how
         * secret_print came to propose printing a key it cannot read. */
        if (!pgpid_secret_is_local(key))
            continue;
        if (n >= MAX_SECKEYS) {
            over = true;
            continue;
        }
        snprintf(fprs[n], sizeof fprs[0], "%s", key->fpr);
        /* Bounded explicitly: the compiler cannot see that a fingerprint is
         * forty characters and the line has room for both. */
        snprintf(shown[n], sizeof shown[0], "%.40s  %.80s",
                 key->fpr, key->nuid ? key->uid[0].text : "");
        items[n] = shown[n];
        n++;
    }
    pgpid_keys_free(kr);

    if (over) {
        pgpid_error(_("Error: More than %d secret keys here; name the one you mean."),
                    MAX_SECKEYS);
        return false;
    }
    if (!n) {
        pgpid_error(_("Error: No secret key here."));
        return false;
    }
    size_t picked = 0;
    if (!pgpid_choose(prompt, items, n, &picked))
        return false;
    snprintf(out, max, "%.40s", fprs[picked]);
    return true;
}
