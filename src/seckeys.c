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
    gpgme_ctx_t ctx;
    if (pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL))
        return false;

    static char fprs[MAX_SECKEYS][41];
    static char shown[MAX_SECKEYS][128];
    const char *items[MAX_SECKEYS];
    size_t n = 0;
    bool over = false;

    if (!gpgme_op_keylist_start(ctx, NULL, 1)) {
        gpgme_key_t key = NULL;
        while (!gpgme_op_keylist_next(ctx, &key)) {
            if (key->subkeys && key->subkeys->fpr && !key->revoked && !key->expired) {
                if (n >= MAX_SECKEYS) {
                    over = true;
                } else {
                    snprintf(fprs[n], sizeof fprs[0], "%s", key->subkeys->fpr);
                    snprintf(shown[n], sizeof shown[0], "%s  %s",
                             key->subkeys->fpr,
                             key->uids && key->uids->uid ? key->uids->uid : "");
                    items[n] = shown[n];
                    n++;
                }
            }
            gpgme_key_unref(key);
        }
    }
    gpgme_op_keylist_end(ctx);
    gpgme_release(ctx);

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
