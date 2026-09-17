/* Changing which names a certificate answers to.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Three operations that `email` and `property` both need, written once.
 *
 * Revoking a uid leaves it on the certificate forever, marked revoked: the
 * packet never goes away, and whoever holds the certificate keeps the uid
 * until they refresh. It is not the end of it, though — a self-signature made
 * after the revocation supersedes it (RFC 9580: a revocation revokes the
 * *earlier* certifications of the same issuer), and the certifications other
 * people made over that uid count again. [pgpid_readd_uid] is that road, and
 * it is why putting the same string back is not the same as inventing a new
 * one.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_UIDS 256

/** Does this uid end in an address, the shape every mail client reads? */
bool pgpid_uid_has_address(const char *uid)
{
    const char *lt = NULL;
    for (const char *p = uid; *p; p++)
        if (*p == '<')
            lt = p;
    if (!lt)
        return false;
    const char *gt = strchr(lt, '>');
    if (!gt || gt == lt + 1)
        return false;
    for (const char *p = gt + 1; *p; p++)
        if (*p != ' ' && *p != '\t')
            return false;
    /* No nested brackets: "a <b <c>>" is not an address. */
    for (const char *p = lt + 1; p < gt; p++)
        if (*p == '<' || *p == '>')
            return false;
    return true;
}

/** The address inside such a uid, or NULL. Points into `uid`. */
const char *pgpid_uid_address(const char *uid, size_t *len)
{
    if (!pgpid_uid_has_address(uid))
        return NULL;
    const char *lt = NULL;
    for (const char *p = uid; *p; p++)
        if (*p == '<')
            lt = p;
    const char *gt = strchr(lt, '>');
    *len = (size_t)(gt - lt - 1);
    return lt + 1;
}

/**
 * Revoke one uid.
 *
 * The confirmation is not ceremony: the sentence it shows is the only place
 * anybody learns that the name stays on the certificate afterwards. Callers
 * that already asked pass `assume_yes`.
 */
bool pgpid_revoke_uid(const char *user, const char *uid, bool assume_yes)
{
    if (!assume_yes) {
        pgpid_error(_("Error: Revoking a User ID leaves it on the certificate forever,"));
        pgpid_error(_("marked revoked; those who hold it keep it until they refresh."));
        pgpid_error(_("Adding the identical value later signs it anew and it stands"));
        pgpid_error(_("again. Pass --yes if that is what you want:"));
        pgpid_error(_("  %s"), uid);
        return false;
    }
    pgpid_error(_("Notice: Revoking %s inside certificate %s…"), uid, user);
    const char *argv[] = { "--batch", "--quick-revoke-uid", user, uid, NULL };
    if (pgpid_run_engine(argv)) {
        pgpid_error(_("Error: gpg would not revoke %s."), uid);
        return false;
    }
    return true;
}

/**
 * Sign a revoked uid again, by the one route gpg leaves open.
 *
 * gpg refuses `--quick-add-uid` for a uid the certificate already carries,
 * revoked or not, and its menu will not sign one either. So the packet goes
 * first: `deluid` drops the uid and its signatures from *this* keyring, and
 * `--quick-add-uid` then mints a fresh self-signature over the same string.
 *
 * What the keyservers hold comes back at the next refresh: the old revocation,
 * which is older than the new self-signature and therefore superseded, and the
 * certifications other people made over that uid, which count again — this is
 * the whole point of putting the same string back rather than a new one.
 */
bool pgpid_readd_uid(const char *user, const char *uid)
{
    unsigned index = pgpid_uid_index(user, uid);
    if (!index) {
        pgpid_error(_("Error: Certificate %s carries no '%s' to sign again."), user, uid);
        return false;
    }
    pgpid_error(_("Notice: '%s' was revoked earlier; signing it again…"), uid);
    char script[PGPID_UID_MAX + 64];
    snprintf(script, sizeof script, "uid %u\ndeluid\ny\nsave\n", index);
    const char *drop[] = { "--batch", "--command-fd", "0", "--edit-key", user, NULL };
    if (pgpid_run_engine_input(drop, script)) {
        pgpid_error(_("Error: gpg would not drop the revoked '%s' — right PIN?"), uid);
        return false;
    }
    const char *add[] = { "--batch", "--quick-add-uid", user, uid, NULL };
    if (pgpid_run_engine(add)) {
        pgpid_error(_("Error: gpg would not add '%s'."), uid);
        return false;
    }
    return true;
}

/**
 * Make sure the certificate still announces an address as its main identity.
 *
 * Revoking a uid leaves the primary flag on the revoked one; gpg then falls
 * back on whatever uid it lists first, which since the vCard shapes exist may
 * be a phone number. Mail clients read that field.
 */
bool pgpid_fix_primary(const char *user)
{
    struct pgpid_uid uids[MAX_UIDS];
    size_t n = pgpid_list_uids(user, true, uids, MAX_UIDS);

    const char *newest = NULL;
    long newest_date = -1;
    bool first = true;
    for (size_t i = 0; i < n; i++) {
        if (!pgpid_uid_stands(uids[i].validity))
            continue;
        if (first) {
            first = false;
            if (pgpid_uid_has_address(uids[i].text))
                return true;   /* already an address in front */
        }
        if (!pgpid_uid_has_address(uids[i].text))
            continue;
        if (uids[i].created >= newest_date) {
            newest_date = uids[i].created;
            newest = uids[i].text;
        }
    }
    if (!newest) {
        pgpid_error(_("Warning: No address left on certificate %s to carry the "
                    "primary User ID flag."), user);
        return true;
    }
    pgpid_error(_("Notice: Main identity is no longer an address: moving the "
                "primary User ID flag to %s."), newest);
    const char *argv[] = { "--batch", "--quick-set-primary-uid", user, newest, NULL };
    if (pgpid_run_engine(argv)) {
        pgpid_error(_("Error: gpg would not move the primary User ID flag."));
        return false;
    }
    return true;
}

/**
 * Give a certificate minted before the vCard shapes existed its identity uid.
 *
 * Its identifier is buried in a comment of an older uid; this mints
 * `UID:urn:eid:<eid>` and an `FN:` from the name part, and leaves the old
 * uids exactly where they are — the web of trust rests on their
 * certifications, and the primary flag stays where its holder put it.
 *
 * Does nothing at all when there is no secret key, when the identity uid is
 * already there, or when the old uids disagree about the identifier.
 */
bool pgpid_upgrade_uids(const char *user, const char *keyservers)
{
    struct pgpid_uid uids[MAX_UIDS];
    size_t n = pgpid_list_uids(user, true, uids, MAX_UIDS);
    if (!n)
        return true;   /* no secret key: not ours to upgrade */

    char eid[64] = "";
    const char *name_from = NULL;
    size_t usable = 0;
    for (size_t i = 0; i < n; i++) {
        if (!strncmp(uids[i].text, "UID:urn:eid:", 12))
            return true;   /* already shaped */
        if (!pgpid_uid_stands(uids[i].validity))
            continue;
        usable++;
        if (!name_from)
            name_from = uids[i].text;
        char *found = pgpid_eid_of_uid(uids[i].text);
        if (!found)
            continue;
        if (*eid && strcmp(eid, found)) {
            free(found);
            return true;   /* the old uids disagree: not ours to decide */
        }
        snprintf(eid, sizeof eid, "%s", found);
        free(found);
    }
    if (!usable || !*eid)
        return true;

    char uid[600];
    snprintf(uid, sizeof uid, "UID:urn:eid:%s", eid);
    pgpid_error(_("Notice: Minting the identity uid %s…"), uid);
    const char *add[] = { "--batch", "--quick-add-uid", user, uid, NULL };
    if (pgpid_run_engine(add)) {
        pgpid_error(_("Error: gpg would not add %s."), uid);
        return false;
    }

    /* The name part of the oldest legacy uid, up to its comment or address. */
    char fn[600] = "";
    if (name_from) {
        size_t k = 0;
        for (const char *p = name_from; *p && *p != '(' && *p != '<' && k < sizeof fn - 1; p++)
            fn[k++] = *p;
        while (k && (fn[k - 1] == ' ' || fn[k - 1] == '\t'))
            k--;
        fn[k] = '\0';
    }
    if (*fn) {
        char fnuid[620];
        snprintf(fnuid, sizeof fnuid, "FN:%s", fn);
        const char *addfn[] = { "--batch", "--quick-add-uid", user, fnuid, NULL };
        if (pgpid_run_engine(addfn))
            pgpid_error(_("Warning: gpg would not add %s."), fnuid);
    }

    /* The minted uids must not take the primary flag. Nothing here sets one,
     * so gpg falls back to the most recent self-signature -- and all three
     * new uids are signed in the same second, which leaves the identity
     * anchor in front. It is the address that belongs there: the primary uid
     * is what mail clients show, which is the rule gen_key already follows
     * with --quick-set-primary-uid. */
    if (!pgpid_fix_primary(user))
        return false;

    /* Published here rather than left to the caller. The caller publishes
     * what *it* changed, and only if it changed something: an add that turns
     * out to be a no-op, or a revoke that finds nothing and returns early,
     * would leave a certificate reshaped on this machine and nowhere else.
     * The cost is one extra upload on the single occasion a certificate is
     * migrated, against a migration nobody else ever sees. */
    if (pgpid_send_to_keyservers(user, keyservers ? keyservers : PGPID_KEYSERVERS))
        pgpid_error(_("Warning: The reshaped certificate could not be published."));
    return true;
}
