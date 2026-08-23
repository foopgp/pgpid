/* A card somebody can hand over.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Everything on this card is public and meant to be read across a table: a
 * name, an identifier, a fingerprint, an address, and a QR code leading to
 * the keyserver. It is the opposite of `print_secret`, which is why the two
 * are no longer both called `print` — the name now says which one must never
 * go near a shared printer.
 *
 * The fingerprint is set in two lines of five groups because that is how one
 * gets read aloud, and reading it aloud against the other person's screen is
 * the check a certification rests on.
 */
#include "pgpid.h"
#include "sticker.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAX_UIDS 256

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " print_card [OPTIONS]... [NAME|EMAIL|KEYID|U4|U5]\n"
        "\n"
        "Produce or print a PGP ID sticker or business card. Without a target,\n"
        "the certificate the connected card belongs to.\n"
        "\n"
        "One address appears on it: the argument itself when that is what was\n"
        "given, otherwise the most recent one the certificate still stands by.\n"
        "\n"
        "OPTIONS:\n"
        "  -P, --print PRINTER|FILE.svg  Printer to send to, or an SVG file to write\n"
        "                                when the name ends in '.svg'\n"
        "  -t, --template FILE.svg       Use this template instead of the sticker\n"
        "  -N, --name NAME               Override the displayed name\n"
        "  -g, --no-color                Grayscale instead of colour\n"
        "  -h, --help                    Print this help and exit\n"
        "  -V, --version                 Print the version and exit\n"),
            PGPID_NAME);
}

/** Replace every occurrence of KEY by VALUE. Caller frees. */
static char *substitute(const char *in, const char *key, const char *value)
{
    size_t klen = strlen(key), vlen = strlen(value);
    size_t count = 0;
    for (const char *p = in; (p = strstr(p, key)); p += klen)
        count++;
    char *out = malloc(strlen(in) + count * (vlen > klen ? vlen - klen : 0) + 1);
    if (!out)
        return NULL;
    char *w = out;
    for (const char *p = in; *p;) {
        if (!strncmp(p, key, klen)) {
            memcpy(w, value, vlen);
            w += vlen;
            p += klen;
        } else {
            *w++ = *p++;
        }
    }
    *w = '\0';
    return out;
}

/** What XML will not carry raw. */
static void xml_escape(const char *in, char *out, size_t max)
{
    size_t n = 0;
    for (; *in && n + 7 < max; in++) {
        switch (*in) {
        case '&': memcpy(out + n, "&amp;", 5);  n += 5; break;
        case '<': memcpy(out + n, "&lt;", 4);   n += 4; break;
        case '>': memcpy(out + n, "&gt;", 4);   n += 4; break;
        case '"': memcpy(out + n, "&quot;", 6); n += 6; break;
        case '\'': memcpy(out + n, "&apos;", 6); n += 6; break;
        default: out[n++] = *in; break;
        }
    }
    out[n] = '\0';
}

/** The address in a uid, copied out. */
static bool address_of(const char *uid, char *out, size_t max)
{
    size_t len = 0;
    const char *at = pgpid_uid_address(uid, &len);
    if (!at || len >= max)
        return false;
    memcpy(out, at, len);
    out[len] = '\0';
    return true;
}

int pgpid_action_print_card(int argc, char **argv)
{
    const char *printer = NULL, *template_path = NULL, *given_name = NULL;
    const char *target = NULL;
    bool nocolor = false;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-P") || !strcmp(a, "--print") || !strcmp(a, "--printer")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a printer or an SVG file."), a);
                return PGPID_USAGE;
            }
            printer = argv[i];
        } else if (!strcmp(a, "-t") || !strcmp(a, "--template")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a template."), a);
                return PGPID_USAGE;
            }
            template_path = argv[i];
        } else if (!strcmp(a, "-N") || !strcmp(a, "--name") || !strcmp(a, "--usename")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a name."), a);
                return PGPID_USAGE;
            }
            given_name = argv[i];
        } else if (!strcmp(a, "-g") || !strcmp(a, "--no-color") || !strcmp(a, "--gray")
                   || !strcmp(a, "--grayscale")) {
            nocolor = true;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("print_card");
            return PGPID_USAGE;
        } else if (!target) {
            target = a;
        }
    }

    char fpr[41] = "", email[320] = "";
    bool email_given = target && strchr(target, '@') && !strchr(target, ' ');

    /* Which certificate. An address may sit on several, and printing a card
     * for the wrong one is worse than printing none. */
    gpgme_ctx_t ctx;
    if (pgpid_ctx_new(&ctx, GPGME_KEYLIST_MODE_LOCAL))
        return PGPID_FAIL;
    char candidates[16][41];
    size_t ncand = 0;
    const char *pattern = target;
    char card_key[41];
    if (!pattern) {
        if (!pgpid_card_certification_key(card_key, sizeof card_key)) {
            gpgme_release(ctx);
            pgpid_error(_("Error: No card answered, so there is no certificate to print."));
            pgpid_error(_("Name one instead."));
            return PGPID_FAIL;
        }
        pattern = card_key;
    }
    if (!gpgme_op_keylist_start(ctx, pattern, 0)) {
        gpgme_key_t key = NULL;
        while (ncand < 16 && !gpgme_op_keylist_next(ctx, &key)) {
            if (!key->revoked && key->subkeys && key->subkeys->fpr)
                snprintf(candidates[ncand++], 41, "%.40s", key->subkeys->fpr);
            gpgme_key_unref(key);
        }
    }
    gpgme_op_keylist_end(ctx);
    gpgme_release(ctx);

    if (email_given) {
        snprintf(email, sizeof email, "%s", target);
        /* Only the certificates that still stand by this address count. */
        size_t kept = 0;
        char keeper[41] = "";
        for (size_t i = 0; i < ncand; i++) {
            struct pgpid_uid uids[MAX_UIDS];
            size_t n = pgpid_list_uids(candidates[i], false, uids, MAX_UIDS);
            for (size_t k = 0; k < n; k++) {
                char addr[320];
                if (!pgpid_uid_stands(uids[k].validity))
                    continue;
                if (address_of(uids[k].text, addr, sizeof addr) && !strcmp(addr, email)) {
                    kept++;
                    snprintf(keeper, sizeof keeper, "%.40s", candidates[i]);
                    break;
                }
            }
        }
        if (!kept) {
            pgpid_error(_("Error: No usable certificate for %s."), email);
            return PGPID_FAIL;
        }
        if (kept > 1) {
            pgpid_error(_("Error: Email %s matches several certificates that still "
                        "stand by it (%zu)."), email, kept);
            return PGPID_FAIL;
        }
        snprintf(fpr, sizeof fpr, "%s", keeper);
    } else {
        if (!ncand) {
            pgpid_error(_("Error: No certificate matches '%s'."), pattern);
            return PGPID_FAIL;
        }
        if (ncand > 1) {
            pgpid_error(_("Error: '%s' matches %zu certificates. Name one."), pattern, ncand);
            return PGPID_FAIL;
        }
        snprintf(fpr, sizeof fpr, "%s", candidates[0]);
    }

    struct pgpid_uid uids[MAX_UIDS];
    size_t nuids = pgpid_list_uids(fpr, false, uids, MAX_UIDS);

    /* The most recent address the certificate still stands by. */
    if (!*email) {
        long newest = -1;
        for (size_t i = 0; i < nuids; i++) {
            char addr[320];
            if (!pgpid_uid_stands(uids[i].validity))
                continue;
            if (!address_of(uids[i].text, addr, sizeof addr))
                continue;
            if (uids[i].created >= newest) {
                newest = uids[i].created;
                snprintf(email, sizeof email, "%s", addr);
            }
        }
        if (!*email) {
            pgpid_error(_("Error: No usable (non-revoked) email in certificate %s."), fpr);
            return PGPID_FAIL;
        }
        pgpid_error(_("Notice: Picking most recent email %s."), email);
    }

    /* The name: what was asked for, else the certificate's own FN:, else the
     * name in front of the address, else the part before the '@'. A vCard
     * prefix is not a display name — it is the shape of a uid. */
    char name[512] = "";
    if (given_name) {
        snprintf(name, sizeof name, "%s", given_name);
    } else {
        for (size_t i = 0; i < nuids && !*name; i++)
            if (pgpid_uid_stands(uids[i].validity) && !strncmp(uids[i].text, "FN:", 3))
                snprintf(name, sizeof name, "%s", uids[i].text + 3);
        for (size_t i = 0; i < nuids && !*name; i++) {
            char addr[320];
            if (!pgpid_uid_stands(uids[i].validity))
                continue;
            if (!address_of(uids[i].text, addr, sizeof addr) || strcmp(addr, email))
                continue;
            size_t k = 0;
            for (const char *p = uids[i].text; *p && *p != '(' && *p != '<'
                 && k < sizeof name - 1; p++)
                name[k++] = *p;
            name[k] = '\0';
            while (k && (name[k - 1] == ' ' || name[k - 1] == '\t'))
                name[--k] = '\0';
            if (!strncmp(name, "EMAIL:", 6) || !strncmp(name, "UID:", 4)
                || !strncmp(name, "NOTE:", 5) || !strncmp(name, "FN:", 3))
                *name = '\0';
        }
        if (!*name)
            snprintf(name, sizeof name, "%.*s", (int)(strchr(email, '@') - email), email);
    }

    char eid[64] = "";
    for (size_t i = 0; i < nuids && !*eid; i++) {
        char *found = pgpid_eid_of_uid(uids[i].text);
        if (!found)
            continue;
        snprintf(eid, sizeof eid, "%s", found);
        free(found);
    }

    char line1[32], line2[32];
    snprintf(line1, sizeof line1, "%.4s %.4s %.4s %.4s %.4s",
             fpr, fpr + 4, fpr + 8, fpr + 12, fpr + 16);
    snprintf(line2, sizeof line2, "%.4s %.4s %.4s %.4s %.4s",
             fpr + 20, fpr + 24, fpr + 28, fpr + 32, fpr + 36);

    char workdir[512] = "/tmp/pgpid-card.XXXXXX";
    if (!mkdtemp(workdir)) {
        pgpid_error(_("Error: Cannot make a working directory."));
        return PGPID_FAIL;
    }

    /* The QR leads to the keyserver's index for this fingerprint: what it is
     * for is somebody's phone, across a table. */
    char url[256], png[600];
    snprintf(url, sizeof url,
             "https://keys.foopgp.org/pks/lookup?op=index&fingerprint=on&search=0x%s", fpr);
    snprintf(png, sizeof png, "%.500s/qr.png", workdir);
    const char *qr[] = { "qrencode", "--output", png, "--", url, NULL };
    if (pgpid_run_program(qr, NULL, NULL)) {
        pgpid_error(_("Error: qrencode would not draw the code."));
        return PGPID_FAIL;
    }
    FILE *f = fopen(png, "rb");
    if (!f) {
        pgpid_error(_("Error: Cannot read the code back."));
        return PGPID_FAIL;
    }
    static unsigned char raw[262144];
    size_t rawlen = fread(raw, 1, sizeof raw, f);
    fclose(f);
    static char href[400000];
    snprintf(href, sizeof href, "data:image/png;base64,");
    pgpid_base64(raw, rawlen, href + strlen(href));

    char *body = NULL;
    if (template_path) {
        FILE *t = fopen(template_path, "r");
        if (!t) {
            pgpid_error(_("Error: Card template '%s' is not readable."), template_path);
            return PGPID_FAIL;
        }
        static char buf[262144];
        size_t n = fread(buf, 1, sizeof buf - 1, t);
        buf[n] = '\0';
        fclose(t);
        body = strdup(buf);
    } else {
        body = strdup(STICKER_TEMPLATE);
    }
    if (!body)
        return PGPID_FAIL;

    char safe_name[2048], safe_email[2048];
    xml_escape(name, safe_name, sizeof safe_name);
    xml_escape(email, safe_email, sizeof safe_email);

    struct { const char *key; const char *value; } fill[] = {
        { "${QR_HREF}",   href },
        { "${NAME}",      safe_name },
        { "${U4}",        eid },
        { "${FPR_LINE1}", line1 },
        { "${FPR_LINE2}", line2 },
        { "${EMAIL}",     safe_email },
        { "${SUBTITLE}",  "Friends of OpenPGP" },
    };
    for (size_t i = 0; i < sizeof fill / sizeof *fill; i++) {
        char *next = substitute(body, fill[i].key, fill[i].value);
        free(body);
        if (!next)
            return PGPID_FAIL;
        body = next;
    }

    if (nocolor) {
        /* The templates use a small fixed palette, so grey is a remap rather
         * than a filter — and stays crisp on a laser printer. */
        static const char *const MAP[][2] = {
            { "#ff8012", "#666666" }, { "#90462f", "#888888" },
            { "#ffefea", "#f0f0f0" }, { "#2c284b", "#222222" },
            { "#5d4ce6", "#555555" }, { "#fafafa", "#ffffff" },
        };
        for (size_t i = 0; i < sizeof MAP / sizeof *MAP; i++) {
            char *next = substitute(body, MAP[i][0], MAP[i][1]);
            free(body);
            if (!next)
                return PGPID_FAIL;
            body = next;
        }
    }

    char svg[600];
    snprintf(svg, sizeof svg, "%.500s/render.svg", workdir);
    FILE *out = fopen(svg, "w");
    if (!out) {
        free(body);
        pgpid_error(_("Error: Cannot write the card."));
        return PGPID_FAIL;
    }
    fputs(body, out);
    fclose(out);
    free(body);

    size_t plen = printer ? strlen(printer) : 0;
    if (printer && plen > 4 && !strcmp(printer + plen - 4, ".svg")) {
        FILE *src = fopen(svg, "rb");
        FILE *dst = fopen(printer, "wb");
        if (!src || !dst) {
            if (src) fclose(src);
            if (dst) fclose(dst);
            pgpid_error(_("Error: Cannot write %s."), printer);
            return PGPID_FAIL;
        }
        char chunk[4096];
        for (size_t n; (n = fread(chunk, 1, sizeof chunk, src));)
            fwrite(chunk, 1, n, dst);
        fclose(src);
        fclose(dst);
        pgpid_error(_("Notice: Wrote SVG to %s."), printer);
        return PGPID_OK;
    }

    if (!printer) {
        pgpid_error(_("Error: Where should this go? Name a printer, or a file ending"));
        pgpid_error(_("in '.svg' to keep it."));
        return PGPID_USAGE;
    }

    char single[600], duped[600], page[600];
    snprintf(single, sizeof single, "%.500s/single.pdf", workdir);
    snprintf(duped, sizeof duped, "%.500s/duped.pdf", workdir);
    snprintf(page, sizeof page, "%.500s/page.pdf", workdir);
    const char *render[] = { "rsvg-convert", "--format=pdf",
                             "--output", single, svg, NULL };
    if (pgpid_run_program(render, NULL, NULL)) {
        pgpid_error(_("Error: rsvg-convert would not render the card."));
        return PGPID_FAIL;
    }

    /* A4 landscape: the sticker is 85×25 mm, so 3×7 to a page; a full card
     * template is bigger and takes 3×3. pdfjam tiles one page per slot, so
     * the single page is repeated first. --noautoscale keeps the real size —
     * without it the output is about a fifth too big and bleeds off. */
    const char *nup = template_path ? "3x3" : "3x7";
    int copies = template_path ? 9 : 21;
    const char *unite[32];
    size_t at = 0;
    unite[at++] = "pdfunite";
    for (int i = 0; i < copies && at < 30; i++)
        unite[at++] = single;
    unite[at++] = duped;
    unite[at] = NULL;
    if (pgpid_run_program(unite, NULL, NULL)) {
        pgpid_error(_("Error: pdfunite would not repeat the card."));
        return PGPID_FAIL;
    }
    const char *jam[] = { "pdfjam", "--quiet", "--paper", "a4paper", "--landscape",
                          "--nup", nup, "--noautoscale", "true",
                          "--outfile", page, duped, NULL };
    if (pgpid_run_program(jam, NULL, NULL)) {
        pgpid_error(_("Error: pdfjam would not lay the page out."));
        return PGPID_FAIL;
    }

    pgpid_error(_("Notice: Printing %s %s on %s…"), nup,
                template_path ? template_path : "sticker", printer);
    const char *lpr[] = { "lpr", "-P", printer, page, NULL };
    if (pgpid_run_program(lpr, NULL, NULL)) {
        pgpid_error(_("Error: lpr would not print the page."));
        return PGPID_FAIL;
    }
    return PGPID_OK;
}
