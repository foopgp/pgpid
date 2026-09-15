/* Putting a secret key on paper, in pieces.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * A secret key that exists in one place is a secret key one accident away
 * from gone. Paper does not rot on a schedule, does not need a driver, and
 * cannot be read across a network — but a single sheet is a single thing to
 * lose, or to be taken.
 *
 * So it goes out in fragments, and by default any three of five rebuild it
 * (Shamir): fewer than three say nothing at all, and losing two costs
 * nothing. Asking for as many fragments as the threshold turns that off — the
 * pieces are then simply consecutive, and everything rests on the passphrase.
 * The help says so, because somebody will ask for it without meaning that.
 *
 * This is a pipeline over other people's tools — gpg, gfsplit, qrencode,
 * pandoc — and calling them in order is the whole job. Nothing here is faster
 * or more portable in C than it was in the shell; what it gains is one place
 * where the fragment header is written, and the same reader on both sides.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " secret_print [OPTIONS]... KEY_ID|FPR\n"
        "\n"
        "Export and print OpenPGP secrets on multiple QRcode using Shamir's secret\n"
        "sharing, split so that no single sheet carries the key.\n"
        "\n"
        "Missing input will be asked interactively, unless --batch.\n"
        "\n"
        "OPTIONS:\n"
        "  -p, --passphrase PASSPHRASE    Passphrase to access secret parts of OpenPGP key\n"
        "  -P, --passfrom FILE            Get passphrase from first line of FILE (eg: fifo, tmpfs, /dev/stdin ...)\n"
        "  -t, --printer PRINTER          Name of printer to use. Empty to produce the sheets and send nothing\n"
        "  -w, --with-passphrase          Also print passphrase beside QR codes (INCREASE UX, DECREASE SECURITY)\n"
        "  -W, --workdir DIRECTORY        Use given working directory instead of a temporary directory (don't forget to shred its content)\n"
        "  -S, --split NUM                Number of shares to be generated, 3 to %d - Default: 5\n"
        "  -T, --threshold NUM            Number of shares necessary to reconstruct the secret - Default: 3\n"
        "  -h, --help                     Print this help and exit\n"
        "  -V, --version                  Print the version and exit\n"
        "\n"
        "Note: Split number should be greater than threshold number.\n"
        "      If they are equal, a simple split is used instead of Shamir's secret sharing,\n"
        "      and all secret protection relies on the passphrase.\n"
        "      In other terms: if (split_NUM == threshold_NUM), then no passphrase or\n"
        "      printing passphrase is VERY UNSECURE.\n"
        "\n"
        "Photographs are left out of what is printed. A backup does not need your\n"
        "face, and paper is handled by whoever finds it.\n"),
            PGPID_NAME, PGPID_SPLIT_MAX);
}

/* Is there anything called SECRET* here already? Reusing a directory that
 * still holds fragments would mix two keys into one set of sheets. */
static bool workdir_is_unclean(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d)
        return false;
    bool found = false;
    for (struct dirent *e; !found && (e = readdir(d));)
        if (!strncmp(e->d_name, "SECRET", 6))
            found = true;
    closedir(d);
    return found;
}

static bool first_line_of(const char *path, char *out, size_t max)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        pgpid_error(_("Error: Cannot read %s."), path);
        return false;
    }
    if (!fgets(out, (int)max, f))
        *out = '\0';
    fclose(f);
    size_t n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        out[--n] = '\0';
    return true;
}

/**
 * The three uids worth printing, and no more.
 *
 * A QR code holds what it holds: past a few hundred bytes the modules get
 * small enough that a phone camera in ordinary light stops reading them, and
 * a backup nobody can scan is not a backup. So the paper carries the
 * identity, the name, and one address — enough to know whose key this is and
 * to write back — and drops the rest, which is re-addable from a keyring
 * anyway.
 *
 * The address is the primary uid when the primary is an address, which is
 * where this project puts it; failing that the most recent one that stands.
 */
static size_t choose_three(const struct pgpid_uid *uids, size_t n,
                           const char *keep[3])
{
    size_t nkeep = 0;
    const char *identity = NULL, *fn = NULL, *address = NULL;
    long newest = -1;

    for (size_t i = 0; i < n; i++) {
        if (!pgpid_uid_stands(uids[i].validity))
            continue;
        if (!identity && !strncmp(uids[i].text, "UID:urn:eid:", 12))
            identity = uids[i].text;
        if (!fn && !strncmp(uids[i].text, "FN:", 3))
            fn = uids[i].text;
    }
    /* The same rule as everywhere else, now that there is only one. */
    const struct pgpid_uid *picked = pgpid_preferred_uid(uids, n);
    address = picked ? picked->text : NULL;
    (void)newest;
    if (identity)
        keep[nkeep++] = identity;
    if (fn)
        keep[nkeep++] = fn;
    if (address)
        keep[nkeep++] = address;
    return nkeep;
}

/**
 * Rewrite an exported key, keeping only the uids named.
 *
 * Packet surgery rather than a round trip through a scratch keyring: a uid's
 * self-signature binds that uid and nothing else, so dropping the pair leaves
 * every remaining signature as valid as it was. Nothing is re-signed, which
 * means nothing needs the passphrase and nothing changes date.
 *
 * A signature belongs to whatever came before it. Anything that is not a uid,
 * an attribute or a signature — the key and its subkeys — is always kept, and
 * puts the stream back into "keeping" state.
 */
static bool keep_only(const char *path, const char *keep[3], size_t nkeep)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    static unsigned char buf[1048576];
    size_t len = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (!len)
        return false;

    static unsigned char out[1048576];
    size_t at = 0;
    const unsigned char *p = buf, *end = buf + len;
    struct pgpid_packet pkt;
    bool keeping = true;

    while (pgpid_packet_next(p, end, &pkt)) {
        const unsigned char *start = p;
        p = pkt.next;

        if (pkt.tag == TAG_USER_ID) {
            keeping = false;
            for (size_t i = 0; i < nkeep; i++)
                if (strlen(keep[i]) == pkt.len && !memcmp(keep[i], pkt.body, pkt.len))
                    keeping = true;
        } else if (pkt.tag == TAG_USER_ATTR) {
            keeping = false;   /* a face is not part of a backup */
        } else if (pkt.tag != TAG_SIGNATURE) {
            keeping = true;
        }

        if (!keeping)
            continue;
        size_t size = (size_t)(pkt.next - start);
        if (at + size > sizeof out)
            return false;
        memcpy(out + at, start, size);
        at += size;
    }

    FILE *w = fopen(path, "wb");
    if (!w)
        return false;
    size_t wrote = fwrite(out, 1, at, w);
    fclose(w);
    return wrote == at;
}

/** The uids of a certificate, one per line, for the sheet to be recognisable. */
static void uid_block(const char *fpr, char *out, size_t max)
{
    struct pgpid_uid uids[64];
    size_t n = pgpid_list_uids(fpr, false, uids, 64);
    size_t at = 0;
    *out = '\0';
    for (size_t i = 0; i < n && at + 2 < max; i++) {
        if (!pgpid_uid_stands(uids[i].validity))
            continue;
        int wrote = snprintf(out + at, max - at, "%s\n\n", uids[i].text);
        if (wrote < 0 || (size_t)wrote >= max - at)
            break;
        at += (size_t)wrote;
    }
}

/* The destinations CUPS knows, plus the choice of printing nowhere.
 *
 * `lpstat -e` rather than the `lpstat -p` the shell parses: it prints the
 * names alone, one per line, with no sentence around them for a translation
 * to move out from under the parser. The shell works around that with
 * `LANG=`; not needing the workaround is better than carrying it.
 *
 * No CUPS at all is not fatal here — the sheets can still be produced and
 * sent nowhere, which is entry zero.
 */
#define PRINTERS_MAX 32

static bool choose_printer(char *out, size_t max)
{
    char listing[4096] = "";
    const char *lpstat[] = { "lpstat", "-e", NULL };
    /* A byte count, not a status: this one returns what it read. */
    if (pgpid_capture(lpstat, listing, sizeof listing) <= 0)
        listing[0] = '\0';

    const char *items[PRINTERS_MAX];
    char names[PRINTERS_MAX][128];
    size_t n = 0;
    items[n++] = _("none - produce the sheets and send nothing");

    for (char *line = listing, *nl; *line && n < PRINTERS_MAX; line = nl) {
        nl = strchr(line, '\n');
        if (nl)
            *nl++ = '\0';
        else
            nl = line + strlen(line);
        if (!*line)
            continue;
        snprintf(names[n], sizeof names[n], "%s", line);
        items[n] = names[n];
        n++;
    }

    size_t picked = 0;
    if (!pgpid_choose(_("Which printer? Its number: "), items, n, &picked))
        return false;
    /* Entry zero is the one that is not a printer. */
    snprintf(out, max, "%s", picked ? items[picked] : "");
    return true;
}

int pgpid_action_secret_print(int argc, char **argv)
{
    char passphrase[512] = "";
    const char *printer = NULL, *given_workdir = NULL, *keyid = NULL;
    bool with_passphrase = false, passphrase_given = false, printer_given = false;
    int splits = 5, threshold = 3;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-p") || !strcmp(a, "--passphrase")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a passphrase."), a);
                return PGPID_USAGE;
            }
            snprintf(passphrase, sizeof passphrase, "%s", argv[i]);
            passphrase_given = true;
        } else if (!strcmp(a, "-P") || !strcmp(a, "--passfrom")
                   || !strcmp(a, "--pass-from")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a file."), a);
                return PGPID_USAGE;
            }
            if (!first_line_of(argv[i], passphrase, sizeof passphrase))
                return PGPID_FAIL;
            passphrase_given = true;
        } else if (!strcmp(a, "-t") || !strcmp(a, "--printer")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a printer, empty for none."), a);
                return PGPID_USAGE;
            }
            printer = argv[i];
            printer_given = true;
        } else if (!strcmp(a, "-w") || !strcmp(a, "--with-passphrase")) {
            with_passphrase = true;
        } else if (!strcmp(a, "-W") || !strcmp(a, "--workdir")
                   || !strcmp(a, "-D") || !strcmp(a, "--tmpdir")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a directory."), a);
                return PGPID_USAGE;
            }
            struct stat st;
            if (stat(argv[i], &st) || !S_ISDIR(st.st_mode)) {
                pgpid_error(_("Error: Nonexistent or unattainable directory (%s)."), argv[i]);
                return PGPID_USAGE;
            }
            given_workdir = argv[i];
        } else if (!strcmp(a, "-S") || !strcmp(a, "--split")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a number."), a);
                return PGPID_USAGE;
            }
            splits = atoi(argv[i]);
        } else if (!strcmp(a, "-T") || !strncmp(a, "--thres", 7)) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a number."), a);
                return PGPID_USAGE;
            }
            threshold = atoi(argv[i]);
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
            pgpid_try_help("secret_print");
            return PGPID_USAGE;
        } else if (!keyid) {
            keyid = a;
        }
    }

    if (!keyid) {
        /* Same question the shell puts through a radiolist. Printing the
         * wrong secret key onto paper is not a mistake one takes back. */
        static char picked[41];
        if (!pgpid_choose_secret_key(_("Which secret key? Its number: "),
                                     picked, sizeof picked)) {
            pgpid_error(_("Error: Which secret key should be printed?"));
            usage(stderr);
            return PGPID_USAGE;
        }
        keyid = picked;
    }
    if (!passphrase_given) {
        /* Nothing is echoed, and an empty answer is an answer: a key that
         * carries no passphrase is exported by giving none. */
        if (!pgpid_ask_secret(_("Passphrase of the secret key (empty if none): "),
                              passphrase, sizeof passphrase)) {
            pgpid_error(_("Error: The passphrase is needed to export the secret parts."));
            pgpid_error(_("Give --passphrase, or --passfrom to keep it off the process list."));
            return PGPID_USAGE;
        }
    }
    if (!printer_given) {
        static char chosen[128];
        if (!choose_printer(chosen, sizeof chosen)) {
            pgpid_error(_("Error: Where should this be printed? Name a printer, or pass"));
            pgpid_error(_("--printer '' to produce the sheets and send nothing."));
            return PGPID_USAGE;
        }
        printer = chosen;
    }
    if (splits < 3) {
        pgpid_error(_("Error: Splits number (%d) can't be lower than 3."), splits);
        return PGPID_USAGE;
    }
    /* Refused here rather than found out on paper: the QR header spells the
     * fragment's number as a single digit, so `scan` cannot read back more
     * than ten of them. */
    if (splits > PGPID_SPLIT_MAX) {
        pgpid_error(_("Error: Splits number (%d) can't be higher than %d: the QR header "
                    "spells it as one digit."), splits, PGPID_SPLIT_MAX);
        return PGPID_USAGE;
    }
    if (splits < threshold) {
        pgpid_error(_("Warning: Threshold can't be greater than the number of splits, "
                    "reducing threshold to %d."), splits);
        threshold = splits;
    }
    /* Same count as threshold: no sharing left to do, the pieces are simply
     * consecutive and each one leaks its part. */
    int qrversion = (splits == threshold) ? 4 : 5;

    char workdir[512];
    bool temporary = !given_workdir;
    if (given_workdir) {
        snprintf(workdir, sizeof workdir, "%s", given_workdir);
    } else {
        snprintf(workdir, sizeof workdir, "/tmp/pgpid-print.XXXXXX");
        if (!mkdtemp(workdir)) {
            pgpid_error(_("Error: Cannot make a working directory."));
            return PGPID_FAIL;
        }
    }
    if (workdir_is_unclean(workdir)) {
        pgpid_error(_("Error: Working directory is unclean (it holds SECRET*)."));
        pgpid_error(_("Suggestion: shred --remove '%s'/* && rmdir '%s'"), workdir, workdir);
        return PGPID_USAGE;
    }

    char listing[8192], fpr[41] = "";
    const char *find[] = { "--list-secret-keys", "--with-colons", keyid, NULL };
    if (pgpid_capture_engine(find, listing, sizeof listing) > 0)
        for (char *line = listing, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
            if (strncmp(line, "fpr:", 4))
                continue;
            unsigned field = 1;
            char *at = line;
            for (; *at && field < 10; at++)
                if (*at == ':')
                    field++;
            char *end = strchr(at, ':');
            if (end)
                *end = '\0';
            if (pgpid_is_fingerprint(at))
                snprintf(fpr, sizeof fpr, "%s", at);
            break;
        }
    if (!*fpr) {
        pgpid_error(_("Error: No secret for '%s' here."), keyid);
        return PGPID_FAIL;
    }

    /* Photographs are dropped here: a backup does not need a face, and each
     * kilobyte of picture is another fragment somebody has to keep. */
    char priv[600], answer[600];
    snprintf(priv, sizeof priv, "%s/s.gpg", workdir);
    snprintf(answer, sizeof answer, "%s\n", passphrase);
    const char *export[] = { "--batch", "--passphrase-fd", "0", "--pinentry-mode",
                             "loopback", "--export-options",
                             "export-minimal,export-clean,no-export-attributes",
                             "--export-secret-key", fpr, NULL };
    if (pgpid_run_engine_io(export, answer, priv)) {
        pgpid_error(_("Error: gpg would not export the secret key — right passphrase?"));
        return PGPID_FAIL;
    }

    /* Down to three uids: the identity, the name, one address. What is left
     * out is what a keyring can give back; what stays is what tells somebody
     * whose key they are holding. */
    {
        struct pgpid_uid all[256];
        size_t n = pgpid_list_uids(fpr, true, all, 256);
        const char *keep[3];
        size_t nkeep = choose_three(all, n, keep);
        if (!nkeep) {
            pgpid_error(_("Error: %s carries no uid worth printing."), fpr);
            return PGPID_FAIL;
        }
        if (!keep_only(priv, keep, nkeep)) {
            pgpid_error(_("Error: Cannot trim the export down to its three uids."));
            return PGPID_FAIL;
        }
        pgpid_error(_("Notice: Printing %zu uid(s) of %zu — the rest comes back from "
                    "a keyring."), nkeep, n);
    }

    char pattern[600];
    if (qrversion == 4) {
        char b64[600], prefix[600];
        snprintf(b64, sizeof b64, "%s/s.gpg.b64url", workdir);
        snprintf(prefix, sizeof prefix, "%s/SECRET-", workdir);
        const char *enc[] = { "basenc", "--base64url", "--wrap", "0", priv, NULL };
        if (pgpid_run_program(enc, NULL, b64)) {
            pgpid_error(_("Error: basenc would not encode the export."));
            return PGPID_FAIL;
        }
        char n[16];
        snprintf(n, sizeof n, "%d", splits);
        const char *sp[] = { "split", b64, "-d", "-n", n, prefix, NULL };
        if (pgpid_run_program(sp, NULL, NULL)) {
            pgpid_error(_("Error: split would not cut the export in %d."), splits);
            return PGPID_FAIL;
        }
    } else {
        char base[600], t[16], m[16];
        snprintf(base, sizeof base, "%s/SECRET", workdir);
        snprintf(t, sizeof t, "%d", threshold);
        snprintf(m, sizeof m, "%d", splits);
        const char *gf[] = { "gfsplit", "-n", t, "-m", m, priv, base, NULL };
        if (pgpid_run_program(gf, NULL, NULL)) {
            pgpid_error(_("Error: gfsplit would not share the secret out."));
            return PGPID_FAIL;
        }
        /* gfsplit writes SECRET.001…; each becomes SECRET-001, base64url'd. */
        DIR *d = opendir(workdir);
        if (!d)
            return PGPID_FAIL;
        for (struct dirent *e; (e = readdir(d));) {
            if (strncmp(e->d_name, "SECRET.", 7))
                continue;
            char from[800], to[800];
            snprintf(from, sizeof from, "%.500s/%.250s", workdir, e->d_name);
            snprintf(to, sizeof to, "%.500s/SECRET-%.240s", workdir, e->d_name + 7);
            const char *enc[] = { "basenc", "--base64url", "--wrap", "0", from, NULL };
            if (pgpid_run_program(enc, NULL, to)) {
                pgpid_error(_("Error: basenc would not encode %s."), e->d_name);
                closedir(d);
                return PGPID_FAIL;
            }
        }
        closedir(d);
    }
    (void)pattern;

    char uids[4096];
    uid_block(fpr, uids, sizeof uids);
    char host[128] = "";
    gethostname(host, sizeof host - 1);
    char today[16];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(today, sizeof today, "%Y-%m-%d", &tm);

    if (*printer)
        pgpid_error(_("Notice: Printing the secret split into %d fragments on %s…"),
                    splits, printer);
    else
        pgpid_error(_("Notice: Producing %d fragments in %s, sending nothing."),
                    splits, workdir);

    /* The fragments in order: gfsplit numbers them, and reading the directory
     * gives them back in whatever order the filesystem feels like.
     *
     * Counted before they are collected. --split takes any number, and with
     * --workdir the directory belongs to the caller besides — a fragment left
     * out of the sheet is a secret nobody will put back together. */
    size_t nfrag = 0;
    DIR *d = opendir(workdir);
    if (!d)
        return PGPID_FAIL;
    for (struct dirent *e; (e = readdir(d));)
        if (!strncmp(e->d_name, "SECRET-", 7))
            nfrag++;
    if (!nfrag) {
        closedir(d);
        pgpid_error(_("Error: No fragment was produced."));
        return PGPID_FAIL;
    }
    char (*names)[64] = calloc(nfrag, sizeof *names);
    if (!names) {
        closedir(d);
        pgpid_error(_("Error: Out of memory."));
        return PGPID_FAIL;
    }
    rewinddir(d);
    size_t got = 0;
    for (struct dirent *e; (e = readdir(d)) && got < nfrag;)
        if (!strncmp(e->d_name, "SECRET-", 7))
            snprintf(names[got++], sizeof names[0], "%.63s", e->d_name);
    closedir(d);
    nfrag = got;
    if (nfrag > PGPID_SPLIT_MAX) {
        pgpid_error(_("Error: %zu fragments in %s, and a QR header can only number "
                    "%d."), nfrag, workdir, PGPID_SPLIT_MAX);
        free(names);
        return PGPID_FAIL;
    }
    for (size_t i = 1; i < nfrag; i++)
        for (size_t k = i; k && strcmp(names[k - 1], names[k]) > 0; k--) {
            char t[64];
            snprintf(t, sizeof t, "%s", names[k - 1]);
            snprintf(names[k - 1], sizeof names[0], "%.63s", names[k]);
            snprintf(names[k], sizeof names[0], "%.63s", t);
        }

    for (size_t i = 0; i < nfrag; i++) {
        char frag[600], png[620], pdf[620], header[16];
        snprintf(frag, sizeof frag, "%.500s/%.63s", workdir, names[i]);
        snprintf(png, sizeof png, "%.599s.png", frag);
        snprintf(pdf, sizeof pdf, "%.599s.pdf", frag);

        /* The header is what `scan` reads first: a '~', the version, how many
         * fragments are needed less one, and which fragment this is. Version 5
         * adds the three digits gfsplit needs to put them back together. */
        if (qrversion == 5)
            snprintf(header, sizeof header, "~%d%d%zu%s", qrversion, threshold - 1, i,
                     names[i] + 7);
        else
            snprintf(header, sizeof header, "~%d%d%zu", qrversion, threshold - 1, i);

        FILE *in = fopen(frag, "r");
        if (!in) {
            pgpid_error(_("Error: Cannot read the fragment %s."), frag);
            free(names);
            return PGPID_FAIL;
        }
        static char payload[262144];
        snprintf(payload, sizeof payload, "%s", header);
        size_t at = strlen(payload);
        at += fread(payload + at, 1, sizeof payload - at - 1, in);
        payload[at] = '\0';
        fclose(in);

        const char *qr[] = { "qrencode", "--level", qrversion == 5 ? "L" : "M",
                             "--dpi=50", "--output", png, NULL };
        if (pgpid_run_program(qr, payload, NULL)) {
            pgpid_error(_("Error: qrencode would not draw fragment %zu."), i + 1);
            free(names);
            return PGPID_FAIL;
        }

        char sheet[8192];
        snprintf(sheet, sizeof sheet,
                 "\\pagenumbering{gobble}\n\n"
                 "*%s - %s*\n\n"
                 "*" PGPID_NAME " print_secret " PGPID_VERSION
                 " - QR version: %d*\n\n"
                 "## PGPID SECRET (/%d) - FRAGMENT %zu/%d\n\n"
                 "```\n\n%s```\n"
                 ">     0x %.4s %.4s %.4s %.4s %.4s %.4s %.4s %.4s %.4s %.4s\n\n"
                 "![qrcode %zu](%s)\n\n%s%s\n",
                 host, today, qrversion, threshold, i + 1, splits, uids,
                 fpr, fpr + 4, fpr + 8, fpr + 12, fpr + 16, fpr + 20, fpr + 24,
                 fpr + 28, fpr + 32, fpr + 36,
                 i + 1, png,
                 with_passphrase ? "Passphrase: " : "",
                 with_passphrase ? passphrase : "");

        char rough[640];
        snprintf(rough, sizeof rough, "%.599s.rough.pdf", frag);
        const char *doc[] = { "pandoc", "--from", "markdown", "--to", "pdf",
                              "-fmarkdown-implicit_figures", NULL };
        if (pgpid_run_program(doc, sheet, rough)) {
            pgpid_error(_("Error: pandoc would not lay fragment %zu out."), i + 1);
            free(names);
            return PGPID_FAIL;
        }
        const char *crop[] = { "pdfcrop", "--quiet", "--margins", "4", rough, pdf, NULL };
        if (pgpid_run_program(crop, NULL, NULL)) {
            pgpid_error(_("Error: pdfcrop would not trim fragment %zu."), i + 1);
            free(names);
            return PGPID_FAIL;
        }
        unlink(rough);

        if (*printer) {
            const char *print[] = { "lpr", "-#", "1", "-P", printer, pdf, NULL };
            if (pgpid_run_program(print, NULL, NULL)) {
                pgpid_error(_("Error: lpr would not print fragment %zu."), i + 1);
                free(names);
            return PGPID_FAIL;
            }
        }
    }

    if (temporary && *printer) {
        /* Sent to a printer: nothing here is worth the risk of being left. */
        for (size_t i = 0; i < nfrag; i++) {
            char frag[600], png[620], pdf[620];
            snprintf(frag, sizeof frag, "%.500s/%.63s", workdir, names[i]);
            snprintf(png, sizeof png, "%.599s.png", frag);
            snprintf(pdf, sizeof pdf, "%.599s.pdf", frag);
            unlink(frag);
            unlink(png);
            unlink(pdf);
        }
        unlink(priv);
        pgpid_error(_("Notice: The working copies are removed. Shred %s if anything "
                    "is left."), workdir);
    } else {
        /* shred, not bl-security: the suggestion has to name something the
         * person running this actually has, and pgpid does not pull the shell
         * libraries in. coreutils is always there. */
        pgpid_error(_("Notice: The fragments are in %s. Shred them once they are on "
                    "paper: find '%s' -type f -exec shred --remove {} +"), workdir, workdir);
    }
    free(names);
    return PGPID_OK;
}
