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
    fprintf(out,
        "Usage: " PGPID_MIP_NAME " print_secret [OPTIONS]... KEY\n"
        "\n"
        "Print an OpenPGP secret key as QR codes, split so that no single sheet\n"
        "carries it. By default five fragments of which any three rebuild it.\n"
        "\n"
        "OPTIONS:\n"
        "  -p, --passphrase PASSPHRASE    The passphrase protecting the secret parts\n"
        "  -P, --passfrom FILE            Read it from the first line of FILE instead\n"
        "  -t, --printer PRINTER          Where to print. Empty to produce the sheets\n"
        "                                 and send nothing — they stay in the workdir\n"
        "  -w, --with-passphrase          Print the passphrase beside the QR codes\n"
        "                                 Easier to use, and no longer a split secret\n"
        "  -W, --workdir DIRECTORY        Work here instead of a temporary directory\n"
        "                                 Its contents must be shredded afterwards\n"
        "  -S, --split NUM                Fragments to produce - Default: 5\n"
        "  -T, --threshold NUM            Fragments needed to rebuild - Default: 3\n"
        "  -h, --help                     Print this help and exit\n"
        "  -V, --version                  Print the version and exit\n"
        "\n"
        "With --split equal to --threshold there is no secret sharing: the\n"
        "fragments are consecutive pieces and each one leaks its part. Everything\n"
        "then rests on the passphrase, and printing it alongside leaves nothing.\n"
        "\n"
        "Photographs are left out of what is printed. A backup does not need your\n"
        "face, and paper is handled by whoever finds it.\n");
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
        pgpid_error("Error: Cannot read %s.", path);
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

int pgpid_action_print_secret(int argc, char **argv)
{
    char passphrase[512] = "";
    const char *printer = NULL, *given_workdir = NULL, *keyid = NULL;
    bool with_passphrase = false, passphrase_given = false, printer_given = false;
    int splits = 5, threshold = 3;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-p") || !strcmp(a, "--passphrase")) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants a passphrase.", a);
                return PGPID_USAGE;
            }
            snprintf(passphrase, sizeof passphrase, "%s", argv[i]);
            passphrase_given = true;
        } else if (!strcmp(a, "-P") || !strcmp(a, "--passfrom")
                   || !strcmp(a, "--pass-from")) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants a file.", a);
                return PGPID_USAGE;
            }
            if (!first_line_of(argv[i], passphrase, sizeof passphrase))
                return PGPID_FAIL;
            passphrase_given = true;
        } else if (!strcmp(a, "-t") || !strcmp(a, "--printer")) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants a printer, empty for none.", a);
                return PGPID_USAGE;
            }
            printer = argv[i];
            printer_given = true;
        } else if (!strcmp(a, "-w") || !strcmp(a, "--with-passphrase")) {
            with_passphrase = true;
        } else if (!strcmp(a, "-W") || !strcmp(a, "--workdir")
                   || !strcmp(a, "-D") || !strcmp(a, "--tmpdir")) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants a directory.", a);
                return PGPID_USAGE;
            }
            struct stat st;
            if (stat(argv[i], &st) || !S_ISDIR(st.st_mode)) {
                pgpid_error("Error: Nonexistent or unattainable directory (%s).", argv[i]);
                return PGPID_USAGE;
            }
            given_workdir = argv[i];
        } else if (!strcmp(a, "-S") || !strcmp(a, "--split")) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants a number.", a);
                return PGPID_USAGE;
            }
            splits = atoi(argv[i]);
        } else if (!strcmp(a, "-T") || !strncmp(a, "--thres", 7)) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants a number.", a);
                return PGPID_USAGE;
            }
            threshold = atoi(argv[i]);
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_MIP_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            continue;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error("Error: Unrecognized option '%s'.", a);
            pgpid_error("Try '" PGPID_MIP_NAME " print_secret --help' for more information.");
            return PGPID_USAGE;
        } else if (!keyid) {
            keyid = a;
        }
    }

    if (!keyid) {
        pgpid_error("Error: Which secret key? This machine may hold several.");
        usage(stderr);
        return PGPID_USAGE;
    }
    if (!passphrase_given) {
        pgpid_error("Error: The passphrase is needed to export the secret parts.");
        pgpid_error("Give --passphrase, or --passfrom to keep it off the process list.");
        return PGPID_USAGE;
    }
    if (!printer_given) {
        pgpid_error("Error: Where should this be printed? Name a printer, or pass");
        pgpid_error("--printer '' to produce the sheets and send nothing.");
        return PGPID_USAGE;
    }
    if (splits < 3) {
        pgpid_error("Error: Splits number (%d) can't be lower than 3.", splits);
        return PGPID_USAGE;
    }
    if (splits < threshold) {
        pgpid_error("Warning: Threshold can't be greater than the number of splits, "
                    "reducing threshold to %d.", splits);
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
        snprintf(workdir, sizeof workdir, "/tmp/pgpid-mip-print.XXXXXX");
        if (!mkdtemp(workdir)) {
            pgpid_error("Error: Cannot make a working directory.");
            return PGPID_FAIL;
        }
    }
    if (workdir_is_unclean(workdir)) {
        pgpid_error("Error: Working directory is unclean (it holds SECRET*).");
        pgpid_error("Suggestion: bl-security shred_path --remove '%s'", workdir);
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
        pgpid_error("Error: No secret for '%s' here.", keyid);
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
        pgpid_error("Error: gpg would not export the secret key — right passphrase?");
        return PGPID_FAIL;
    }

    char pattern[600];
    if (qrversion == 4) {
        char b64[600], prefix[600];
        snprintf(b64, sizeof b64, "%s/s.gpg.b64url", workdir);
        snprintf(prefix, sizeof prefix, "%s/SECRET-", workdir);
        const char *enc[] = { "basenc", "--base64url", "--wrap", "0", priv, NULL };
        if (pgpid_run_program(enc, NULL, b64)) {
            pgpid_error("Error: basenc would not encode the export.");
            return PGPID_FAIL;
        }
        char n[16];
        snprintf(n, sizeof n, "%d", splits);
        const char *sp[] = { "split", b64, "-d", "-n", n, prefix, NULL };
        if (pgpid_run_program(sp, NULL, NULL)) {
            pgpid_error("Error: split would not cut the export in %d.", splits);
            return PGPID_FAIL;
        }
    } else {
        char base[600], t[16], m[16];
        snprintf(base, sizeof base, "%s/SECRET", workdir);
        snprintf(t, sizeof t, "%d", threshold);
        snprintf(m, sizeof m, "%d", splits);
        const char *gf[] = { "gfsplit", "-n", t, "-m", m, priv, base, NULL };
        if (pgpid_run_program(gf, NULL, NULL)) {
            pgpid_error("Error: gfsplit would not share the secret out.");
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
                pgpid_error("Error: basenc would not encode %s.", e->d_name);
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
        pgpid_error("Notice: Printing the secret split into %d fragments on %s…",
                    splits, printer);
    else
        pgpid_error("Notice: Producing %d fragments in %s, sending nothing.",
                    splits, workdir);

    /* The fragments in order: gfsplit numbers them, and reading the directory
     * gives them back in whatever order the filesystem feels like. */
    char names[64][64];
    size_t nfrag = 0;
    DIR *d = opendir(workdir);
    if (!d)
        return PGPID_FAIL;
    for (struct dirent *e; (e = readdir(d)) && nfrag < 64;)
        if (!strncmp(e->d_name, "SECRET-", 7))
            snprintf(names[nfrag++], sizeof names[0], "%.63s", e->d_name);
    closedir(d);
    for (size_t i = 1; i < nfrag; i++)
        for (size_t k = i; k && strcmp(names[k - 1], names[k]) > 0; k--) {
            char t[64];
            snprintf(t, sizeof t, "%s", names[k - 1]);
            snprintf(names[k - 1], sizeof names[0], "%.63s", names[k]);
            snprintf(names[k], sizeof names[0], "%.63s", t);
        }
    if (!nfrag) {
        pgpid_error("Error: No fragment was produced.");
        return PGPID_FAIL;
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
            pgpid_error("Error: Cannot read the fragment %s.", frag);
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
            pgpid_error("Error: qrencode would not draw fragment %zu.", i + 1);
            return PGPID_FAIL;
        }

        char sheet[8192];
        snprintf(sheet, sizeof sheet,
                 "\\pagenumbering{gobble}\n\n"
                 "*%s - %s*\n\n"
                 "*" PGPID_MIP_NAME " print_secret " PGPID_MIP_VERSION
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
            pgpid_error("Error: pandoc would not lay fragment %zu out.", i + 1);
            return PGPID_FAIL;
        }
        const char *crop[] = { "pdfcrop", "--quiet", "--margins", "4", rough, pdf, NULL };
        if (pgpid_run_program(crop, NULL, NULL)) {
            pgpid_error("Error: pdfcrop would not trim fragment %zu.", i + 1);
            return PGPID_FAIL;
        }
        unlink(rough);

        if (*printer) {
            const char *print[] = { "lpr", "-#", "1", "-P", printer, pdf, NULL };
            if (pgpid_run_program(print, NULL, NULL)) {
                pgpid_error("Error: lpr would not print fragment %zu.", i + 1);
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
        pgpid_error("Notice: The working copies are removed. Shred %s if anything "
                    "is left.", workdir);
    } else {
        pgpid_error("Notice: The fragments are in %s. Shred it once they are on "
                    "paper: bl-security shred_path --remove '%s'", workdir, workdir);
    }
    return PGPID_OK;
}
