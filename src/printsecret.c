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
 * rsvg-convert — and calling them in order is the whole job. Nothing here is faster
 * or more portable in C than it was in the shell; what it gains is one place
 * where the fragment header is written, and the same reader on both sides.
 */
#include "pgpid.h"

#include <stdarg.h>
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
        "Export and print PGP secrets on multiple QRcode using Shamir's secret\n"
        "sharing, split so that no single sheet carries the key.\n"
        "\n"
        "Missing input will be asked interactively, unless --batch.\n"
        "\n"
        "OPTIONS:\n"
        "  -p, --passphrase PASSPHRASE    Passphrase to access secret parts of PGP key\n"
        "  -P, --passfrom FILE            Get passphrase from first line of FILE (eg: fifo, tmpfs, /dev/stdin ...)\n"
        "  -t, --printer PRINTER          Name of printer to use. Empty to produce the sheets and send nothing\n"
        "  -w, --with-passphrase          Also print passphrase beside QR codes (INCREASE UX, DECREASE SECURITY)\n"
        "  -W, --workdir DIRECTORY        Use given working directory instead of a temporary directory (don't forget to shred its content)\n"
        "  -S, --split NUM                Number of shares to be generated, 3 to %d - Default: 5\n"
        "  -T, --threshold NUM            Number of shares necessary to reconstruct the secret, 2 or more - Default: 3\n"
        "  -h, --help                     Print this help and exit\n"
        "  -V, --version                  Print the version and exit\n"
        "\n"
        "Note: Split number should be greater than threshold number.\n"
        "      If they are equal, a simple split is used instead of Shamir's secret sharing,\n"
        "      and all secret protection relies on the passphrase.\n"
        "      In other terms: if (split_NUM == threshold_NUM), then no passphrase or\n"
        "      printing passphrase is VERY UNSECURE.\n"
        "      A share is the size of the whole secret, so a secret above %d bytes\n"
        "      only goes on paper cut, which is the equal case. It is refused with\n"
        "      the numbers rather than printed too dense to scan.\n"
        "\n"
        "The codes are QR version 6 (draft-foopgp-secret-sheets), two to an A4 page:\n"
        "cut each page in two, and keep the halves in different places. Versions 4\n"
        "and 5 are no longer written, and secret_scan still reads them.\n"
        "\n"
        "Photographs are left out of what is printed. A backup does not need your\n"
        "face, and paper is handled by whoever finds it.\n"),
            PGPID_NAME, PGPID_SPLIT_MAX, PGPID_SHEET_MAX);
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


/* Room for a whole export as base45: three characters for every two octets. */
#define RAW_MAX (1 << 20)
static char text[(RAW_MAX / 2 + 1) * 3 + 4];

static bool write_text(const char *path, const char *s, size_t n)
{
    FILE *out = fopen(path, "wb");
    if (!out)
        return false;
    size_t wrote = fwrite(s, 1, n, out);
    return fclose(out) == 0 && wrote == n;
}

/** Whole file in, base45 out, no line breaks. Answers false on any trouble. */
static bool encode_file(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb");
    if (!in)
        return false;
    static unsigned char raw[RAW_MAX];
    size_t len = fread(raw, 1, sizeof raw, in);
    bool whole = feof(in) && !ferror(in);
    fclose(in);
    if (!len || !whole)
        return false;

    pgpid_base45(raw, len, text);
    return write_text(to, text, strlen(text));
}

/**
 * The export, cut into SPLITS pieces of equal size, each encoded on its own.
 *
 * `split -n` cuts by bytes and leaves the remainder on the last piece, which
 * is what this does: the pieces are reassembled back to back, so where the
 * cuts fall does not matter as long as the order does. The names are the ones
 * split -d would have given, since the rest of this file looks for them.
 *
 * Version 4 cut the base64url text. base45 cannot be cut that way: its
 * characters go by threes, and a cut between two of them leaves a piece that
 * decodes to nothing. So the octets are cut, and each piece encoded.
 */
static bool encode_and_cut(const char *priv, const char *workdir, int splits)
{
    FILE *in = fopen(priv, "rb");
    if (!in)
        return false;
    static unsigned char raw[RAW_MAX];
    size_t len = fread(raw, 1, sizeof raw, in);
    bool whole = feof(in) && !ferror(in);
    fclose(in);
    if (!len || !whole || splits < 1)
        return false;

    size_t each = len / (size_t)splits;
    if (!each)
        return false;
    for (int i = 0; i < splits; i++) {
        char path[700];
        snprintf(path, sizeof path, "%.600s/SECRET-%02d", workdir, i);
        size_t from = (size_t)i * each;
        size_t n = (i == splits - 1) ? len - from : each;
        pgpid_base45(raw + from, n, text);
        if (!write_text(path, text, strlen(text)))
            return false;
    }
    return true;
}


/** XML-escaped copy of TEXT, for dropping into an SVG. */
static void xml_escape(const char *in, char *out, size_t max)
{
    size_t o = 0;
    for (const char *p = in; *p && o + 8 < max; p++) {
        const char *rep = *p == '&' ? "&amp;" : *p == '<' ? "&lt;"
                        : *p == '>' ? "&gt;" : NULL;
        if (rep) {
            size_t n = strlen(rep);
            memcpy(out + o, rep, n);
            o += n;
        } else {
            out[o++] = *p;
        }
    }
    out[o] = '\0';
}

/* What every half of every page shows besides its own code. */
struct sheet {
    const char *uids[3];        /* the identity, the address, the name */
    size_t nuids;
    int threshold, splits;
    const char *fpr, *host, *today, *passphrase;
};

/* printf onto the end of a buffer, and false once it is full. */
static bool append(char *buf, size_t max, size_t *at, const char *fmt, ...)
{
    if (*at >= max)
        return false;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *at, max - *at, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= max - *at)
        return false;
    *at += (size_t)n;
    return true;
}

/**
 * WHAT in lines of at most BUDGET bytes, never inside a UTF-8 character: cut
 * at a space when there is one in the second half of the budget, else after a
 * '-', '.' or '_', else anywhere. With EXACT, nothing is dropped and the cut
 * is anywhere -- for a passphrase, where a space lost at the end of a line
 * would be a passphrase lost. Answers how many lines were written.
 */
static size_t wrap(const char *what, size_t budget, bool exact, char lines[][128],
                   size_t max)
{
    size_t n = 0;
    while (*what && n < max) {
        size_t len = strlen(what), take = len, skip = 0;
        if (len > budget) {
            take = budget;
            for (size_t k = budget; !exact && k > budget / 2; k--)
                if (what[k] == ' ') {
                    take = k;
                    skip = 1;
                    break;
                }
            if (!skip && !exact)
                for (size_t k = budget - 1; k > budget / 2; k--)
                    if (strchr("-._", what[k])) {
                        take = k + 1;
                        break;
                    }
            /* Back to the start of a character: a continuation byte is
             * 10xxxxxx. */
            while (take > 1 && ((unsigned char)what[take] & 0xC0) == 0x80)
                take--;
        }
        if (take > 127)
            take = 127;
        memcpy(lines[n], what, take);
        lines[n++][take] = '\0';
        what += take + skip;
    }
    return n;
}

/**
 * The code in MATRIX (qrencode's ASCII, two characters a module, no margin)
 * as one path of squares, SIZE tenths of a millimetre wide with its quiet
 * zone, at X, Y.
 *
 * One path, so that squares side by side are one shape and no renderer draws
 * a seam between them; and a viewBox counted in modules, so that no
 * coordinate is ever a fraction -- see the note on the locale in
 * append_half.
 */
static bool append_code(char *buf, size_t max, size_t *at, const char *matrix,
                        int x, int y, int size)
{
    FILE *f = fopen(matrix, "r");
    if (!f)
        return false;
    static char line[4096];
    int row = 0, modules = -1;
    bool ok = true;
    long start = (long)*at;
    ok = append(buf, max, at, "<path d='");
    while (ok && fgets(line, sizeof line, f)) {
        size_t len = strcspn(line, "\r\n");
        if (!len)
            continue;
        if (modules < 0)
            modules = (int)(len / 2);
        if ((int)(len / 2) != modules) {
            ok = false;
            break;
        }
        for (int m = 0; ok && m < modules;) {
            if (line[2 * m] != '#') {
                m++;
                continue;
            }
            int from = m;
            while (m < modules && line[2 * m] == '#')
                m++;
            ok = append(buf, max, at, "M%d %dh%dv1h-%dz", from, row, m - from, m - from);
        }
        row++;
    }
    fclose(f);
    if (!ok || modules <= 0 || row != modules)
        return false;
    /* The path went in first so its size was known; the frame goes round it. */
    static char path[1 << 20];
    size_t plen = *at - (size_t)start;
    if (plen >= sizeof path)
        return false;
    memcpy(path, buf + start, plen);
    *at = (size_t)start;
    return append(buf, max, at,
                  "<svg x='%d' y='%d' width='%d' height='%d' viewBox='-4 -4 %d %d'>"
                  "%.*s' fill='black'/></svg>\n",
                  x, y, size, size, modules + 8, modules + 8, (int)plen, path);
}

/**
 * One fragment on a half page, Y0 tenths of a millimetre down.
 *
 * The uids across the top, as many as the secret carries and no more: they
 * are what tells a finder whose key this is. Below, the code on the right,
 * as large as the half allows, and everything else in a column on its left,
 * cut into lines the column can hold -- the title, what printed it, where and
 * when, the fingerprint last, and the passphrase after it when asked for.
 *
 * Integers, not %f: snprintf writes the *locale's* decimal separator, so
 * under a French locale a coordinate came out "78,0" and librsvg read it as
 * something else entirely -- the QR landed at the top of the page, over the
 * text. Nothing generated for a machine should pass through the locale, on
 * the way out any more than on the way in. The page is counted in tenths of
 * a millimetre, and the code in modules.
 */
static bool append_half(char *buf, size_t max, size_t *at, int y0,
                        const struct sheet *s, size_t number, const char *matrix)
{
    const char *mono = "font-family='monospace' font-size='28'";
    const char *italic = "font-family='serif' font-style='italic' font-size='30'";
    const char *bold = "font-family='serif' font-weight='bold' font-size='50'";
    char lines[48][128], safe[512];
    int y = y0 + 90;
    bool ok = true;

    for (size_t u = 0; ok && u < s->nuids; u++) {
        size_t n = wrap(s->uids[u], 104, false, lines, 4);
        for (size_t k = 0; ok && k < n; k++, y += 38) {
            xml_escape(lines[k], safe, sizeof safe);
            ok = append(buf, max, at, "<text x='140' y='%d' %s xml:space='preserve'>%s</text>\n",
                        y, mono, safe);
        }
    }
    /* The code ends 13.8 cm down the half and 1 cm from the right edge --
     * past that a printer's margin may bite -- and is 12 cm wide, less if
     * long uids took more lines than three. */
    int size = y0 + 1380 - (y - 38 + 14);
    if (size > 1200)
        size = 1200;
    int top = y0 + 1380 - size, x = 2100 - 100 - size;
    ok = ok && append_code(buf, max, at, matrix, x, top, size);

    y += 112;
    ok = ok && append(buf, max, at,
                      "<text x='140' y='%d' %s>PGPID SECRET (/%d)</text>\n"
                      "<text x='140' y='%d' %s>FRAGMENT %zu/%d</text>\n",
                      y, bold, s->threshold, y + 60, bold, number, s->splits);
    y += 170;

    /* The column stops short of the code's quiet zone. */
    const char *column[] = { PGPID_NAME " secret_print", PGPID_VERSION, "QR version: 6",
                             s->host, s->today };
    for (size_t c = 0; ok && c < sizeof column / sizeof *column; c++) {
        size_t n = wrap(column[c], 30, false, lines, 4);
        for (size_t k = 0; ok && k < n; k++, y += 46) {
            xml_escape(lines[k], safe, sizeof safe);
            ok = append(buf, max, at, "<text x='140' y='%d' %s xml:space='preserve'>%s</text>\n",
                        y, italic, safe);
        }
    }
    y += 54;
    ok = ok && append(buf, max, at,
                      "<text x='140' y='%d' %s xml:space='preserve'>0x %.4s %.4s %.4s %.4s %.4s</text>\n"
                      "<text x='140' y='%d' %s xml:space='preserve'>   %.4s %.4s %.4s %.4s %.4s</text>\n",
                      y, mono, s->fpr, s->fpr + 4, s->fpr + 8, s->fpr + 12, s->fpr + 16,
                      y + 38, mono, s->fpr + 20, s->fpr + 24, s->fpr + 28, s->fpr + 32,
                      s->fpr + 36);
    y += 38;
    /* Only when it was asked for: --with-passphrase puts the one thing on the
     * sheet that makes a single sheet worth stealing. */
    if (ok && s->passphrase && *s->passphrase) {
        y += 80;
        ok = append(buf, max, at, "<text x='140' y='%d' %s>Passphrase:</text>\n", y, italic);
        /* Its spaces drawn, as an open box: one at the end of a line would
         * otherwise not be seen, and a passphrase is retyped from this. */
        static char visible[1600];
        size_t v = 0;
        for (const char *c = s->passphrase; *c && v + 4 < sizeof visible; c++) {
            if (*c == ' ') {
                memcpy(visible + v, "\xe2\x90\xa3", 3);
                v += 3;
            } else {
                visible[v++] = *c;
            }
        }
        visible[v] = '\0';
        size_t n = wrap(visible, 30, true, lines, 12);
        for (size_t k = 0; ok && k < n; k++) {
            y += 46;
            xml_escape(lines[k], safe, sizeof safe);
            ok = append(buf, max, at, "<text x='140' y='%d' %s xml:space='preserve'>%s</text>\n",
                        y, mono, safe);
        }
    }
    return ok;
}

/**
 * One A4 page, holding COUNT fragments, one or two, rendered to PDF.
 *
 * Two to a page: a set of five takes three sheets of paper instead of five,
 * and a line across the middle says where to cut, and that the halves are
 * not to be kept together -- until the scissors, the page holds two shares.
 *
 * Was markdown through pandoc and then pdfcrop: two programs, and between
 * them a TeX distribution -- 275 MB of dependency for a page with a few
 * lines and a picture on it. rsvg-convert was already here for the business
 * card, and it writes PDF.
 */
static bool page_to_pdf(const char *pdf, const struct sheet *s, size_t first,
                        const char *const matrices[2], size_t count)
{
    static char svg[4 << 20];
    size_t at = 0;
    bool ok = append(svg, sizeof svg, &at,
                     "<svg xmlns='http://www.w3.org/2000/svg' width='210mm' height='297mm'"
                     " viewBox='0 0 2100 2970'>\n"
                     "<rect width='2100' height='2970' fill='white'/>\n");
    for (size_t h = 0; ok && h < count; h++)
        ok = append_half(svg, sizeof svg, &at, (int)h * 1485, s, first + h + 1, matrices[h]);
    if (ok && count == 2)
        ok = append(svg, sizeof svg, &at,
                    "<line x1='60' y1='1485' x2='2040' y2='1485' stroke='black'"
                    " stroke-width='3' stroke-dasharray='20,15'/>\n"
                    "<rect x='620' y='1463' width='860' height='44' fill='white'/>\n"
                    "<text x='1050' y='1494' text-anchor='middle' font-family='serif'"
                    " font-style='italic' font-size='26'>"
                    "cut here, and keep each half in a different place</text>\n");
    ok = ok && append(svg, sizeof svg, &at, "</svg>\n");
    if (!ok)
        return false;

    char svgpath[640];
    snprintf(svgpath, sizeof svgpath, "%.599s.svg", pdf);
    /* From here on the file exists and holds the fragments' codes, so every
     * way out of this function goes past the shredding. A half-written sheet
     * is still half a secret. */
    ok = write_text(svgpath, svg, at);
    if (ok) {
        const char *render[] = { "rsvg-convert", "--format", "pdf",
                                 "--output", pdf, svgpath, NULL };
        ok = pgpid_run_program(render, NULL, NULL) == 0;
    }
    pgpid_shred_path(svgpath);
    return ok;
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
     * fragment's number as a single hexadecimal digit, so `scan` cannot read
     * back more than sixteen of them. */
    if (splits > PGPID_SPLIT_MAX) {
        pgpid_error(_("Error: Splits number (%d) can't be higher than %d: the QR header "
                    "spells it as one hexadecimal digit."), splits, PGPID_SPLIT_MAX);
        return PGPID_USAGE;
    }
    /* A threshold of one is a polynomial of degree nought: every share is
     * the secret itself, printed in full on every sheet. */
    if (threshold < 2) {
        pgpid_error(_("Error: Threshold number (%d) can't be lower than 2."), threshold);
        return PGPID_USAGE;
    }
    if (splits < threshold) {
        pgpid_error(_("Warning: Threshold can't be greater than the number of splits, "
                    "reducing threshold to %d."), splits);
        threshold = splits;
    }
    /* Same count as threshold: no sharing left to do, the pieces are simply
     * consecutive and each one leaks its part. Version 6 is either, and says
     * which with its header. */
    bool cut = splits == threshold;
    size_t sheet_max = PGPID_SHEET_MAX;

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
     * whose key they are holding -- in the code, and across the top of the
     * sheet, identity first, then the address, then the name. */
    struct sheet sheet = { .nuids = 0 };
    static char printed[3][512];
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
        const char *order[] = { "UID:urn:eid:", "", "FN:" };
        for (size_t o = 0; o < 3; o++)
            for (size_t k = 0; k < nkeep; k++) {
                bool identity = !strncmp(keep[k], "UID:urn:eid:", 12);
                bool name = !strncmp(keep[k], "FN:", 3);
                bool wanted = *order[o] ? !strncmp(keep[k], order[o], strlen(order[o]))
                                        : !identity && !name;
                if (wanted) {
                    snprintf(printed[sheet.nuids], sizeof printed[0], "%s", keep[k]);
                    sheet.uids[sheet.nuids] = printed[sheet.nuids];
                    sheet.nuids++;
                    break;
                }
            }
    }

    /* What one sheet would have to carry, now that the export is final: the
     * whole secret if it is shared out, the secret over the number of pieces
     * if it is cut. Checked here, before a single fragment is written, so a
     * refusal leaves nothing behind to shred. */
    struct stat st;
    if (stat(priv, &st) || st.st_size <= 0) {
        pgpid_error(_("Error: The export could not be measured."));
        return PGPID_FAIL;
    }
    size_t exported = (size_t)st.st_size;
    size_t per_sheet = !cut ? exported
                            : (exported + (size_t)splits - 1) / (size_t)splits;
    if (per_sheet > sheet_max) {
        /* How few pieces would do, and what to say about it. */
        int needed = (int)((exported + sheet_max - 1) / sheet_max);
        if (needed < 3)
            needed = 3;
        pgpid_error(_("Error: One sheet would carry %zu bytes of the secret, and %d is "
                    "what one can still be read back from."), per_sheet, (int)sheet_max);
        if (!cut)
            pgpid_error(_("Notice: Every share of a shared secret is the size of the "
                        "secret, so more shares make none of them smaller. Cutting does, "
                        "and a cut is asked for by making --threshold equal to --split."));
        if (needed > PGPID_SPLIT_MAX)
            pgpid_error(_("Notice: Even %d pieces would not be enough, and %d is as many "
                        "as a fragment's header can number."), needed, PGPID_SPLIT_MAX);
        else if (needed <= threshold)
            pgpid_error(_("Suggestion: --threshold %d, or --split %d. Every sheet is "
                        "then needed."), splits, threshold);
        else if (needed <= splits)
            pgpid_error(_("Suggestion: --threshold %d. Every sheet is then needed."),
                        splits);
        else
            pgpid_error(_("Suggestion: --split %d --threshold %d. Every sheet is then "
                        "needed."), needed, needed);
        return PGPID_FAIL;
    }

    char pattern[600];
    if (cut) {
        /* Encoded and cut here rather than by `basenc | split`. Two spawns
         * fewer, two packages fewer to depend on -- and the secret stops
         * passing through a file of its own on the way: it went to
         * s.gpg.b64url, which then had to be shredded like everything else.
         * The codec is already in this program; it was being asked of
         * coreutils out of habit. */
        if (!encode_and_cut(priv, workdir, splits)) {
            pgpid_error(_("Error: The export could not be cut in %d."), splits);
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
        /* gfsplit writes SECRET.001…; each becomes SECRET-001, in base45. */
        DIR *d = opendir(workdir);
        if (!d)
            return PGPID_FAIL;
        for (struct dirent *e; (e = readdir(d));) {
            if (strncmp(e->d_name, "SECRET.", 7))
                continue;
            char from[800], to[800];
            snprintf(from, sizeof from, "%.500s/%.250s", workdir, e->d_name);
            snprintf(to, sizeof to, "%.500s/SECRET-%.240s", workdir, e->d_name + 7);
            if (!encode_file(from, to)) {
                pgpid_error(_("Error: %s could not be encoded."), e->d_name);
                closedir(d);
                return PGPID_FAIL;
            }
        }
        closedir(d);
    }
    (void)pattern;

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

    /* Each fragment's code, drawn by qrencode as text: the page draws the
     * squares itself. No mode forced: qrencode puts the '~' in a byte segment
     * of its own and the base45 after it in alphanumeric mode, which is where
     * the smaller symbol comes from. */
    for (size_t i = 0; i < nfrag; i++) {
        char frag[600], matrix[620], header[64];
        snprintf(frag, sizeof frag, "%.500s/%.63s", workdir, names[i]);
        snprintf(matrix, sizeof matrix, "%.599s.qr", frag);

        /* The header is what `scan` reads first: a '~', the version, how many
         * fragments are needed less one, and which fragment this is, each in
         * one upper-case hexadecimal digit. Then the number gfsplit needs to
         * put a share back together -- its file names have it in decimal, the
         * code in two hexadecimal digits, a share number never passing 255 --
         * or "**" in its place for a piece of a cut secret. */
        if (!cut)
            snprintf(header, sizeof header, "~6%X%zX%02X", (unsigned)(threshold - 1), i,
                     (unsigned)atoi(names[i] + 7));
        else
            snprintf(header, sizeof header, "~6%X%zX**", (unsigned)(threshold - 1), i);

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

        const char *qr[] = { "qrencode", "--level", cut ? "M" : "L", "--type", "ASCII",
                             "--margin", "0", "--output", matrix, NULL };
        if (pgpid_run_program(qr, payload, NULL)) {
            pgpid_error(_("Error: qrencode would not draw fragment %zu."), i + 1);
            free(names);
            return PGPID_FAIL;
        }
    }

    sheet.threshold = threshold;
    sheet.splits = (int)nfrag;
    sheet.fpr = fpr;
    sheet.host = host;
    sheet.today = today;
    sheet.passphrase = with_passphrase ? passphrase : NULL;
    size_t npages = (nfrag + 1) / 2;
    for (size_t pg = 0; pg < npages; pg++) {
        char matrices[2][620], pdf[620];
        const char *two[2] = { matrices[0], matrices[1] };
        size_t count = (2 * pg + 1 < nfrag) ? 2 : 1;
        for (size_t h = 0; h < count; h++)
            snprintf(matrices[h], sizeof matrices[0], "%.500s/%.63s.qr", workdir,
                     names[2 * pg + h]);
        snprintf(pdf, sizeof pdf, "%.500s/SECRET-page-%zu.pdf", workdir, pg + 1);
        if (!page_to_pdf(pdf, &sheet, 2 * pg, two, count)) {
            pgpid_error(_("Error: Fragment %zu could not be laid out."), 2 * pg + 1);
            free(names);
            return PGPID_FAIL;
        }
        if (*printer) {
            const char *print[] = { "lpr", "-#", "1", "-P", printer, pdf, NULL };
            if (pgpid_run_program(print, NULL, NULL)) {
                pgpid_error(_("Error: lpr would not print fragment %zu."), 2 * pg + 1);
                free(names);
                return PGPID_FAIL;
            }
        }
    }

    if (temporary && *printer) {
        /* Sent to a printer: nothing here is worth the risk of being left. */
        for (size_t i = 0; i < nfrag; i++) {
            char frag[600], matrix[620], pdf[620];
            snprintf(frag, sizeof frag, "%.500s/%.63s", workdir, names[i]);
            snprintf(matrix, sizeof matrix, "%.599s.qr", frag);
            snprintf(pdf, sizeof pdf, "%.500s/SECRET-page-%zu.pdf", workdir, i / 2 + 1);
            pgpid_shred_path(frag);
            pgpid_shred_path(matrix);
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
