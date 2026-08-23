/* One table, three shapes: for an eye, for a shell, for a document.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * Every action here answers with rows of named values, so the format is not
 * each action's business: it is said once, globally, next to --homedir.
 *
 *   raw   the values, columns aligned — the default, for reading
 *   info  key=value, tab separated — for a shell to eval
 *   md    a Markdown table — for pasting into a document
 *
 * Rows are held until the end because alignment cannot be known before the
 * last one is in. A keyring is a hundred rows; a keyserver's would not be,
 * and that is the day this grows a streaming mode rather than today.
 */
#include "pgpid.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

pgpid_format_t pgpid_format = PGPID_FMT_RAW;

static const char *const *columns = NULL;
static size_t ncols = 0;
static char **cells = NULL;      /* nrows * ncols, owned */
static size_t nrows = 0, capacity = 0;

/* Characters, not bytes: an accented name is not two columns wide. */
static size_t width(const char *s)
{
    size_t n = 0;
    for (; *s; s++)
        if ((*s & 0xC0) != 0x80)
            n++;
    return n;
}

static void pad_to(size_t have, size_t want)
{
    for (; have < want; have++)
        putchar(' ');
}

void pgpid_table_start(const char *const *keys, size_t n)
{
    columns = keys;
    ncols = n;
    nrows = 0;
}

void pgpid_table_row(const char *const *values)
{
    if (nrows == capacity) {
        size_t grown = capacity ? capacity * 2 : 64;
        char **bigger = realloc(cells, grown * ncols * sizeof *bigger);
        if (!bigger)
            return;
        cells = bigger;
        capacity = grown;
    }
    for (size_t c = 0; c < ncols; c++) {
        const char *v = values[c] ? values[c] : "";
        cells[nrows * ncols + c] = strdup(v);
    }
    nrows++;
}

/* `|` would end a Markdown cell, so it is escaped there and nowhere else. */
static void put_md(const char *s)
{
    for (; *s; s++) {
        if (*s == '|')
            putchar('\\');
        putchar(*s);
    }
}

void pgpid_table_end(void)
{
    if (pgpid_format == PGPID_FMT_INFO) {
        for (size_t r = 0; r < nrows; r++) {
            for (size_t c = 0; c < ncols; c++)
                printf("%s%s=%s", c ? "\t" : "", columns[c], cells[r * ncols + c]);
            putchar('\n');
        }
    } else {
        /* Widths, header included for the table that shows one. */
        size_t *w = calloc(ncols, sizeof *w);
        if (w) {
            for (size_t c = 0; c < ncols; c++) {
                if (pgpid_format == PGPID_FMT_MD)
                    w[c] = width(columns[c]);
                for (size_t r = 0; r < nrows; r++) {
                    size_t k = width(cells[r * ncols + c]);
                    if (k > w[c])
                        w[c] = k;
                }
            }
        }

        if (pgpid_format == PGPID_FMT_MD) {
            for (size_t c = 0; c < ncols; c++) {
                printf("| ");
                put_md(columns[c]);
                pad_to(width(columns[c]), w ? w[c] : 0);
                putchar(' ');
            }
            printf("|\n");
            for (size_t c = 0; c < ncols; c++) {
                printf("| ");
                for (size_t i = 0; i < (w ? w[c] : 3); i++)
                    putchar('-');
                putchar(' ');
            }
            printf("|\n");
        }

        for (size_t r = 0; r < nrows; r++) {
            for (size_t c = 0; c < ncols; c++) {
                const char *v = cells[r * ncols + c];
                if (pgpid_format == PGPID_FMT_MD) {
                    printf("| ");
                    put_md(v);
                    pad_to(width(v), w ? w[c] : 0);
                    putchar(' ');
                } else {
                    /* A single column is a value, not a table: padding it
                     * would change what the caller reads. */
                    if (c)
                        printf("  ");
                    fputs(v, stdout);
                    if (ncols > 1 && c + 1 < ncols)
                        pad_to(width(v), w ? w[c] : 0);
                }
            }
            if (pgpid_format == PGPID_FMT_MD)
                putchar('|');
            putchar('\n');
        }
        free(w);
    }

    for (size_t i = 0; i < nrows * ncols; i++)
        free(cells[i]);
    free(cells);
    cells = NULL;
    nrows = capacity = 0;
}
