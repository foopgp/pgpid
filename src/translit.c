/* Turning a name into the letters an identifier is derived from.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The rule is the draft's, `MRZ-transliterate`: decompose, drop the
 * diacritics, keep only A–Z, uppercase. Not iconv's `//TRANSLIT`, which is
 * what the shell uses and which **depends on the locales installed on the
 * machine** — measured on 2026-08-22, the same civil status yields an
 * identifier under fr_FR.UTF-8 and an outright error under LC_ALL=C. An
 * identifier that depends on where it was computed is not an identifier.
 *
 * What is implemented here is a table rather than full Unicode
 * normalisation, covering Latin-1 Supplement and Latin Extended-A — every
 * letter a European name is written with. Outside that range the draft's rule
 * applies unchanged: what is not A–Z after decomposition is dropped. A name
 * in another script reaches us already transliterated, because that is what a
 * passport carries.
 */
#include "pgpid.h"

#include <string.h>

/* One entry per codepoint that decomposes to a letter and a mark, plus the
 * Latin letters that do not decompose at all — Ø, Æ, Đ, Þ, ß, Ł, Œ. Those
 * last ones the draft would simply drop, since NFD leaves them whole; they
 * are mapped here and the caller is told, because dropping the first letter
 * of ØSTERGAARD silently is worse than either answer. */
static const struct {
    unsigned cp;
    const char *ascii;
    bool decomposes;   /* false: not a diacritic, the draft would drop it */
} MAP[] = {
    { 0x00C0, "A", true }, { 0x00C1, "A", true }, { 0x00C2, "A", true },
    { 0x00C3, "A", true }, { 0x00C4, "A", true }, { 0x00C5, "A", true },
    { 0x00C6, "AE", false },
    { 0x00C7, "C", true },
    { 0x00C8, "E", true }, { 0x00C9, "E", true }, { 0x00CA, "E", true },
    { 0x00CB, "E", true },
    { 0x00CC, "I", true }, { 0x00CD, "I", true }, { 0x00CE, "I", true },
    { 0x00CF, "I", true },
    { 0x00D0, "D", false },
    { 0x00D1, "N", true },
    { 0x00D2, "O", true }, { 0x00D3, "O", true }, { 0x00D4, "O", true },
    { 0x00D5, "O", true }, { 0x00D6, "O", true },
    { 0x00D8, "O", false },
    { 0x00D9, "U", true }, { 0x00DA, "U", true }, { 0x00DB, "U", true },
    { 0x00DC, "U", true },
    { 0x00DD, "Y", true },
    { 0x00DE, "TH", false },
    { 0x00DF, "SS", false },
    { 0x0100, "A", true }, { 0x0102, "A", true }, { 0x0104, "A", true },
    { 0x0106, "C", true }, { 0x0108, "C", true }, { 0x010A, "C", true },
    { 0x010C, "C", true },
    { 0x010E, "D", true }, { 0x0110, "D", false },
    { 0x0112, "E", true }, { 0x0114, "E", true }, { 0x0116, "E", true },
    { 0x0118, "E", true }, { 0x011A, "E", true },
    { 0x011C, "G", true }, { 0x011E, "G", true }, { 0x0120, "G", true },
    { 0x0122, "G", true },
    { 0x0124, "H", true }, { 0x0126, "H", false },
    { 0x0128, "I", true }, { 0x012A, "I", true }, { 0x012C, "I", true },
    { 0x012E, "I", true }, { 0x0130, "I", true }, { 0x0132, "IJ", false },
    { 0x0134, "J", true },
    { 0x0136, "K", true },
    { 0x0139, "L", true }, { 0x013B, "L", true }, { 0x013D, "L", true },
    { 0x013F, "L", true }, { 0x0141, "L", false },
    { 0x0143, "N", true }, { 0x0145, "N", true }, { 0x0147, "N", true },
    { 0x014A, "NG", false },
    { 0x014C, "O", true }, { 0x014E, "O", true }, { 0x0150, "O", true },
    { 0x0152, "OE", false },
    { 0x0154, "R", true }, { 0x0156, "R", true }, { 0x0158, "R", true },
    { 0x015A, "S", true }, { 0x015C, "S", true }, { 0x015E, "S", true },
    { 0x0160, "S", true },
    { 0x0162, "T", true }, { 0x0164, "T", true }, { 0x0166, "T", false },
    { 0x0168, "U", true }, { 0x016A, "U", true }, { 0x016C, "U", true },
    { 0x016E, "U", true }, { 0x0170, "U", true }, { 0x0172, "U", true },
    { 0x0174, "W", true },
    { 0x0176, "Y", true }, { 0x0178, "Y", true },
    { 0x0179, "Z", true }, { 0x017B, "Z", true }, { 0x017D, "Z", true },
};

/* Decode one UTF-8 sequence, advancing *p. Returns the codepoint, or -1 on a
 * byte that is not valid UTF-8 — refused rather than reinterpreted, since a
 * mis-decoded name mints the wrong identifier. */
static long utf8_next(const unsigned char **p)
{
    const unsigned char *s = *p;
    unsigned c = *s;
    unsigned need;
    long cp;

    if (c < 0x80) { *p = s + 1; return c; }
    else if ((c & 0xE0) == 0xC0) { need = 1; cp = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { need = 2; cp = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0) { need = 3; cp = c & 0x07; }
    else return -1;

    for (unsigned i = 1; i <= need; i++) {
        if ((s[i] & 0xC0) != 0x80)
            return -1;
        cp = (cp << 6) | (s[i] & 0x3F);
    }
    *p = s + need + 1;
    return cp;
}

int pgpid_transliterate(const char *in, char *out, size_t max,
                        char *dropped, size_t dropped_max)
{
    const unsigned char *p = (const unsigned char *)in;
    size_t o = 0, d = 0;
    if (dropped_max)
        dropped[0] = '\0';

    while (*p) {
        const unsigned char *before = p;
        long cp = utf8_next(&p);
        if (cp < 0)
            return -1;

        /* Separators become the '<' the format uses; runs squeeze into one,
         * and the split happens here — before transliteration, so that the
         * hyphen of DE CLÉREL-DE-TOCQUEVILLE still marks a boundary when it
         * is read. */
        if (cp == ' ' || cp == ';' || cp == ',' || cp == '-' || cp == '<') {
            if (o && o < max - 1 && out[o - 1] != '<')
                out[o++] = '<';
            continue;
        }

        if (cp >= 'a' && cp <= 'z') cp -= 32;
        if (cp >= 'A' && cp <= 'Z') {
            if (o < max - 1)
                out[o++] = (char)cp;
            continue;
        }

        /* To its capital before looking it up — and the two ranges do not
         * agree on how far that is. Latin-1 puts the lowercase 0x20 above
         * (ü is Ü + 0x20); Latin Extended-A pairs them one apart (ū is Ū + 1).
         * Reading one rule into both is how 'Jürgen' became 'JRGEN' and
         * 'François' became 'FRANOIS' — dropped, not mistranslated, which is
         * the kind of wrong that looks like nothing at all. */
        unsigned capital = (unsigned)cp;
        if (cp >= 0x00E0 && cp <= 0x00FE && cp != 0x00F7)
            capital = (unsigned)cp - 0x20;
        else if (cp >= 0x0100 && cp <= 0x017F && (cp & 1))
            capital = (unsigned)cp - 1;

        const char *ascii = NULL;
        bool decomposes = true;
        for (size_t i = 0; i < sizeof MAP / sizeof *MAP; i++) {
            if (MAP[i].cp == capital || MAP[i].cp == (unsigned)cp) {
                ascii = MAP[i].ascii;
                decomposes = MAP[i].decomposes;
                break;
            }
        }
        if (ascii) {
            for (const char *a = ascii; *a && o < max - 1; a++)
                out[o++] = *a;
            /* A letter the draft's own rule would have dropped: mapped here,
             * and named, so the difference is visible rather than assumed. */
            if (!decomposes && d + (p - before) + 1 < dropped_max) {
                memcpy(dropped + d, before, (size_t)(p - before));
                d += (size_t)(p - before);
                dropped[d] = '\0';
            }
            continue;
        }
        /* Outside the table and not a letter: gone, as the rule says. */
    }
    out[o] = '\0';
    return (int)o;
}
