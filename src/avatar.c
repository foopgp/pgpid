/* The image a certificate wears, read from its attribute packets.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * gpgme cannot see an image. Its user id carries the text, the validity and
 * the signatures, and nothing of the attribute packet the picture lives in —
 * so a certificate's face is the one thing the library will not hand over.
 *
 * `bl-pgpid avatar` works around that by asking gpg to display the photos and
 * pointing --photo-viewer at a shell that copies each file aside. It works,
 * but it yields files and nothing else: no date, no revocation, not even
 * which packet a given image came from. On 2026-08-20 a certificate carrying
 * two standing images showed the wrong one, and repairing it there meant
 * pairing the files with a second walk of gpg's output by position.
 *
 * Here the walk is direct. Export the certificate, read the packet stream,
 * and every image arrives with the certification that put it there: when, by
 * whom, and whether a later one took it back. Reading only — adding an image
 * still belongs to bl-pgpid.
 */
#include "pgpid.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* Packet tags, RFC 9580 §5.  */
#define TAG_SIGNATURE      2
#define TAG_USER_ID       13
#define TAG_USER_ATTR     17

/* Signature types, §5.2.1: certifying a user id, and taking it back. */
#define SIG_CERT_LOWEST   0x10
#define SIG_CERT_HIGHEST  0x13
#define SIG_CERT_REVOKE   0x30

/* Attribute subpacket types, §5.12: one is defined, and it is the image. */
#define ATTR_IMAGE         1

/* How many images one certificate may carry before we stop reading. Ours
 * revoke as they replace, so a long history is normal and a thousand is not.
 */
#define MAX_IMAGES        64

/* How many certificates one search may act on at once. A pattern that finds
 * more than this is a pattern, not a target. */
#define MAX_KEYS          64

struct image {
    const unsigned char *data;   /* into the exported buffer, never freed */
    size_t len;
    unsigned long created;       /* newest certification that stands it up */
    bool revoked;
    unsigned index;              /* packet order among attributes, as a keyserver counts */
    unsigned uidno;              /* the number gpg gives it, uids and attributes together */
};

struct packet {
    unsigned tag;
    const unsigned char *body;
    size_t len;
    const unsigned char *next;
};

/* One packet at P. False at the end of the stream, or on a header we do not
 * read — a truncated export must stop the walk, not wander into it. */
static bool packet_next(const unsigned char *p, const unsigned char *end,
                        struct packet *out)
{
    if (p >= end || !(*p & 0x80))
        return false;
    unsigned b0 = *p++;
    size_t len;

    if (b0 & 0x40) {                      /* current format */
        out->tag = b0 & 0x3F;
        if (p >= end)
            return false;
        unsigned l0 = *p++;
        if (l0 < 192) {
            len = l0;
        } else if (l0 < 224) {
            if (p >= end)
                return false;
            len = ((size_t)(l0 - 192) << 8) + *p++ + 192;
        } else if (l0 == 255) {
            if ((size_t)(end - p) < 4)
                return false;
            len = ((size_t)p[0] << 24) | ((size_t)p[1] << 16)
                | ((size_t)p[2] << 8) | p[3];
            p += 4;
        } else {
            return false;             /* partial length: not on these packets */
        }
    } else {                              /* historical format */
        out->tag = (b0 >> 2) & 0x0F;
        unsigned lt = b0 & 0x03;
        if (lt == 0) {
            if (p >= end)
                return false;
            len = *p++;
        } else if (lt == 1) {
            if ((size_t)(end - p) < 2)
                return false;
            len = ((size_t)p[0] << 8) | p[1];
            p += 2;
        } else if (lt == 2) {
            if ((size_t)(end - p) < 4)
                return false;
            len = ((size_t)p[0] << 24) | ((size_t)p[1] << 16)
                | ((size_t)p[2] << 8) | p[3];
            p += 4;
        } else {
            len = (size_t)(end - p);              /* runs to the end */
        }
    }

    if (len > (size_t)(end - p))
        return false;
    out->body = p;
    out->len = len;
    out->next = p + len;
    return true;
}

/* A subpacket length, shared by attribute and signature subpackets (§5.2.3.7
 * and §5.12). Advances P past the length itself. */
static bool sub_length(const unsigned char **p, const unsigned char *end,
                       size_t *len)
{
    if (*p >= end)
        return false;
    unsigned b0 = *(*p)++;
    if (b0 < 192) {
        *len = b0;
        return true;
    }
    if (b0 < 224) {
        if (*p >= end)
            return false;
        *len = ((size_t)(b0 - 192) << 8) + *(*p)++ + 192;
        return true;
    }
    if (b0 == 255) {
        if ((size_t)(end - *p) < 4)
            return false;
        *len = ((size_t)(*p)[0] << 24) | ((size_t)(*p)[1] << 16)
             | ((size_t)(*p)[2] << 8) | (*p)[3];
        *p += 4;
        return true;
    }
    return false;
}

/* The JPEG inside an attribute packet, or false when it carries none.
 * The image subpacket opens with a header whose own length is given first,
 * so an unknown header version is skipped rather than guessed at. */
static bool attribute_image(const struct packet *pkt,
                            const unsigned char **data, size_t *len)
{
    const unsigned char *p = pkt->body, *end = pkt->body + pkt->len;
    while (p < end) {
        size_t sl;
        if (!sub_length(&p, end, &sl) || sl == 0 || sl > (size_t)(end - p))
            return false;
        const unsigned char *sub = p + 1;         /* past the type byte */
        size_t sublen = sl - 1;
        unsigned type = *p;
        p += sl;
        if (type != ATTR_IMAGE || sublen < 3)
            continue;
        size_t hdr = (size_t)sub[0] | ((size_t)sub[1] << 8);   /* little endian */
        if (hdr < 4 || hdr > sublen)
            continue;
        /* Version 1, encoding 1: the only image an attribute packet has ever
         * been allowed to hold. We write .jpg files, so we check rather than
         * assume. */
        if (sub[2] != 1 || sub[3] != 1)
            continue;
        *data = sub + hdr;
        *len = sublen - hdr;
        return *len > 0;
    }
    return false;
}

/* What a signature says about the packet before it: its kind, when it was
 * made, and who made it. Only the hashed half is read — the unhashed half is
 * not covered by the signature, so nothing there may decide anything. */
static bool signature_read(const struct packet *pkt, unsigned *type,
                           unsigned long *created, const char **issuer_hex)
{
    static char issuer[17];
    const unsigned char *p = pkt->body, *end = pkt->body + pkt->len;
    if (p >= end)
        return false;
    unsigned version = *p++;
    size_t hashed_len;

    if (version == 4) {
        if ((size_t)(end - p) < 5)
            return false;
        *type = *p++;
        p += 2;                                   /* public key, hash */
        hashed_len = ((size_t)p[0] << 8) | p[1];
        p += 2;
    } else if (version == 6) {
        if ((size_t)(end - p) < 7)
            return false;
        *type = *p++;
        p += 2;
        hashed_len = ((size_t)p[0] << 24) | ((size_t)p[1] << 16)
                   | ((size_t)p[2] << 8) | p[3];
        p += 4;
    } else {
        return false;                             /* v3 and older: gone */
    }
    if (hashed_len > (size_t)(end - p))
        return false;

    *created = 0;
    *issuer_hex = NULL;
    issuer[0] = '\0';
    const unsigned char *hp = p, *hend = p + hashed_len;
    while (hp < hend) {
        size_t sl;
        if (!sub_length(&hp, hend, &sl) || sl == 0 || sl > (size_t)(hend - hp))
            break;
        unsigned st = *hp & 0x7F;                 /* the critical bit is not the type */
        const unsigned char *sv = hp + 1;
        size_t svlen = sl - 1;
        hp += sl;
        if (st == 2 && svlen >= 4) {              /* creation time */
            *created = ((unsigned long)sv[0] << 24) | ((unsigned long)sv[1] << 16)
                     | ((unsigned long)sv[2] << 8) | sv[3];
        } else if (st == 16 && svlen >= 8) {      /* issuer key id */
            for (int i = 0; i < 8; i++)
                snprintf(issuer + i * 2, 3, "%02X", sv[i]);
            *issuer_hex = issuer;
        } else if (st == 33 && svlen >= 21) {     /* issuer fingerprint */
            /* The key id sits at the end of a v4 fingerprint and at the
             * front of a v6 one, so the version byte decides where to look. */
            const unsigned char *id = (sv[0] == 6) ? sv + 1 : sv + svlen - 8;
            for (int i = 0; i < 8; i++)
                snprintf(issuer + i * 2, 3, "%02X", id[i]);
            *issuer_hex = issuer;
        }
    }
    return *created != 0;
}

/* Every image the certificate carries, in packet order, each one already
 * knowing whether it still stands. Returns how many were found. */
static size_t walk_images(const unsigned char *buf, size_t buflen,
                          const char *keyid, struct image *imgs, size_t max)
{
    const unsigned char *p = buf, *end = buf + buflen;
    struct packet pkt;
    struct image *target = NULL;      /* the attribute the signatures certify */
    unsigned long newest = 0;
    unsigned newest_type = 0;
    size_t n = 0;
    unsigned index = 0, uidno = 0;

    while (packet_next(p, end, &pkt)) {
        p = pkt.next;
        switch (pkt.tag) {
        case TAG_USER_ATTR: {
            /* gpg numbers uids and attributes in one sequence, which is what
             * `uid N` selects; the keyserver counts attributes alone. Both
             * are needed, so both are kept. */
            index++;
            uidno++;
            target = NULL;
            const unsigned char *data;
            size_t len;
            if (n >= max || !attribute_image(&pkt, &data, &len))
                break;
            imgs[n] = (struct image){ .data = data, .len = len,
                                      .index = index, .uidno = uidno };
            target = &imgs[n++];
            newest = 0;
            newest_type = 0;
            break;
        }
        case TAG_USER_ID:
            uidno++;
            target = NULL;            /* what follows certifies text, not us */
            break;
        case TAG_SIGNATURE: {
            unsigned type;
            unsigned long created;
            const char *issuer;
            if (!target || !signature_read(&pkt, &type, &created, &issuer))
                break;
            /* Only the certificate's own word counts. A third party may
             * certify an image; it may not take it back. */
            if (!issuer || strcasecmp(issuer, keyid))
                break;
            if (type != SIG_CERT_REVOKE
                && (type < SIG_CERT_LOWEST || type > SIG_CERT_HIGHEST))
                break;
            if (created < newest)
                break;
            newest = created;
            newest_type = type;
            target->created = created;
            target->revoked = (newest_type == SIG_CERT_REVOKE);
            break;
        }
        default:
            /* A key or subkey packet ends the run of certifications. */
            target = NULL;
            break;
        }
    }
    return n;
}

/* Standing images first, newest of them first; the ones taken back follow in
 * the same order. "The avatar" is then simply the first. */
static int by_standing_then_date(const void *a, const void *b)
{
    const struct image *x = a, *y = b;
    if (x->revoked != y->revoked)
        return x->revoked ? 1 : -1;
    if (x->created != y->created)
        return x->created > y->created ? -1 : 1;
    return x->index < y->index ? -1 : 1;
}

/* A directory of ours, or nothing. Refuses one that is already there under
 * another name than a plain directory of our own — the path is predictable,
 * so it is worth being sure of before writing into it. */
static bool workdir_ready(const char *dir)
{
    if (mkdir(dir, 0700) && errno != EEXIST) {
        pgpid_error("Error: Cannot create '%s': %s.", dir, strerror(errno));
        return false;
    }
    struct stat st;
    if (lstat(dir, &st)) {
        pgpid_error("Error: Cannot read '%s': %s.", dir, strerror(errno));
        return false;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid()) {
        pgpid_error("Error: '%s' is not a directory of yours.", dir);
        return false;
    }
    return true;
}

/* The image on disk, its path printed. Named by certificate and packet
 * order, which is how a keyserver numbers them too. */
static bool write_image(const char *dir, const char *fpr,
                        const struct image *img)
{
    char path[4096];
    snprintf(path, sizeof path, "%s/%s-%u.jpg", dir, fpr, img->index);
    FILE *f = fopen(path, "wb");
    if (!f) {
        pgpid_error("Error: Cannot write '%s': %s.", path, strerror(errno));
        return false;
    }
    bool ok = fwrite(img->data, 1, img->len, f) == img->len;
    if (fclose(f) || !ok) {
        pgpid_error("Error: Cannot write '%s': %s.", path, strerror(errno));
        return false;
    }
    puts(path);
    return true;
}

/* ---- writing ---------------------------------------------------------- *
 *
 * Two warnings earned the hard way, both on 2026-08-20.
 *
 * The number `uid N` selects is **not** the packet order this file walks for
 * reading. gpg numbers what it displays, and it displays the primary uid
 * first — on the certificate that started all this, its two addresses come
 * out reversed. Revoking is permanent, so the numbering used here is read
 * back from gpg's own listing and never derived from the packets.
 *
 * And gpgme is no help: it does not merely hide the image, it does not list
 * attribute packets at all. Its user id chain held two entries for a
 * certificate wearing five images.
 */

/* Run a program with these arguments and give back its exit status, or -1.
 * No shell: what is passed is what is executed. */
static int run_program(const char *const *argv)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    int st;
    if (waitpid(pid, &st, 0) != pid)
        return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

/* The image, brought to the 180×180 an attribute packet is meant to carry.
 * Resizing lives in graphicsmagick rather than in here: the operation is
 * worth no library of our own, it happens once when someone changes a
 * picture, and it is the one step that parses a file we were handed — which
 * is a reason to keep it in a process of its own rather than beside the key
 * material. Returns the path to use, or NULL. */
static const char *resized(const char *image, const char *dir, char *buf,
                           size_t buflen)
{
    snprintf(buf, buflen, "%s/new.jpg", dir);
    const char *geometry[] = { "gm", "convert", "-geometry", "180^",
                               "-gravity", "center", "-extent", "180",
                               "-strip", image, NULL, NULL };
    /* Room for the prefix on top of any path the buffer can hold. */
    char target[sizeof "jpeg:" + 4096];
    snprintf(target, sizeof target, "jpeg:%s", buf);
    geometry[10] = target;
    int rc = run_program(geometry);
    if (rc == 127) {
        pgpid_error("Error: graphicsmagick is needed to resize an image - install 'graphicsmagick'.");
        return NULL;
    }
    if (rc) {
        pgpid_error("Error: Cannot read '%s' as an image.", image);
        return NULL;
    }
    return buf;
}

/* The numbers gpg gives the attribute packets that still stand, in the order
 * gpg itself lists them — the only numbering `uid N` agrees with. */
static size_t standing_uidnos(const char *fpr, unsigned *out, size_t max)
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
    unsigned uidno = 0;
    char line[8192];
    while (f && fgets(line, sizeof line, f)) {
        bool uid = !strncmp(line, "uid:", 4);
        bool uat = !strncmp(line, "uat:", 4);
        if (!uid && !uat)
            continue;
        uidno++;
        if (uat && line[4] != 'r' && n < max)
            out[n++] = uidno;
    }
    if (f)
        fclose(f);
    int st;
    waitpid(pid, &st, 0);
    return n;
}

/* The conversation gpg holds while editing a certificate. Answers are keyed
 * by the prompt that asks for them rather than fed in order, so a gpg that
 * asks one question more — or one fewer — does not silently shift every
 * later answer onto the wrong question. */
struct edit {
    const unsigned *revoke;   /* attribute numbers to take back, gpg's own */
    size_t nrevoke, at;
    const char *addfile;      /* the image to put on, or NULL */
    bool selected, asked, added, saved;
};

static gpgme_error_t edit_cb(void *opaque, const char *keyword,
                             const char *args, int fd)
{
    struct edit *e = opaque;
    const char *answer = NULL;
    char sel[32];

    if (fd < 0 || !keyword)
        return 0;                          /* a status line, not a question */

    /* gpgme hands the status word in `keyword` and the name of the question
     * in `args` — GET_LINE / keyedit.prompt, not the other way round. Anything
     * else reaching here with a writable fd would leave gpg waiting on an
     * answer that never comes, so the default below says something. */
    if (strcmp(keyword, "GET_LINE") && strcmp(keyword, "GET_BOOL")
        && strcmp(keyword, "GET_HIDDEN"))
        return 0;
    const char *ask = args ? args : "";

    if (!strcmp(ask, "keyedit.prompt")) {
        if (e->at < e->nrevoke) {
            snprintf(sel, sizeof sel, "uid %u", e->revoke[e->at]);
            if (!e->selected) {
                e->selected = true;
            } else if (!e->asked) {
                e->asked = true;
                answer = "revuid";
            } else {
                /* deselect, and on to the next */
                e->selected = false;
                e->asked = false;
                e->at++;
            }
            if (!answer)
                answer = sel;
        } else if (e->addfile && !e->added) {
            e->added = true;
            answer = "addphoto";
        } else if (!e->saved) {
            e->saved = true;
            answer = "save";
        } else {
            answer = "quit";
        }
    } else if (!strcmp(ask, "keyedit.revoke.uid.okay")
            || !strcmp(ask, "ask_revocation_reason.okay")
            || !strcmp(ask, "photoid.jpeg.size")
            || !strcmp(ask, "keyedit.save.okay")) {
        answer = "y";
    } else if (!strcmp(ask, "ask_revocation_reason.code")) {
        answer = "4";                      /* 4: the user id is no longer valid */
    } else if (!strcmp(ask, "ask_revocation_reason.text")) {
        answer = "";
    } else if (!strcmp(ask, "photoid.jpeg.add")) {
        answer = e->addfile ? e->addfile : "";
    } else {
        /* An unknown question still needs an answer, or gpg stops here.
         * An empty line is the mildest thing to say. */
        answer = "";
    }

    if (write(fd, answer, strlen(answer)) < 0 || write(fd, "\n", 1) < 0)
        return gpgme_error_from_errno(errno);
    return 0;
}

/* Take back every image that stands, then put this one on. Either half may
 * be asked for alone. */
static int replace_avatar(gpgme_ctx_t ctx, gpgme_key_t key, const char *image,
                          const char *dir, bool revoke_only)
{
    const char *fpr = key->fpr ? key->fpr : "";
    char newpath[4096];
    const char *addfile = NULL;

    if (image && !(addfile = resized(image, dir, newpath, sizeof newpath)))
        return PGPID_FAIL;

    unsigned nos[MAX_IMAGES];
    size_t n = standing_uidnos(fpr, nos, MAX_IMAGES);
    if (!n && !addfile) {
        pgpid_error("Notice: No image to take back.");
        return PGPID_NOTHING;
    }
    /* Revoking runs from the last to the first: gpg renumbers nothing during
     * a session, but a reader of this list should not have to know that. */
    for (size_t i = 0; i < n / 2; i++) {
        unsigned t = nos[i];
        nos[i] = nos[n - 1 - i];
        nos[n - 1 - i] = t;
    }

    struct edit e = { .revoke = nos, .nrevoke = n,
                      .addfile = revoke_only ? NULL : addfile };
    gpgme_data_t out;
    gpgme_error_t err = gpgme_data_new(&out);
    if (err) {
        pgpid_gpgme_error("gpgme_data_new", err);
        return PGPID_FAIL;
    }
    if (n)
        pgpid_error("Info: Taking back %zu image(s) on %s…", n, fpr);
    if (e.addfile)
        pgpid_error("Info: Putting %s on %s…", image, fpr);

    err = gpgme_op_interact(ctx, key, 0, edit_cb, &e, out);
    gpgme_data_release(out);
    if (err) {
        pgpid_gpgme_error("gpgme_op_interact", err);
        pgpid_error("Notice: A certificate is edited with its secret key - is the right one at hand?");
        return PGPID_FAIL;
    }
    return PGPID_OK;
}

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: " PGPID_MIP_NAME " avatar [OPTIONS]... [NAME|EMAIL|KEYID|U4|U5]\n"
        "\n"
        "Extract the image an OpenPGP certificate wears and print its path.\n"
        "The image that stands today comes first, so the first line is the\n"
        "avatar. Missing selector means the first secret certificate.\n"
        "\n"
        "Writing needs the certificate\'s secret key, and takes a fingerprint\n"
        "only: revoking cannot be undone, so a search must never become a\n"
        "target. A new image is brought to 180x180 first.\n"
        "\n"
        "OPTIONS:\n"
        "  -E, --extract-all           Print every image, revoked ones included\n"
        "  -A, --replace-to IMAGE      Take back every image that stands and put IMAGE on\n"
        "  -R, --revoke                Just take back every image that stands\n"
        "  -W, --workdir DIRECTORY     Where the images are written\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n");
}

/* The certificate to read when the caller named none: the first secret one,
 * which is the one the security key carries. */
static gpgme_error_t first_secret(gpgme_ctx_t ctx, gpgme_key_t *key)
{
    gpgme_error_t err = gpgme_op_keylist_start(ctx, NULL, 1);
    if (err)
        return err;
    err = gpgme_op_keylist_next(ctx, key);
    gpgme_op_keylist_end(ctx);
    return err;
}

/* Read one certificate's images out, print what was asked for. */
static int one_key(gpgme_ctx_t ctx, gpgme_key_t key, const char *dir, bool all)
{
    const char *fpr = key->fpr ? key->fpr : "";
    const char *keyid = (key->subkeys && key->subkeys->keyid)
                      ? key->subkeys->keyid : "";

    gpgme_data_t out;
    gpgme_error_t err = gpgme_data_new(&out);
    if (err) {
        pgpid_gpgme_error("gpgme_data_new", err);
        return PGPID_FAIL;
    }
    err = gpgme_op_export(ctx, fpr, 0, out);
    if (err) {
        gpgme_data_release(out);
        pgpid_gpgme_error("gpgme_op_export", err);
        return PGPID_FAIL;
    }
    size_t buflen = 0;
    char *buf = gpgme_data_release_and_get_mem(out, &buflen);
    if (!buf)
        return PGPID_FAIL;

    struct image imgs[MAX_IMAGES];
    size_t n = walk_images((const unsigned char *)buf, buflen, keyid,
                           imgs, MAX_IMAGES);
    int ret = PGPID_NOTHING;
    if (n) {
        qsort(imgs, n, sizeof imgs[0], by_standing_then_date);
        /* Without --extract-all the answer is the avatar, and an avatar that
         * has been taken back is not one. */
        size_t want = all ? n : (imgs[0].revoked ? 0 : 1);
        ret = want ? PGPID_OK : PGPID_NOTHING;
        for (size_t i = 0; i < want; i++)
            if (!write_image(dir, fpr, &imgs[i]))
                ret = PGPID_FAIL;
    }
    gpgme_free(buf);
    return ret;
}

int pgpid_action_avatar(int argc, char **argv)
{
    bool all = false, revoke = false;
    const char *workdir = NULL;
    const char *selector = NULL;
    const char *image = NULL;
    char defdir[64];

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-E") || !strcmp(a, "--extract-all")) {
            all = true;
        } else if (!strcmp(a, "-A") || !strcmp(a, "--replace-to")
                   || !strcmp(a, "--add")) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants an image.", a);
                return PGPID_USAGE;
            }
            image = argv[i];
        } else if (!strcmp(a, "-R") || !strcmp(a, "--revoke")) {
            revoke = true;
        } else if (!strcmp(a, "-W") || !strcmp(a, "--workdir")
                   || !strcmp(a, "--tmpdir")) {
            if (++i >= argc) {
                pgpid_error("Error: '%s' wants a directory.", a);
                return PGPID_USAGE;
            }
            workdir = argv[i];
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_MIP_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            if (++i < argc)
                selector = argv[i];
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error("Error: Unrecognized option '%s'.", a);
            pgpid_error("Try '" PGPID_MIP_NAME " avatar --help' for more information.");
            return PGPID_USAGE;
        } else if (!selector) {
            selector = a;
        } else {
            pgpid_error("Error: One certificate at a time.");
            return PGPID_USAGE;
        }
    }

    if (!workdir) {
        snprintf(defdir, sizeof defdir, "/tmp/pgpid-mip-avatar.%lu",
                 (unsigned long)getuid());
        workdir = defdir;
    }
    if (!workdir_ready(workdir))
        return PGPID_FAIL;

    /* Writing takes a fingerprint and nothing else. `del` holds the same
     * line for the same reason: being shown too much costs nothing, being
     * revoked by accident cannot be undone. */
    if ((image || revoke) && (!selector || !pgpid_is_fingerprint(selector))) {
        pgpid_error("Error: Changing an image wants a fingerprint, not a search.");
        return PGPID_USAGE;
    }
    if (image && revoke) {
        pgpid_error("Error: '--revoke' takes every image back; '--replace-to' already does.");
        return PGPID_USAGE;
    }

    gpgme_ctx_t ctx;
    gpgme_error_t err = pgpid_ctx_new(&ctx, 0);
    if (err) {
        pgpid_gpgme_error("gpgme_new", err);
        return PGPID_FAIL;
    }

    int ret = PGPID_NOTHING;
    gpgme_key_t key = NULL;

    if (selector) {
        /* The listing is closed before anything else is asked of this
         * context: gpgme carries one operation at a time, and starting an
         * edit while the enumeration is still open leaves both waiting on
         * each other with nothing said. */
        gpgme_key_t found[MAX_KEYS];
        size_t nfound = 0;
        err = gpgme_op_keylist_start(ctx, selector, 0);
        if (err) {
            gpgme_release(ctx);
            pgpid_gpgme_error("gpgme_op_keylist_start", err);
            return PGPID_FAIL;
        }
        while (nfound < MAX_KEYS && !gpgme_op_keylist_next(ctx, &key))
            found[nfound++] = key;
        gpgme_op_keylist_end(ctx);

        for (size_t k = 0; k < nfound; k++) {
            int r = (image || revoke)
                  ? replace_avatar(ctx, found[k], image, workdir, revoke)
                  : one_key(ctx, found[k], workdir, all);
            gpgme_key_unref(found[k]);
            if (r == PGPID_FAIL)
                ret = PGPID_FAIL;
            else if (r == PGPID_OK && ret != PGPID_FAIL)
                ret = PGPID_OK;
        }
    } else if (!(err = first_secret(ctx, &key))) {
        ret = one_key(ctx, key, workdir, all);
        gpgme_key_unref(key);
    } else {
        pgpid_error("Error: No secret certificate to read - name one.");
        ret = PGPID_FAIL;
    }

    if (ret == PGPID_NOTHING)
        pgpid_error("Notice: No image in that certificate.");
    gpgme_release(ctx);
    return ret;
}
