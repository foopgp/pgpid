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

/* What an image is here: the bytes, and what the certificate says about
 * them. The packet walking itself lives in packets.c, shared with whoever
 * else needs it. */
struct image {
    const unsigned char *data;   /* into the exported buffer, never freed */
    size_t len;
    unsigned long created;       /* newest certification that stands it up */
    bool revoked;
    unsigned index;              /* packet order among attributes, as a keyserver counts */
    unsigned uidno;              /* the number gpg gives it, uids and attributes together */
};

/* How many images one certificate may carry before we stop reading. Ours
 * revoke as they replace, so a long history is normal and a thousand is not.
 */
#define MAX_IMAGES        64

/* Every image the certificate carries, in packet order, each one already
 * knowing whether it still stands. Returns how many were found. */
static size_t walk_images(const unsigned char *buf, size_t buflen,
                          const char *keyid, struct image *imgs, size_t max)
{
    const unsigned char *p = buf, *end = buf + buflen;
    struct pgpid_packet pkt;
    struct image *target = NULL;      /* the attribute the signatures certify */
    unsigned long newest = 0;
    unsigned newest_type = 0;
    size_t n = 0;
    unsigned index = 0, uidno = 0;

    while (pgpid_packet_next(p, end, &pkt)) {
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
            if (n >= max || !pgpid_attribute_image(&pkt, &data, &len))
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
            if (!target || !pgpid_signature_read(&pkt, &type, &created, &issuer))
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

static int by_standing_then_date(const void *a, const void *b);

/**
 * The image that stands today, for whoever else needs it.
 *
 * Shared with to_vcard so that a certificate's card and its avatar cannot
 * show two different faces — which is exactly what happened when the two
 * were chosen by different rules: the shell's card takes the first standing
 * image in packet order, and on a certificate carrying several that is the
 * oldest one, not the one its owner set.
 */
bool pgpid_current_image(const unsigned char *buf, size_t len, const char *keyid,
                         const unsigned char **data, size_t *ilen)
{
    struct image imgs[MAX_IMAGES];
    size_t n = walk_images(buf, len, keyid, imgs, MAX_IMAGES);
    if (!n)
        return false;
    qsort(imgs, n, sizeof imgs[0], by_standing_then_date);
    if (imgs[0].revoked)
        return false;
    *data = imgs[0].data;
    *ilen = imgs[0].len;
    return true;
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
        pgpid_error(_("Error: Cannot create '%s': %s."), dir, strerror(errno));
        return false;
    }
    struct stat st;
    if (lstat(dir, &st)) {
        pgpid_error(_("Error: Cannot read '%s': %s."), dir, strerror(errno));
        return false;
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid()) {
        pgpid_error(_("Error: '%s' is not a directory of yours."), dir);
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
        pgpid_error(_("Error: Cannot write '%s': %s."), path, strerror(errno));
        return false;
    }
    bool ok = fwrite(img->data, 1, img->len, f) == img->len;
    if (fclose(f) || !ok) {
        pgpid_error(_("Error: Cannot write '%s': %s."), path, strerror(errno));
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
        pgpid_error(_("Error: graphicsmagick is needed to resize an image - install 'graphicsmagick'."));
        return NULL;
    }
    if (rc) {
        pgpid_error(_("Error: Cannot read '%s' as an image."), image);
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
                          const char *dir, bool revoke_only,
                          const char *keyservers)
{
    const char *fpr = key->fpr ? key->fpr : "";
    char newpath[4096];
    const char *addfile = NULL;

    if (image && !(addfile = resized(image, dir, newpath, sizeof newpath)))
        return PGPID_FAIL;

    unsigned nos[MAX_IMAGES];
    size_t n = standing_uidnos(fpr, nos, MAX_IMAGES);
    if (!n && !addfile) {
        pgpid_error(_("Notice: No image to take back."));
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
        pgpid_gpgme_error(_("gpgme_data_new"), err);
        return PGPID_FAIL;
    }
    if (n)
        pgpid_error(_("Info: Taking back %zu image(s) on %s…"), n, fpr);
    if (e.addfile)
        pgpid_error(_("Info: Putting %s on %s…"), image, fpr);

    err = gpgme_op_interact(ctx, key, 0, edit_cb, &e, out);
    gpgme_data_release(out);
    if (err) {
        pgpid_gpgme_error(_("gpgme_op_interact"), err);
        pgpid_error(_("Notice: A certificate is edited with its secret key - is the right one at hand?"));
        return PGPID_FAIL;
    }
    /* A changed certificate that stays home is a certificate nobody can
     * check. Publishing is therefore what happens unless somebody says
     * otherwise, and `--keyservers ""` is how they say it. */
    return pgpid_send_to_keyservers(fpr, keyservers ? keyservers
                                                    : PGPID_KEYSERVERS);
}

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " avatar [OPTIONS]... [NAME|EMAIL|KEYID|U4|U5]\n"
        "\n"
        "Extract the image an OpenPGP certificate wears and print its path.\n"
        "The image that stands today comes first, so the first line is the\n"
        "avatar. Missing selector means the first secret certificate.\n"
        "\n"
        "Writing needs the certificate\'s secret key, and takes a fingerprint\n"
        "only: revoking cannot be undone, so a search must never become a\n"
        "target. A new image is brought to 180x180 first, and the changed\n"
        "certificate is sent to the default keyservers unless told otherwise.\n"
        "\n"
        "OPTIONS:\n"
        "  -E, --extract-all           Print every image, revoked ones included\n"
        "  -A, --replace-to IMAGE      Take back every image that stands and put IMAGE on\n"
        "  -R, --revoke                Just take back every image that stands\n"
        "  -K, --keyservers SERVERS    Send the changed certificate to these, space separated\n"
        "                              Empty for none. Default: "
        "%s"
        "\n"
        "  -W, --workdir DIRECTORY     Where the images are written\n"
        "  -h, --help                  Print this help and exit\n"
        "  -V, --version               Print the version and exit\n"),
            PGPID_NAME, PGPID_KEYSERVERS);
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
        pgpid_gpgme_error(_("gpgme_data_new"), err);
        return PGPID_FAIL;
    }
    err = gpgme_op_export(ctx, fpr, 0, out);
    if (err) {
        gpgme_data_release(out);
        pgpid_gpgme_error(_("gpgme_op_export"), err);
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
    const char *keyservers = NULL;
    char defdir[64];

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-E") || !strcmp(a, "--extract-all")) {
            all = true;
        } else if (!strcmp(a, "-A") || !strcmp(a, "--replace-to")
                   || !strcmp(a, "--add")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants an image."), a);
                return PGPID_USAGE;
            }
            image = argv[i];
        } else if (!strcmp(a, "-R") || !strcmp(a, "--revoke")) {
            revoke = true;
        } else if (!strcmp(a, "-K") || !strcmp(a, "--keyservers")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a list of servers, empty for none."), a);
                return PGPID_USAGE;
            }
            keyservers = argv[i];
        } else if (!strcmp(a, "-W") || !strcmp(a, "--workdir")
                   || !strcmp(a, "--tmpdir")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a directory."), a);
                return PGPID_USAGE;
            }
            workdir = argv[i];
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--")) {
            if (++i < argc)
                selector = argv[i];
            break;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("avatar");
            return PGPID_USAGE;
        } else if (!selector) {
            selector = a;
        } else {
            pgpid_error(_("Error: One certificate at a time."));
            return PGPID_USAGE;
        }
    }

    if (!workdir) {
        snprintf(defdir, sizeof defdir, "/tmp/pgpid-avatar.%lu",
                 (unsigned long)getuid());
        workdir = defdir;
    }
    if (!workdir_ready(workdir))
        return PGPID_FAIL;

    /* Writing takes a fingerprint and nothing else. `del` holds the same
     * line for the same reason: being shown too much costs nothing, being
     * revoked by accident cannot be undone. */
    if ((image || revoke) && (!selector || !pgpid_is_fingerprint(selector))) {
        pgpid_error(_("Error: Changing an image wants a fingerprint, not a search."));
        return PGPID_USAGE;
    }
    if (keyservers && !image && !revoke) {
        pgpid_error(_("Error: '--keyservers' publishes a change; there is none to make."));
        pgpid_error(_("Notice: To publish a certificate as it stands, see '%s push'."),
                    PGPID_NAME);
        return PGPID_USAGE;
    }
    if (image && revoke) {
        pgpid_error(_("Error: '--revoke' takes every image back; '--replace-to' already does."));
        return PGPID_USAGE;
    }

    gpgme_ctx_t ctx;
    gpgme_error_t err = pgpid_ctx_new(&ctx, 0);
    if (err) {
        pgpid_gpgme_error(_("gpgme_new"), err);
        return PGPID_FAIL;
    }

    int ret = PGPID_NOTHING;
    gpgme_key_t key = NULL;

    if (selector) {
        /* The listing is closed before anything else is asked of this
         * context: gpgme carries one operation at a time, and starting an
         * edit while the enumeration is still open leaves both waiting on
         * each other with nothing said. */
        /* However many the selector matches. A fixed few would have --revoke
         * act on some of them and leave the rest without a word. */
        gpgme_key_t *found = NULL;
        size_t nfound = 0, cap = 0;
        err = gpgme_op_keylist_start(ctx, selector, 0);
        if (err) {
            gpgme_release(ctx);
            pgpid_gpgme_error(_("gpgme_op_keylist_start"), err);
            return PGPID_FAIL;
        }
        while (!gpgme_op_keylist_next(ctx, &key)) {
            if (nfound == cap) {
                size_t grown = cap ? cap * 2 : 32;
                gpgme_key_t *bigger = realloc(found, grown * sizeof *bigger);
                if (!bigger) {
                    pgpid_error(_("Error: Out of memory."));
                    gpgme_key_unref(key);
                    for (size_t k = 0; k < nfound; k++)
                        gpgme_key_unref(found[k]);
                    free(found);
                    gpgme_op_keylist_end(ctx);
                    gpgme_release(ctx);
                    return PGPID_FAIL;
                }
                found = bigger;
                cap = grown;
            }
            found[nfound++] = key;
        }
        gpgme_op_keylist_end(ctx);

        for (size_t k = 0; k < nfound; k++) {
            int r = (image || revoke)
                  ? replace_avatar(ctx, found[k], image, workdir, revoke,
                                   keyservers)
                  : one_key(ctx, found[k], workdir, all);
            gpgme_key_unref(found[k]);
            if (r == PGPID_FAIL)
                ret = PGPID_FAIL;
            else if (r == PGPID_OK && ret != PGPID_FAIL)
                ret = PGPID_OK;
        }
        free(found);
    } else if (!(err = first_secret(ctx, &key))) {
        ret = one_key(ctx, key, workdir, all);
        gpgme_key_unref(key);
    } else {
        pgpid_error(_("Error: No secret certificate to read - name one."));
        ret = PGPID_FAIL;
    }

    if (ret == PGPID_NOTHING)
        pgpid_error(_("Notice: No image in that certificate."));
    gpgme_release(ctx);
    return ret;
}
