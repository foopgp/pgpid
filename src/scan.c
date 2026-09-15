/* Putting a secret key back together off paper.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * The other half of `print_secret`, and the half that matters: a backup
 * nobody has ever restored is a hope, not a backup.
 *
 * Each QR code opens with a header saying which scheme made it, how many
 * fragments are needed, and which one this is. Fragments from two different
 * printings would rebuild nothing, so disagreement on the first two stops
 * everything rather than producing a plausible ruin.
 *
 * A camera is read on request, never by default. `--camera` turns the action
 * into the conversation it becomes there — hold up a sheet, it is taken, hold
 * up the next — and without it the action reads what it was handed and names
 * what is missing. The distinction matters: one of the two waits for a human,
 * and something driving this from a script must be able to choose the other.
 */
#include "pgpid.h"

#include <fcntl.h>
#include <linux/videodev2.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

#define MAX_PARTS PGPID_SPLIT_MAX

static void usage(FILE *out)
{
    fprintf(out, _("Usage: "
        "%s"
        " secret_scan [OPTIONS]... IMAGES...\n"
        "\n"
        "Reconstitute OpenPGP secrets from QRcodes scanned from IMAGES.\n"
        "Output OpenPGP certification key fingerprint.\n"
        "Images may be PNG, JPEG, or PDF.\n"
        "\n"
        "QR code versions 4 and 5, which is what print_secret writes. Versions 1\n"
        "to 3 were experimental and never released; 'bl-pgpkey scan' still reads\n"
        "them. A key that arrives protected stays protected: taking the\n"
        "passphrase off is the business of whoever moves it onto a card.\n"
        "\n"
        "OPTIONS:\n"

        "  -c, --camera [V4LDEVICE]      Read the fragments off a camera (/dev/v4l/by-id/...)\n"
        "      --cameras                 List the cameras this machine has, and read nothing\n"
        "      --camera-size WIDTHxHEIGHT  Ask the camera for that frame instead of 640x480\n"
        "  -W, --workdir DIRECTORY       Use given working directory instead of a temporary directory (don't forget to shred its content)\n"
        "  -h, --help                    Print this help and exit\n"
        "  -V, --version                 Print the version and exit\n"
        "\n"
        "Without --camera, fragments missing are named rather than worked around:\n"
        "the action reads what it is given and stops. With it, it waits in front\n"
        "of the camera until it has enough, or until three codes in a row say\n"
        "nothing.\n"),
            PGPID_NAME);
}


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

/** Does this file begin like a PDF? */
static bool is_pdf(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    char head[5] = { 0 };
    size_t n = fread(head, 1, 4, f);
    fclose(f);
    return n == 4 && !memcmp(head, "%PDF", 4);
}

/**
 * Take every fragment out of what zbar printed.
 *
 * zbarimg and zbarcam both prefix each payload with "QR-Code:" and separate
 * them with newlines — which a payload never contains, being base64url behind
 * a seven-character head. Answers how many fragments were taken **that were
 * not already held** — a fragment shown twice is not progress — or 3 for a
 * sheet that cannot be read as one set. A repeat is still weighed against the
 * version and the division: a piece of another printing must be refused
 * whether or not its number is one we lack.
 */
static int take_payloads(char *raw, char parts[][262144], bool *have,
                         int *version, int *needed_less_one)
{
    int taken = 0;
    for (char *line = raw, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
        const char *at = strstr(line, "QR-Code:");
        if (!at)
            continue;
        at += 8;
        if (at[0] != '~' || at[1] < '1' || at[1] > '9')
            continue;
        int v = at[1] - '0';
        int max = at[2] - '0';
        int index = at[3] - '0';
        if (*version < 0)
            *version = v;
        if (*needed_less_one < 0)
            *needed_less_one = max;
        if (v != *version) {
            pgpid_error(_("Crit: QR codes don't share the same version (%d != %d)."),
                        *version, v);
            return 3;
        }
        if (max != *needed_less_one) {
            pgpid_error(_("Crit: QR codes don't share the same division (%d != %d)."),
                        *needed_less_one, max);
            return 3;
        }
        if (index < 0 || index >= MAX_PARTS) {
            pgpid_error(_("Crit: Fragment number %d is out of range."), index);
            return 3;
        }
        if (have[index])
            continue;
        snprintf(parts[index], sizeof parts[0], "%s", at + 4);
        have[index] = true;
        taken++;
    }
    return taken;
}

/* How many cameras we are willing to enumerate. More than this on one machine
 * and naming the one wanted is the shorter conversation anyway. */
#define MAX_CAMERAS 8

struct camera {
    char path[32];
    char name[32];
    char bus[32];
};

/**
 * The cameras on this machine, asked of the kernel rather than guessed.
 *
 * `/dev/video*` is not a list of cameras: a modern kernel gives one webcam two
 * nodes, one that captures frames and one that carries metadata, and this
 * laptop has exactly that — two entries under /dev/v4l/by-id for a single
 * Quanta webcam. Counting the files would find two cameras where there is one,
 * and then ask which of them the person meant. So each is opened and asked
 * what it can do: only a node that says V4L2_CAP_VIDEO_CAPTURE is one.
 */
static size_t list_cameras(struct camera *out, size_t max)
{
    size_t n = 0;
    for (int i = 0; i < 64 && n < max; i++) {
        char path[32];
        snprintf(path, sizeof path, "/dev/video%d", i);
        int fd = open(path, O_RDONLY | O_NONBLOCK);
        if (fd < 0)
            continue;
        struct v4l2_capability cap;
        memset(&cap, 0, sizeof cap);
        if (ioctl(fd, VIDIOC_QUERYCAP, &cap) == 0) {
            /* device_caps describes this node; capabilities describes the
             * whole device, and would say "capture" for the metadata node
             * of a camera that also captures. */
            unsigned which = (cap.capabilities & V4L2_CAP_DEVICE_CAPS)
                           ? cap.device_caps : cap.capabilities;
            if (which & V4L2_CAP_VIDEO_CAPTURE) {
                /* One camera, several capture nodes: the USB camera on this
                 * desk answers on /dev/video2 and /dev/video4, both saying
                 * "USB Live camera" and both sharing a bus. Offering the same
                 * lens twice is asking a question with a wrong answer in it,
                 * so the first node of each device is the one kept. */
                bool seen = false;
                for (size_t k = 0; k < n && !seen; k++)
                    seen = *cap.bus_info && !strcmp(out[k].bus, (const char *)cap.bus_info);
                if (!seen) {
                    snprintf(out[n].path, sizeof out[0].path, "%s", path);
                    snprintf(out[n].name, sizeof out[0].name, "%s", cap.card);
                    snprintf(out[n].bus, sizeof out[0].bus, "%s", cap.bus_info);
                    n++;
                }
            }
        }
        close(fd);
    }
    return n;
}

/**
 * Which camera, when the option named none.
 *
 * One is used and said out loud — a person watching a black preview needs to
 * know which lens is being asked. Several is a question, and a question is
 * asked interactively and refused under --batch, as everything missing is
 * here: something driving this from a script must fail rather than have one
 * picked for it. Letting zbarcam take its own default does neither; it picks
 * in silence, and on a machine with an internal webcam and a USB one that is
 * a coin toss nobody sees.
 */
static const char *choose_camera(char *buf, size_t max)
{
    struct camera cams[MAX_CAMERAS];
    size_t n = list_cameras(cams, MAX_CAMERAS);

    if (!n) {
        pgpid_error(_("Error: No camera on this machine."));
        return NULL;
    }
    if (n == 1) {
        pgpid_error(_("Info: Reading from %s (%s)."), cams[0].path, cams[0].name);
        snprintf(buf, max, "%s", cams[0].path);
        return buf;
    }

    for (size_t i = 0; i < n; i++)
        pgpid_error(_("Notice: %zu. %s (%s)"), i + 1, cams[i].path, cams[i].name);
    if (pgpid_batch) {
        pgpid_error(_("Error: %zu cameras here. Name one: --camera DEVICE."), n);
        return NULL;
    }
    char answer[16];
    if (!pgpid_ask(_("Which camera? "), answer, sizeof answer))
        return NULL;
    char *end = NULL;
    long pick = strtol(answer, &end, 10);
    if (pick < 1 || (size_t)pick > n) {
        pgpid_error(_("Error: '%s' is not one of the %zu."), answer, n);
        return NULL;
    }
    snprintf(buf, max, "%s", cams[pick - 1].path);
    return buf;
}

/**
 * Read fragments off a camera until there are enough of them.
 *
 * `zbarcam --oneshot` shows what the camera sees and exits on the first code
 * it reads, so the loop is ours: hold up a sheet, it is taken, hold up the
 * next. How many are needed is not known until the first one has been read —
 * the head of every fragment says how the secret was divided — so the count
 * only appears once there is something to count.
 *
 * Three refusals in a row and it stops, as `bl-pgpkey scan` did: a camera
 * that reads nothing three times is a camera pointed at a wall, or a lens
 * cap, and looping for ever in front of one helps nobody.
 */
static int scan_camera(const char *device, const char *size, const char *workdir,
                       char parts[][262144], bool *have,
                       int *version, int *needed_less_one)
{
    /* In memory, never on disk. The images path writes what zbar printed to a
     * file and unlinks it after reading; between those two a Ctrl-C leaves a
     * piece of somebody's secret key sitting in /tmp — and a camera scan is
     * exactly where one presses Ctrl-C, because zbarcam --oneshot waits for a
     * code that may never come. pgpid_capture keeps it in a buffer, so there
     * is nothing to leave behind and nothing to clean up. */
    (void)workdir;
    static char raw[1048576];
    int empty = 0;

    char chosen[32];
    if (!device || !*device) {
        device = choose_camera(chosen, sizeof chosen);
        if (!device)
            return PGPID_USAGE;
    }

    /* Said out loud, because it is the difference between a sheet that reads
     * and one that does not, and because a camera named on the command line
     * never goes through choose_camera and would otherwise say nothing at
     * all. */
    /* 640x480, as `bl-pgpkey scan` asked for, and for a reason that only
     * shows with a camera in your hand: zbarcam's viewfinder *is* the frame.
     * Asked for the largest a camera streams, it covered the screen and every
     * frame was slow to scan — the opposite of help while somebody holds up a
     * sheet. A fragment of a split secret is sixty-odd modules and reads at
     * this size; a secret printed whole is twice that and needs
     * --camera-size, which is the one place to pay for it. */
    char prescale[40];
    snprintf(prescale, sizeof prescale, "--prescale=%s", size ? size : "640x480");
    pgpid_error(_("Info: %s, %s."), device, size ? size : "640x480");

    for (;;) {
        int needed = *needed_less_one >= 0 ? *needed_less_one + 1 : -1;
        size_t got = 0;
        for (size_t i = 0; i < MAX_PARTS; i++)
            if (have[i])
                got++;
        if (needed > 0 && (int)got >= needed) {
            /* Said out loud: the loop has been asking for one more each time
             * round, so it owes the person the moment it stops asking. */
            pgpid_error(_("Info: %d of %d fragments — that is all of them."),
                        needed, needed);
            return PGPID_OK;
        }

        /* It waits, and it waits without a deadline: zbarcam --oneshot returns
         * when it reads a code and not before. Three *refusals* end the loop,
         * but a camera that simply sees nothing never refuses — so the way
         * out is said out loud rather than left to be discovered. */
        if (needed > 0)
            pgpid_error(_("Info: %zu of %d fragments; show the camera another "
                        "(Ctrl-C to stop)."), got, needed);
        else
            pgpid_error(_("Info: Show the camera a fragment (Ctrl-C to stop)."));

        const char *zbar[] = { "zbarcam", "-Sdisable", "-Sqrcode.enable",
                               "--oneshot", prescale, device, NULL };
        raw[0] = '\0';
        /* pgpid_capture answers the number of bytes it kept, not a status:
         * zero is "the program said nothing", and anything else is output.
         * Reading it as a status inverts the test, which is what it did here
         * for one commit — a fragment read in two seconds was reported as a
         * camera that saw nothing. */
        bool read_something = pgpid_capture(zbar, raw, sizeof raw) > 0
                           && strstr(raw, "QR-Code:");

        int taken = read_something
                  ? take_payloads(raw, parts, have, version, needed_less_one) : 0;
        if (taken == 3)
            return 3;
        if (taken > 0) {
            empty = 0;
            continue;
        }
        if (++empty >= 3) {
            pgpid_error(_("Error: Three in a row that brought nothing new."));
            return PGPID_FAIL;
        }
        /* Two different disappointments, and saying which is the whole help
         * one gets here: a camera that gave nothing back is pointed wrong or
         * shut, while a code that is not a fragment is the wrong piece of
         * paper — a business card, another person's sheet, a QR off a poster.
         * The payload itself is not printed: the next one may well be a piece
         * of a secret key, and a message is a thing that ends up in a log. */
        /* Three disappointments, and which one decides what to do next:
         * point the lens elsewhere, turn the sheet over, or go and fetch the
         * piece that is missing. */
        if (read_something && strstr(raw, ":~"))
            pgpid_error(_("Notice: That fragment is already in hand — another?"));
        else if (read_something)
            pgpid_error(_("Notice: That is a QR code, but not a fragment of a "
                        "secret — wrong sheet?"));
        else
            pgpid_error(_("Notice: Nothing read from '%s' — try again."), device);
    }
}

int pgpid_action_secret_scan(int argc, char **argv)
{
    const char *given_workdir = NULL;
    const char *camera = NULL;
    const char *given_size = NULL;
    bool list_only = false;
    /* A secret is cut into PGPID_SPLIT_MAX fragments at most, so that is how
     * many images there can be to read. More is not a longer job, it is a
     * mistake — and one worth naming before anything is decoded. */
    const char *images[PGPID_SPLIT_MAX];
    size_t nimages = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "-W") || !strcmp(a, "--workdir")
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
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return PGPID_OK;
        } else if (!strcmp(a, "-V") || !strcmp(a, "--version")) {
            printf("%s %s\n", argv[0], PGPID_VERSION);
            return PGPID_OK;
        } else if (!strcmp(a, "--camera-size") || !strcmp(a, "--camerasize")) {
            if (++i >= argc) {
                pgpid_error(_("Error: '%s' wants a size, as WIDTHxHEIGHT."), a);
                return PGPID_USAGE;
            }
            unsigned w = 0, h = 0;
            if (sscanf(argv[i], "%ux%u", &w, &h) != 2 || !w || !h) {
                pgpid_error(_("Error: '%s' is not a size. Give it as WIDTHxHEIGHT."), argv[i]);
                return PGPID_USAGE;
            }
            given_size = argv[i];
        } else if (!strcmp(a, "--cameras")) {
            list_only = true;
        } else if (!strcmp(a, "-c") || !strcmp(a, "--camera")) {
            /* The device is optional: zbarcam takes the first camera when it
             * is given none, and naming one matters only where there are
             * several. */
            camera = (i + 1 < argc && argv[i + 1][0] != '-') ? argv[++i] : "";
        } else if (!strcmp(a, "--")) {
            continue;
        } else if (a[0] == '-' && a[1]) {
            pgpid_error(_("Error: Unrecognized option '%s'."), a);
            pgpid_try_help("secret_scan");
            return PGPID_USAGE;
        } else if (nimages < PGPID_SPLIT_MAX) {
            images[nimages++] = a;
        } else {
            pgpid_error(_("Error: Too many images given. Maximum: %d."),
                        PGPID_SPLIT_MAX);
            return PGPID_USAGE;
        }
    }

    /* Answered before anything else is prepared: nothing is read, so there is
     * no working directory to make and nothing to clean up afterwards.
     *
     * It exists because a window has no way of choosing. Asked which camera,
     * this action asks back, and a program driving it has no answer to give
     * and no list to put in front of the person who does -- foodjis was left
     * either taking whichever camera came first, which is the coin toss the
     * enumeration was written to stop, or reading the choice off a sentence
     * meant for a human and translated. */
    if (list_only) {
        struct camera cams[MAX_CAMERAS];
        size_t n = list_cameras(cams, MAX_CAMERAS);
        static const char *const COLUMNS[] = { "device", "name" };
        pgpid_table_start(COLUMNS, 2);
        for (size_t i = 0; i < n; i++) {
            const char *values[] = { cams[i].path, cams[i].name };
            pgpid_table_row(values);
        }
        pgpid_table_end();
        return n ? PGPID_OK : PGPID_NOTHING;
    }

    if (!nimages && !camera) {
        pgpid_error(_("Error: Which images? Name some, or --camera to read them off one."));
        usage(stderr);
        return PGPID_USAGE;
    }

    char workdir[512];
    if (given_workdir) {
        snprintf(workdir, sizeof workdir, "%s", given_workdir);
    } else {
        snprintf(workdir, sizeof workdir, "/tmp/pgpid-scan.XXXXXX");
        if (!mkdtemp(workdir)) {
            pgpid_error(_("Error: Cannot make a working directory."));
            return PGPID_FAIL;
        }
    }
    if (workdir_is_unclean(workdir)) {
        pgpid_error(_("Error: Working directory is unclean (it holds SECRET*)."));
        pgpid_error(_("Suggestion: bl-security shred_path --remove '%s'"), workdir);
        return PGPID_USAGE;
    }

    char parts[MAX_PARTS][262144];
    bool have[MAX_PARTS] = { false };
    int version = -1, needed_less_one = -1;

    for (size_t i = 0; i < nimages; i++) {
        char image[600];
        snprintf(image, sizeof image, "%.550s", images[i]);
        if (is_pdf(images[i])) {
            char converted[600], from[620];
            snprintf(converted, sizeof converted, "%.500s/scan-%zu.png", workdir, i);
            snprintf(from, sizeof from, "pdf:%.550s", images[i]);
            const char *conv[] = { "convert", from, converted, NULL };
            if (pgpid_run_program(conv, NULL, NULL)) {
                pgpid_error(_("Error: Can't convert pdf %s."), images[i]);
                return PGPID_FAIL;
            }
            snprintf(image, sizeof image, "%s", converted);
        }

        /* In memory, like the camera path: what zbar prints is a piece of a
         * secret key, and a file holding one between a write and an unlink is
         * a file a crash leaves behind. */
        static char raw[1048576];
        raw[0] = '\0';
        const char *zbar[] = { "zbarimg", "--quiet", "-Sdisable", "-Sqrcode.enable",
                               image, NULL };
        /* Bytes kept, not a status — see the camera loop. */
        if (pgpid_capture(zbar, raw, sizeof raw) <= 0) {
            pgpid_error(_("Error: No QR code with expected data in '%s'."), images[i]);
            return PGPID_FAIL;
        }

        int taken = take_payloads(raw, parts, have, &version, &needed_less_one);
        if (taken == 3)
            return 3;
        bool any = taken > 0;
        if (!any) {
            pgpid_error(_("Error: No QR code with expected data in '%s'."), images[i]);
            return PGPID_FAIL;
        }
        pgpid_error(_("Info: QR code(s) with expected data read from '%s'."), images[i]);
    }

    if (camera) {
        int rc = scan_camera(camera, given_size, workdir, parts, have, &version, &needed_less_one);
        if (rc)
            return rc;
    }

    if (version != 4 && version != 5) {
        pgpid_error(_("Crit: Unsupported qrcode version (%d)."), version);
        pgpid_error(_("Only versions 4 and 5 are read here. Versions 1 to 3 were "
                    "experimental, never released, and needed an extra passphrase "
                    "that also protected the key."));
        pgpid_error(_("'bl-pgpkey scan' still reads them, should such a sheet turn up."));
        return 3;
    }

    int needed = needed_less_one + 1;
    size_t got = 0;
    for (size_t i = 0; i < MAX_PARTS; i++)
        if (have[i])
            got++;
    if ((int)got < needed) {
        char missing[256] = "";
        for (size_t i = 0; i < (size_t)needed; i++)
            if (!have[i])
                snprintf(missing + strlen(missing), sizeof missing - strlen(missing),
                         "%s%zu", *missing ? ", " : "", i + 1);
        pgpid_error(_("Error: %zu fragment(s) of the %d needed; missing: %s."),
                    got, needed, missing);
        return PGPID_FAIL;
    }

    char secret[600];
    snprintf(secret, sizeof secret, "%.500s/SECRET", workdir);

    if (version == 4) {
        /* Consecutive pieces: back to back, in order, then decoded whole. */
        char joined[2621440] = "";
        size_t at = 0;
        for (size_t i = 0; i < MAX_PARTS; i++) {
            if (!have[i])
                continue;
            int wrote = snprintf(joined + at, sizeof joined - at, "%s", parts[i]);
            if (wrote < 0)
                break;
            at += (size_t)wrote;
        }
        const char *dec[] = { "basenc", "--decode", "--base64url", NULL };
        if (pgpid_run_program(dec, joined, secret)) {
            pgpid_error(_("Error: basenc would not decode the fragments."));
            return PGPID_FAIL;
        }
    } else {
        /* Shares: the first three characters of each are the number gfsplit
         * needs to know which share it is holding. */
        for (size_t i = 0; i < MAX_PARTS; i++) {
            if (!have[i])
                continue;
            char share[620];
            snprintf(share, sizeof share, "%.500s/SECRET.%.3s", workdir, parts[i]);
            const char *dec[] = { "basenc", "--decode", "--base64url", NULL };
            if (pgpid_run_program(dec, parts[i] + 3, share)) {
                pgpid_error(_("Error: basenc would not decode fragment %zu."), i + 1);
                return PGPID_FAIL;
            }
        }
        const char *comb[MAX_PARTS + 2];
        size_t at = 0;
        comb[at++] = "gfcombine";
        char names[MAX_PARTS][620];
        for (size_t i = 0; i < MAX_PARTS; i++) {
            if (!have[i])
                continue;
            snprintf(names[at - 1], sizeof names[0], "%.500s/SECRET.%.3s",
                     workdir, parts[i]);
            comb[at] = names[at - 1];
            at++;
        }
        comb[at] = NULL;
        if (pgpid_run_program(comb, NULL, NULL)) {
            pgpid_error(_("Error: gfcombine would not put the fragments back together."));
            return PGPID_FAIL;
        }
    }

    /* No passphrase: a secret key protected the way RFC 9580 means it imports
     * as it stands, still protected, and whoever moves it onto a card strips
     * it there. Versions 1 to 3 were the exception — the passphrase that
     * over-encrypted their fragments also protected the key they rebuilt —
     * and those are not read here. */
    const char *import[] = { "--batch", "--import", secret, NULL };
    if (pgpid_run_engine(import)) {
        pgpid_error(_("Error: gpg would not import what came back."));
        pgpid_error(_("Fragments from two different printings, most likely."));
        return PGPID_FAIL;
    }

    /* The fingerprint of what was just restored, read off the packets. */
    char packets[262144];
    const char *list[] = { "--list-packets", secret, NULL };
    if (pgpid_capture_engine(list, packets, sizeof packets) > 0)
        for (char *line = packets, *save; (line = strtok_r(line, "\n", &save)); line = NULL) {
            const char *at = strstr(line, "issuer");
            if (!at)
                continue;
            for (const char *p = at; *p; p++) {
                size_t n = 0;
                while (p[n] && strchr("0123456789ABCDEFabcdef", p[n]))
                    n++;
                if (n == 40) {
                    /* Both, and they are not the same thing. stdout is the
                     * fingerprint, for whatever runs this and reads it back;
                     * stderr is the sentence, for the person at the terminal
                     * -- who otherwise watches a scan end in silence, the one
                     * line that said it worked having been swallowed by the
                     * caller's $( ). */
                    pgpid_error(_("Notice: Secret key put back together: %.40s."), p);
                    printf("%.40s\n", p);
                    return PGPID_OK;
                }
                if (n)
                    p += n - 1;
            }
        }
    pgpid_error(_("Notice: Secret key put back together, and imported."));
    return PGPID_OK;
}
