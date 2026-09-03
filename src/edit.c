/* Answering gpg's --edit-key questions, without gpgme.
 *
 * Copyright 2026 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
 * Copyright 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
 *
 * SPDX-License-Identifier: GPL-3.0-only
 *
 * This is what gpgme_op_interact did, and it did it by running the same gpg
 * with the same two pipes: answers go down --command-fd, questions come up
 * --status-fd as "[GNUPG:] GET_LINE keyedit.prompt" lines. Keeping it here
 * costs one file and removes a library.
 *
 * Every question must be answered or gpg waits for ever, so the caller's
 * function is asked about all of them and an empty line is a valid answer.
 */
#include "pgpid.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int pgpid_edit_key(const char *fpr, pgpid_edit_fn fn, void *opaque)
{
    int cmd[2], sta[2];
    if (pipe(cmd))
        return -1;
    if (pipe(sta)) {
        close(cmd[0]);
        close(cmd[1]);
        return -1;
    }

    char cmdfd[16], stafd[16];
    snprintf(cmdfd, sizeof cmdfd, "%d", cmd[0]);
    snprintf(stafd, sizeof stafd, "%d", sta[1]);

    pid_t pid = fork();
    if (pid < 0) {
        close(cmd[0]); close(cmd[1]); close(sta[0]); close(sta[1]);
        return -1;
    }
    if (pid == 0) {
        close(cmd[1]);
        close(sta[0]);
        /* gpg's own chatter would land in the caller's output; the answers
         * are on the status pipe and that is what is read. */
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, STDOUT_FILENO);
            close(null);
        }
        /* --no-tty or gpg goes looking for /dev/tty and gives up: the
         * questions come up the status pipe, the answers go down the
         * command pipe, and there is no terminal in the picture. */
        const char *argv[] = { "--no-tty", "--status-fd", stafd,
                               "--command-fd", cmdfd, "--edit-key", fpr, NULL };
        pgpid_exec_engine(argv);
        _exit(127);
    }

    close(cmd[0]);
    close(sta[1]);

    FILE *status = fdopen(sta[0], "r");
    if (!status) {
        close(cmd[1]);
        close(sta[0]);
        waitpid(pid, NULL, 0);
        return -1;
    }

    char line[4096];
    while (fgets(line, sizeof line, status)) {
        char *p = strchr(line, '\n');
        if (p)
            *p = '\0';
        if (strncmp(line, "[GNUPG:] ", 9))
            continue;
        char *word = line + 9;
        char *ask = strchr(word, ' ');
        if (ask)
            *ask++ = '\0';
        if (strcmp(word, "GET_LINE") && strcmp(word, "GET_BOOL")
            && strcmp(word, "GET_HIDDEN"))
            continue;

        const char *answer = fn(opaque, word, ask ? ask : "");
        if (!answer)
            answer = "";
        if (write(cmd[1], answer, strlen(answer)) < 0
            || write(cmd[1], "\n", 1) < 0)
            break;
    }

    fclose(status);
    close(cmd[1]);
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}
