/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 *
 * @author Your Name <andrewid@andrew.cmu.edu>
 * TODO: Include your name and Andrew ID here.
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 * @brief <Write main's function header documentation. What does main do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");

            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

void unix_error(char *msg) {
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(0);
}

pid_t Fork(void) {
    pid_t pid;
    if ((pid = fork()) < 0)
        unix_error("Fork error \n");
    return pid;
}

int Open(char *pathname, int flags, mode_t mode) {
    int fd;
    if ((fd = open(pathname, flags, mode)) < 0) {
        if (errno == ENOENT) {
            sio_printf("%s: No such file or directory\n", pathname);
        } else if (errno == EACCES) {
            sio_printf("%s: Permission denied\n", pathname);
        } else {
            sio_printf("%s: Could not open file\n", pathname);
        }
        return -1;
    }
    return fd;
}

void Close(int fd) {
    if ((close(fd)) < 0) {
        sio_printf("%s: Unable to close file or directory\n", strerror(errno));
        exit(0);
    }
}

void continue_job(jid_t jid, job_state state, sigset_t prev) {
    pid_t pid = job_get_pid(jid);

    // forward the SIGCONT signal to process group PID
    kill(-pid, SIGCONT);
    job_set_state(jid, state);

    // case 1: foreground job
    if (state == FG) {
        while (fg_job()) {
            sigsuspend(&prev);
        }
    }
    // case 2: background job
    else {
        sio_printf("[%d] (%d) %s\n", jid, pid, job_get_cmdline(jid));
    }
    return;
}

void bgfg_handler(struct cmdline_tokens *token, job_state state) {

    // get the string format of the job state passed in
    const char *str_state;

    if (state == FG) {
        str_state = "fg";
    } else {
        str_state = "bg";
    }

    // PID and JID NULL check
    char *id = token->argv[1];
    if (id == NULL) {
        sio_printf("%s command requires PID or %%jobid argument\n", str_state);
        return;
    }

    // set up signal masks, jid, and pid
    sigset_t mask, prev;
    sigfillset(&mask);

    jid_t jid = 0;
    pid_t pid = 0;

    // block signals
    sigprocmask(SIG_BLOCK, &mask, &prev);

    // case 1: valid argument -- parse JID and PID
    if (id[0] == '%') {

        // search by jid
        jid = atoi(&(id[1]));

        // check if the job exists
        if (!job_exists(jid)) {
            sio_printf("%s: No such job\n", id);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            return;
        } else {
            // if the job exists, call continue_job to forward SIGCONT signal
            continue_job(jid, state, prev);
        }
    } else if (isdigit(id[0])) {
        // search by PID
        pid = atoi(&(id[0]));

        // get corresponding JID
        jid = job_from_pid(pid);

        // check if the job exists
        if (!job_exists(jid)) {
            sio_printf("%s: No such job\n", id);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            return;
        } else {
            // if the job exists, call continue_job to forward SIGCONT signal
            continue_job(jid, state, prev);
        }
    }
    // case 2: invalid argument
    else {
        sio_printf("%s: argument must be a PID or %%jobid\n", str_state);
    }

    // unblock signals
    sigprocmask(SIG_SETMASK, &prev, NULL);
    return;
}

/**
 * @brief This helper function handles the execution of builtin commands using
 * case/switch statements. This function is only called in eval.
 * @param[in] token The command line token
 * @return 1 if the parsed command is a builtin command, 0 if otherwise
 * Errors are handled with the wrappers Open and Close.
 * referenced CSAPP textbook page 781, figure 8.24
 */
int builtin_cmd(struct cmdline_tokens *token) {

    // set up signal masks
    sigset_t mask, prev;
    sigfillset(&mask);

    switch (token->builtin) {

    // case 1: not a builtin command
    case BUILTIN_NONE:
        return 0;

    // case 2: quit
    case BUILTIN_QUIT:
        exit(0);
        return 1;

    // case 3: jobs command
    case BUILTIN_JOBS:
        sigprocmask(SIG_BLOCK, &mask, &prev);

        // outfile NULL check
        if (token->outfile) {

            // call Open with parameters for STDOUT file
            int fd = Open(token->outfile, (O_WRONLY | O_CREAT | O_TRUNC),
                          (S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH));
            if (fd > 0) {
                list_jobs(fd);
                Close(fd);
            }
        } else {
            list_jobs(STDOUT_FILENO);
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);
        return 1;

    // case 4: fg command
    case BUILTIN_FG:
        bgfg_handler(token, FG);
        return 1;

    // case 5: bg command
    case BUILTIN_BG:
        bgfg_handler(token, BG);
        return 1;
    default:
        return 1;
    }
}

/**
 * @brief <What does eval do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;
    pid_t pid;
    // Parse command line
    parse_result = parseline(cmdline, &token);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    // TODO: Implement commands here.

    if (!builtin_cmd(&token)) {

        sigset_t mask, prevMask;
        jid_t jobId;
        sigfillset(&mask);
        sigprocmask(SIG_BLOCK, &mask, &prevMask);

        if ((pid = Fork()) == 0) {

            sigprocmask(SIG_SETMASK, &prevMask, NULL);
            setpgid(0, 0);
            int fd;

            // input file
            if (token.infile) {
                fd = Open(token.infile, O_RDONLY, 0);

                if (fd < 0) {
                    exit(0);
                }

                dup2(fd, STDIN_FILENO);
                Close(fd);
            }

            // output file
            if (token.outfile) {
                fd = Open(token.outfile, (O_WRONLY | O_CREAT | O_TRUNC),
                          (S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH));

                if (fd < 0) {
                    exit(0);
                }

                dup2(fd, STDOUT_FILENO);
                Close(fd);
            }

            if (execve(token.argv[0], token.argv, environ) < 0) {

                printf("%s: Command Not Found. \n", token.argv[0]);
                exit(0);
            }
        }

        if ((parse_result == PARSELINE_FG)) {

            jobId = add_job(pid, FG, cmdline);

            while (fg_job() == jobId) {
                sigsuspend(&prevMask);
            }
        }

        if ((parse_result == PARSELINE_BG)) {

            jobId = add_job(pid, BG, cmdline);
            sio_printf("[%d] (%d) %s \n", jobId, pid, cmdline);
        }

        sigprocmask(SIG_SETMASK, &prevMask, NULL);
    }
    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief <What does sigchld_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigchld_handler(int sig) {
    // set up signal masks
    sigset_t mask, prev;
    sigfillset(&mask);

    // save errno
    int old_errno = errno;
    int status;
    pid_t pid;

    // temporarily block signals to protect shared data
    sigprocmask(SIG_BLOCK, &mask, &prev);

    // handler loops until there are no more stopped/terminated children in the
    // waitset
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {

        jid_t job = job_from_pid(pid);

        // case 1: child process terminated normally
        if (WIFEXITED(status)) {
            delete_job(job);
        }

        // case 2: child process terminated due to uncaught signal
        else if (WIFSIGNALED(status)) {
            sio_printf("Job [%d] (%d) terminated by signal %d\n", job, pid,
                       WTERMSIG(status));
            delete_job(job);
        }
        // case 3: child process stopped by signal
        else if (WIFSTOPPED(status)) {
            sio_printf("Job [%d] (%d) stopped by signal %d\n", job, pid,
                       WSTOPSIG(status));
            job_set_state(job, ST);
        }
    }

    // unblock signal
    sigprocmask(SIG_SETMASK, &prev, NULL);

    // restore errno
    errno = old_errno;
    return;
}

/**
 * @brief <What does sigint_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigint_handler(int sig) {}

/**
 * @brief <What does sigtstp_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
 */
void sigtstp_handler(int sig) {}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
