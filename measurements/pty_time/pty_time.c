#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <stdint.h>
#include <pty.h>

#define CHECK_STATUS(status) do { \
    if ((status) < 0) { \
        char STATUS_BUFFER[4096]; \
        snprintf(STATUS_BUFFER, sizeof(STATUS_BUFFER), "status failed on line %d", __LINE__); \
        perror(STATUS_BUFFER); \
        exit(1); \
    } \
} while (0);

int Write(int fd, void *buf, size_t nbytes) {
    size_t written = 0;
    while (written < nbytes) {
        ssize_t res = write(fd, (char *)buf + written, nbytes - written);
        if (res < 0) {
            return -1;
        }
        written += res;
    }
    return 0;
}
int Read(int fd, void *buf, size_t nbytes) {
    size_t nread = 0;
    while (nread < nbytes) {
        ssize_t res = read(fd, (char *)buf + nread, nbytes - nread);
        if (res < 0) {
            return -1;
        }
        nread += res;
    }
    return 0;
}
uint64_t get_time(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}
int main(int argc, char *argv[]) {
    if (argc == 1) {
        fprintf(stderr, "Usage: %s <string to search for> cmd args\n", argv[0]);
        return 1;
    }
    uint64_t start = get_time();
    char name[1000];
    // p for primary r for replica
    int pstdin, pstdout, rstdin, rstdout;
    CHECK_STATUS(openpty(&pstdin, &rstdin, name, NULL, NULL));
    CHECK_STATUS(openpty(&pstdout, &rstdout, name, NULL, NULL));
    int fildes[2];
    CHECK_STATUS(pipe(fildes));
    pid_t pid = fork();
    const char *key = argv[1];
    const size_t key_len = strlen(key);
    if (pid == 0) {
        // close fildes read end
        close(fildes[0]);
        // close stdin, stdout, stderr
        close(0);
        close(1);
        close(2);
        // copy replica
        dup2(rstdin, 0);
        dup2(rstdout, 1);
        dup2(rstdout, 2);
        close(pstdin);
        close(pstdout);
        uint64_t time = get_time();
        CHECK_STATUS(Write(fildes[1], &time, sizeof(time)));
        execvp(argv[2], argv + 2);
        CHECK_STATUS(0);  // should never reach
    }
    close(rstdin);
    close(rstdout);
    char buf[16 * 1024];
    size_t nread = 0;
    while (1) {
        assert(sizeof(buf) - nread);
        ssize_t nbytes = read(pstdout, buf + nread, sizeof(buf) - nread);
        CHECK_STATUS(nbytes);
        if (strstr((nread > key_len) ? buf + nread - key_len : buf, key) != NULL) {
            uint64_t now = get_time();
            uint64_t then;
            CHECK_STATUS(Read(fildes[0], &then, sizeof(then)));
            now -= start;
            then -= start;
            printf("process start at: %lu microseconds\nkey string at: %lu microseconds\ndiff: %lu microseconds\n", then, now, now - then);
            // printf("%s\n", buf);

            // Closing the write end of the pipe closes the child process
            // At least it does for hop
            // TODO(hosono) ssh doesn't actually close when you close this file
            CHECK_STATUS(close(pstdin));

            CHECK_STATUS(kill(pid, SIGINT));

            // We intentionally orphan the process here since hop and ssh both close once stdin is closed
            if (waitpid(pid, NULL, WNOHANG) == -1) {
                perror("waitpid");
                return 1;
            }
            return 0;
        }
        nread += nbytes;
    }
}

