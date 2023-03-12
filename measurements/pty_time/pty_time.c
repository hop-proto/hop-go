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
    int primary, replica;
    CHECK_STATUS(openpty(&primary, &replica, name, NULL, NULL));
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
        dup2(replica, 0);
        dup2(replica, 1);
        dup2(replica, 2);
        close(primary);
        uint64_t time = get_time();
        CHECK_STATUS(Write(fildes[1], &time, sizeof(time)));
        execvp(argv[2], argv + 2);
        CHECK_STATUS(0);  // should never reach
    }
    close(replica);
    char buf[16 * 1024];
    size_t nread = 0;
    while (1) {
        assert(sizeof(buf) - nread);
        ssize_t nbytes = read(primary, buf + nread, sizeof(buf) - nread);
        CHECK_STATUS(nbytes);
        if (strstr((nread > key_len) ? buf + nread - key_len : buf, key) != NULL) {
            uint64_t now = get_time();
            uint64_t then;
            CHECK_STATUS(Read(fildes[0], &then, sizeof(then)));
            now -= start;
            then -= start;
            printf("process start at: %llu microseconds\nkey string at: %llu microseconds\ndiff: %llu microseconds\n", then, now, now - then);
            // printf("%s\n", buf);
            

            // Write "exit" to the pipe closes both ssh and hop
            char* exit_str = "exit\n";
            CHECK_STATUS(Write(primary, exit_str, strlen(exit_str)));

            // We intentionally orphan the process here since hop takes a while to exit
            // sending "exit" will close both hop and ssh eventually
            return 0;
        }
        nread += nbytes;
    }
}

