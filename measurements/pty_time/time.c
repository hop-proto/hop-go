#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK_STATUS(status) do { \
    if ((status) < 0) { \
        char STATUS_BUFFER[4096]; \
        snprintf(STATUS_BUFFER, sizeof(STATUS_BUFFER), "status failed on line %d", __LINE__); \
        perror(STATUS_BUFFER); \
        exit(1); \
    } \
} while (0);

int main(int argc, char *argv[]) {
    if (argc == 1) {
        fprintf(stderr, "Usage: %s <string to search for> cmd args\n", argv[0]);
        return 1;
    }

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[1], argv + 1);
        CHECK_STATUS(-1);  // should never reach
    }
    CHECK_STATUS(waitpid(pid, NULL, 0));

    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);

    uint64_t usecs = 0;
    usecs += (end.tv_sec - start.tv_sec) * 1000000;
    usecs += (end.tv_nsec - start.tv_nsec) / 1000;

    fprintf(stderr, "%lu\n", usecs);
}
