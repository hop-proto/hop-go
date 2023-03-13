CC := gcc
CFLAGS := -Ofast -Wextra -Wall -Werror

GO_FILES := $(shell find .. -name "*.go")

default: pty_time/pty_time hop

pty_time/pty_time: pty_time/pty_time.c
	$(CC) $(CFLAGS) $^ -o $@

hop: $(GO_FILES)
	go build -o hop ../cmd/hop/main.go

BIG_FILES := 1kB_file 1MB_file 100MB_file 1GB_file 10GB_file

.PHONY: files
files: $(BIG_FILES)

1kB_file:
	dd bs=1000 count=1 if=/dev/urandom of=$@ status=progress

1MB_file:
	dd bs=1000000 count=1 if=/dev/urandom of=$@ status=progress

100MB_file:
	dd bs=4000000 count=25 if=/dev/urandom of=$@ status=progress

1GB_file:
	dd bs=4000000 count=250 if=/dev/urandom of=$@ status=progress

10GB_file:
	dd bs=4000000 count=2500 if=/dev/urandom of=$@ status=progress

.PHONY: clean
clean:
	-rm pty_time/pty_time
	-rm hop
	-rm $(BIG_FILES)
