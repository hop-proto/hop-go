CC := gcc
CFLAGS := -Ofast -Wextra -Wall -Werror

GO_FILES := $(shell find .. -name "*.go")

default: pty_time/pty_time hop

pty_time/pty_time: pty_time/pty_time.c
	$(CC) $(CFLAGS) $^ -o $@

hop: $(GO_FILES)
	go build -o hop ../cmd/hop/main.go

.PHONY: clean
clean:
	-rm pty_time/pty_time
	-rm hop
