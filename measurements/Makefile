CC := gcc
CFLAGS := -Ofast -g

GO_FILES := $(shell find .. -name "*.go")

default: pty_time/pty_time hop

pty_time/pty_time: pty_time/pty_time.c
	$(CC) $(CFLAGS) $^ -o $@

hop: $(GO_FILES)
	go build ../cmd/hop/main.go
	mv main hop

.PHONY: clean
clean:
	-rm pty_time/pty_time
	-rm hop
