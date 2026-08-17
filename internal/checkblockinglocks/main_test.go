package main

import (
	"os"
	"path/filepath"
	"testing"
)

func analyzeTestSource(t *testing.T, source string) []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.go")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	diagnostics, err := analyzeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return diagnostics
}

func TestRejectsBlockingChannelOperationUnderLock(t *testing.T) {
	diagnostics := analyzeTestSource(t, `package p
import "sync"
type owner struct { l sync.Mutex; queue chan int }
func send(o *owner) {
	o.l.Lock()
	defer o.l.Unlock()
	o.queue <- 1
}`)
	if len(diagnostics) != 1 {
		t.Fatalf("got %d diagnostics, want 1: %v", len(diagnostics), diagnostics)
	}
}

func TestAcceptsCancellationAndAdmissionAfterUnlock(t *testing.T) {
	diagnostics := analyzeTestSource(t, `package p
import "sync"
type owner struct { lifecycleMu sync.Mutex; queue chan int }
func send(o *owner) {
	o.lifecycleMu.Lock()
	o.lifecycleMu.Unlock()
	o.queue <- 1
}
func trySend(o *owner) {
	o.lifecycleMu.Lock()
	defer o.lifecycleMu.Unlock()
	select { case o.queue <- 1: default: }
}`)
	if len(diagnostics) != 0 {
		t.Fatalf("unexpected diagnostics: %v", diagnostics)
	}
}
