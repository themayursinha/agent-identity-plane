//go:build unix

package main

import (
	"bytes"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestWriteActorPipeSucceedsForSmallPayload(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	payload := []byte(`{"version":"1"}`)
	if err := writeActorPipe(int(w.Fd()), payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload)+1)
	n, err := r.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:n], payload) {
		t.Fatalf("got %q", got[:n])
	}
}

func TestWriteActorPipeFailsWhenPipeFull(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	fd := int(w.Fd())
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	junk := bytes.Repeat([]byte("x"), 4096)
	for {
		_, err := syscall.Write(fd, junk)
		if err != nil {
			break
		}
	}
	if err := writeActorPipe(fd, []byte(`{"version":"1"}`)); err == nil || !strings.Contains(err.Error(), "pipe capacity") {
		t.Fatalf("got %v", err)
	}
}
