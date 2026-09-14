//go:build unix

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/themayursinha/agent-identity-plane/internal/visoradapter"
	"github.com/themayursinha/agent-identity-plane/internal/visorsession"
)

// execVisor replaces this process with mcp-visor so SIGTERM hits visor,
// not a wrapper. The STS token is not in the child environment. actorJSON
// is written to a pipe dup2'd onto fd 3 (CLOEXEC cleared). The write is
// non-blocking so a pipe smaller than the payload fails closed instead of
// waiting for visor to become the reader.
func execVisor(name string, args []string, actorJSON []byte) error {
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	if len(actorJSON) == 0 {
		return fmt.Errorf("visor-session: verified actor context required")
	}
	if len(actorJSON) > visoradapter.MaxActorJSONBytes {
		return fmt.Errorf("visor-session: verified actor context exceeds pipe-safe size")
	}
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	if err := writeActorPipe(int(w.Fd()), actorJSON); err != nil {
		_ = r.Close()
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		_ = r.Close()
		return err
	}
	rawFD := int(r.Fd())
	if err := syscall.Dup2(rawFD, visorsession.ActorFD); err != nil {
		_ = r.Close()
		return err
	}
	if rawFD != visorsession.ActorFD {
		_ = r.Close()
		r = nil
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(visorsession.ActorFD), syscall.F_SETFD, 0); errno != 0 {
		if r != nil {
			_ = r.Close()
		}
		return errno
	}
	argv := append([]string{path}, args...)
	err = syscall.Exec(path, argv, visorsession.ChildEnv(os.Environ()))
	runtime.KeepAlive(r)
	return err
}

// writeActorPipe places the whole payload with write(2) in non-blocking
// mode. A pipe that cannot accept the bytes without a reader fails closed
// instead of blocking until exec.
func writeActorPipe(fd int, actorJSON []byte) error {
	if err := syscall.SetNonblock(fd, true); err != nil {
		return err
	}
	wrote := 0
	for wrote < len(actorJSON) {
		n, err := syscall.Write(fd, actorJSON[wrote:])
		if n > 0 {
			wrote += n
		}
		if err == nil {
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return fmt.Errorf("visor-session: verified actor context exceeds pipe capacity")
		}
		return err
	}
	return nil
}
