//go:build unix

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/themayursinha/agent-identity-plane/internal/visoradapter"
	"github.com/themayursinha/agent-identity-plane/internal/visorsession"
)

// execVisor replaces this process with mcp-visor so SIGTERM hits visor,
// not a wrapper. The STS token is not in the child environment. actorJSON
// is written to a pipe dup2'd onto fd 3 (CLOEXEC cleared). The payload is
// capped below typical pipe capacity so this write cannot deadlock waiting
// for visor to become the reader.
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
	if _, err := w.Write(actorJSON); err != nil {
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
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(visorsession.ActorFD), syscall.F_SETFD, 0); errno != 0 {
		return errno
	}
	argv := append([]string{path}, args...)
	return syscall.Exec(path, argv, visorsession.ChildEnv(os.Environ()))
}
