//go:build unix

package main

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/themayursinha/agent-identity-plane/internal/visorsession"
)

// execVisor replaces this process with mcp-visor so SIGTERM hits visor,
// not a wrapper. The STS token is not in the child environment.
func execVisor(name string, args []string) error {
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	argv := append([]string{path}, args...)
	return syscall.Exec(path, argv, visorsession.ChildEnv(os.Environ()))
}
