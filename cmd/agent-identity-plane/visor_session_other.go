//go:build !unix

package main

import (
	"os"
	"os/exec"

	"github.com/themayursinha/agent-identity-plane/internal/visorsession"
)

func execVisor(name string, args []string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = visorsession.ChildEnv(os.Environ())
	return cmd.Run()
}
