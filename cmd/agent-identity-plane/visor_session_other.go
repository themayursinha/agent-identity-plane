//go:build !unix

package main

import "fmt"

func execVisor(string, []string) error {
	return fmt.Errorf("visor-session: exec is supported on Unix only")
}
