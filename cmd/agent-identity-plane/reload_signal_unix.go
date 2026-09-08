//go:build unix

package main

import (
	"os"
	"syscall"
)

var reloadSignals = []os.Signal{syscall.SIGHUP}
