//go:build !unix

package main

import "os"

var reloadSignals []os.Signal
