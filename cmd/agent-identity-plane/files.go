package main

import "github.com/themayursinha/agent-identity-plane/internal/identfile"

type namedPath struct {
	flag string
	path string
}

func rejectAliasedPaths(files []namedPath) error {
	named := make([]identfile.Named, len(files))
	for i, f := range files {
		named[i] = identfile.Named{Flag: f.flag, Path: f.path}
	}
	return identfile.RejectAliased(named)
}
