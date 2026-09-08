package main

import (
	"fmt"
	"os"
	"path/filepath"
)

type namedPath struct {
	flag string
	path string
}

// rejectAliasedPaths fails closed when two exclusive identity files
// resolve to the same path or inode (symlinks and hard links included).
func rejectAliasedPaths(files []namedPath) error {
	for i := range files {
		if files[i].path == "" {
			continue
		}
		for j := i + 1; j < len(files); j++ {
			if files[j].path == "" {
				continue
			}
			same, err := filesAlias(files[i].path, files[j].path)
			if err != nil {
				return err
			}
			if same {
				return fmt.Errorf("serve: %s and %s must not refer to the same file", files[i].flag, files[j].flag)
			}
		}
	}
	return nil
}

func filesAlias(a, b string) (bool, error) {
	if a == "" || b == "" {
		return false, nil
	}
	ca, err := canonicalPath(a)
	if err != nil {
		return false, err
	}
	cb, err := canonicalPath(b)
	if err != nil {
		return false, err
	}
	if ca == cb {
		return true, nil
	}
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	if errA == nil && errB == nil {
		return os.SameFile(fa, fb), nil
	}
	return false, nil
}

func canonicalPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved, nil
	}
	dir, base := filepath.Split(abs)
	if dir == "" {
		return abs, nil
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Join(resolved, base), nil
	}
	return abs, nil
}
