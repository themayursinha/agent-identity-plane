package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const maxSymlinkHops = 256

type namedPath struct {
	flag string
	path string
}

// rejectAliasedPaths fails closed when two exclusive identity files
// resolve to the same path or inode. Resolution follows symlink chains
// including a dangling final component, so two links to the same
// not-yet-created target are aliases.
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
	return resolvePath(filepath.Clean(abs), 0, map[string]struct{}{})
}

func resolvePath(abs string, hops int, seen map[string]struct{}) (string, error) {
	if hops > maxSymlinkHops {
		return "", fmt.Errorf("serve: symlink hop limit exceeded")
	}
	dir, base := filepath.Split(abs)
	parent := filepath.Clean(dir)
	if dir != "" && parent != abs {
		resolved, err := resolvePath(parent, hops, seen)
		if err != nil {
			return "", err
		}
		abs = filepath.Join(resolved, base)
	}
	if _, ok := seen[abs]; ok {
		return "", fmt.Errorf("serve: symlink loop at %s", abs)
	}
	fi, err := os.Lstat(abs)
	if err != nil {
		return abs, nil
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return abs, nil
	}
	seen[abs] = struct{}{}
	target, err := os.Readlink(abs)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(abs), target)
	}
	return resolvePath(filepath.Clean(target), hops+1, seen)
}
