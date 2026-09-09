// Package identfile rejects aliased exclusive identity-file paths.
package identfile

import (
	"fmt"
	"os"
	"path/filepath"
)

const maxSymlinkHops = 256

// Named is a flag and the path it opens as exclusive identity state.
type Named struct {
	Flag string
	Path string
}

// RejectAliased fails closed when two exclusive identity files resolve
// to the same path or inode. Resolution follows symlink chains including
// a dangling final component, so two links to the same not-yet-created
// target are aliases. Call this before opening any of the files.
func RejectAliased(files []Named) error {
	for i := range files {
		if files[i].Path == "" {
			continue
		}
		for j := i + 1; j < len(files); j++ {
			if files[j].Path == "" {
				continue
			}
			same, err := filesAlias(files[i].Path, files[j].Path)
			if err != nil {
				return err
			}
			if same {
				return fmt.Errorf("identity: %s and %s must not refer to the same file", files[i].Flag, files[j].Flag)
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
		return "", fmt.Errorf("identity: symlink hop limit exceeded")
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
		return "", fmt.Errorf("identity: symlink loop at %s", abs)
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
