package identfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectAliasedPathsSameString(t *testing.T) {
	p := filepath.Join(t.TempDir(), "shared.jsonl")
	err := RejectAliased([]Named{
		{"-audit-log", p},
		{"-dpop-replay", p},
	})
	if err == nil || !strings.Contains(err.Error(), "must not refer to the same file") {
		t.Fatalf("got %v", err)
	}
}

func TestRejectAliasedPathsRelativeAndAbs(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	err = RejectAliased([]Named{
		{"-audit-log", "audit.jsonl"},
		{"-dpop-replay", p},
	})
	if err == nil {
		t.Fatal("expected abs/relative alias to fail")
	}
}

func TestRejectAliasedPathsSymlink(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(audit, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "replay.jsonl")
	if err := os.Symlink(audit, link); err != nil {
		t.Fatal(err)
	}
	if err := RejectAliased([]Named{{"-audit-log", audit}, {"-dpop-replay", link}}); err == nil {
		t.Fatal("expected symlink alias to fail")
	}
}

func TestRejectAliasedPathsHardLink(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(audit, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	replay := filepath.Join(dir, "replay.jsonl")
	if err := os.Link(audit, replay); err != nil {
		t.Fatal(err)
	}
	if err := RejectAliased([]Named{{"-audit-log", audit}, {"-dpop-replay", replay}}); err == nil {
		t.Fatal("expected hard-link alias to fail")
	}
}

func TestRejectAliasedPathsDistinctOK(t *testing.T) {
	dir := t.TempDir()
	err := RejectAliased([]Named{
		{"-audit-log", filepath.Join(dir, "audit.jsonl")},
		{"-dpop-replay", filepath.Join(dir, "replay.jsonl")},
		{"-denylist", filepath.Join(dir, "denylist.json")},
		{"-tls-key", ""},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRejectAliasedPathsDanglingSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "shared.jsonl")
	a := filepath.Join(dir, "audit.jsonl")
	b := filepath.Join(dir, "replay.jsonl")
	if err := os.Symlink(target, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, b); err != nil {
		t.Fatal(err)
	}
	if err := RejectAliased([]Named{{"-audit-log", a}, {"-dpop-replay", b}}); err == nil {
		t.Fatal("dangling symlinks to the same target must alias")
	}
}
