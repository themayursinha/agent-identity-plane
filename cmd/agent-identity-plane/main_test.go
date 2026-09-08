package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIDemoAndLint(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "aip")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	demo := exec.Command(bin, "demo", "-strict")
	out, err = demo.CombinedOutput()
	if err != nil {
		t.Fatalf("demo: %v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "scenario: allow") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "attack: unregistered_agent deny") {
		t.Fatal(s)
	}

	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// testdata lives at module root; tests run from this package dir.
	reg := filepath.Join(root, "..", "..", "testdata", "registry.json")
	if _, err := os.Stat(reg); err != nil {
		reg = filepath.Join(root, "testdata", "registry.json")
	}
	lint := exec.Command(bin, "registry", "lint", reg)
	out, err = lint.CombinedOutput()
	if err != nil {
		t.Fatalf("lint: %v\n%s", err, out)
	}

	ver := exec.Command(bin, "version")
	out, err = ver.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "v0.1.0") {
		t.Fatalf("version %s", out)
	}
}
