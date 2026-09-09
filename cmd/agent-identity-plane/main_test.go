package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/token"
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
	if !strings.Contains(string(out), "v0.8.0") {
		t.Fatalf("version %s", out)
	}

	tr := exec.Command(bin, "trace", "-audit", filepath.Join(t.TempDir(), "missing.jsonl"))
	out, err = tr.CombinedOutput()
	if err == nil {
		t.Fatal("trace without txn or jti must fail")
	}
	if !strings.Contains(string(out), "-txn") && !strings.Contains(string(out), "-jti") {
		t.Fatalf("trace usage: %s", out)
	}

	gw := exec.Command(bin, "visor-gateway")
	out, err = gw.CombinedOutput()
	if err == nil {
		t.Fatal("visor-gateway without flags must fail")
	}
	if !strings.Contains(string(out), "-dpop-replay") {
		t.Fatalf("visor-gateway usage: %s", out)
	}

	vs := exec.Command(bin, "visor-session")
	out, err = vs.CombinedOutput()
	if err == nil {
		t.Fatal("visor-session without flags must fail")
	}
	if !strings.Contains(string(out), "-gateway") || !strings.Contains(string(out), "-dpop-key") {
		t.Fatalf("visor-session usage: %s", out)
	}
}

func TestCLIVisorSessionRejectsTypedClientID(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "aip")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	kf, err := token.GenerateEd25519("wl-1")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "workload.json")
	b, err := json.Marshal(kf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	vs := exec.Command(bin, "visor-session",
		"-gateway", "http://127.0.0.1:1/session",
		"-token", "x",
		"-dpop-key", keyPath,
		"-print",
		"--", "-client-id", "spoofed")
	out, err = vs.CombinedOutput()
	if err == nil {
		t.Fatalf("typed client-id must fail: %s", out)
	}
	if !strings.Contains(string(out), "identity flags") {
		t.Fatalf("visor-session reject: %s", out)
	}
}

func TestCLITraceJTI(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "aip")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	path := filepath.Join(t.TempDir(), "sts.jsonl")
	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err := l.Append(audit.Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-1", JTI: "jti-stolen", AgentID: "oncall"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	tr := exec.Command(bin, "trace", "-jti", "jti-stolen", "-audit", path)
	out, err = tr.CombinedOutput()
	if err != nil {
		t.Fatalf("trace: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "jti=jti-stolen") || !strings.Contains(string(out), "token_minted") {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(string(out), "verified=") {
		t.Fatalf("missing trust label: %s", out)
	}
}

func TestCLITraceRejectsGenericAuditPrefix(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "aip")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	path := filepath.Join(t.TempDir(), "sts.jsonl")
	l, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err := l.Append(audit.Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-1", JTI: "jti-stolen"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte(`{"event_type":"note"}`+"\n"), b...), 0o600); err != nil {
		t.Fatal(err)
	}
	tr := exec.Command(bin, "trace", "-jti", "jti-stolen", "-audit", path)
	out, err = tr.CombinedOutput()
	if err == nil {
		t.Fatalf("generic prefix on -audit must fail: %s", out)
	}
}
