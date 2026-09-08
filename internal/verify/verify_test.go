package verify_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

func TestHelpers(t *testing.T) {
	log, err := audit.NewLogger(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	_, gw, err := w.UberHappyPath()
	if err != nil {
		t.Fatal(err)
	}
	c, err := w.Verifier.Verify(gw, scenario.Gateway)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify.RequireDepth(c, 2); err != nil {
		t.Fatal(err)
	}
	if err := verify.RequireDepth(c, 1); err != verify.ErrDepth {
		t.Fatalf("got %v", err)
	}
	if err := verify.RequireAgent(c, scenario.Invest); err != nil {
		t.Fatal(err)
	}
	if err := verify.RequireAgent(c, scenario.Oncall); err != verify.ErrAgent {
		t.Fatalf("got %v", err)
	}
	if err := verify.RequireScope(c, "mcp:github:pr"); err != nil {
		t.Fatal(err)
	}
	if err := verify.RequireScope(c, "secret:exfil"); err != verify.ErrScope {
		t.Fatalf("got %v", err)
	}
	if err := verify.RequirePrincipal(c, scenario.User); err != nil {
		t.Fatal(err)
	}
}
