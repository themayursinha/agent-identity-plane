package verify_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
	"github.com/themayursinha/agent-identity-plane/internal/token"
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
	_, gw, err := w.HappyPath()
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

func TestVerifyRejectsNonSingleAudience(t *testing.T) {
	log, err := audit.NewLogger(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	_, gw, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	_, claims, _, err := token.ParseUnverified(gw)
	if err != nil {
		t.Fatal(err)
	}
	claims.Aud = token.Audience{scenario.Gateway, "https://other.example"}
	signer, err := token.SignerFromKeyFile(w.STSKey)
	if err != nil {
		t.Fatal(err)
	}
	multi, err := signer.SignClaims(claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Verifier.Verify(multi, scenario.Gateway); err != token.ErrAudience {
		t.Fatalf("got %v want ErrAudience", err)
	}
}
