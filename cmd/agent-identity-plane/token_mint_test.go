package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
	"github.com/themayursinha/agent-identity-plane/internal/token"
)

func TestTokenMintOperatorHops(t *testing.T) {
	dir := t.TempDir()
	log, err := audit.NewLogger(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	w, err := scenario.NewWorld(time.Now().UTC(), log)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(w.STS.Handler())
	t.Cleanup(ts.Close)

	writeKey := func(name string, kf *token.KeyFile) string {
		t.Helper()
		path := filepath.Join(dir, name)
		b, err := json.Marshal(kf)
		if err != nil {
			t.Fatal(err)
		}
		if err := token.WriteSecretFile(path, append(b, '\n')); err != nil {
			t.Fatal(err)
		}
		return path
	}
	idp := writeKey("idp.json", w.IdPKey)
	oncall := writeKey("wl-oncall.json", w.WL[scenario.WLOncall])
	invest := writeKey("wl-invest.json", w.WL[scenario.WLInvest])
	stsURL := ts.URL + "/oauth/token"

	hop1, err := mintAccessToken([]string{
		"-sts", stsURL,
		"-issuer", scenario.Issuer,
		"-idp-key", idp,
		"-idp-issuer", scenario.IdPIssuer,
		"-user", scenario.User,
		"-actor-key", oncall,
		"-agent-id", scenario.Oncall,
		"-audience", scenario.Invest,
		"-scope", "mcp:github:pr mcp:alerts:read",
	})
	if err != nil {
		t.Fatalf("hop1: %v", err)
	}
	if _, err := w.Verifier.Verify(hop1, scenario.Invest); err != nil {
		t.Fatalf("hop1 verify: %v", err)
	}

	hop2, err := mintAccessToken([]string{
		"-sts", stsURL,
		"-issuer", scenario.Issuer,
		"-subject-token", hop1,
		"-actor-key", invest,
		"-agent-id", scenario.Invest,
		"-audience", scenario.Gateway,
		"-scope", "mcp:github:pr",
	})
	if err != nil {
		t.Fatalf("hop2: %v", err)
	}
	if _, err := w.Verifier.Verify(hop2, scenario.Gateway); err != nil {
		t.Fatalf("hop2 verify: %v", err)
	}

	open := filepath.Join(dir, "open.json")
	if err := os.WriteFile(open, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := mintAccessToken([]string{
		"-sts", stsURL,
		"-issuer", scenario.Issuer,
		"-idp-key", idp,
		"-idp-issuer", scenario.IdPIssuer,
		"-user", scenario.User,
		"-actor-key", open,
		"-agent-id", scenario.Oncall,
		"-audience", scenario.Invest,
	}); err == nil {
		t.Fatal("world-readable actor key must fail")
	}

	unbound, err := token.GenerateEd25519("wl-x")
	if err != nil {
		t.Fatal(err)
	}
	unboundPath := writeKey("unbound.json", unbound)
	if _, err := mintAccessToken([]string{
		"-sts", stsURL,
		"-issuer", scenario.Issuer,
		"-idp-key", idp,
		"-idp-issuer", scenario.IdPIssuer,
		"-user", scenario.User,
		"-actor-key", unboundPath,
		"-agent-id", scenario.Oncall,
		"-audience", scenario.Invest,
	}); err == nil {
		t.Fatal("unbound actor key must fail")
	}

	if _, err := mintAccessToken([]string{
		"-sts", "http://example.test/oauth/token",
		"-issuer", scenario.Issuer,
		"-idp-key", idp,
		"-idp-issuer", scenario.IdPIssuer,
		"-user", scenario.User,
		"-actor-key", oncall,
		"-agent-id", scenario.Oncall,
		"-audience", scenario.Invest,
	}); err == nil {
		t.Fatal("non-loopback http STS must fail")
	}
}
