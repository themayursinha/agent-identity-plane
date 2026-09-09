package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/a2a"
	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
	"github.com/themayursinha/agent-identity-plane/internal/visoradapter"
)

func TestIdentityOnlyGateway(t *testing.T) {
	log, err := audit.NewLogger(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	_, gwTok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	h := a2a.Middleware(w.Verifier, scenario.Gateway)(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		chain, _ := a2a.Chain(r.Context())
		m := visoradapter.FromChain(chain, visoradapter.Options{ShortName: true})
		rw.Header().Set("X-Visor-Client-Id", m.ClientID)
		rw.Header().Set("X-Visor-Session-Id", m.SessionID)
		_ = json.NewEncoder(rw).Encode(m)
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+gwTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Visor-Client-Id"); got != "investigation" {
		t.Fatalf("client-id %s", got)
	}
	if resp.Header.Get("X-Visor-Session-Id") == "" {
		t.Fatal("missing session id")
	}

	bad, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
	resp2, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp2.StatusCode)
	}
}
