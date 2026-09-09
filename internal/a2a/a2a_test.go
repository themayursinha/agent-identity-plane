package a2a

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
)

func TestMiddlewareAndTripper(t *testing.T) {
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

	inner := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		c, ok := Chain(r.Context())
		if !ok || c.Actor != scenario.Invest {
			http.Error(rw, "no chain", 500)
			return
		}
		rw.WriteHeader(204)
	})
	h := Middleware(w.Verifier, scenario.Gateway)(inner)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+gwTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d %s", resp.StatusCode, b)
	}

	// Tripper: oncall calls investigation (audience from context).
	user, _ := w.UserToken()
	actor, _ := w.ActorToken(scenario.WLOncall)
	seen := ""
	dest := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		if r.Header.Get("DPoP") == "" {
			t.Error("missing DPoP")
		}
		rw.WriteHeader(204)
	}))
	t.Cleanup(dest.Close)
	client := &http.Client{Transport: &Tripper{
		Exchanger: LocalExchanger{STS: w.STS},
		AgentID:   scenario.Oncall,
		Audience:  scenario.Invest,
		ActorToken: func(ctx context.Context) (string, error) {
			return actor, nil
		},
		ProofKey: func(ctx context.Context) (*token.KeyFile, error) {
			return w.WL[scenario.WLOncall], nil
		},
		Now: func() time.Time { return w.Now },
	}}
	ctx := WithSubjectToken(context.Background(), user)
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, dest.URL, nil)
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != 204 || seen == "" {
		t.Fatalf("status %d auth %q", resp2.StatusCode, seen)
	}
	if _, err := w.Verifier.Verify(seen[len("Bearer "):], scenario.Invest); err != nil {
		t.Fatal(err)
	}
}

func TestMiddlewareRejectsMissing(t *testing.T) {
	log, _ := audit.NewLogger(filepath.Join(t.TempDir(), "a.jsonl"))
	t.Cleanup(func() { _ = log.Close() })
	w, _ := scenario.NewWorld(time.Now().UTC(), log)
	h := Middleware(w.Verifier, scenario.Gateway)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(204)
	}))
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestLocalExchangerDeny(t *testing.T) {
	log, _ := audit.NewLogger(filepath.Join(t.TempDir(), "a.jsonl"))
	t.Cleanup(func() { _ = log.Close() })
	w, _ := scenario.NewWorld(time.Now().UTC(), log)
	ex := LocalExchanger{STS: w.STS}
	_, err := ex.Exchange(context.Background(), sts.ExchangeRequest{AgentID: "x", Audience: "y"})
	if err == nil {
		t.Fatal("expected error")
	}
}
