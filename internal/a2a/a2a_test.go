package a2a

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	if !strings.HasPrefix(seen, "DPoP ") {
		t.Fatalf("auth %q", seen)
	}
	if _, err := w.Verifier.Verify(AccessToken(seen), scenario.Invest); err != nil {
		t.Fatal(err)
	}
}

func TestTripperRetriesUseDPoPNonce(t *testing.T) {
	log, err := audit.NewLogger(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	user, err := w.UserToken()
	if err != nil {
		t.Fatal(err)
	}
	actor, err := w.ActorToken(scenario.WLOncall)
	if err != nil {
		t.Fatal(err)
	}
	exchanges := 0
	ex := countingExchanger{inner: LocalExchanger{STS: w.STS}, n: &exchanges}
	n := 0
	var nonce string
	dest := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		n++
		if n == 1 {
			rw.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", algs="EdDSA"`)
			rw.Header().Set("DPoP-Nonce", "n-test")
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw := r.Header.Get("DPoP")
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			t.Errorf("dpop %q", raw)
			rw.WriteHeader(400)
			return
		}
		pb, err := token.B64Decode(parts[1])
		if err != nil {
			t.Error(err)
			rw.WriteHeader(400)
			return
		}
		var c struct {
			Nonce string `json:"nonce"`
		}
		if err := json.Unmarshal(pb, &c); err != nil {
			t.Error(err)
			rw.WriteHeader(400)
			return
		}
		nonce = c.Nonce
		rw.WriteHeader(204)
	}))
	t.Cleanup(dest.Close)
	client := &http.Client{Transport: &Tripper{
		Exchanger: ex,
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, dest.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if n != 2 {
		t.Fatalf("requests %d", n)
	}
	if exchanges != 1 {
		t.Fatalf("exchanges %d", exchanges)
	}
	if nonce != "n-test" {
		t.Fatalf("nonce %q", nonce)
	}
}

type countingExchanger struct {
	inner Exchanger
	n     *int
}

func (c countingExchanger) Exchange(ctx context.Context, req sts.ExchangeRequest) (sts.ExchangeResult, error) {
	*c.n++
	return c.inner.Exchange(ctx, req)
}

func TestAccessTokenAcceptsDPoPScheme(t *testing.T) {
	tok := "header.payload.sig"
	if got := AccessToken("DPoP " + tok); got != tok {
		t.Fatalf("%q", got)
	}
	if got := AccessToken("Bearer " + tok); got != tok {
		t.Fatalf("%q", got)
	}
	if AccessToken("Basic x") != "" {
		t.Fatal("basic")
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

func TestTripperDPoPHTUUsesHTTPSURL(t *testing.T) {
	log, err := audit.NewLogger(filepath.Join(t.TempDir(), "a.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	user, err := w.UserToken()
	if err != nil {
		t.Fatal(err)
	}
	actor, err := w.ActorToken(scenario.WLOncall)
	if err != nil {
		t.Fatal(err)
	}
	var htu string
	dest := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("DPoP")
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			t.Errorf("dpop %q", raw)
			rw.WriteHeader(400)
			return
		}
		pb, err := token.B64Decode(parts[1])
		if err != nil {
			t.Error(err)
			rw.WriteHeader(400)
			return
		}
		var c struct {
			HTU string `json:"htu"`
		}
		if err := json.Unmarshal(pb, &c); err != nil {
			t.Error(err)
			rw.WriteHeader(400)
			return
		}
		htu = c.HTU
		rw.WriteHeader(204)
	}))
	t.Cleanup(dest.Close)
	base := dest.Client().Transport
	client := dest.Client()
	client.Transport = &Tripper{
		Base:      base,
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
	}
	ctx := WithSubjectToken(context.Background(), user)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dest.URL+"/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("status %d htu %s", resp.StatusCode, htu)
	}
	if !strings.HasPrefix(htu, "https://") || !strings.HasSuffix(htu, "/session") {
		t.Fatalf("htu %s", htu)
	}
}
