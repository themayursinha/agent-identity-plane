package sts_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/attest"
	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
)

func TestSTSIssuedSubjectJTIReplay(t *testing.T) {
	w := testWorld(t)
	user, _ := w.UserToken()
	r1 := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if r1.ReasonCode != sts.ReasonOK {
		t.Fatal(r1.ReasonCode, r1.ErrorDesc)
	}
	r2 := w.Exchange(scenario.Invest, scenario.WLInvest, r1.Token, scenario.Gateway, "mcp:github:pr")
	if r2.ReasonCode != sts.ReasonOK {
		t.Fatal(r2.ReasonCode, r2.ErrorDesc)
	}
	r3 := w.Exchange(scenario.Invest, scenario.WLInvest, r1.Token, scenario.Gateway, "mcp:github:pr")
	if r3.ReasonCode != sts.ReasonReplayedToken {
		t.Fatalf("got %s want replayed_token", r3.ReasonCode)
	}
	if r3.Token != "" {
		t.Fatal("token issued on replay")
	}
}

func TestKeyringOverlapOnSTS(t *testing.T) {
	w := testWorld(t)
	user, _ := w.UserToken()
	r1 := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if r1.ReasonCode != sts.ReasonOK {
		t.Fatal(r1)
	}
	next, err := token.GenerateEd25519("sts-2")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.STS.Signer.Replace("sts-1", []*token.KeyFile{w.STSKey, next}); err != nil {
		t.Fatal(err)
	}
	if err := w.STS.Signer.Replace("sts-2", []*token.KeyFile{w.STSKey, next}); err != nil {
		t.Fatal(err)
	}
	w.Verifier.Keys = w.STS.Signer.JWKS()
	if _, err := w.Verifier.Verify(r1.Token, scenario.Invest); err != nil {
		t.Fatalf("old kid should still verify: %v", err)
	}
	r2 := w.Exchange(scenario.Invest, scenario.WLInvest, r1.Token, scenario.Gateway, "mcp:github:pr")
	if r2.ReasonCode != sts.ReasonOK {
		t.Fatal(r2.ReasonCode, r2.ErrorDesc)
	}
	h, _, _, err := token.ParseUnverified(r2.Token)
	if err != nil {
		t.Fatal(err)
	}
	if h.KID != "sts-2" {
		t.Fatalf("kid %s", h.KID)
	}
}

func TestReplaySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "replay.jsonl")
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	c1, err := sts.OpenReplayCache(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	exp := now.Add(2 * time.Minute).Unix()
	if err := c1.Consume("jti-restart", exp); err != nil {
		t.Fatal(err)
	}
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	c2, err := sts.OpenReplayCache(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c2.Close() })
	if err := c2.Consume("jti-restart", exp); err != sts.ErrReplay {
		t.Fatalf("got %v want ErrReplay", err)
	}
}

func TestReplayRejectsForeignJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mixed.jsonl")
	if err := os.WriteFile(path, []byte(`{"event_type":"token_denied","reason_code":"ok"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sts.OpenReplayCache(path, nil); err == nil {
		t.Fatal("audit-shaped replay log must fail closed")
	}
}

func TestReplayRejectsIncompleteRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.jsonl")
	if err := os.WriteFile(path, []byte(`{"jti":"consumed-token"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sts.OpenReplayCache(path, nil); err == nil {
		t.Fatal("replay record missing until must fail closed")
	}
}

func TestReplayRetainsClockSkewWindow(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	cur := now
	cache := sts.NewReplayCache(func() time.Time { return cur })
	exp := now.Unix()
	if err := cache.Consume("jti-skew", exp); err != nil {
		t.Fatal(err)
	}
	cur = now.Add(token.ClockSkew)
	if err := cache.Consume("jti-skew", exp); err != sts.ErrReplay {
		t.Fatalf("still within skew, got %v", err)
	}
}

func TestNilReplayFailsClosed(t *testing.T) {
	w := testWorld(t)
	w.STS.Replay = nil
	user, _ := w.UserToken()
	r1 := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if r1.ReasonCode != sts.ReasonOK {
		t.Fatal(r1)
	}
	r2 := w.Exchange(scenario.Invest, scenario.WLInvest, r1.Token, scenario.Gateway, "mcp:github:pr")
	if r2.ReasonCode != sts.ReasonReplayedToken {
		t.Fatalf("nil replay cache must fail closed, got %s", r2.ReasonCode)
	}
}

func TestReloadPublishesRegistryAndKeyringTogether(t *testing.T) {
	w := testWorld(t)
	dir := t.TempDir()
	regPath := filepath.Join(dir, "registry.json")
	keyPath := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(regPath, []byte(`{
	  "version": 1,
	  "agents": [
	    {"id":"spiffe://example.test/agent/oncall","workloads":["spiffe://example.test/workload/oncall"],"audiences":["spiffe://example.test/agent/investigation"],"max_scopes":["mcp:github:pr"],"max_depth":4}
	  ]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	next, err := token.GenerateEd25519("sts-2")
	if err != nil {
		t.Fatal(err)
	}
	rel := sts.NewReloader(w.STS, regPath, keyPath)
	preload, err := json.Marshal(map[string]any{"active_kid": "sts-1", "keys": []any{w.STSKey, next}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, preload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rel.Reload(); err != nil {
		t.Fatal(err)
	}
	if w.STS.Signer.ActiveKID() != "sts-1" || !w.STS.Signer.HasKID("sts-2") {
		t.Fatal("preload must publish sts-2 without activating it")
	}
	activate, err := json.Marshal(map[string]any{"active_kid": "sts-2", "keys": []any{w.STSKey, next}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, activate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rel.Reload(); err != nil {
		t.Fatal(err)
	}
	if w.STS.Signer.ActiveKID() != "sts-2" {
		t.Fatalf("kid %s", w.STS.Signer.ActiveKID())
	}
	user, _ := w.UserToken()
	res := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if res.ReasonCode != sts.ReasonOK {
		t.Fatal(res.ReasonCode, res.ErrorDesc)
	}
	h, _, _, err := token.ParseUnverified(res.Token)
	if err != nil {
		t.Fatal(err)
	}
	if h.KID != "sts-2" {
		t.Fatalf("minted kid %s", h.KID)
	}
}

func TestReloadRejectsUnpublishedActivation(t *testing.T) {
	w := testWorld(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "keys.json")
	next, err := token.GenerateEd25519("sts-2")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"active_kid": "sts-2", "keys": []any{w.STSKey, next}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	rel := sts.NewReloader(w.STS, "", keyPath)
	if err := rel.Reload(); err == nil {
		t.Fatal("expected unpublished activation to fail")
	}
	if w.STS.Signer.ActiveKID() != "sts-1" {
		t.Fatalf("active mutated: %s", w.STS.Signer.ActiveKID())
	}
}

func TestReloadRejectsMutatedPublishedMaterial(t *testing.T) {
	w := testWorld(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "keys.json")
	mutated, err := token.GenerateEd25519("sts-1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"active_kid": "sts-1", "keys": []any{mutated}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	rel := sts.NewReloader(w.STS, "", keyPath)
	if err := rel.Reload(); err == nil {
		t.Fatal("expected mutated published material to fail")
	}
	if w.STS.Signer.ActiveKID() != "sts-1" {
		t.Fatalf("active mutated: %s", w.STS.Signer.ActiveKID())
	}
}

func TestRegistryReloadFailClosed(t *testing.T) {
	w := testWorld(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "registry.json")
	if err := os.WriteFile(good, []byte(`{
	  "version": 1,
	  "agents": [
	    {"id":"spiffe://example.test/agent/oncall","workloads":["spiffe://example.test/workload/oncall"],"audiences":["spiffe://example.test/agent/investigation"],"max_scopes":["mcp:github:pr"],"max_depth":4}
	  ]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rel := sts.NewReloader(w.STS, good, "")
	if err := rel.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte(`{"version":1,"agents":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rel.Reload(); err == nil {
		t.Fatal("expected invalid registry to fail")
	}
	user, _ := w.UserToken()
	res := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if res.ReasonCode != sts.ReasonOK {
		t.Fatalf("previous registry should remain: %s %s", res.ReasonCode, res.ErrorDesc)
	}
}

func TestDenylistReloadFailClosed(t *testing.T) {
	w := testWorld(t)
	path := filepath.Join(t.TempDir(), "denylist.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"agents":["spiffe://example.test/agent/oncall"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rel := sts.NewReloader(w.STS, "", "")
	rel.DenylistPath = path
	if err := rel.Reload(); err != nil {
		t.Fatal(err)
	}
	user, _ := w.UserToken()
	res := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if res.ReasonCode != sts.ReasonAgentDenied {
		t.Fatalf("got %s", res.ReasonCode)
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"agents":[]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rel.Reload(); err == nil {
		t.Fatal("expected invalid denylist to fail")
	}
	res = w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if res.ReasonCode != sts.ReasonAgentDenied {
		t.Fatalf("previous denylist should remain: %s", res.ReasonCode)
	}
}

func TestRateLimitHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	w.STS.RateLimit = 1
	h := w.STS.Handler()
	denied := 0
	for i := 0; i < 8; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		if rw.Code == http.StatusTooManyRequests {
			denied++
		}
	}
	if denied == 0 {
		t.Fatal("expected some rate-limited responses")
	}
	if w.STS.Metrics.Denied.Load() == 0 {
		t.Fatal("rate-limit denials must increment aip_sts_denied_total")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, `"event_type":"token_denied"`) {
		t.Fatalf("missing token_denied audit: %s", body)
	}
	if !strings.Contains(body, `"reason_code":"rate_limited"`) {
		t.Fatalf("missing rate_limited audit: %s", body)
	}
}

func TestReadyzAndMetrics(t *testing.T) {
	w := testWorld(t)
	ts := httptest.NewServer(w.STS.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("readyz %d", resp.StatusCode)
	}
	resp, err = http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "aip_sts_minted_total") {
		t.Fatalf("metrics: %s", buf[:n])
	}
}

func TestReadyzFailsWhenLiveWorkloadJWKSUnavailable(t *testing.T) {
	w := testWorld(t)
	w.STS.Attestor = attest.FirstSuccessful{
		w.STS.Attestor,
		&attest.SPIFFEJWT{KeysFn: func() (token.JWKS, error) {
			return token.JWKS{}, errors.New("jwks down")
		}},
	}
	ts := httptest.NewServer(w.STS.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz %d", resp.StatusCode)
	}
}

func TestNewServerTLSPairRequired(t *testing.T) {
	w := testWorld(t)
	w.STS.TLSCertFile = "cert.pem"
	if _, err := sts.NewServer(w.STS); err == nil {
		t.Fatal("expected cert/key pair error")
	}
}

func TestTLSHandlerHealthz(t *testing.T) {
	w := testWorld(t)
	ts := httptest.NewTLSServer(w.STS.Handler())
	t.Cleanup(ts.Close)
	resp, err := ts.Client().Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
