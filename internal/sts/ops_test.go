package sts_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestRateLimitHTTP(t *testing.T) {
	w := testWorld(t)
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
