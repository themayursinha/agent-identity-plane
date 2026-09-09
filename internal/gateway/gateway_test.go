package gateway_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/denylist"
	"github.com/themayursinha/agent-identity-plane/internal/dpop"
	"github.com/themayursinha/agent-identity-plane/internal/gateway"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

func testWorld(t *testing.T) *scenario.World {
	t.Helper()
	log, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func replay(w *scenario.World) *sts.ReplayCache {
	return sts.NewReplayCache(func() time.Time { return w.Now })
}

func pepReq(t *testing.T, w *scenario.World, method, path, tok, workload string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Host = "visor-gateway.test"
	req.Header.Set("Authorization", "Bearer "+tok)
	htu, err := dpop.RequestURI(req)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := w.Prove(workload, method, htu, tok)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("DPoP", proof)
	return req
}

func TestIdentityOnlyGateway(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Bind:         "127.0.0.1:0",
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ShortName:    true,
		ProofReplay:  replay(w),
	}
	h := cfg.Handler()
	req := pepReq(t, w, http.MethodPost, "/session", tok, scenario.WLInvest)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if got := rw.Header().Get("X-Visor-Client-Id"); got != "investigation" {
		t.Fatalf("client-id %s", got)
	}
	var m map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["client_id"] != "investigation" {
		t.Fatalf("%v", m)
	}
}

func TestGatewayAcceptsDPoPAuthorization(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ShortName:    true,
		ProofReplay:  replay(w),
	}
	req := pepReq(t, w, http.MethodPost, "/session", tok, scenario.WLInvest)
	req.Header.Set("Authorization", "DPoP "+tok)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
}

func TestGatewayDefaultClientIDIsFullActorURI(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ProofReplay:  replay(w),
	}
	req := pepReq(t, w, http.MethodPost, "/session", tok, scenario.WLInvest)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	want := scenario.Invest
	if got := rw.Header().Get("X-Visor-Client-Id"); got != want {
		t.Fatalf("client-id %s want %s", got, want)
	}
}

func TestGatewayRejectsMissingBearer(t *testing.T) {
	w := testWorld(t)
	path := filepath.Join(t.TempDir(), "g-audit.jsonl")
	log, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        log,
		IdentityOnly: true,
		ShortName:    true,
	}
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/session", nil))
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rw.Code)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"reason_code":"missing_bearer"`) {
		t.Fatalf("audit: %s", raw)
	}
}

func TestGatewayOverwritesSpoofedVisorHeaders(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Visor-Client-Id") != "investigation" {
			t.Errorf("client-id %s", r.Header.Get("X-Visor-Client-Id"))
		}
		if r.Header.Get("X-Visor-Session-Id") == "" {
			t.Error("missing session")
		}
		if r.Header.Get("X-Actor-Chain") == "" {
			t.Error("missing actor chain")
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("bearer forwarded: %s", r.Header.Get("Authorization"))
		}
		rw.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(rw, "ok")
	}))
	t.Cleanup(backend.Close)
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:    scenario.Gateway,
		Verifier:    w.Verifier,
		Audit:       w.STS.Audit,
		Backend:     u,
		ShortName:   true,
		ProofReplay: replay(w),
	}
	req := pepReq(t, w, http.MethodPost, "/mcp", tok, scenario.WLInvest)
	req.Header.Set("X-Visor-Client-Id", "spoofed")
	req.Header.Set("Connection", "X-Visor-Client-Id, X-Visor-Session-Id, X-Actor-Chain")
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
}

func TestGatewayDoesNotCallBackendWithoutBearer(t *testing.T) {
	w := testWorld(t)
	called := 0
	backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		called++
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "g-audit.jsonl")
	log, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	cfg := &gateway.Config{
		Audience: scenario.Gateway,
		Verifier: w.Verifier,
		Audit:    log,
		Backend:  u,
	}
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rw.Code)
	}
	if called != 0 {
		t.Fatalf("backend called %d times", called)
	}
}

func TestGatewayInvalidTokenAudits(t *testing.T) {
	w := testWorld(t)
	path := filepath.Join(t.TempDir(), "g-audit.jsonl")
	log, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        log,
		IdentityOnly: true,
	}
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Header.Set("Authorization", "Bearer not-a-jwt")
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rw.Code)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"reason_code":"invalid_token"`) {
		t.Fatalf("audit: %s", raw)
	}
}

func TestGatewayRateLimitAudits(t *testing.T) {
	w := testWorld(t)
	path := filepath.Join(t.TempDir(), "g-audit.jsonl")
	log, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        log,
		IdentityOnly: true,
		RateLimit:    1,
	}
	h := cfg.Handler()
	denied := 0
	for i := 0; i < 8; i++ {
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, httptest.NewRequest(http.MethodPost, "/session", nil))
		if rw.Code == http.StatusTooManyRequests {
			denied++
		}
	}
	if denied == 0 {
		t.Fatal("expected rate-limited responses")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"reason_code":"rate_limited"`) {
		t.Fatalf("audit: %s", raw)
	}
}

func TestNewServerRejectsUnspecifiedBind(t *testing.T) {
	w := testWorld(t)
	cfg := &gateway.Config{
		Bind:         "0.0.0.0:8090",
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ProofReplay:  replay(w),
	}
	if _, err := gateway.NewServer(cfg); err == nil {
		t.Fatal("expected unspecified bind error")
	}
}

func TestNewServerRequiresBackendOrIdentityOnly(t *testing.T) {
	w := testWorld(t)
	cfg := &gateway.Config{
		Bind:        "127.0.0.1:8090",
		Audience:    scenario.Gateway,
		Verifier:    w.Verifier,
		Audit:       w.STS.Audit,
		ProofReplay: replay(w),
	}
	if _, err := gateway.NewServer(cfg); err == nil {
		t.Fatal("expected backend or identity-only")
	}
}

func TestReadyzRequiresJWKS(t *testing.T) {
	w := testWorld(t)
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		IdentityOnly: true,
	}
	ts := httptest.NewServer(cfg.Handler())
	t.Cleanup(ts.Close)
	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("readyz %d", resp.StatusCode)
	}
}

func TestReadyzRejectsEmptyJWKS(t *testing.T) {
	cfg := &gateway.Config{
		Audience:     "https://mcp-gateway.example.test",
		Verifier:     &verify.Verifier{KeysFn: func() (token.JWKS, error) { return token.JWKS{}, nil }},
		IdentityOnly: true,
	}
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz %d", rw.Code)
	}
}

func TestGatewayTLSPairRequired(t *testing.T) {
	w := testWorld(t)
	cfg := &gateway.Config{
		Bind:         "127.0.0.1:8090",
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		TLSCertFile:  "cert.pem",
		ProofReplay:  replay(w),
	}
	if _, err := gateway.NewServer(cfg); err == nil {
		t.Fatal("expected cert/key pair error")
	}
}

func TestNewServerRequiresAudit(t *testing.T) {
	w := testWorld(t)
	cfg := &gateway.Config{
		Bind:         "127.0.0.1:8090",
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		IdentityOnly: true,
	}
	if _, err := gateway.NewServer(cfg); err == nil {
		t.Fatal("expected audit required")
	}
}

func TestNewServerRejectsEmptyIssuer(t *testing.T) {
	w := testWorld(t)
	v := *w.Verifier
	v.Issuer = ""
	cfg := &gateway.Config{
		Bind:         "127.0.0.1:8090",
		Audience:     scenario.Gateway,
		Verifier:     &v,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ProofReplay:  replay(w),
	}
	if _, err := gateway.NewServer(cfg); err == nil {
		t.Fatal("expected issuer required")
	}
}

func TestNewServerRejectsNonHTTPBackend(t *testing.T) {
	w := testWorld(t)
	u, err := url.Parse("ftp://127.0.0.1:21/mcp")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Bind:        "127.0.0.1:8090",
		Audience:    scenario.Gateway,
		Verifier:    w.Verifier,
		Audit:       w.STS.Audit,
		Backend:     u,
		ProofReplay: replay(w),
	}
	if _, err := gateway.NewServer(cfg); err == nil {
		t.Fatal("expected http/https backend")
	}
}

func TestGatewayRejectsTokenWithoutActor(t *testing.T) {
	w := testWorld(t)
	tok, err := w.STS.Signer.SignClaims(token.Claims{
		Iss: scenario.Issuer,
		Sub: scenario.User,
		Aud: token.Audience{scenario.Gateway},
		Exp: w.Now.Add(time.Minute).Unix(),
		Iat: w.Now.Unix(),
		Jti: "no-act",
		Txn: "txn-no-act",
	})
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		called++
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "g-audit.jsonl")
	log, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	cfg := &gateway.Config{
		Audience:  scenario.Gateway,
		Verifier:  w.Verifier,
		Audit:     log,
		Backend:   u,
		ShortName: true,
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if called != 0 {
		t.Fatalf("backend called %d times", called)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"reason_code":"incomplete_chain"`) {
		t.Fatalf("audit: %s", raw)
	}
}

func TestGatewayAuditFailureFailsClosed(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		called++
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	log, err := audit.NewLogger(filepath.Join(t.TempDir(), "g-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:    scenario.Gateway,
		Verifier:    w.Verifier,
		Audit:       log,
		Backend:     u,
		ShortName:   true,
		ProofReplay: replay(w),
	}
	req := pepReq(t, w, http.MethodPost, "/mcp", tok, scenario.WLInvest)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if called != 0 {
		t.Fatalf("backend called %d times", called)
	}

	deny := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(deny, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if deny.Code != http.StatusServiceUnavailable {
		t.Fatalf("deny status %d", deny.Code)
	}
}

func TestGatewayDeniesListedHop(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	d, err := denylist.New(denylist.File{Version: 1, Agents: []string{scenario.Oncall}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		DenylistFn:   func() (*denylist.List, error) { return d, nil },
	}
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), denylist.ReasonAgentDenied) {
		t.Fatalf("body %s", rw.Body.String())
	}
}

func TestGatewayDenylistUnavailableNoBackend(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		called++
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience: scenario.Gateway,
		Verifier: w.Verifier,
		Audit:    w.STS.Audit,
		Backend:  u,
		DenylistFn: func() (*denylist.List, error) {
			return nil, os.ErrNotExist
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if called != 0 {
		t.Fatalf("backend called %d", called)
	}
}

func TestNewServerRequiresDPoPReplay(t *testing.T) {
	w := testWorld(t)
	cfg := &gateway.Config{
		Bind:         "127.0.0.1:8090",
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
	}
	if _, err := gateway.NewServer(cfg); err == nil {
		t.Fatal("expected DPoP replay required")
	}
}

func TestGatewayRejectsMissingDPoP(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	backend := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		called++
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:    scenario.Gateway,
		Verifier:    w.Verifier,
		Audit:       w.STS.Audit,
		Backend:     u,
		ProofReplay: replay(w),
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Host = "visor-gateway.test"
	req.Header.Set("Authorization", "Bearer "+tok)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if called != 0 {
		t.Fatalf("backend called %d", called)
	}
	if !strings.Contains(rw.Body.String(), "dpop") {
		t.Fatalf("body %s", rw.Body.String())
	}
	if got := rw.Header().Get("WWW-Authenticate"); !strings.Contains(got, "DPoP") {
		t.Fatalf("WWW-Authenticate %q", got)
	}
}

func TestGatewayDPoPDenyRecordsJTI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	_, claims, _, err := token.ParseUnverified(tok)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        log,
		IdentityOnly: true,
		ProofReplay:  replay(w),
	}
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "visor-gateway.test"
	req.Header.Set("Authorization", "Bearer "+tok)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	recs, err := audit.Trace(audit.Query{JTI: claims.Jti}, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range recs {
		if r.EventType == "identity_denied" && r.JTI == claims.Jti && r.Txn == claims.Txn {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing dpop deny in %+v", recs)
	}
}

func TestGatewayExpiredTokenDenyRecordsJTI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	_, claims, _, err := token.ParseUnverified(tok)
	if err != nil {
		t.Fatal(err)
	}
	w.Verifier.Now = func() time.Time { return w.Now.Add(24 * time.Hour) }
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        log,
		IdentityOnly: true,
		ProofReplay:  replay(w),
	}
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "visor-gateway.test"
	req.Header.Set("Authorization", "Bearer "+tok)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	recs, err := audit.Trace(audit.Query{JTI: claims.Jti}, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range recs {
		if r.EventType == "identity_denied" && r.JTI == claims.Jti && r.Txn == claims.Txn {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing expired deny in %+v", recs)
	}
}

func TestGatewayRejectsWrongDPoPKey(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ProofReplay:  replay(w),
	}
	req := pepReq(t, w, http.MethodPost, "/session", tok, scenario.WLOncall)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), gateway.ReasonInvalidDPoP) && !strings.Contains(rw.Body.String(), "dpop") {
		t.Fatalf("body %s", rw.Body.String())
	}
}

func TestGatewayRejectsReplayedDPoP(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ProofReplay:  replay(w),
	}
	req := pepReq(t, w, http.MethodPost, "/session", tok, scenario.WLInvest)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != 200 {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	req2 := httptest.NewRequest(http.MethodPost, "/session", nil)
	req2.Host = req.Host
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set("DPoP", req.Header.Get("DPoP"))
	rw2 := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw2, req2)
	if rw2.Code != http.StatusUnauthorized {
		t.Fatalf("replay status %d %s", rw2.Code, rw2.Body.String())
	}
	if !strings.Contains(rw2.Body.String(), gateway.ReasonReplayedDPoP) && !strings.Contains(rw2.Body.String(), "already") {
		t.Fatalf("body %s", rw2.Body.String())
	}
}

func TestGatewayRejectsLegacyUnprefixedProofJTI(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	req := pepReq(t, w, http.MethodPost, "/session", tok, scenario.WLInvest)
	parts := strings.Split(req.Header.Get("DPoP"), ".")
	if len(parts) != 3 {
		t.Fatal("proof")
	}
	pb, err := token.B64Decode(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var pc struct {
		JTI string `json:"jti"`
		IAT int64  `json:"iat"`
	}
	if err := json.Unmarshal(pb, &pc); err != nil {
		t.Fatal(err)
	}
	cache := replay(w)
	if err := cache.Consume(pc.JTI, pc.IAT); err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ProofReplay:  cache,
	}
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), gateway.ReasonReplayedDPoP) && !strings.Contains(rw.Body.String(), "already") {
		t.Fatalf("body %s", rw.Body.String())
	}
}

func TestGatewayIgnoresForwardedProtoForHTU(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ProofReplay:  replay(w),
	}
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "visor-gateway.test"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Forwarded-Proto", "https")
	proof, err := w.Prove(scenario.WLInvest, http.MethodPost, "https://visor-gateway.test/session", tok)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("DPoP", proof)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
}

func TestGatewayRejectsMissingCNF(t *testing.T) {
	w := testWorld(t)
	tok, err := w.STS.Signer.SignClaims(token.Claims{
		Iss: scenario.Issuer,
		Sub: scenario.User,
		Aud: token.Audience{scenario.Gateway},
		Exp: w.Now.Add(time.Minute).Unix(),
		Iat: w.Now.Unix(),
		Jti: "no-cnf",
		Txn: "txn-no-cnf",
		Act: &token.Actor{Iss: scenario.Issuer, Sub: scenario.Invest},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ProofReplay:  replay(w),
	}
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "visor-gateway.test"
	req.Header.Set("Authorization", "Bearer "+tok)
	rw := httptest.NewRecorder()
	cfg.Handler().ServeHTTP(rw, req)
	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "confirmation") {
		t.Fatalf("body %s", rw.Body.String())
	}
}
