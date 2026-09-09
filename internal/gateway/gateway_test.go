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
	"github.com/themayursinha/agent-identity-plane/internal/gateway"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
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
	}
	h := cfg.Handler()
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
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
	}
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
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
		rw.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(rw, "ok")
	}))
	t.Cleanup(backend.Close)
	u, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &gateway.Config{
		Audience:  scenario.Gateway,
		Verifier:  w.Verifier,
		Audit:     w.STS.Audit,
		Backend:   u,
		ShortName: true,
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
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
	}
	if _, err := gateway.NewServer(cfg); err == nil {
		t.Fatal("expected unspecified bind error")
	}
}

func TestNewServerRequiresBackendOrIdentityOnly(t *testing.T) {
	w := testWorld(t)
	cfg := &gateway.Config{
		Bind:     "127.0.0.1:8090",
		Audience: scenario.Gateway,
		Verifier: w.Verifier,
		Audit:    w.STS.Audit,
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
		Bind:     "127.0.0.1:8090",
		Audience: scenario.Gateway,
		Verifier: w.Verifier,
		Audit:    w.STS.Audit,
		Backend:  u,
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
