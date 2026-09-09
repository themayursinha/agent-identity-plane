package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/a2a"
	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
	"github.com/themayursinha/agent-identity-plane/internal/visoradapter"
)

const (
	ReasonOK           = "ok"
	ReasonMissingToken = "missing_bearer"
	ReasonInvalidToken = "invalid_token"
	ReasonIncomplete   = "incomplete_chain"
	ReasonRateLimited  = "rate_limited"
	ReasonNotReady     = "jwks_unavailable"
	ReasonAuditFailed  = "audit_unavailable"
)

const (
	headerVisorClient  = "X-Visor-Client-Id"
	headerVisorSession = "X-Visor-Session-Id"
	headerActorChain   = "X-Actor-Chain"
)

// Metrics are process-local visor-gateway counters.
type Metrics struct {
	Allowed     atomic.Int64
	Denied      atomic.Int64
	RateLimited atomic.Int64
}

// Config is the visor-gateway identity PEP.
type Config struct {
	Bind         string
	Audience     string
	Verifier     *verify.Verifier
	Audit        *audit.Logger
	Backend      *url.URL
	IdentityOnly bool
	ShortName    bool
	RateLimit    float64
	TLSCertFile  string
	TLSKeyFile   string
	Metrics      Metrics

	limiter *tokenBucket
	once    sync.Once
}

func (c *Config) initLimiter() {
	c.once.Do(func() {
		if c.limiter == nil && c.RateLimit > 0 {
			c.limiter = newTokenBucket(c.RateLimit)
		}
	})
}

// Handler serves health, ready, metrics, and the identity PEP.
func (c *Config) Handler() http.Handler {
	c.initLimiter()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := c.keysReady(); err != nil {
			http.Error(w, "not ready\n", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w, "aip_gateway_allowed_total %d\n", c.Metrics.Allowed.Load())
		_, _ = fmt.Fprintf(w, "aip_gateway_denied_total %d\n", c.Metrics.Denied.Load())
		_, _ = fmt.Fprintf(w, "aip_gateway_rate_limited_total %d\n", c.Metrics.RateLimited.Load())
	})
	mux.HandleFunc("/", c.handlePEP)
	return mux
}

func (c *Config) keysReady() error {
	if c == nil || c.Verifier == nil {
		return fmt.Errorf("gateway: verifier required")
	}
	n := len(c.Verifier.Keys.Keys)
	if c.Verifier.KeysFn != nil {
		ks, err := c.Verifier.KeysFn()
		if err != nil {
			return err
		}
		n = len(ks.Keys)
	}
	if n == 0 {
		return fmt.Errorf("gateway: empty JWKS")
	}
	return nil
}

func (c *Config) handlePEP(w http.ResponseWriter, r *http.Request) {
	if !c.limiter.allow() {
		c.writeDeny(w, http.StatusTooManyRequests, ReasonRateLimited, "rate limited")
		return
	}
	raw := a2a.BearerToken(r.Header.Get("Authorization"))
	if raw == "" {
		c.writeDeny(w, http.StatusUnauthorized, ReasonMissingToken, "missing bearer token")
		return
	}
	chain, err := c.Verifier.Verify(raw, c.Audience)
	if err != nil {
		c.writeDeny(w, http.StatusUnauthorized, ReasonInvalidToken, err.Error())
		return
	}
	m := visoradapter.FromChain(chain, visoradapter.Options{ShortName: c.ShortName})
	if err := m.Complete(); err != nil {
		c.writeDeny(w, http.StatusUnauthorized, ReasonIncomplete, err.Error())
		return
	}
	if err := c.record(audit.Event{
		EventType:  "identity_allowed",
		ReasonCode: ReasonOK,
		Txn:        m.SessionID,
		AgentID:    m.ActingAgent,
		Principal:  m.Principal,
		Audience:   c.Audience,
		Scope:      m.Scope,
		JTI:        chain.JTI,
		Hops:       m.Hops,
	}); err != nil {
		c.failClosed(w)
		return
	}
	c.Metrics.Allowed.Add(1)
	applyIdentityHeaders(w.Header(), m)
	if c.IdentityOnly || c.Backend == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(m)
		return
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(c.Backend)
			pr.Out.Host = c.Backend.Host
			pr.Out.Header.Del("Authorization")
			applyIdentityHeaders(pr.Out.Header, m)
		},
	}
	proxy.ServeHTTP(w, r)
}

func applyIdentityHeaders(h http.Header, m visoradapter.Mapping) {
	h.Del(headerVisorClient)
	h.Del(headerVisorSession)
	h.Del(headerActorChain)
	h.Set(headerVisorClient, m.ClientID)
	h.Set(headerVisorSession, m.SessionID)
	h.Set(headerActorChain, strings.Join(m.Hops, " > "))
}

func (c *Config) record(ev audit.Event) error {
	if c.Audit == nil {
		return fmt.Errorf("gateway: audit required")
	}
	return c.Audit.Append(ev)
}

func (c *Config) failClosed(w http.ResponseWriter) {
	c.Metrics.Denied.Add(1)
	http.Error(w, "audit unavailable\n", http.StatusServiceUnavailable)
}

func (c *Config) writeDeny(w http.ResponseWriter, status int, reason, desc string) {
	if err := c.record(audit.Event{
		EventType:  "identity_denied",
		ReasonCode: reason,
		Audience:   c.Audience,
	}); err != nil {
		c.failClosed(w)
		return
	}
	c.Metrics.Denied.Add(1)
	if reason == ReasonRateLimited {
		c.Metrics.RateLimited.Add(1)
	}
	http.Error(w, desc+"\n", status)
}

// Server is a bound visor-gateway HTTP server.
type Server struct {
	HTTP        *http.Server
	tlsCertFile string
	tlsKeyFile  string
}

func NewServer(cfg *Config) (*Server, error) {
	bind := cfg.Bind
	if bind == "" {
		bind = "127.0.0.1:8090"
	}
	if err := sts.ValidateBind(bind); err != nil {
		return nil, err
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, fmt.Errorf("gateway: -tls-cert and -tls-key must be set together")
	}
	if cfg.Verifier == nil || cfg.Audience == "" || strings.TrimSpace(cfg.Verifier.Issuer) == "" {
		return nil, fmt.Errorf("gateway: verifier, audience, and issuer required")
	}
	if cfg.Audit == nil {
		return nil, fmt.Errorf("gateway: audit required")
	}
	if !cfg.IdentityOnly && cfg.Backend == nil {
		return nil, fmt.Errorf("gateway: -backend or -identity-only is required")
	}
	if err := CheckBackend(cfg.Backend); err != nil {
		return nil, err
	}
	srv := &http.Server{
		Addr:              bind,
		Handler:           cfg.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if cfg.TLSCertFile != "" {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &Server{HTTP: srv, tlsCertFile: cfg.TLSCertFile, tlsKeyFile: cfg.TLSKeyFile}, nil
}

func (s *Server) ListenAndServe() error {
	if s.tlsCertFile != "" {
		return s.HTTP.ListenAndServeTLS(s.tlsCertFile, s.tlsKeyFile)
	}
	return s.HTTP.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error { return s.HTTP.Shutdown(ctx) }

// CheckBackend allows only http and https backends. Nil is valid for identity-only.
func CheckBackend(u *url.URL) error {
	if u == nil {
		return nil
	}
	if u.Host == "" {
		return fmt.Errorf("gateway: -backend must be http or https")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("gateway: -backend must be http or https")
	}
}

type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64
	burst  float64
}

func newTokenBucket(rate float64) *tokenBucket {
	if rate <= 0 {
		return nil
	}
	burst := rate
	if burst < 1 {
		burst = 1
	}
	return &tokenBucket{tokens: burst, last: time.Now(), rate: rate, burst: burst}
}

func (b *tokenBucket) allow() bool {
	if b == nil {
		return true
	}
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
