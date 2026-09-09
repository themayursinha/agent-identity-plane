package sts

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/dpop"
)

const maxTokenBody = 1 << 20

// ValidateBind rejects unspecified addresses (0.0.0.0, ::, empty host).
func ValidateBind(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnspecifiedBind, err)
	}
	if port == "" {
		return ErrUnspecifiedBind
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return ErrUnspecifiedBind
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsUnspecified() {
		return ErrUnspecifiedBind
	}
	return nil
}

// Handler returns the STS HTTP mux.
func (c *Config) Handler() http.Handler {
	c.live.Lock()
	if c.limiter == nil && c.RateLimit > 0 {
		c.limiter = newTokenBucket(c.RateLimit)
	}
	c.live.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		snap := c.snapshot()
		if snap.Registry == nil || snap.Signer == nil || snap.Signer.ActiveKID() == "" {
			http.Error(w, "not ready\n", http.StatusServiceUnavailable)
			return
		}
		if r, ok := snap.Attestor.(interface{ Ready() error }); ok {
			if err := r.Ready(); err != nil {
				http.Error(w, "not ready\n", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w, "aip_sts_minted_total %d\n", c.Metrics.Minted.Load())
		_, _ = fmt.Fprintf(w, "aip_sts_denied_total %d\n", c.Metrics.Denied.Load())
		_, _ = fmt.Fprintf(w, "aip_sts_replay_rejected_total %d\n", c.Metrics.Replays.Load())
		_, _ = fmt.Fprintf(w, "aip_sts_reloads_total %d\n", c.Metrics.Reloads.Load())
		_, _ = fmt.Fprintf(w, "aip_sts_reload_failures_total %d\n", c.Metrics.ReloadFails.Load())
		_, _ = fmt.Fprintf(w, "aip_sts_rate_limited_total %d\n", c.Metrics.RateLimited.Load())
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, r *http.Request) {
		snap := c.snapshot()
		w.Header().Set("Content-Type", "application/json")
		if snap.Signer == nil {
			http.Error(w, `{"keys":[]}`, http.StatusServiceUnavailable)
			return
		}
		b, _ := json.Marshal(snap.Signer.JWKS())
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                c.Issuer,
			"token_endpoint":                        c.Issuer + "/oauth/token",
			"jwks_uri":                              c.Issuer + "/jwks.json",
			"grant_types_supported":                 []string{GrantTokenExchange},
			"token_endpoint_auth_methods_supported": []string{"none"},
		})
	})
	mux.HandleFunc("POST /oauth/token", c.handleToken)
	return mux
}

func (c *Config) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenBody)
	c.live.RLock()
	lim := c.limiter
	c.live.RUnlock()
	if !lim.allow() {
		c.writeHTTPDeny(w, http.StatusTooManyRequests, "temporarily_unavailable", "rate limited", ReasonRateLimited)
		return
	}
	if err := r.ParseForm(); err != nil {
		c.writeHTTPDeny(w, http.StatusBadRequest, "invalid_request", "malformed form", ReasonInvalidRequest)
		return
	}
	req := ExchangeRequest{
		GrantType:          r.Form.Get("grant_type"),
		SubjectToken:       r.Form.Get("subject_token"),
		SubjectTokenType:   r.Form.Get("subject_token_type"),
		ActorToken:         r.Form.Get("actor_token"),
		ActorTokenType:     r.Form.Get("actor_token_type"),
		Audience:           r.Form.Get("audience"),
		Scope:              r.Form.Get("scope"),
		RequestedTokenType: r.Form.Get("requested_token_type"),
		AgentID:            r.Form.Get("agent_id"),
		Purp:               r.Form.Get("purp"),
	}
	if strings.TrimSpace(r.Header.Get("DPoP")) != "" {
		proof, err := dpop.Verify(r, "", "", c.now())
		if err != nil {
			c.writeHTTPDeny(w, http.StatusBadRequest, "invalid_dpop_proof", err.Error(), ReasonInvalidDPoP)
			return
		}
		if err := c.Replay.Consume(dpop.ReplayJTI(proof.JTI), proof.IAT, proof.JTI); err != nil {
			if errors.Is(err, ErrReplay) {
				c.writeHTTPDeny(w, http.StatusBadRequest, "invalid_dpop_proof", "dpop proof jti already used", ReasonReplayedToken)
				return
			}
			c.writeHTTPDeny(w, http.StatusInternalServerError, "server_error", err.Error(), ReasonInvalidRequest)
			return
		}
		req.ConfirmJKT = proof.JKT
	}
	res := c.Exchange(r.Context(), req)
	if res.ReasonCode != ReasonOK {
		status := http.StatusBadRequest
		if res.Error == "access_denied" {
			status = http.StatusForbidden
		}
		if res.ReasonCode == ReasonReplayedToken {
			status = http.StatusBadRequest
		}
		writeOAuthErrorCode(w, status, res.Error, res.ErrorDesc, res.ReasonCode)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      res.Token,
		"issued_token_type": TokenTypeJWT,
		"token_type":        "DPoP",
		"expires_in":        res.ExpiresIn,
		"scope":             res.Issued.Scope,
	})
}

func (c *Config) writeHTTPDeny(w http.ResponseWriter, status int, oauthErr, desc, reason string) {
	c.Metrics.Denied.Add(1)
	if reason == ReasonRateLimited {
		c.Metrics.RateLimited.Add(1)
	}
	if c.Audit != nil {
		_ = c.Audit.Append(audit.Event{
			EventType:  "token_denied",
			ReasonCode: reason,
		})
	}
	writeOAuthErrorCode(w, status, oauthErr, desc, reason)
}

func writeOAuthErrorCode(w http.ResponseWriter, status int, err, desc, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             err,
		"error_description": desc,
		"reason_code":       reason,
	})
}

// Server is a bound STS HTTP server.
type Server struct {
	HTTP        *http.Server
	tlsCertFile string
	tlsKeyFile  string
}

func NewServer(cfg *Config) (*Server, error) {
	bind := cfg.Bind
	if bind == "" {
		bind = "127.0.0.1:8080"
	}
	if err := ValidateBind(bind); err != nil {
		return nil, err
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, fmt.Errorf("sts: -tls-cert and -tls-key must be set together")
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
func (s *Server) Close() error                       { return s.HTTP.Close() }
func (s *Server) Addr() string                       { return s.HTTP.Addr }
