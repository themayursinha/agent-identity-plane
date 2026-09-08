package sts

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(c.Signer.JWKS())
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
	if err := r.ParseForm(); err != nil {
		writeOAuthErrorCode(w, http.StatusBadRequest, "invalid_request", "malformed form", ReasonInvalidRequest)
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
	res := c.Exchange(r.Context(), req)
	if res.ReasonCode != ReasonOK {
		status := http.StatusBadRequest
		if res.Error == "access_denied" {
			status = http.StatusForbidden
		}
		writeOAuthErrorCode(w, status, res.Error, res.ErrorDesc, res.ReasonCode)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":      res.Token,
		"issued_token_type": TokenTypeJWT,
		"token_type":        "Bearer",
		"expires_in":        res.ExpiresIn,
		"scope":             res.Issued.Scope,
	})
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
	HTTP *http.Server
}

func NewServer(cfg *Config) (*Server, error) {
	bind := cfg.Bind
	if bind == "" {
		bind = "127.0.0.1:8080"
	}
	if err := ValidateBind(bind); err != nil {
		return nil, err
	}
	return &Server{
		HTTP: &http.Server{
			Addr:              bind,
			Handler:           cfg.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
		},
	}, nil
}

func (s *Server) ListenAndServe() error              { return s.HTTP.ListenAndServe() }
func (s *Server) Shutdown(ctx context.Context) error { return s.HTTP.Shutdown(ctx) }
func (s *Server) Close() error                       { return s.HTTP.Close() }
func (s *Server) Addr() string                       { return s.HTTP.Addr }
