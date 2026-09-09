package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/attest"
	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/jsonutil"
	"github.com/themayursinha/agent-identity-plane/internal/registry"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "listen address (unspecified hosts are rejected)")
	regPath := fs.String("registry", "", "agent registry JSON")
	issuer := fs.String("issuer", "https://sts.example.test", "token issuer")
	keyPath := fs.String("signing-key", "", "Ed25519 STS key or keyring file (mode 0600)")
	wlPath := fs.String("workload-keys", "", "workload JWKS or workload-key file")
	idpPath := fs.String("idp-jwks", "", "trusted IdP JWKS for first-hop user tokens")
	idpIss := fs.String("idp-issuer", "", "expected IdP iss claim")
	spiffePath := fs.String("spiffe-jwks", "", "optional JWT-SVID JWKS bundle file")
	spiffeURL := fs.String("spiffe-jwks-url", "", "optional JWT-SVID JWKS URL (https, or loopback http)")
	spiffeOIDC := fs.String("spiffe-oidc-issuer", "", "optional OIDC issuer for JWT-SVID JWKS discovery")
	auditPath := fs.String("audit-log", "", "hash-linked JSONL audit path (required)")
	replayPath := fs.String("replay-log", "", "durable consumed-jti JSONL (required; survives restart)")
	ttl := fs.Duration("ttl", 120*time.Second, "minted token TTL")
	tlsCert := fs.String("tls-cert", "", "PEM certificate for HTTPS (requires -tls-key)")
	tlsKey := fs.String("tls-key", "", "PEM private key for HTTPS (requires -tls-cert)")
	rate := fs.Float64("rate-limit", 30, "max POST /oauth/token per second (0 disables)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *regPath == "" || *keyPath == "" || *wlPath == "" || *idpPath == "" || *auditPath == "" || *replayPath == "" {
		return fmt.Errorf("serve requires -registry, -signing-key, -workload-keys, -idp-jwks, -audit-log, and -replay-log")
	}
	nSpiffe := 0
	if *spiffePath != "" {
		nSpiffe++
	}
	if *spiffeURL != "" {
		nSpiffe++
	}
	if *spiffeOIDC != "" {
		nSpiffe++
	}
	if nSpiffe > 1 {
		return fmt.Errorf("serve: use one of -spiffe-jwks, -spiffe-jwks-url, or -spiffe-oidc-issuer")
	}
	if *spiffeURL != "" {
		if err := verify.CheckJWKSURL(*spiffeURL); err != nil {
			return err
		}
	}
	if *spiffeOIDC != "" {
		if err := verify.CheckJWKSURL(*spiffeOIDC); err != nil {
			return err
		}
	}
	if err := rejectAliasedPaths([]namedPath{
		{"-registry", *regPath},
		{"-signing-key", *keyPath},
		{"-workload-keys", *wlPath},
		{"-idp-jwks", *idpPath},
		{"-spiffe-jwks", *spiffePath},
		{"-audit-log", *auditPath},
		{"-replay-log", *replayPath},
		{"-tls-cert", *tlsCert},
		{"-tls-key", *tlsKey},
	}); err != nil {
		return err
	}
	reg, err := registry.LoadFile(*regPath)
	if err != nil {
		return err
	}
	kr, err := token.LoadSigningFile(*keyPath)
	if err != nil {
		return err
	}
	wlKeys, err := loadJWKS(*wlPath)
	if err != nil {
		return err
	}
	idpKeys, err := loadJWKS(*idpPath)
	if err != nil {
		return err
	}
	local := &attest.LocalKeys{Keys: wlKeys, Audience: *issuer, Now: func() int64 { return time.Now().Unix() }}
	var attestor attest.WorkloadAttestor = local
	now := func() int64 { return time.Now().Unix() }
	switch {
	case *spiffePath != "":
		bundle, err := loadJWKS(*spiffePath)
		if err != nil {
			return err
		}
		attestor = attest.FirstSuccessful{local, &attest.SPIFFEJWT{Bundle: bundle, Audience: *issuer, Now: now}}
	case *spiffeURL != "":
		fn, err := verify.LiveJWKS("", *spiffeURL)
		if err != nil {
			return err
		}
		if _, err := fn(); err != nil {
			return fmt.Errorf("serve: -spiffe-jwks-url: %w", err)
		}
		attestor = attest.FirstSuccessful{local, &attest.SPIFFEJWT{KeysFn: fn, Audience: *issuer, Now: now}}
	case *spiffeOIDC != "":
		fn, err := verify.LiveOIDC(*spiffeOIDC)
		if err != nil {
			return err
		}
		attestor = attest.FirstSuccessful{local, &attest.SPIFFEJWT{KeysFn: fn, Audience: *issuer, Issuer: *spiffeOIDC, Now: now}}
	}
	log, err := audit.NewLogger(*auditPath)
	if err != nil {
		return err
	}
	defer log.Close()
	replay, err := sts.OpenReplayCache(*replayPath, nil)
	if err != nil {
		return err
	}
	defer replay.Close()
	cfg := &sts.Config{
		Issuer:      *issuer,
		TTL:         *ttl,
		Bind:        *listen,
		Registry:    reg,
		Signer:      kr,
		Attestor:    attestor,
		IdPKeys:     idpKeys,
		IdPIssuer:   *idpIss,
		Audit:       log,
		Replay:      replay,
		RateLimit:   *rate,
		TLSCertFile: *tlsCert,
		TLSKeyFile:  *tlsKey,
	}
	srv, err := sts.NewServer(cfg)
	if err != nil {
		return err
	}
	reloader := sts.NewReloader(cfg, *regPath, *keyPath)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reloadCh := make(chan os.Signal, 1)
	if len(reloadSignals) > 0 {
		signal.Notify(reloadCh, reloadSignals...)
		defer signal.Stop(reloadCh)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	for {
		select {
		case <-ctx.Done():
			shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(shCtx)
		case <-reloadCh:
			if err := reloader.Reload(); err != nil {
				fmt.Fprintf(os.Stderr, "reload failed (previous snapshot kept): %v\n", err)
			}
		case err := <-errCh:
			return err
		}
	}
}

func loadJWKS(path string) (token.JWKS, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return token.JWKS{}, err
	}
	var wrapped struct {
		Keys      []token.JWK `json:"keys"`
		Workloads []token.JWK `json:"workloads"`
	}
	if err := jsonutil.Unmarshal(b, &wrapped); err != nil {
		return token.JWKS{}, err
	}
	keys := wrapped.Keys
	if len(keys) == 0 {
		keys = wrapped.Workloads
	}
	if len(keys) == 0 {
		return token.ParseJWKS(b)
	}
	return token.JWKS{Keys: keys}, nil
}
