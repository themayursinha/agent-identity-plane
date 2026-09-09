package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/gateway"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

func cmdVisorGateway(args []string) error {
	fs := flag.NewFlagSet("visor-gateway", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8090", "listen address (unspecified hosts are rejected)")
	audience := fs.String("audience", "https://mcp-gateway.example.test", "expected token audience")
	issuer := fs.String("issuer", "https://sts.example.test", "STS issuer")
	jwksPath := fs.String("jwks", "", "STS JWKS file (re-read on each verify)")
	jwksURL := fs.String("jwks-url", "", "STS JWKS URL (https, or loopback http)")
	backend := fs.String("backend", "", "reverse-proxy base URL for an HTTP service (not visor stdio)")
	identityOnly := fs.Bool("identity-only", false, "verify and return mapping JSON without proxying")
	shortName := fs.Bool("client-short-name", true, "derive visor client-id from the last URI segment")
	auditPath := fs.String("audit-log", "", "hash-linked JSONL audit path (required)")
	tlsCert := fs.String("tls-cert", "", "PEM certificate for HTTPS (requires -tls-key)")
	tlsKey := fs.String("tls-key", "", "PEM private key for HTTPS (requires -tls-cert)")
	rate := fs.Float64("rate-limit", 30, "max identity-PEP requests per second (0 disables)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *auditPath == "" {
		return fmt.Errorf("visor-gateway requires -audit-log")
	}
	if *backend != "" && *identityOnly {
		return fmt.Errorf("visor-gateway: use -backend or -identity-only, not both")
	}
	if *backend == "" && !*identityOnly {
		return fmt.Errorf("visor-gateway requires -backend or -identity-only")
	}
	fn, err := verify.LiveJWKS(*jwksPath, *jwksURL)
	if err != nil {
		return err
	}
	if err := rejectAliasedPaths([]namedPath{
		{"-audit-log", *auditPath},
		{"-jwks", *jwksPath},
		{"-tls-cert", *tlsCert},
		{"-tls-key", *tlsKey},
	}); err != nil {
		return err
	}
	log, err := audit.NewLogger(*auditPath)
	if err != nil {
		return err
	}
	defer log.Close()
	cfg := &gateway.Config{
		Bind:         *listen,
		Audience:     *audience,
		Verifier:     &verify.Verifier{Issuer: *issuer, KeysFn: fn},
		Audit:        log,
		IdentityOnly: *identityOnly,
		ShortName:    *shortName,
		RateLimit:    *rate,
		TLSCertFile:  *tlsCert,
		TLSKeyFile:   *tlsKey,
	}
	if *backend != "" {
		u, err := url.Parse(*backend)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("visor-gateway: invalid -backend")
		}
		cfg.Backend = u
	}
	srv, err := gateway.NewServer(cfg)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shCtx)
	case err := <-errCh:
		return err
	}
}
