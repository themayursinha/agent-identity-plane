package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/gateway"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "listen address")
	audience := flag.String("audience", "https://mcp-gateway.example.test", "expected token audience")
	issuer := flag.String("issuer", "https://sts.example.test", "STS issuer")
	jwksPath := flag.String("jwks", "", "STS JWKS file (re-read on each verify)")
	jwksURL := flag.String("jwks-url", "", "STS JWKS URL (https, or loopback http)")
	backend := flag.String("backend", "", "reverse-proxy base URL")
	identityOnly := flag.Bool("identity-only", true, "return mapping JSON without proxying")
	shortName := flag.Bool("client-short-name", false, "opt-in last URI segment as visor client-id (can collide across prefixes)")
	auditPath := flag.String("audit-log", "", "audit JSONL (required)")
	flag.Parse()

	if err := sts.ValidateBind(*listen); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if *auditPath == "" {
		fmt.Fprintln(os.Stderr, "error: -audit-log is required")
		os.Exit(1)
	}
	fn, err := verify.LiveJWKS(*jwksPath, *jwksURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	log, err := audit.NewLogger(*auditPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()
	cfg := &gateway.Config{
		Bind:         *listen,
		Audience:     *audience,
		Verifier:     &verify.Verifier{Issuer: *issuer, KeysFn: fn},
		Audit:        log,
		IdentityOnly: *identityOnly,
		ShortName:    *shortName,
	}
	if *backend != "" {
		u, err := url.Parse(*backend)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		cfg.Backend = u
		cfg.IdentityOnly = false
	}
	srv, err := gateway.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "visor-gateway listening on %s audience=%s\n", *listen, *audience)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
