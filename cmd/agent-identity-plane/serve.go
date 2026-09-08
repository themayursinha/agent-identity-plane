package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/attest"
	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/registry"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
)

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "listen address (unspecified hosts are rejected)")
	regPath := fs.String("registry", "", "agent registry JSON")
	issuer := fs.String("issuer", "https://sts.example.test", "token issuer")
	keyPath := fs.String("signing-key", "", "Ed25519 STS key file")
	wlPath := fs.String("workload-keys", "", "workload JWKS or workload-key file")
	idpPath := fs.String("idp-jwks", "", "trusted IdP JWKS for first-hop user tokens")
	idpIss := fs.String("idp-issuer", "", "expected IdP iss claim")
	spiffePath := fs.String("spiffe-jwks", "", "optional JWT-SVID JWKS bundle")
	auditPath := fs.String("audit-log", "", "hash-linked JSONL audit path (required)")
	ttl := fs.Duration("ttl", 120*time.Second, "minted token TTL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *regPath == "" || *keyPath == "" || *wlPath == "" || *idpPath == "" || *auditPath == "" {
		return fmt.Errorf("serve requires -registry, -signing-key, -workload-keys, -idp-jwks, and -audit-log")
	}
	reg, err := registry.LoadFile(*regPath)
	if err != nil {
		return err
	}
	kf, err := loadKeyFile(*keyPath)
	if err != nil {
		return err
	}
	signer, err := token.SignerFromKeyFile(kf)
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
	if *spiffePath != "" {
		bundle, err := loadJWKS(*spiffePath)
		if err != nil {
			return err
		}
		spiffe := &attest.SPIFFEJWT{Bundle: bundle, Audience: *issuer, Now: func() int64 { return time.Now().Unix() }}
		attestor = attest.FirstSuccessful{local, spiffe}
	}
	log, err := audit.NewLogger(*auditPath)
	if err != nil {
		return err
	}
	defer log.Close()
	cfg := &sts.Config{
		Issuer:    *issuer,
		TTL:       *ttl,
		Bind:      *listen,
		Registry:  reg,
		Signer:    signer,
		Attestor:  attestor,
		IdPKeys:   idpKeys,
		IdPIssuer: *idpIss,
		Audit:     log,
	}
	srv, err := sts.NewServer(cfg)
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

func loadKeyFile(path string) (*token.KeyFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var kf token.KeyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return nil, err
	}
	return &kf, nil
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
	if err := json.Unmarshal(b, &wrapped); err != nil {
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
