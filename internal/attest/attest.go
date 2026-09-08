package attest

import (
	"context"
	"errors"
	"strings"

	"github.com/themayursinha/agent-identity-plane/internal/token"
)

var (
	ErrUnattested = errors.New("attest: workload unattested")
	ErrAudience   = errors.New("attest: actor token audience mismatch")
	ErrExpired    = errors.New("attest: actor token expired")
)

// WorkloadIdentity is the attested compute identity of a caller.
type WorkloadIdentity struct {
	ID     string
	Issuer string
	JTI    string
}

// WorkloadAttestor verifies an actor_token and returns a workload identity.
type WorkloadAttestor interface {
	Attest(ctx context.Context, actorToken string) (WorkloadIdentity, error)
}

// LocalKeys verifies Ed25519 JWTs whose sub is a registered workload id
// and whose signature matches the corresponding public key.
type LocalKeys struct {
	Keys     token.JWKS
	Audience string // typically the STS issuer
	Now      func() int64
}

func (l *LocalKeys) Attest(ctx context.Context, actorToken string) (WorkloadIdentity, error) {
	_ = ctx
	_, c, err := token.Verify(actorToken, l.Keys)
	if err != nil {
		return WorkloadIdentity{}, ErrUnattested
	}
	if err := c.ValidateSubject(); err != nil {
		return WorkloadIdentity{}, ErrUnattested
	}
	if l.Audience != "" && !c.Aud.Contains(l.Audience) {
		return WorkloadIdentity{}, ErrAudience
	}
	if l.Now != nil {
		if c.Exp == 0 || l.Now() > c.Exp {
			return WorkloadIdentity{}, ErrExpired
		}
	}
	return WorkloadIdentity{ID: c.Sub, Issuer: c.Iss, JTI: c.Jti}, nil
}

// SPIFFEJWT verifies JWT-SVIDs against a JWKS bundle (SPIRE OIDC discovery
// dump or a static bundle file). The subject must be a spiffe:// URI.
type SPIFFEJWT struct {
	Bundle   token.JWKS
	Audience string
	Now      func() int64
}

func (s *SPIFFEJWT) Attest(ctx context.Context, actorToken string) (WorkloadIdentity, error) {
	_ = ctx
	_, c, err := token.Verify(actorToken, s.Bundle)
	if err != nil {
		return WorkloadIdentity{}, ErrUnattested
	}
	if err := c.ValidateSubject(); err != nil {
		return WorkloadIdentity{}, ErrUnattested
	}
	if !strings.HasPrefix(c.Sub, "spiffe://") {
		return WorkloadIdentity{}, ErrUnattested
	}
	if s.Audience != "" && !c.Aud.Contains(s.Audience) {
		return WorkloadIdentity{}, ErrAudience
	}
	if s.Now != nil && (c.Exp == 0 || s.Now() > c.Exp) {
		return WorkloadIdentity{}, ErrExpired
	}
	return WorkloadIdentity{ID: c.Sub, Issuer: c.Iss, JTI: c.Jti}, nil
}

// FirstSuccessful tries attestors in order and returns the first success.
type FirstSuccessful []WorkloadAttestor

func (f FirstSuccessful) Attest(ctx context.Context, actorToken string) (WorkloadIdentity, error) {
	var last error
	for _, a := range f {
		id, err := a.Attest(ctx, actorToken)
		if err == nil {
			return id, nil
		}
		last = err
	}
	if last == nil {
		return WorkloadIdentity{}, ErrUnattested
	}
	return WorkloadIdentity{}, last
}
