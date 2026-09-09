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

func (l *LocalKeys) keys() (token.JWKS, error) {
	if l == nil || len(l.Keys.Keys) == 0 {
		return token.JWKS{}, ErrUnattested
	}
	return l.Keys, nil
}

func (l *LocalKeys) Ready() error {
	_, err := l.keys()
	return err
}

func (l *LocalKeys) Attest(ctx context.Context, actorToken string) (WorkloadIdentity, error) {
	_ = ctx
	ks, err := l.keys()
	if err != nil {
		return WorkloadIdentity{}, ErrUnattested
	}
	_, c, err := token.Verify(actorToken, ks)
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

// SPIFFEJWT verifies JWT-SVIDs against a JWKS bundle (file) or a live
// KeysFn (OIDC discovery / JWKS URL). The subject must be a spiffe:// URI.
// This is not a SPIRE Workload API client.
type SPIFFEJWT struct {
	Bundle   token.JWKS
	KeysFn   func() (token.JWKS, error)
	Audience string
	Issuer   string
	Now      func() int64
}

func (s *SPIFFEJWT) keys() (token.JWKS, error) {
	if s != nil && s.KeysFn != nil {
		return s.KeysFn()
	}
	if s == nil || len(s.Bundle.Keys) == 0 {
		return token.JWKS{}, ErrUnattested
	}
	return s.Bundle, nil
}

func (s *SPIFFEJWT) Ready() error {
	_, err := s.keys()
	return err
}

func (s *SPIFFEJWT) Attest(ctx context.Context, actorToken string) (WorkloadIdentity, error) {
	_ = ctx
	ks, err := s.keys()
	if err != nil {
		return WorkloadIdentity{}, ErrUnattested
	}
	_, c, err := token.Verify(actorToken, ks)
	if err != nil {
		return WorkloadIdentity{}, ErrUnattested
	}
	if err := c.ValidateSubject(); err != nil {
		return WorkloadIdentity{}, ErrUnattested
	}
	if !strings.HasPrefix(c.Sub, "spiffe://") {
		return WorkloadIdentity{}, ErrUnattested
	}
	if s.Issuer != "" {
		if err := c.ValidateIssuer(s.Issuer); err != nil {
			return WorkloadIdentity{}, ErrUnattested
		}
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

func (f FirstSuccessful) Ready() error {
	for _, a := range f {
		r, ok := a.(interface{ Ready() error })
		if !ok {
			continue
		}
		if err := r.Ready(); err != nil {
			return err
		}
	}
	return nil
}
