package verify

import (
	"errors"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/token"
)

var (
	ErrDepth     = errors.New("verify: depth exceeded")
	ErrAgent     = errors.New("verify: unexpected actor")
	ErrScope     = errors.New("verify: missing scope")
	ErrPrincipal = errors.New("verify: unexpected principal")
)

// ActorChain is the verified identity of a request.
type ActorChain struct {
	Principal string
	Actor     string
	Hops      []string
	Depth     int
	Scope     string
	Txn       string
	Audience  string
	JTI       string
	Issuer    string
	Expires   time.Time
	Claims    token.Claims
	Raw       string
}

// Verifier checks STS-issued tokens.
type Verifier struct {
	Keys   token.JWKS
	Issuer string
	Now    func() time.Time
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now().UTC()
}

func (v *Verifier) Verify(raw, audience string) (ActorChain, error) {
	_, c, err := token.Verify(raw, v.Keys)
	if err != nil {
		return ActorChain{}, err
	}
	if err := c.ValidateIssuer(v.Issuer); err != nil {
		return ActorChain{}, err
	}
	if err := c.ValidateSubject(); err != nil {
		return ActorChain{}, err
	}
	if err := c.ValidateAudience(audience); err != nil {
		return ActorChain{}, err
	}
	if err := c.ValidateTime(v.now(), 0); err != nil {
		return ActorChain{}, err
	}
	actors := c.ActorSubs()
	hops := append([]string{c.Sub}, actors...)
	actor := ""
	if c.Act != nil {
		actor = c.Act.Sub
	}
	aud, _ := c.Aud.Single()
	return ActorChain{
		Principal: c.Sub,
		Actor:     actor,
		Hops:      hops,
		Depth:     len(actors),
		Scope:     c.Scope,
		Txn:       c.Txn,
		Audience:  aud,
		JTI:       c.Jti,
		Issuer:    c.Iss,
		Expires:   time.Unix(c.Exp, 0).UTC(),
		Claims:    c,
		Raw:       raw,
	}, nil
}

func RequireDepth(c ActorChain, max int) error {
	if c.Depth > max {
		return ErrDepth
	}
	return nil
}

func RequireAgent(c ActorChain, agentID string) error {
	if c.Actor != agentID {
		return ErrAgent
	}
	return nil
}

func RequireScope(c ActorChain, scope string) error {
	if !token.Subset(token.ScopeSet(scope), token.ScopeSet(c.Scope)) {
		return ErrScope
	}
	return nil
}

func RequirePrincipal(c ActorChain, principal string) error {
	if c.Principal != principal {
		return ErrPrincipal
	}
	return nil
}
