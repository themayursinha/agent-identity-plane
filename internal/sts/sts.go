package sts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/attest"
	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/denylist"
	"github.com/themayursinha/agent-identity-plane/internal/registry"
	"github.com/themayursinha/agent-identity-plane/internal/token"
)

const (
	GrantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeJWT       = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeAccess    = "urn:ietf:params:oauth:token-type:access_token"
)

const (
	ReasonOK                     = "ok"
	ReasonInvalidRequest         = "invalid_request"
	ReasonInvalidActorToken      = "invalid_actor_token"
	ReasonInvalidSubjectToken    = "invalid_subject_token"
	ReasonAgentNotRegistered     = "agent_not_registered"
	ReasonAgentNotAuthorizedOnWL = "agent_not_authorized_on_workload"
	ReasonAudienceNotAllowed     = "audience_not_allowed"
	ReasonScopeWidening          = "scope_widening"
	ReasonDepthExceeded          = "depth_exceeded"
	ReasonExpired                = "expired"
	ReasonChainIntegrity         = "chain_integrity"
	ReasonAgentNotYetValid       = "agent_not_yet_valid"
	ReasonAgentExpired           = "agent_expired"
	ReasonReplayedToken          = "replayed_token"
	ReasonRateLimited            = "rate_limited"
	ReasonAgentDenied            = denylist.ReasonAgentDenied
	ReasonWorkloadDenied         = denylist.ReasonWorkloadDenied
	ReasonPrincipalDenied        = denylist.ReasonPrincipalDenied
	ReasonMissingCNF             = "missing_cnf"
	ReasonInvalidDPoP            = "invalid_dpop_proof"
)

var ErrUnspecifiedBind = errors.New("sts: listen address must not be unspecified")

// Metrics are process-local STS counters exposed at GET /metrics.
type Metrics struct {
	Minted      atomic.Int64
	Denied      atomic.Int64
	Replays     atomic.Int64
	Reloads     atomic.Int64
	ReloadFails atomic.Int64
	RateLimited atomic.Int64
}

// Config is the STS runtime configuration.
type Config struct {
	live sync.RWMutex

	Issuer      string
	TTL         time.Duration
	Bind        string
	Registry    *registry.Registry
	Signer      *token.Keyring
	Attestor    attest.WorkloadAttestor
	IdPKeys     token.JWKS
	IdPIssuer   string
	Audit       *audit.Logger
	Now         func() time.Time
	Replay      *ReplayCache
	RateLimit   float64 // token-exchange requests per second; 0 disables
	TLSCertFile string
	TLSKeyFile  string
	Denylist    *denylist.List
	Metrics     Metrics

	limiter *tokenBucket
}

type identitySnap struct {
	Registry  *registry.Registry
	Signer    *token.Keyring
	Attestor  attest.WorkloadAttestor
	IdPKeys   token.JWKS
	IdPIssuer string
	Denylist  *denylist.List
}

// SetRegistry replaces the live registry. Reloader must not combine this
// with ReplaceKeyring; use installIdentity so one request never observes
// a torn registry/keyring pair.
func (c *Config) SetRegistry(r *registry.Registry) {
	_ = c.installIdentity(r, nil, nil)
}

// ReplaceKeyring swaps signing material in place.
func (c *Config) ReplaceKeyring(kr *token.Keyring) error {
	if kr == nil || kr.ActiveKID() == "" {
		return token.ErrInvalidKey
	}
	return c.installIdentity(nil, kr, nil)
}

// installIdentity publishes registry, keyring, and/or denylist under one
// lock so Exchange, /jwks.json, and /readyz observe a single snapshot.
func (c *Config) installIdentity(reg *registry.Registry, kr *token.Keyring, dl *denylist.List) error {
	if c == nil {
		return token.ErrInvalidKey
	}
	c.live.Lock()
	defer c.live.Unlock()
	if kr != nil {
		if err := token.AllowActivation(c.Signer, kr); err != nil {
			return err
		}
	}
	if reg != nil {
		c.Registry = reg
	}
	if kr != nil {
		c.Signer = kr
	}
	if dl != nil {
		c.Denylist = dl
	}
	return nil
}

func (c *Config) snapshot() identitySnap {
	c.live.RLock()
	defer c.live.RUnlock()
	return identitySnap{
		Registry:  c.Registry,
		Signer:    c.Signer,
		Attestor:  c.Attestor,
		IdPKeys:   c.IdPKeys,
		IdPIssuer: c.IdPIssuer,
		Denylist:  c.Denylist,
	}
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

func (c *Config) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return 120 * time.Second
}

// ExchangeRequest is an RFC 8693 token-exchange request plus agent_id.
type ExchangeRequest struct {
	GrantType          string
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string
	Audience           string
	Scope              string
	RequestedTokenType string
	AgentID            string
	Purp               string
	ConfirmJKT         string // RFC 7638 thumbprint of a workload-possessed DPoP key
}

// ExchangeResult is either a minted token or a deny.
type ExchangeResult struct {
	Token      string
	ExpiresIn  int
	Issued     token.Claims
	ReasonCode string
	Error      string
	ErrorDesc  string
}

type outcome struct {
	ExchangeResult
	workload string
}

func deny(code, oauthError, desc string) outcome {
	return outcome{ExchangeResult: ExchangeResult{
		ReasonCode: code,
		Error:      oauthError,
		ErrorDesc:  desc,
	}}
}

// Exchange performs one token exchange and writes an audit record first.
func (c *Config) Exchange(ctx context.Context, req ExchangeRequest) ExchangeResult {
	out := c.exchange(ctx, req)
	if c.Audit != nil {
		ev := audit.Event{
			ReasonCode: out.ReasonCode,
			AgentID:    req.AgentID,
			Audience:   req.Audience,
			Workload:   out.workload,
		}
		if out.ReasonCode == ReasonOK {
			c.Metrics.Minted.Add(1)
			ev.EventType = "token_minted"
			ev.Txn = out.Issued.Txn
			ev.JTI = out.Issued.Jti
			ev.Principal = out.Issued.Sub
			ev.Depth = out.Issued.Depth()
			ev.Hops = append([]string{out.Issued.Sub}, out.Issued.ActorSubs()...)
			ev.Scope = out.Issued.Scope
		} else {
			c.Metrics.Denied.Add(1)
			if out.ReasonCode == ReasonReplayedToken {
				c.Metrics.Replays.Add(1)
			}
			ev.EventType = "token_denied"
			ev.Scope = req.Scope
		}
		_ = c.Audit.Append(ev)
	}
	return out.ExchangeResult
}

func (c *Config) exchange(ctx context.Context, req ExchangeRequest) outcome {
	snap := c.snapshot()
	if snap.Signer == nil || snap.Registry == nil || snap.Attestor == nil || c.Issuer == "" {
		return deny(ReasonInvalidRequest, "invalid_request", "sts not configured")
	}
	if req.GrantType != "" && req.GrantType != GrantTokenExchange {
		return deny(ReasonInvalidRequest, "unsupported_grant_type", "grant_type")
	}
	if strings.TrimSpace(req.SubjectToken) == "" || strings.TrimSpace(req.ActorToken) == "" {
		return deny(ReasonInvalidRequest, "invalid_request", "subject_token and actor_token required")
	}
	if strings.TrimSpace(req.AgentID) == "" || strings.TrimSpace(req.Audience) == "" {
		return deny(ReasonInvalidRequest, "invalid_request", "agent_id and audience required")
	}
	if req.RequestedTokenType != "" && req.RequestedTokenType != TokenTypeJWT && req.RequestedTokenType != TokenTypeAccess {
		return deny(ReasonInvalidRequest, "invalid_request", "requested_token_type")
	}

	wl, err := snap.Attestor.Attest(ctx, req.ActorToken)
	if err != nil {
		return deny(ReasonInvalidActorToken, "invalid_request", err.Error())
	}

	now := c.now()
	agent, err := snap.Registry.Authorize(req.AgentID, wl.ID, req.Audience, now)
	if err != nil {
		return deny(mapRegistryErr(err), "access_denied", err.Error())
	}
	if snap.Denylist.HasAgent(req.AgentID) {
		return deny(ReasonAgentDenied, "access_denied", "agent is denied")
	}
	if snap.Denylist.HasWorkload(wl.ID) {
		return deny(ReasonWorkloadDenied, "access_denied", "workload is denied")
	}

	sub, fromSTS, err := c.verifySubject(req.SubjectToken, snap)
	if err != nil {
		return deny(ReasonInvalidSubjectToken, "invalid_request", err.Error())
	}
	if err := sub.ValidateSubject(); err != nil {
		return deny(ReasonInvalidSubjectToken, "invalid_request", err.Error())
	}
	if snap.Denylist.HasPrincipal(sub.Sub) {
		return deny(ReasonPrincipalDenied, "access_denied", "principal is denied")
	}
	if err := sub.ValidateTime(now, 0); err != nil {
		if errors.Is(err, token.ErrExpired) {
			return deny(ReasonExpired, "invalid_request", err.Error())
		}
		return deny(ReasonInvalidSubjectToken, "invalid_request", err.Error())
	}

	if fromSTS {
		if err := sub.ValidateAudience(req.AgentID); err != nil {
			return deny(ReasonChainIntegrity, "access_denied", "subject token audience must be the requesting agent")
		}
	} else {
		if err := sub.ValidateAudience(req.AgentID); err != nil {
			return deny(ReasonInvalidSubjectToken, "invalid_request", "user token audience must be the requesting agent")
		}
	}

	issuedScope, err := narrowScope(req.Scope, sub.Scope, agent.MaxScopes)
	if err != nil {
		return deny(ReasonScopeWidening, "access_denied", err.Error())
	}

	newChain := token.AppendChain(sub)
	depth := len(newChain) + 1
	if depth > agent.MaxDepth {
		return deny(ReasonDepthExceeded, "access_denied", "delegation depth exceeded")
	}

	txn := sub.Txn
	if !fromSTS {
		if txn == "" {
			txn = newID("txn")
		}
		if len(sub.ActChain) != 0 || sub.Act != nil {
			return deny(ReasonChainIntegrity, "access_denied", "user token must not carry an actor chain")
		}
	} else if txn == "" {
		return deny(ReasonChainIntegrity, "invalid_request", "missing txn")
	}

	if fromSTS {
		if err := c.Replay.Consume(sub.Jti, sub.Exp); err != nil {
			if errors.Is(err, ErrReplay) || errors.Is(err, errEmptyJTI) || errors.Is(err, ErrReplayUnavailable) {
				return deny(ReasonReplayedToken, "invalid_grant", err.Error())
			}
			return deny(ReasonInvalidRequest, "server_error", err.Error())
		}
	}

	jkt := strings.TrimSpace(req.ConfirmJKT)
	if jkt == "" {
		jkt = wl.PossessedJKT
	}
	if jkt == "" {
		return deny(ReasonMissingCNF, "invalid_request", "confirmation key must be possessed by the workload")
	}

	ttl := c.ttl()
	claims := token.Claims{
		Iss:      c.Issuer,
		Sub:      sub.Sub,
		Aud:      token.Audience{req.Audience},
		Exp:      now.Add(ttl).Unix(),
		Nbf:      now.Unix(),
		Iat:      now.Unix(),
		Jti:      newID("jti"),
		Txn:      txn,
		Act:      token.NestedAct(c.Issuer, req.AgentID, sub.Act),
		ActChain: newChain,
		Scope:    issuedScope,
		Purp:     req.Purp,
		Cnf:      &token.Confirmation{JKT: jkt},
	}
	if claims.Purp == "" {
		claims.Purp = sub.Purp
	}

	raw, err := snap.Signer.SignClaims(claims)
	if err != nil {
		return deny(ReasonInvalidRequest, "server_error", err.Error())
	}
	return outcome{
		ExchangeResult: ExchangeResult{
			Token:      raw,
			ExpiresIn:  int(ttl.Seconds()),
			Issued:     claims,
			ReasonCode: ReasonOK,
		},
		workload: wl.ID,
	}
}

func (c *Config) verifySubject(raw string, snap identitySnap) (token.Claims, bool, error) {
	if snap.Signer != nil {
		if _, claims, err := token.Verify(raw, snap.Signer.JWKS()); err == nil {
			if claims.Iss != c.Issuer {
				return token.Claims{}, false, token.ErrIssuerMismatch
			}
			return claims, true, nil
		}
	}
	if _, claims, err := token.Verify(raw, snap.IdPKeys); err == nil {
		if snap.IdPIssuer != "" && claims.Iss != snap.IdPIssuer {
			return token.Claims{}, false, token.ErrIssuerMismatch
		}
		return claims, false, nil
	}
	return token.Claims{}, false, token.ErrBadSignature
}

func mapRegistryErr(err error) string {
	switch {
	case errors.Is(err, registry.ErrAgentNotFound):
		return ReasonAgentNotRegistered
	case errors.Is(err, registry.ErrNotAuthorized):
		return ReasonAgentNotAuthorizedOnWL
	case errors.Is(err, registry.ErrAudienceNotAllowed):
		return ReasonAudienceNotAllowed
	case errors.Is(err, registry.ErrNotYetValid):
		return ReasonAgentNotYetValid
	case errors.Is(err, registry.ErrExpired):
		return ReasonAgentExpired
	default:
		return ReasonInvalidRequest
	}
}

func narrowScope(requested, incoming string, max []string) (string, error) {
	ceiling := token.ScopeSet(strings.Join(max, " "))
	if incoming != "" {
		ceiling = token.Intersect(ceiling, token.ScopeSet(incoming))
	}
	var want map[string]struct{}
	if strings.TrimSpace(requested) == "" {
		want = token.CopySet(ceiling)
	} else {
		want = token.ScopeSet(requested)
		if !token.Subset(want, ceiling) {
			return "", errors.New("requested scope is not a subset of allowed scopes")
		}
	}
	return token.JoinScopes(want), nil
}

func newID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + "-" + hex.EncodeToString(b[:])
}
