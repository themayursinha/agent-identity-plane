package scenario

import (
	"context"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/attest"
	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/registry"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

const (
	Issuer    = "https://sts.example.test"
	IdPIssuer = "https://idp.example.test"
	Oncall    = "spiffe://example.test/agent/oncall"
	Invest    = "spiffe://example.test/agent/investigation"
	Monitor   = "spiffe://example.test/agent/monitoring"
	Gateway   = "https://mcp-gateway.example.test"
	WLOncall  = "spiffe://example.test/workload/oncall"
	WLInvest  = "spiffe://example.test/workload/investigation"
	WLMonitor = "spiffe://example.test/workload/monitoring"
	User      = "user1"
)

// World is a self-contained test/demo environment.
type World struct {
	Now       time.Time
	STSKey    *token.KeyFile
	IdPKey    *token.KeyFile
	WL        map[string]*token.KeyFile
	Registry  *registry.Registry
	STS       *sts.Config
	Verifier  *verify.Verifier
	AuditPath string
}

func NewWorld(now time.Time, auditLog *audit.Logger) (*World, error) {
	stsKey, err := token.GenerateEd25519("sts-1")
	if err != nil {
		return nil, err
	}
	idpKey, err := token.GenerateEd25519("idp-1")
	if err != nil {
		return nil, err
	}
	wl := map[string]*token.KeyFile{}
	for _, id := range []string{WLOncall, WLInvest, WLMonitor} {
		kf, err := token.GenerateEd25519("wl-" + short(id))
		if err != nil {
			return nil, err
		}
		kf.Sub = id
		wl[id] = kf
	}
	reg, err := registry.New(registry.File{
		Version: 1,
		Agents: []registry.Agent{
			{
				ID: Oncall, Workloads: []string{WLOncall},
				Audiences: []string{Invest},
				MaxScopes: []string{"mcp:github:pr", "mcp:alerts:read", "mcp:alerts:write"},
				MaxDepth:  4,
			},
			{
				ID: Invest, Workloads: []string{WLInvest},
				Audiences: []string{Monitor, Gateway},
				MaxScopes: []string{"mcp:github:pr", "mcp:alerts:read"},
				MaxDepth:  4,
			},
			{
				ID: Monitor, Workloads: []string{WLMonitor},
				Audiences: []string{Gateway},
				MaxScopes: []string{"mcp:github:pr"},
				MaxDepth:  4,
			},
		},
	})
	if err != nil {
		return nil, err
	}
	signer, err := token.NewKeyring(stsKey.KID, []*token.KeyFile{stsKey})
	if err != nil {
		return nil, err
	}
	idpSigner, err := token.SignerFromKeyFile(idpKey)
	if err != nil {
		return nil, err
	}
	var wlKeys token.JWKS
	for _, kf := range wl {
		s, err := token.SignerFromKeyFile(kf)
		if err != nil {
			return nil, err
		}
		wlKeys = token.MergeJWKS(wlKeys, s.JWKS())
	}
	att := &attest.LocalKeys{
		Keys:     wlKeys,
		Audience: Issuer,
		Now:      func() int64 { return now.Unix() },
	}
	cfg := &sts.Config{
		Issuer:    Issuer,
		TTL:       120 * time.Second,
		Bind:      "127.0.0.1:0",
		Registry:  reg,
		Signer:    signer,
		Attestor:  att,
		IdPKeys:   idpSigner.JWKS(),
		IdPIssuer: IdPIssuer,
		Audit:     auditLog,
		Now:       func() time.Time { return now },
		Replay:    sts.NewReplayCache(func() time.Time { return now }),
	}
	return &World{
		Now:      now,
		STSKey:   stsKey,
		IdPKey:   idpKey,
		WL:       wl,
		Registry: reg,
		STS:      cfg,
		Verifier: &verify.Verifier{Keys: signer.JWKS(), Issuer: Issuer, Now: func() time.Time { return now }},
	}, nil
}

func (w *World) UserToken() (string, error) {
	s, err := token.SignerFromKeyFile(w.IdPKey)
	if err != nil {
		return "", err
	}
	return s.SignClaims(token.Claims{
		Iss:   IdPIssuer,
		Sub:   User,
		Aud:   token.Audience{Oncall},
		Exp:   w.Now.Add(10 * time.Minute).Unix(),
		Iat:   w.Now.Unix(),
		Jti:   "user-session",
		Scope: "mcp:github:pr mcp:alerts:read mcp:alerts:write",
	})
}

func (w *World) ActorToken(workload string) (string, error) {
	kf, ok := w.WL[workload]
	if !ok {
		return "", errUnknownWorkload
	}
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		return "", err
	}
	return s.SignClaims(token.Claims{
		Iss: "spiffe://example.test",
		Sub: workload,
		Aud: token.Audience{Issuer},
		Exp: w.Now.Add(5 * time.Minute).Unix(),
		Iat: w.Now.Unix(),
	})
}

var errUnknownWorkload = errString("unknown workload")

type errString string

func (e errString) Error() string { return string(e) }

func (w *World) Exchange(agentID, workload, subject, audience, scope string) sts.ExchangeResult {
	actor, err := w.ActorToken(workload)
	if err != nil {
		return sts.ExchangeResult{ReasonCode: sts.ReasonInvalidActorToken, ErrorDesc: err.Error()}
	}
	return w.STS.Exchange(context.Background(), sts.ExchangeRequest{
		GrantType:    sts.GrantTokenExchange,
		SubjectToken: subject,
		ActorToken:   actor,
		Audience:     audience,
		AgentID:      agentID,
		Scope:        scope,
	})
}

func (w *World) HappyPath() (oncallTok, investTok string, err error) {
	user, err := w.UserToken()
	if err != nil {
		return "", "", err
	}
	r1 := w.Exchange(Oncall, WLOncall, user, Invest, "mcp:github:pr mcp:alerts:read")
	if r1.ReasonCode != sts.ReasonOK {
		return "", "", errString(r1.ReasonCode + ": " + r1.ErrorDesc)
	}
	r2 := w.Exchange(Invest, WLInvest, r1.Token, Gateway, "mcp:github:pr")
	if r2.ReasonCode != sts.ReasonOK {
		return "", "", errString(r2.ReasonCode + ": " + r2.ErrorDesc)
	}
	return r1.Token, r2.Token, nil
}

func short(id string) string {
	for i := len(id) - 1; i >= 0; i-- {
		if id[i] == '/' {
			return id[i+1:]
		}
	}
	return id
}
