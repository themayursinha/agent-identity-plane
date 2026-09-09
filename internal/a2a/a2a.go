package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/dpop"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

type ctxKey int

const (
	ctxSubject ctxKey = iota
	ctxAudience
	ctxChain
)

func WithSubjectToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, ctxSubject, token)
}

func SubjectToken(ctx context.Context) string {
	s, _ := ctx.Value(ctxSubject).(string)
	return s
}

func WithAudience(ctx context.Context, aud string) context.Context {
	return context.WithValue(ctx, ctxAudience, aud)
}

func Audience(ctx context.Context) string {
	s, _ := ctx.Value(ctxAudience).(string)
	return s
}

func WithChain(ctx context.Context, c verify.ActorChain) context.Context {
	return context.WithValue(ctx, ctxChain, c)
}

func Chain(ctx context.Context) (verify.ActorChain, bool) {
	c, ok := ctx.Value(ctxChain).(verify.ActorChain)
	return c, ok
}

// Exchanger mints the next-hop token.
type Exchanger interface {
	Exchange(ctx context.Context, req sts.ExchangeRequest) (sts.ExchangeResult, error)
}

// HTTPExchanger calls POST /oauth/token on a remote STS.
type HTTPExchanger struct {
	Endpoint string
	Client   *http.Client
	ProofKey func(ctx context.Context) (*token.KeyFile, error)
	Now      func() time.Time
}

func (h HTTPExchanger) Exchange(ctx context.Context, req sts.ExchangeRequest) (sts.ExchangeResult, error) {
	cl := h.Client
	if cl == nil {
		cl = http.DefaultClient
	}
	form := url.Values{}
	form.Set("grant_type", sts.GrantTokenExchange)
	form.Set("subject_token", req.SubjectToken)
	form.Set("subject_token_type", sts.TokenTypeJWT)
	form.Set("actor_token", req.ActorToken)
	form.Set("actor_token_type", sts.TokenTypeJWT)
	form.Set("audience", req.Audience)
	form.Set("agent_id", req.AgentID)
	if req.Scope != "" {
		form.Set("scope", req.Scope)
	}
	if req.Purp != "" {
		form.Set("purp", req.Purp)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return sts.ExchangeResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if h.ProofKey != nil {
		kf, err := h.ProofKey(ctx)
		if err != nil {
			return sts.ExchangeResult{}, err
		}
		htu, err := dpop.OutboundURI(httpReq)
		if err != nil {
			return sts.ExchangeResult{}, err
		}
		now := time.Now().UTC()
		if h.Now != nil {
			now = h.Now()
		}
		proof, err := dpop.Prove(kf, http.MethodPost, htu, "", now)
		if err != nil {
			return sts.ExchangeResult{}, err
		}
		httpReq.Header.Set("DPoP", proof)
	}
	resp, err := cl.Do(httpReq)
	if err != nil {
		return sts.ExchangeResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var errDoc struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
			Reason      string `json:"reason_code"`
		}
		_ = json.Unmarshal(body, &errDoc)
		return sts.ExchangeResult{
			ReasonCode: errDoc.Reason,
			Error:      errDoc.Error,
			ErrorDesc:  errDoc.Description,
		}, fmt.Errorf("sts exchange: %s (%s)", errDoc.Reason, errDoc.Description)
	}
	var okDoc struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(body, &okDoc); err != nil {
		return sts.ExchangeResult{}, err
	}
	return sts.ExchangeResult{Token: okDoc.AccessToken, ExpiresIn: okDoc.ExpiresIn, ReasonCode: sts.ReasonOK}, nil
}

// LocalExchanger uses an in-process STS Config.
type LocalExchanger struct {
	STS *sts.Config
}

func (l LocalExchanger) Exchange(ctx context.Context, req sts.ExchangeRequest) (sts.ExchangeResult, error) {
	res := l.STS.Exchange(ctx, req)
	if res.ReasonCode != sts.ReasonOK {
		return res, fmt.Errorf("sts exchange: %s (%s)", res.ReasonCode, res.ErrorDesc)
	}
	return res, nil
}

// Tripper is an http.RoundTripper that exchanges for the destination
// audience and injects Authorization. Resource DPoP uses the DPoP
// scheme (RFC 9449); hops without a proof key use Bearer.
type Tripper struct {
	Base       http.RoundTripper
	Exchanger  Exchanger
	AgentID    string
	ActorToken func(ctx context.Context) (string, error)
	Audience   string
	Scope      string
	ProofKey   func(ctx context.Context) (*token.KeyFile, error)
	Now        func() time.Time
}

func (t *Tripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	subject := SubjectToken(req.Context())
	if subject == "" {
		return nil, fmt.Errorf("a2a: missing subject token in context")
	}
	aud := Audience(req.Context())
	if aud == "" {
		aud = t.Audience
	}
	if aud == "" {
		return nil, fmt.Errorf("a2a: missing audience")
	}
	actor, err := t.ActorToken(req.Context())
	if err != nil {
		return nil, err
	}
	res, err := t.Exchanger.Exchange(req.Context(), sts.ExchangeRequest{
		GrantType:    sts.GrantTokenExchange,
		SubjectToken: subject,
		ActorToken:   actor,
		Audience:     aud,
		AgentID:      t.AgentID,
		Scope:        t.Scope,
	})
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	scheme := "Bearer"
	if t.ProofKey != nil {
		scheme = "DPoP"
	}
	clone.Header.Set("Authorization", scheme+" "+res.Token)
	if t.ProofKey != nil {
		kf, err := t.ProofKey(req.Context())
		if err != nil {
			return nil, err
		}
		htu, err := dpop.OutboundURI(clone)
		if err != nil {
			return nil, err
		}
		now := time.Now().UTC()
		if t.Now != nil {
			now = t.Now()
		}
		proof, err := dpop.Prove(kf, clone.Method, htu, res.Token, now)
		if err != nil {
			return nil, err
		}
		clone.Header.Set("DPoP", proof)
	}
	if clone.Body != nil && req.Body != nil && req.GetBody != nil {
		b, _ := req.GetBody()
		clone.Body = b
	} else if req.Body != nil && clone.Body == nil {
		clone.Body = io.NopCloser(bytes.NewReader(nil))
	}
	return base.RoundTrip(clone)
}

// Middleware verifies a Bearer token for audience and stores the chain.
func Middleware(v *verify.Verifier, audience string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := AccessToken(r.Header.Get("Authorization"))
			if raw == "" {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			chain, err := v.Verify(raw, audience)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			ctx := WithChain(r.Context(), chain)
			ctx = WithSubjectToken(ctx, raw)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AccessToken returns the credential from Authorization Bearer or DPoP.
func AccessToken(h string) string {
	h = strings.TrimSpace(h)
	for _, p := range []string{"Bearer ", "DPoP "} {
		if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
			return strings.TrimSpace(h[len(p):])
		}
	}
	return ""
}

// BearerToken is AccessToken.
func BearerToken(h string) string {
	return AccessToken(h)
}
