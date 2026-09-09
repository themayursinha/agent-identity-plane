package sts_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/attest"
	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/denylist"
	"github.com/themayursinha/agent-identity-plane/internal/dpop"
	"github.com/themayursinha/agent-identity-plane/internal/registry"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

func testWorld(t *testing.T) *scenario.World {
	t.Helper()
	log, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestHappyPathActorChain(t *testing.T) {
	w := testWorld(t)
	oncall, gw, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	c1, err := w.Verifier.Verify(oncall, scenario.Invest)
	if err != nil {
		t.Fatal(err)
	}
	if c1.Principal != scenario.User || c1.Actor != scenario.Oncall || c1.Txn == "" {
		t.Fatalf("%+v", c1)
	}
	c2, err := w.Verifier.Verify(gw, scenario.Gateway)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Txn != c1.Txn {
		t.Fatal("txn mutated")
	}
	if c2.Principal != scenario.User {
		t.Fatal("sub mutated")
	}
	if c2.Actor != scenario.Invest {
		t.Fatalf("actor %s", c2.Actor)
	}
	if c2.Depth != 2 {
		t.Fatalf("depth %d", c2.Depth)
	}
	_, minted, err := token.Verify(gw, w.Verifier.Keys)
	if err != nil {
		t.Fatal(err)
	}
	want, err := w.WL[scenario.WLInvest].PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if minted.ConfirmJKT() != want {
		t.Fatalf("cnf.jkt %s want %s", minted.ConfirmJKT(), want)
	}
	if !strings.Contains(c2.Scope, "mcp:github:pr") {
		t.Fatalf("scope %s", c2.Scope)
	}
	if err := verify.RequirePrincipal(c2, scenario.User); err != nil {
		t.Fatal(err)
	}
}

func TestUnregisteredAgent(t *testing.T) {
	w := testWorld(t)
	user, _ := w.UserToken()
	res := w.Exchange("spiffe://example.test/agent/rogue", scenario.WLOncall, user, scenario.Invest, "")
	if res.ReasonCode != sts.ReasonAgentNotRegistered {
		t.Fatalf("got %s", res.ReasonCode)
	}
	if res.Token != "" {
		t.Fatal("token issued")
	}
}

func TestWrongWorkload(t *testing.T) {
	w := testWorld(t)
	user, _ := w.UserToken()
	res := w.Exchange(scenario.Oncall, scenario.WLInvest, user, scenario.Invest, "")
	if res.ReasonCode != sts.ReasonAgentNotAuthorizedOnWL {
		t.Fatalf("got %s", res.ReasonCode)
	}
}

func TestAudienceNotAllowed(t *testing.T) {
	w := testWorld(t)
	user, _ := w.UserToken()
	res := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Gateway, "")
	if res.ReasonCode != sts.ReasonAudienceNotAllowed {
		t.Fatalf("got %s", res.ReasonCode)
	}
}

func TestReplayWrongAudience(t *testing.T) {
	w := testWorld(t)
	_, gw, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Verifier.Verify(gw, "https://evil.example"); err != token.ErrAudience {
		t.Fatalf("got %v", err)
	}
}

func TestScopeWidening(t *testing.T) {
	w := testWorld(t)
	user, _ := w.UserToken()
	res := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr secret:exfil")
	if res.ReasonCode != sts.ReasonScopeWidening {
		t.Fatalf("got %s", res.ReasonCode)
	}
}

func TestDepthExceeded(t *testing.T) {
	w := testWorld(t)
	regJSON := `{
	  "version": 1,
	  "agents": [
	    {"id":"spiffe://example.test/agent/oncall","workloads":["spiffe://example.test/workload/oncall"],"audiences":["spiffe://example.test/agent/investigation"],"max_scopes":["mcp:github:pr"],"max_depth":4},
	    {"id":"spiffe://example.test/agent/investigation","workloads":["spiffe://example.test/workload/investigation"],"audiences":["https://mcp-gateway.example.test"],"max_scopes":["mcp:github:pr"],"max_depth":1}
	  ]
	}`
	r, err := registry.LoadJSON([]byte(regJSON))
	if err != nil {
		t.Fatal(err)
	}
	w.STS.SetRegistry(r)
	user, _ := w.UserToken()
	r1 := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if r1.ReasonCode != sts.ReasonOK {
		t.Fatal(r1.ReasonCode, r1.ErrorDesc)
	}
	r2 := w.Exchange(scenario.Invest, scenario.WLInvest, r1.Token, scenario.Gateway, "mcp:github:pr")
	if r2.ReasonCode != sts.ReasonDepthExceeded {
		t.Fatalf("got %s %s", r2.ReasonCode, r2.ErrorDesc)
	}
}

func TestForgedChain(t *testing.T) {
	w := testWorld(t)
	user, _ := w.UserToken()
	r1 := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if r1.ReasonCode != sts.ReasonOK {
		t.Fatal(r1)
	}
	// Tamper unsigned: parse, change act, re-sign with IdP key (wrong issuer chain).
	_, c, _, err := token.ParseUnverified(r1.Token)
	if err != nil {
		t.Fatal(err)
	}
	c.Act = &token.Actor{Sub: "spiffe://example.test/agent/forged"}
	idp, _ := token.SignerFromKeyFile(w.IdPKey)
	forged, _ := idp.SignClaims(c)
	res := w.Exchange(scenario.Invest, scenario.WLInvest, forged, scenario.Gateway, "mcp:github:pr")
	if res.ReasonCode != sts.ReasonInvalidSubjectToken && res.ReasonCode != sts.ReasonChainIntegrity {
		t.Fatalf("got %s", res.ReasonCode)
	}
}

func TestExpiredSubject(t *testing.T) {
	w := testWorld(t)
	s, _ := token.SignerFromKeyFile(w.IdPKey)
	expired, _ := s.SignClaims(token.Claims{
		Iss: scenario.IdPIssuer,
		Sub: scenario.User,
		Aud: token.Audience{scenario.Oncall},
		Exp: w.Now.Add(-time.Hour).Unix(),
		Iat: w.Now.Add(-2 * time.Hour).Unix(),
	})
	res := w.Exchange(scenario.Oncall, scenario.WLOncall, expired, scenario.Invest, "")
	if res.ReasonCode != sts.ReasonExpired {
		t.Fatalf("got %s", res.ReasonCode)
	}
}

func TestValidateBind(t *testing.T) {
	if err := sts.ValidateBind("0.0.0.0:8080"); err == nil {
		t.Fatal("0.0.0.0")
	}
	if err := sts.ValidateBind(":8080"); err == nil {
		t.Fatal("empty host")
	}
	if err := sts.ValidateBind("[::]:8080"); err == nil {
		t.Fatal("::")
	}
	if err := sts.ValidateBind("127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPExchange(t *testing.T) {
	w := testWorld(t)
	ts := httptest.NewServer(w.STS.Handler())
	t.Cleanup(ts.Close)
	user, _ := w.UserToken()
	actor, _ := w.ActorToken(scenario.WLOncall)
	form := url.Values{}
	form.Set("grant_type", sts.GrantTokenExchange)
	form.Set("subject_token", user)
	form.Set("actor_token", actor)
	form.Set("audience", scenario.Invest)
	form.Set("agent_id", scenario.Oncall)
	form.Set("scope", "mcp:github:pr")
	resp, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if doc["token_type"] != "DPoP" {
		t.Fatalf("token_type %v", doc["token_type"])
	}
}

func TestHTTPUnauthenticatedUTF8DoesNotBreakAuditChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := audit.NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	user, err := w.UserToken()
	if err != nil {
		t.Fatal(err)
	}
	mint := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if mint.ReasonCode != sts.ReasonOK {
		t.Fatal(mint.ReasonCode, mint.ErrorDesc)
	}
	ts := httptest.NewServer(w.STS.Handler())
	t.Cleanup(ts.Close)
	form := url.Values{}
	form.Set("grant_type", sts.GrantTokenExchange)
	form.Set("subject_token", "x")
	form.Set("actor_token", "y")
	form.Set("audience", "aud")
	form.Set("agent_id", "\xff")
	resp, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("invalid agent_id must not mint")
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := audit.NewLogger(path); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	recs, err := audit.Trace(audit.Query{JTI: mint.Issued.Jti}, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("minted hop lost after UTF-8 deny")
	}
}

func TestHTTPTokenEndpointProofJTIDoesNotPoisonSubjectReplay(t *testing.T) {
	w := testWorld(t)
	ts := httptest.NewServer(w.STS.Handler())
	t.Cleanup(ts.Close)
	user, err := w.UserToken()
	if err != nil {
		t.Fatal(err)
	}
	actor, err := w.ActorToken(scenario.WLOncall)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{}
	form.Set("grant_type", sts.GrantTokenExchange)
	form.Set("subject_token", user)
	form.Set("actor_token", actor)
	form.Set("audience", scenario.Invest)
	form.Set("agent_id", scenario.Oncall)
	form.Set("scope", "mcp:github:pr")
	resp, err := http.Post(ts.URL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var minted struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&minted); err != nil {
		t.Fatal(err)
	}
	_, claims, _, err := token.ParseUnverified(minted.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := signProofJTI(w.WL[scenario.WLOncall], http.MethodPost, "http://sts.test/oauth/token", claims.Jti, w.Now)
	if err != nil {
		t.Fatal(err)
	}
	poison := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type="+sts.GrantTokenExchange))
	poison.Host = "sts.test"
	poison.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	poison.Header.Set("DPoP", proof)
	pr := httptest.NewRecorder()
	w.STS.Handler().ServeHTTP(pr, poison)
	if pr.Code == 200 {
		t.Fatal("poisoned request minted")
	}
	next := w.Exchange(scenario.Invest, scenario.WLInvest, minted.AccessToken, scenario.Gateway, "mcp:github:pr")
	if next.ReasonCode != sts.ReasonOK {
		t.Fatalf("subject poisoned: %s %s", next.ReasonCode, next.ErrorDesc)
	}
}

func signProofJTI(kf *token.KeyFile, method, htu, jti string, now time.Time) (string, error) {
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(struct {
		Alg string    `json:"alg"`
		Typ string    `json:"typ"`
		JWK token.JWK `json:"jwk"`
	}{Alg: token.AlgEdDSA, Typ: dpop.Typ, JWK: s.PublicJWK().PublicMembers()})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"jti": jti,
		"htm": method,
		"htu": htu,
		"iat": now.Unix(),
	})
	if err != nil {
		return "", err
	}
	return s.Sign(header, payload)
}

func TestNewServerRejectsUnspecified(t *testing.T) {
	w := testWorld(t)
	w.STS.Bind = "0.0.0.0:9"
	if _, err := sts.NewServer(w.STS); err == nil {
		t.Fatal("expected bind error")
	}
}

func TestMissingTokens(t *testing.T) {
	w := testWorld(t)
	res := w.STS.Exchange(context.Background(), sts.ExchangeRequest{AgentID: scenario.Oncall, Audience: scenario.Invest})
	if res.ReasonCode != sts.ReasonInvalidRequest {
		t.Fatalf("got %s", res.ReasonCode)
	}
}

func TestDenylistBlocksAgentWorkloadPrincipal(t *testing.T) {
	w := testWorld(t)
	user, _ := w.UserToken()
	d, err := denylist.New(denylist.File{Version: 1, Agents: []string{scenario.Oncall}})
	if err != nil {
		t.Fatal(err)
	}
	w.STS.Denylist = d
	res := w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if res.ReasonCode != sts.ReasonAgentDenied || res.Token != "" {
		t.Fatalf("agent: %s %s token=%q", res.ReasonCode, res.ErrorDesc, res.Token)
	}

	d, err = denylist.New(denylist.File{Version: 1, Workloads: []string{scenario.WLOncall}})
	if err != nil {
		t.Fatal(err)
	}
	w.STS.Denylist = d
	res = w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if res.ReasonCode != sts.ReasonWorkloadDenied || res.Token != "" {
		t.Fatalf("workload: %s token=%q", res.ReasonCode, res.Token)
	}

	d, err = denylist.New(denylist.File{Version: 1, Principals: []string{scenario.User}})
	if err != nil {
		t.Fatal(err)
	}
	w.STS.Denylist = d
	res = w.Exchange(scenario.Oncall, scenario.WLOncall, user, scenario.Invest, "mcp:github:pr")
	if res.ReasonCode != sts.ReasonPrincipalDenied || res.Token != "" {
		t.Fatalf("principal: %s token=%q", res.ReasonCode, res.Token)
	}
}

func TestSPIFFEIssuerKeyIsNotConfirmation(t *testing.T) {
	w := testWorld(t)
	issuer, err := token.GenerateEd25519("spire")
	if err != nil {
		t.Fatal(err)
	}
	issSigner, err := token.SignerFromKeyFile(issuer)
	if err != nil {
		t.Fatal(err)
	}
	svid, err := issSigner.SignClaims(token.Claims{
		Iss: "https://spire.example.test",
		Sub: scenario.WLOncall,
		Aud: token.Audience{scenario.Issuer},
		Exp: w.Now.Add(time.Minute).Unix(),
		Iat: w.Now.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	w.STS.Attestor = &attest.SPIFFEJWT{
		Bundle:   issSigner.JWKS(),
		Audience: scenario.Issuer,
		Now:      func() int64 { return w.Now.Unix() },
	}
	user, err := w.UserToken()
	if err != nil {
		t.Fatal(err)
	}
	req := sts.ExchangeRequest{
		GrantType:    sts.GrantTokenExchange,
		SubjectToken: user,
		ActorToken:   svid,
		Audience:     scenario.Invest,
		AgentID:      scenario.Oncall,
		Scope:        "mcp:github:pr",
	}
	res := w.STS.Exchange(context.Background(), req)
	if res.ReasonCode != sts.ReasonMissingCNF || res.Token != "" {
		t.Fatalf("got %s %s token=%q", res.ReasonCode, res.ErrorDesc, res.Token)
	}
	pop, err := token.GenerateEd25519("wl-pop")
	if err != nil {
		t.Fatal(err)
	}
	jkt, err := pop.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	req.ConfirmJKT = jkt
	res = w.STS.Exchange(context.Background(), req)
	if res.ReasonCode != sts.ReasonOK {
		t.Fatalf("got %s %s", res.ReasonCode, res.ErrorDesc)
	}
	if res.Issued.ConfirmJKT() != jkt {
		t.Fatalf("cnf %s want %s", res.Issued.ConfirmJKT(), jkt)
	}
	issuerJKT, err := issuer.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if res.Issued.ConfirmJKT() == issuerJKT {
		t.Fatal("cnf.jkt must not be the SPIFFE issuer key")
	}
}
