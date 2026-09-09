package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/a2a"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

const mintUsage = "usage: agent-identity-plane token mint -sts URL -issuer ISS -actor-key FILE -agent-id ID -audience AUD [-idp-key FILE -idp-issuer ISS -user SUB | -subject-token JWT] [-scope SCOPE] [-actor-iss ISS]"

var errMintRedirect = errors.New("token mint: HTTP redirects rejected")

var mintClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		Proxy:               http.ProxyFromEnvironment,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errMintRedirect
	},
}

func cmdTokenMint(args []string) error {
	tok, err := mintAccessToken(args)
	if err != nil {
		return err
	}
	_, err = fmt.Println(tok)
	return err
}

func mintAccessToken(args []string) (string, error) {
	fs := flag.NewFlagSet("token mint", flag.ContinueOnError)
	stsURL := fs.String("sts", "", "STS token endpoint (https, or loopback http)")
	issuer := fs.String("issuer", "", "STS issuer (actor token audience)")
	idpKey := fs.String("idp-key", "", "0600 IdP key for a first-hop user token")
	idpIss := fs.String("idp-issuer", "", "IdP issuer claim")
	user := fs.String("user", "", "user token subject")
	subject := fs.String("subject-token", "", "prior STS access token")
	actorKey := fs.String("actor-key", "", "0600 workload key bound with sub")
	actorIss := fs.String("actor-iss", "", "actor token issuer (default: SPIFFE trust domain of sub)")
	agentID := fs.String("agent-id", "", "requesting agent")
	audience := fs.String("audience", "", "next-hop audience")
	scope := fs.String("scope", "", "requested scope")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 0 {
		return "", fmt.Errorf("%s", mintUsage)
	}
	if *stsURL == "" || *issuer == "" || *actorKey == "" || *agentID == "" || *audience == "" {
		return "", fmt.Errorf("%s", mintUsage)
	}
	hasIDP := *idpKey != "" || *idpIss != "" || *user != ""
	hasSub := *subject != ""
	if hasIDP == hasSub {
		return "", fmt.Errorf("token mint: use -idp-key/-idp-issuer/-user or -subject-token, not both")
	}
	if hasIDP && (*idpKey == "" || *idpIss == "" || *user == "") {
		return "", fmt.Errorf("token mint: first hop requires -idp-key, -idp-issuer, and -user")
	}

	endpoint, err := mintEndpoint(*stsURL)
	if err != nil {
		return "", err
	}
	kf, err := loadSecretKey(*actorKey)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(kf.Sub) == "" {
		return "", fmt.Errorf("token mint: actor key missing sub (keys generate -sub)")
	}
	now := time.Now().UTC()
	actor, err := signActorToken(kf, *actorIss, *issuer, now)
	if err != nil {
		return "", err
	}
	subjectTok := *subject
	if !hasSub {
		subjectTok, err = signUserToken(*idpKey, *idpIss, *user, *agentID, *scope, now)
		if err != nil {
			return "", err
		}
	}
	ex := a2a.HTTPExchanger{Endpoint: endpoint, Client: mintClient}
	res, err := ex.Exchange(context.Background(), sts.ExchangeRequest{
		GrantType:    sts.GrantTokenExchange,
		SubjectToken: subjectTok,
		ActorToken:   actor,
		Audience:     *audience,
		AgentID:      *agentID,
		Scope:        *scope,
	})
	if err != nil {
		return "", err
	}
	if res.ReasonCode != sts.ReasonOK || res.Token == "" {
		return "", fmt.Errorf("token mint: %s (%s)", res.ReasonCode, res.ErrorDesc)
	}
	return res.Token, nil
}

func mintEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: %q", verify.ErrJWKSURL, raw)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/oauth/token"
	}
	out := u.String()
	if err := verify.CheckJWKSURL(out); err != nil {
		return "", err
	}
	return out, nil
}

func loadSecretKey(path string) (*token.KeyFile, error) {
	if err := token.CheckSecretFileMode(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	_, keys, err := token.ParseSigningMaterial(raw)
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 || keys[0] == nil {
		return nil, fmt.Errorf("token mint: %s must contain one key", path)
	}
	return keys[0], nil
}

func signActorToken(kf *token.KeyFile, actorIss, stsIssuer string, now time.Time) (string, error) {
	iss := strings.TrimSpace(actorIss)
	if iss == "" {
		iss = strings.TrimSpace(kf.Issuer)
	}
	if iss == "" {
		iss = spiffeTrustDomain(kf.Sub)
	}
	if iss == "" {
		return "", fmt.Errorf("token mint: actor issuer required (-actor-iss)")
	}
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		return "", err
	}
	jti, err := randomJTI("act")
	if err != nil {
		return "", err
	}
	return s.SignClaims(token.Claims{
		Iss: iss,
		Sub: kf.Sub,
		Aud: token.Audience{stsIssuer},
		Exp: now.Add(5 * time.Minute).Unix(),
		Iat: now.Unix(),
		Jti: jti,
	})
}

func signUserToken(idpPath, idpIss, user, agentID, scope string, now time.Time) (string, error) {
	kf, err := loadSecretKey(idpPath)
	if err != nil {
		return "", err
	}
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		return "", err
	}
	jti, err := randomJTI("usr")
	if err != nil {
		return "", err
	}
	return s.SignClaims(token.Claims{
		Iss:   idpIss,
		Sub:   user,
		Aud:   token.Audience{agentID},
		Exp:   now.Add(10 * time.Minute).Unix(),
		Iat:   now.Unix(),
		Jti:   jti,
		Scope: scope,
	})
}

func spiffeTrustDomain(id string) string {
	if !strings.HasPrefix(id, "spiffe://") {
		return ""
	}
	rest := strings.TrimPrefix(id, "spiffe://")
	host, _, ok := strings.Cut(rest, "/")
	if !ok || host == "" {
		return ""
	}
	return "spiffe://" + host
}

func randomJTI(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(b[:]), nil
}
