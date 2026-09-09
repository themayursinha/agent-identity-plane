// Package dpop verifies RFC 9449 DPoP proofs at visor-gateway.
package dpop

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/token"
)

const Typ = "dpop+jwt"

var (
	ErrMissingProof = errors.New("dpop: missing DPoP header")
	ErrInvalidProof = errors.New("dpop: invalid DPoP proof")
	ErrPrivateJWK   = errors.New("dpop: DPoP jwk must be a public key")
	ErrHTU          = errors.New("dpop: request URI for htu is missing a host")
)

type proofHeader struct {
	Alg string          `json:"alg"`
	Typ string          `json:"typ"`
	JWK json.RawMessage `json:"jwk"`
}

type proofClaims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath,omitempty"`
}

// Result is a verified proof identity for durable jti consumption.
type Result struct {
	JTI string
	IAT int64
	JKT string
}

// AccessTokenHash is base64url(SHA-256(access_token)) as in RFC 9449 ath.
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return token.B64Encode(sum[:])
}

// RequestURI is the RFC 9449 htu value: scheme://host/path with no query
// or fragment. Scheme comes from the TLS state of this request, never
// from X-Forwarded-Proto or the client-supplied URL scheme.
func RequestURI(r *http.Request) (string, error) {
	if r == nil || strings.TrimSpace(r.Host) == "" {
		return "", ErrHTU
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	path := escapedPath(r)
	return scheme + "://" + r.Host + path, nil
}

// OutboundURI is the htu a client puts in a DPoP proof it is about to
// send. Scheme and host come from the request URL (the address the peer
// will observe). Local TLS state is still nil in RoundTrip, so
// RequestURI must not be used here. X-Forwarded-* is ignored.
func OutboundURI(r *http.Request) (string, error) {
	if r == nil || r.URL == nil {
		return "", ErrHTU
	}
	scheme := strings.ToLower(r.URL.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", ErrHTU
	}
	host := r.Host
	if strings.TrimSpace(host) == "" {
		host = r.URL.Host
	}
	if strings.TrimSpace(host) == "" {
		return "", ErrHTU
	}
	return scheme + "://" + host + escapedPath(r), nil
}

func escapedPath(r *http.Request) string {
	if r.URL == nil {
		return "/"
	}
	path := r.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

// Prove signs a DPoP JWT with the workload key for this hop.
func Prove(kf *token.KeyFile, method, htu, accessToken string, now time.Time) (string, error) {
	if kf == nil {
		return "", ErrInvalidProof
	}
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		return "", err
	}
	jwk := s.PublicJWK().PublicMembers()
	header, err := json.Marshal(struct {
		Alg string    `json:"alg"`
		Typ string    `json:"typ"`
		JWK token.JWK `json:"jwk"`
	}{Alg: token.AlgEdDSA, Typ: Typ, JWK: jwk})
	if err != nil {
		return "", err
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	pc := proofClaims{
		JTI: newJTI(),
		HTM: method,
		HTU: htu,
		IAT: now.Unix(),
	}
	if accessToken != "" {
		pc.ATH = AccessTokenHash(accessToken)
	}
	payload, err := json.Marshal(pc)
	if err != nil {
		return "", err
	}
	return s.Sign(header, payload)
}

func newJTI() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "dpop-" + hex.EncodeToString(b[:])
}

// Verify checks the DPoP header against the access token and request.
func Verify(r *http.Request, accessToken, wantJKT string, now time.Time) (Result, error) {
	if r == nil {
		return Result{}, ErrInvalidProof
	}
	raw := strings.TrimSpace(r.Header.Get("DPoP"))
	if raw == "" {
		return Result{}, ErrMissingProof
	}
	tokenRequest := accessToken == "" && wantJKT == ""
	if !tokenRequest && (accessToken == "" || wantJKT == "") {
		return Result{}, ErrInvalidProof
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Result{}, ErrInvalidProof
	}
	hb, err := token.B64Decode(parts[0])
	if err != nil {
		return Result{}, ErrInvalidProof
	}
	var h proofHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return Result{}, ErrInvalidProof
	}
	if h.Typ != Typ {
		return Result{}, ErrInvalidProof
	}
	if h.Alg == "" || strings.EqualFold(h.Alg, token.AlgNone) {
		return Result{}, token.ErrAlgNone
	}
	if len(h.JWK) == 0 {
		return Result{}, ErrInvalidProof
	}
	if err := rejectPrivateJWK(h.JWK); err != nil {
		return Result{}, err
	}
	var jwk token.JWK
	if err := json.Unmarshal(h.JWK, &jwk); err != nil {
		return Result{}, ErrInvalidProof
	}
	if _, _, err := token.Verify(raw, token.JWKS{Keys: []token.JWK{jwk}}); err != nil {
		return Result{}, ErrInvalidProof
	}
	pb, err := token.B64Decode(parts[1])
	if err != nil {
		return Result{}, ErrInvalidProof
	}
	var c proofClaims
	if err := json.Unmarshal(pb, &c); err != nil {
		return Result{}, ErrInvalidProof
	}
	if c.JTI == "" || c.HTM == "" || c.HTU == "" || c.IAT == 0 {
		return Result{}, ErrInvalidProof
	}
	if tokenRequest {
		if c.ATH != "" {
			return Result{}, ErrInvalidProof
		}
	} else if c.ATH == "" {
		return Result{}, ErrInvalidProof
	}
	if c.HTM != r.Method {
		return Result{}, ErrInvalidProof
	}
	wantHTU, err := RequestURI(r)
	if err != nil {
		return Result{}, err
	}
	if c.HTU != wantHTU {
		return Result{}, ErrInvalidProof
	}
	if !tokenRequest && c.ATH != AccessTokenHash(accessToken) {
		return Result{}, ErrInvalidProof
	}
	jkt, err := jwk.Thumbprint()
	if err != nil {
		return Result{}, ErrInvalidProof
	}
	if !tokenRequest && jkt != wantJKT {
		return Result{}, ErrInvalidProof
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := token.ClockSkew
	unix := now.Unix()
	if unix > c.IAT+int64(skew.Seconds()) || unix+int64(skew.Seconds()) < c.IAT {
		return Result{}, ErrInvalidProof
	}
	return Result{JTI: c.JTI, IAT: c.IAT, JKT: jkt}, nil
}

func rejectPrivateJWK(raw json.RawMessage) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return ErrInvalidProof
	}
	for _, k := range []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth"} {
		if _, ok := m[k]; ok {
			return ErrPrivateJWK
		}
	}
	return nil
}
