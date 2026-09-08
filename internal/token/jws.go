package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
)

const (
	AlgEdDSA = "EdDSA"
	AlgES256 = "ES256"
	AlgRS256 = "RS256"
	AlgNone  = "none"
)

var (
	ErrInvalidToken     = errors.New("token: invalid compact jws")
	ErrAlgNone          = errors.New("token: alg none rejected")
	ErrAlgConfusion     = errors.New("token: algorithm does not match key")
	ErrUnknownKey       = errors.New("token: unknown kid")
	ErrBadSignature     = errors.New("token: bad signature")
	ErrUnsupportedAlg   = errors.New("token: unsupported alg")
	ErrUnsupportedCurve = errors.New("token: unsupported curve")
)

// Header is a JWS protected header. typ is optional (JWT).
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	KID string `json:"kid,omitempty"`
}

// JWK is a public JSON Web Key. Only verification material is represented.
type JWK struct {
	KID string `json:"kid,omitempty"`
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// Signer issues compact JWS with EdDSA (Ed25519).
type Signer struct {
	key ed25519.PrivateKey
	kid string
}

func NewSigner(key ed25519.PrivateKey, kid string) *Signer {
	return &Signer{key: key, kid: kid}
}

func (s *Signer) KID() string { return s.kid }

func (s *Signer) PublicJWK() JWK {
	pub := s.key.Public().(ed25519.PublicKey)
	return JWK{
		KID: s.kid,
		Kty: "OKP",
		Use: "sig",
		Alg: AlgEdDSA,
		Crv: "Ed25519",
		X:   B64Encode(pub),
	}
}

func (s *Signer) JWKS() JWKS {
	return JWKS{Keys: []JWK{s.PublicJWK()}}
}

// SignClaims marshals claims as JSON and signs an EdDSA JWT.
func (s *Signer) SignClaims(c Claims) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(Header{Alg: AlgEdDSA, Typ: "JWT", KID: s.kid})
	if err != nil {
		return "", err
	}
	return s.Sign(header, payload)
}

func (s *Signer) Sign(header, payload []byte) (string, error) {
	input := B64Encode(header) + "." + B64Encode(payload)
	sig := ed25519.Sign(s.key, []byte(input))
	return input + "." + B64Encode(sig), nil
}

// ParseUnverified splits a compact JWS and JSON-decodes header and claims
// without verifying the signature. Callers MUST verify before trusting claims.
func ParseUnverified(raw string) (Header, Claims, []byte, error) {
	var h Header
	var c Claims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return h, c, nil, ErrInvalidToken
	}
	hb, err := B64Decode(parts[0])
	if err != nil {
		return h, c, nil, ErrInvalidToken
	}
	pb, err := B64Decode(parts[1])
	if err != nil {
		return h, c, nil, ErrInvalidToken
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return h, c, nil, ErrInvalidToken
	}
	if err := json.Unmarshal(pb, &c); err != nil {
		return h, c, nil, ErrInvalidToken
	}
	return h, c, []byte(parts[0] + "." + parts[1]), nil
}

// Verify checks the compact JWS against the key set. The header alg must
// match the selected key's type; alg=none is always rejected.
func Verify(raw string, keys JWKS) (Header, Claims, error) {
	var zero Header
	var zeroC Claims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return zero, zeroC, ErrInvalidToken
	}
	hb, err := B64Decode(parts[0])
	if err != nil {
		return zero, zeroC, ErrInvalidToken
	}
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil {
		return zero, zeroC, ErrInvalidToken
	}
	if h.Alg == "" || strings.EqualFold(h.Alg, AlgNone) {
		return zero, zeroC, ErrAlgNone
	}
	if parts[2] == "" {
		return zero, zeroC, ErrInvalidToken
	}
	jwk, err := selectKey(keys, h.KID, h.Alg)
	if err != nil {
		return zero, zeroC, err
	}
	if err := matchAlg(h.Alg, jwk); err != nil {
		return zero, zeroC, err
	}
	signing := []byte(parts[0] + "." + parts[1])
	sig, err := B64Decode(parts[2])
	if err != nil {
		return zero, zeroC, ErrBadSignature
	}
	if err := verifySig(h.Alg, jwk, signing, sig); err != nil {
		return zero, zeroC, err
	}
	pb, err := B64Decode(parts[1])
	if err != nil {
		return zero, zeroC, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return zero, zeroC, ErrInvalidToken
	}
	return h, c, nil
}

func selectKey(keys JWKS, kid, alg string) (JWK, error) {
	var matched []JWK
	for _, k := range keys.Keys {
		if kid != "" && k.KID != kid {
			continue
		}
		if k.Alg != "" && k.Alg != alg {
			continue
		}
		matched = append(matched, k)
	}
	if kid == "" && len(matched) != 1 {
		// Without kid, only a singleton key set is unambiguous.
		if len(keys.Keys) == 1 {
			return keys.Keys[0], nil
		}
		return JWK{}, ErrUnknownKey
	}
	if len(matched) == 0 {
		return JWK{}, ErrUnknownKey
	}
	return matched[0], nil
}

func matchAlg(alg string, jwk JWK) error {
	switch alg {
	case AlgEdDSA:
		if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
			return ErrAlgConfusion
		}
		if jwk.Alg != "" && jwk.Alg != AlgEdDSA {
			return ErrAlgConfusion
		}
	case AlgES256:
		if jwk.Kty != "EC" || (jwk.Crv != "" && jwk.Crv != "P-256") {
			return ErrAlgConfusion
		}
		if jwk.Alg != "" && jwk.Alg != AlgES256 {
			return ErrAlgConfusion
		}
	case AlgRS256:
		if jwk.Kty != "RSA" {
			return ErrAlgConfusion
		}
		if jwk.Alg != "" && jwk.Alg != AlgRS256 {
			return ErrAlgConfusion
		}
	default:
		return ErrUnsupportedAlg
	}
	return nil
}

func verifySig(alg string, jwk JWK, signing, sig []byte) error {
	switch alg {
	case AlgEdDSA:
		pub, err := jwk.ed25519()
		if err != nil {
			return err
		}
		if !ed25519.Verify(pub, signing, sig) {
			return ErrBadSignature
		}
		return nil
	case AlgES256:
		pub, err := jwk.ecdsaP256()
		if err != nil {
			return err
		}
		if len(sig) != 64 {
			return ErrBadSignature
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		sum := sha256.Sum256(signing)
		if !ecdsa.Verify(pub, sum[:], r, s) {
			return ErrBadSignature
		}
		return nil
	case AlgRS256:
		pub, err := jwk.rsaPub()
		if err != nil {
			return err
		}
		sum := sha256.Sum256(signing)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
			return ErrBadSignature
		}
		return nil
	default:
		return ErrUnsupportedAlg
	}
}

func (j JWK) ed25519() (ed25519.PublicKey, error) {
	raw, err := B64Decode(j.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	return ed25519.PublicKey(raw), nil
}

func (j JWK) ecdsaP256() (*ecdsa.PublicKey, error) {
	if j.Crv != "" && j.Crv != "P-256" {
		return nil, ErrUnsupportedCurve
	}
	xb, err := B64Decode(j.X)
	if err != nil {
		return nil, ErrInvalidKey
	}
	yb, err := B64Decode(j.Y)
	if err != nil {
		return nil, ErrInvalidKey
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, ErrInvalidKey
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func (j JWK) rsaPub() (*rsa.PublicKey, error) {
	nb, err := B64Decode(j.N)
	if err != nil {
		return nil, ErrInvalidKey
	}
	eb, err := B64Decode(j.E)
	if err != nil {
		return nil, ErrInvalidKey
	}
	e := int(new(big.Int).SetBytes(eb).Int64())
	if e < 3 {
		return nil, ErrInvalidKey
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

// ParseJWKS decodes a JWKS document. Unknown fields are ignored at this
// layer; verification still fail-closes on unusable keys.
func ParseJWKS(raw []byte) (JWKS, error) {
	var ks JWKS
	if err := json.Unmarshal(raw, &ks); err != nil {
		return JWKS{}, err
	}
	return ks, nil
}

func (ks JWKS) Marshal() ([]byte, error) {
	return json.Marshal(ks)
}

// MergeJWKS concatenates key sets. Later duplicates of the same kid win.
func MergeJWKS(sets ...JWKS) JWKS {
	idx := map[string]int{}
	var out []JWK
	for _, s := range sets {
		for _, k := range s.Keys {
			if k.KID != "" {
				if i, ok := idx[k.KID]; ok {
					out[i] = k
					continue
				}
				idx[k.KID] = len(out)
			}
			out = append(out, k)
		}
	}
	return JWKS{Keys: out}
}

// RSAPublicJWK encodes an RSA public key as a JWK.
func RSAPublicJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		KID: kid,
		Kty: "RSA",
		Use: "sig",
		Alg: AlgRS256,
		N:   B64Encode(pub.N.Bytes()),
		E:   B64Encode(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// ECDSAPublicJWK encodes a P-256 public key as a JWK.
func ECDSAPublicJWK(pub *ecdsa.PublicKey, kid string) JWK {
	return JWK{
		KID: kid,
		Kty: "EC",
		Use: "sig",
		Alg: AlgES256,
		Crv: "P-256",
		X:   B64Encode(pad32(pub.X.Bytes())),
		Y:   B64Encode(pad32(pub.Y.Bytes())),
	}
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func B64Encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func B64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
