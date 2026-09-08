package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
)

// KeyFile is a JSON-serializable Ed25519 key pair used by the STS and by
// the localkeys attestor. Private material is omitted when encoding a JWKS.
type KeyFile struct {
	KID    string `json:"kid"`
	Alg    string `json:"alg"`
	Kty    string `json:"kty"`
	Crv    string `json:"crv"`
	X      string `json:"x"`
	D      string `json:"d,omitempty"`
	Issuer string `json:"iss,omitempty"`
	Sub    string `json:"sub,omitempty"`
}

var (
	ErrMissingPrivateKey = errors.New("token: missing private key")
	ErrInvalidKey        = errors.New("token: invalid key material")
)

// GenerateEd25519 returns a KeyFile with a fresh Ed25519 pair.
func GenerateEd25519(kid string) (*KeyFile, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyFile{
		KID: kid,
		Alg: AlgEdDSA,
		Kty: "OKP",
		Crv: "Ed25519",
		X:   B64Encode(pub),
		D:   B64Encode(priv.Seed()),
	}, nil
}

// PublicJWKS returns a JWKS document containing only the public key.
func (k *KeyFile) PublicJWKS() JWKS {
	return JWKS{Keys: []JWK{{
		KID: k.KID,
		Kty: k.Kty,
		Alg: k.Alg,
		Crv: k.Crv,
		X:   k.X,
		Use: "sig",
	}}}
}

// PublicJWK returns the public JWK for this key.
func (k *KeyFile) PublicJWK() JWK {
	return JWK{
		KID: k.KID,
		Kty: k.Kty,
		Alg: k.Alg,
		Crv: k.Crv,
		X:   k.X,
		Use: "sig",
	}
}

// PrivateKey reconstructs the Ed25519 private key from the seed in D.
func (k *KeyFile) PrivateKey() (ed25519.PrivateKey, error) {
	if k.D == "" {
		return nil, ErrMissingPrivateKey
	}
	seed, err := B64Decode(k.D)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: seed length %d", ErrInvalidKey, len(seed))
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicKey reconstructs the Ed25519 public key from X.
func (k *KeyFile) PublicKey() (ed25519.PublicKey, error) {
	raw, err := B64Decode(k.X)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key length %d", ErrInvalidKey, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// SignerFromKeyFile builds an EdDSA signer.
func SignerFromKeyFile(k *KeyFile) (*Signer, error) {
	priv, err := k.PrivateKey()
	if err != nil {
		return nil, err
	}
	return NewSigner(priv, k.KID), nil
}

// MarshalJSON encodes a KeyFile. Callers that persist private keys must
// protect the resulting file; JWKS serving uses PublicJWKS instead.
func (k *KeyFile) MarshalJSON() ([]byte, error) {
	type alias KeyFile
	return json.Marshal((*alias)(k))
}
