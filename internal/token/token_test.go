package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func mustKey(t *testing.T, kid string) *KeyFile {
	t.Helper()
	kf, err := GenerateEd25519(kid)
	if err != nil {
		t.Fatal(err)
	}
	return kf
}

func TestSignVerifyEdDSA(t *testing.T) {
	kf := mustKey(t, "sts-1")
	signer, err := SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	c := Claims{
		Iss:   "https://sts.example.test",
		Sub:   "user1",
		Aud:   Audience{"spiffe://example.test/agent/investigation"},
		Exp:   time.Now().Add(2 * time.Minute).Unix(),
		Iat:   time.Now().Unix(),
		Jti:   "jti-1",
		Txn:   "txn-1",
		Scope: "mcp:github:pr",
		Act:   &Actor{Iss: "https://sts.example.test", Sub: "spiffe://example.test/agent/oncall"},
	}
	raw, err := signer.SignClaims(c)
	if err != nil {
		t.Fatal(err)
	}
	_, got, err := Verify(raw, signer.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != c.Sub || got.Txn != c.Txn || got.Act.Sub != c.Act.Sub {
		t.Fatalf("claims mismatch: %+v", got)
	}
	if _, ok := got.Aud.Single(); !ok {
		t.Fatalf("expected single audience, got %v", got.Aud)
	}
}

func TestRejectAlgNone(t *testing.T) {
	header, _ := json.Marshal(Header{Alg: "none", Typ: "JWT"})
	payload, _ := json.Marshal(Claims{Iss: "x", Sub: "y", Exp: time.Now().Add(time.Minute).Unix()})
	raw := B64Encode(header) + "." + B64Encode(payload) + "."
	_, _, err := Verify(raw, JWKS{})
	if err != ErrAlgNone {
		t.Fatalf("got %v want ErrAlgNone", err)
	}
}

func TestAlgConfusionEdDSAKeyAsRS256(t *testing.T) {
	kf := mustKey(t, "k1")
	jwk := kf.PublicJWK()
	jwk.Alg = ""
	header, _ := json.Marshal(Header{Alg: AlgRS256, KID: "k1"})
	payload, _ := json.Marshal(Claims{Iss: "x", Sub: "y", Exp: time.Now().Add(time.Minute).Unix()})
	raw := B64Encode(header) + "." + B64Encode(payload) + "." + B64Encode([]byte("not-a-sig"))
	_, _, err := Verify(raw, JWKS{Keys: []JWK{jwk}})
	if err != ErrAlgConfusion {
		t.Fatalf("got %v want ErrAlgConfusion", err)
	}
}

func TestTamperedActRejected(t *testing.T) {
	kf := mustKey(t, "sts-1")
	signer, _ := SignerFromKeyFile(kf)
	c := Claims{Iss: "sts", Sub: "user1", Aud: Audience{"next"}, Exp: time.Now().Add(time.Minute).Unix(), Act: &Actor{Sub: "agent-a"}}
	raw, _ := signer.SignClaims(c)
	parts := strings.Split(raw, ".")
	var payload Claims
	pb, _ := B64Decode(parts[1])
	_ = json.Unmarshal(pb, &payload)
	payload.Act = &Actor{Sub: "forged-agent"}
	nb, _ := json.Marshal(payload)
	tampered := parts[0] + "." + B64Encode(nb) + "." + parts[2]
	_, _, err := Verify(tampered, signer.JWKS())
	if err != ErrBadSignature {
		t.Fatalf("got %v want ErrBadSignature", err)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	a := mustKey(t, "a")
	b := mustKey(t, "b")
	sa, _ := SignerFromKeyFile(a)
	raw, _ := sa.SignClaims(Claims{Iss: "sts", Sub: "u", Aud: Audience{"x"}, Exp: time.Now().Add(time.Minute).Unix()})
	sb, _ := SignerFromKeyFile(b)
	_, _, err := Verify(raw, sb.JWKS())
	if err != ErrUnknownKey && err != ErrBadSignature {
		t.Fatalf("got %v", err)
	}
}

func TestES256Verify(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := ECDSAPublicJWK(&priv.PublicKey, "ec1")
	header, _ := json.Marshal(Header{Alg: AlgES256, Typ: "JWT", KID: "ec1"})
	payload, _ := json.Marshal(Claims{Iss: "spire", Sub: "spiffe://td/wl", Exp: time.Now().Add(time.Minute).Unix()})
	signing := B64Encode(header) + "." + B64Encode(payload)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(pad32(r.Bytes()), pad32(s.Bytes())...)
	raw := signing + "." + B64Encode(sig)
	_, c, err := Verify(raw, JWKS{Keys: []JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Sub != "spiffe://td/wl" {
		t.Fatalf("sub %s", c.Sub)
	}
}

func TestRS256Verify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := RSAPublicJWK(&priv.PublicKey, "rsa1")
	header, _ := json.Marshal(Header{Alg: AlgRS256, Typ: "JWT", KID: "rsa1"})
	payload, _ := json.Marshal(Claims{Iss: "idp", Sub: "user1", Exp: time.Now().Add(time.Minute).Unix()})
	signing := B64Encode(header) + "." + B64Encode(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := signing + "." + B64Encode(sig)
	_, c, err := Verify(raw, JWKS{Keys: []JWK{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Sub != "user1" {
		t.Fatal(c.Sub)
	}
}

func TestAudienceJSONRoundTrip(t *testing.T) {
	c := Claims{Aud: Audience{"only-one"}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"aud":"only-one"`) {
		t.Fatalf("single aud should be a string: %s", b)
	}
	var back Claims
	if err := json.Unmarshal([]byte(`{"aud":["a","b"]}`), &back); err != nil {
		t.Fatal(err)
	}
	if !back.Aud.Contains("b") {
		t.Fatal("array aud")
	}
}

func TestScopeSubset(t *testing.T) {
	have := ScopeSet("mcp:github:pr mcp:alerts:read")
	if !Subset(ScopeSet("mcp:github:pr"), have) {
		t.Fatal("expected subset")
	}
	if Subset(ScopeSet("mcp:github:pr extra"), have) {
		t.Fatal("widening")
	}
}

func TestAppendChain(t *testing.T) {
	in := Claims{
		ActChain: []Actor{{Sub: "agent-a"}},
		Act:      &Actor{Iss: "sts", Sub: "agent-b", Act: &Actor{Sub: "agent-a"}},
	}
	out := AppendChain(in)
	if len(out) != 2 || out[0].Sub != "agent-a" || out[1].Sub != "agent-b" {
		t.Fatalf("got %+v", out)
	}
	if out[1].Act != nil {
		t.Fatal("actchain entries must be flat")
	}
}

func TestValidateTime(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	c := Claims{Exp: now.Add(time.Minute).Unix(), Nbf: now.Unix()}
	if err := c.ValidateTime(now, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateTime(now.Add(2*time.Minute), time.Second); err != ErrExpired {
		t.Fatalf("got %v", err)
	}
	if err := c.ValidateTime(now.Add(-2*time.Minute), time.Second); err != ErrNotYetValid {
		t.Fatalf("got %v", err)
	}
}

func TestGoldenVectorStable(t *testing.T) {
	seed := make([]byte, 32)
	seed[31] = 1
	priv := ed25519.NewKeyFromSeed(seed)
	kf := &KeyFile{
		KID: "golden",
		Alg: AlgEdDSA,
		Kty: "OKP",
		Crv: "Ed25519",
		X:   B64Encode(priv.Public().(ed25519.PublicKey)),
		D:   B64Encode(seed),
	}
	signer, err := SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	c := Claims{
		Iss: "https://sts.example.test",
		Sub: "user1",
		Aud: Audience{"spiffe://example.test/agent/investigation"},
		Exp: 1700000120,
		Nbf: 1700000000,
		Iat: 1700000000,
		Jti: "fixed-jti",
		Txn: "fixed-txn",
		Act: &Actor{Iss: "https://sts.example.test", Sub: "spiffe://example.test/agent/oncall"},
	}
	raw, err := signer.SignClaims(c)
	if err != nil {
		t.Fatal(err)
	}
	raw2, _ := signer.SignClaims(c)
	if raw != raw2 {
		t.Fatal("Ed25519 signing must be deterministic")
	}
	if _, _, err := Verify(raw, signer.JWKS()); err != nil {
		t.Fatal(err)
	}
}

func TestJWKThumbprintRFC7638RSA(t *testing.T) {
	j := JWK{
		Kty: "RSA",
		N:   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		E:   "AQAB",
		Alg: "RS256",
		KID: "2011-04-29",
	}
	got, err := j.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if got != want {
		t.Fatalf("thumbprint %s want %s", got, want)
	}
	j.Use = "sig"
	got2, err := j.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if got2 != want {
		t.Fatalf("optional members must not change thumbprint: %s", got2)
	}
}
