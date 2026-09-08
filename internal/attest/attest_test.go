package attest

import (
	"context"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/token"
)

func TestLocalKeysAttest(t *testing.T) {
	kf, err := token.GenerateEd25519("wl-oncall")
	if err != nil {
		t.Fatal(err)
	}
	kf.Sub = "spiffe://example.test/workload/oncall"
	signer, _ := token.SignerFromKeyFile(kf)
	now := time.Now()
	raw, err := signer.SignClaims(token.Claims{
		Iss: "spiffe://example.test",
		Sub: kf.Sub,
		Aud: token.Audience{"https://sts.example.test"},
		Exp: now.Add(time.Minute).Unix(),
		Iat: now.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &LocalKeys{Keys: signer.JWKS(), Audience: "https://sts.example.test", Now: func() int64 { return now.Unix() }}
	id, err := a.Attest(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != kf.Sub {
		t.Fatalf("id %s", id.ID)
	}
}

func TestSPIFFEJWTRejectsNonSPIFFE(t *testing.T) {
	kf, _ := token.GenerateEd25519("wl")
	signer, _ := token.SignerFromKeyFile(kf)
	now := time.Now()
	raw, _ := signer.SignClaims(token.Claims{
		Iss: "https://spire.example.test",
		Sub: "not-a-spiffe-id",
		Aud: token.Audience{"https://sts.example.test"},
		Exp: now.Add(time.Minute).Unix(),
	})
	a := &SPIFFEJWT{Bundle: signer.JWKS(), Audience: "https://sts.example.test", Now: func() int64 { return now.Unix() }}
	if _, err := a.Attest(context.Background(), raw); err != ErrUnattested {
		t.Fatalf("got %v", err)
	}
}

func TestWrongAudience(t *testing.T) {
	kf, _ := token.GenerateEd25519("wl")
	signer, _ := token.SignerFromKeyFile(kf)
	now := time.Now()
	raw, _ := signer.SignClaims(token.Claims{
		Iss: "spiffe://example.test",
		Sub: "spiffe://example.test/workload/oncall",
		Aud: token.Audience{"https://other"},
		Exp: now.Add(time.Minute).Unix(),
	})
	a := &LocalKeys{Keys: signer.JWKS(), Audience: "https://sts.example.test", Now: func() int64 { return now.Unix() }}
	if _, err := a.Attest(context.Background(), raw); err != ErrAudience {
		t.Fatalf("got %v", err)
	}
}
