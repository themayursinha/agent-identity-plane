package attest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
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

func TestSPIFFEJWTLiveJWKSAndIssuer(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := token.SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sub := "spiffe://example.test/workload/oncall"
	rawTok, err := signer.SignClaims(token.Claims{
		Iss: "http://oidc.example.test",
		Sub: sub,
		Aud: token.Audience{"https://sts.example.test"},
		Exp: now.Add(time.Minute).Unix(),
		Iat: now.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &SPIFFEJWT{
		Bundle:   signer.JWKS(),
		Audience: "https://sts.example.test",
		Issuer:   "http://oidc.example.test",
		Now:      func() int64 { return now.Unix() },
	}
	id, err := a.Attest(context.Background(), rawTok)
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != sub {
		t.Fatalf("id %s", id.ID)
	}
	a.Issuer = "https://other.example.test"
	if _, err := a.Attest(context.Background(), rawTok); err != ErrUnattested {
		t.Fatalf("got %v", err)
	}
	a.Issuer = "http://oidc.example.test/"
	if _, err := a.Attest(context.Background(), rawTok); err != nil {
		t.Fatalf("trailing-slash issuer: %v", err)
	}
}

func TestSPIFFEJWTReadyLiveKeys(t *testing.T) {
	a := &SPIFFEJWT{KeysFn: func() (token.JWKS, error) { return token.JWKS{}, errors.New("down") }}
	if err := a.Ready(); err == nil {
		t.Fatal("expected not ready")
	}
}

func TestSPIFFEJWTKeysFnRefetch(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := token.SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := signer.JWKS().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(srv.Close)
	now := time.Now()
	rawTok, err := signer.SignClaims(token.Claims{
		Iss: "http://oidc.example.test",
		Sub: "spiffe://example.test/workload/oncall",
		Aud: token.Audience{"https://sts.example.test"},
		Exp: now.Add(time.Minute).Unix(),
		Iat: now.Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	a := &SPIFFEJWT{
		KeysFn:   func() (token.JWKS, error) { return verify.FetchJWKS(srv.URL) },
		Audience: "https://sts.example.test",
		Now:      func() int64 { return now.Unix() },
	}
	if _, err := a.Attest(context.Background(), rawTok); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Attest(context.Background(), rawTok); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("fetches %d", n)
	}
}

func TestFirstSuccessfulReadyRequiresLive(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := token.SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	local := &LocalKeys{Keys: signer.JWKS(), Audience: "https://sts.example.test"}
	live := &SPIFFEJWT{KeysFn: func() (token.JWKS, error) { return token.JWKS{}, errors.New("down") }}
	f := FirstSuccessful{local, live}
	if err := f.Ready(); err == nil {
		t.Fatal("live attestor down must fail Ready")
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
