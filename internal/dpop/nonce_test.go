package dpop

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/token"
)

func TestNonceCacheIssueHasConsume(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	c := NewNonceCache(func() time.Time { return now })
	n := c.Issue(now)
	if n == "" || !strings.HasPrefix(n, "n-") {
		t.Fatalf("nonce %q", n)
	}
	if !c.Has(n, now) {
		t.Fatal("issued nonce missing")
	}
	if !c.Consume(n, now) {
		t.Fatal("consume")
	}
	if c.Has(n, now) || c.Consume(n, now) {
		t.Fatal("nonce must be single-use")
	}
}

func TestNonceCacheExpire(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	c := NewNonceCache(func() time.Time { return now })
	n := c.Issue(now)
	later := now.Add(NonceTTL + time.Second)
	if c.Has(n, later) || c.Consume(n, later) {
		t.Fatal("expired nonce still valid")
	}
}

func TestProveWithNonceRoundTrip(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	access := "header.payload.sig"
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "visor-gateway.test"
	htu, err := RequestURI(req)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ProveWithNonce(kf, http.MethodPost, htu, access, now, "n-abc")
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("DPoP", proof)
	jkt, err := kf.PublicJWK().Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	res, err := Verify(req, access, jkt, now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Nonce != "n-abc" {
		t.Fatalf("nonce %q", res.Nonce)
	}
}

func TestNonceFromChallenge(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     http.Header{},
	}
	resp.Header.Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", algs="EdDSA"`)
	resp.Header.Set(NonceHeader, "n-xyz")
	if got := NonceFromChallenge(resp); got != "n-xyz" {
		t.Fatalf("%q", got)
	}
	resp.Header.Set("WWW-Authenticate", `DPoP algs="EdDSA"`)
	if NonceFromChallenge(resp) != "" {
		t.Fatal("non-challenge")
	}
}
