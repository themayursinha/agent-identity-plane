package dpop

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/token"
)

func TestRequestURIIgnoresForwardedAndQuery(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/session?x=1#frag", nil)
	req.Host = "visor-gateway.test"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.URL.Scheme = "https"
	got, err := RequestURI(req)
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://visor-gateway.test/session" {
		t.Fatalf("htu %s", got)
	}
	req.TLS = &tls.ConnectionState{}
	got, err = RequestURI(req)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://visor-gateway.test/session" {
		t.Fatalf("tls htu %s", got)
	}
}

func TestProveAndVerify(t *testing.T) {
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
	proof, err := Prove(kf, http.MethodPost, htu, access, now)
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
	if res.JTI == "" || res.JKT != jkt {
		t.Fatalf("%+v", res)
	}
}

func TestRejectPrivateJWK(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	jwk := s.PublicJWK().PublicMembers()
	priv := struct {
		token.JWK
		D string `json:"d"`
	}{JWK: jwk, D: kf.D}
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		JWK any    `json:"jwk"`
	}{Alg: token.AlgEdDSA, Typ: Typ, JWK: priv})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(proofClaims{
		JTI: "dpop-1",
		HTM: http.MethodPost,
		HTU: "http://visor-gateway.test/session",
		IAT: time.Now().Unix(),
		ATH: AccessTokenHash("tok"),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.Sign(header, payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "visor-gateway.test"
	req.Header.Set("DPoP", raw)
	jkt, _ := kf.PublicJWK().Thumbprint()
	_, err = Verify(req, "tok", jkt, time.Now().UTC())
	if err != ErrPrivateJWK {
		t.Fatalf("got %v", err)
	}
}

func TestRejectWrongATH(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "visor-gateway.test"
	htu, _ := RequestURI(req)
	proof, err := Prove(kf, http.MethodPost, htu, "token-a", now)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("DPoP", proof)
	jkt, _ := kf.PublicJWK().Thumbprint()
	if _, err := Verify(req, "token-b", jkt, now); err != ErrInvalidProof {
		t.Fatalf("got %v", err)
	}
}

func TestMissingProof(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "visor-gateway.test"
	_, err := Verify(req, "tok", "jkt", time.Now().UTC())
	if err != ErrMissingProof {
		t.Fatalf("got %v", err)
	}
}

func TestOutboundURIUsesURLSchemeNotTLS(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "https://mcp.example.test/session?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.TLS != nil {
		t.Fatal("outbound request TLS must still be nil")
	}
	got, err := OutboundURI(req)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://mcp.example.test/session" {
		t.Fatalf("outbound htu %s", got)
	}
	in, err := RequestURI(req)
	if err != nil {
		t.Fatal(err)
	}
	if in != "http://mcp.example.test/session" {
		t.Fatalf("inbound htu must not use URL scheme: %s", in)
	}
}

func TestOutboundURIRejectsMissingScheme(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Host = "visor-gateway.test"
	if _, err := OutboundURI(req); err != ErrHTU {
		t.Fatalf("got %v", err)
	}
}

func TestMissingHost(t *testing.T) {
	req := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: "/session"}}
	_, err := RequestURI(req)
	if err != ErrHTU {
		t.Fatalf("got %v", err)
	}
}

func TestRejectsQueryInHTU(t *testing.T) {
	if !strings.Contains(Typ, "dpop") {
		t.Fatal(Typ)
	}
}
