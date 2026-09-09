package verify_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

func TestFetchOIDCLoopback(t *testing.T) {
	kf, err := token.GenerateEd25519("wl-1")
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := s.JWKS().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuer,
			"jwks_uri": issuer + "/jwks.json",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL
	d, err := verify.FetchOIDC(issuer)
	if err != nil {
		t.Fatal(err)
	}
	if d.JWKSURI != issuer+"/jwks.json" {
		t.Fatalf("%+v", d)
	}
	fn, err := verify.LiveOIDC(issuer)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := fn()
	if err != nil {
		t.Fatal(err)
	}
	if len(ks.Keys) != 1 {
		t.Fatalf("%d", len(ks.Keys))
	}
}

func TestFetchOIDCRejectsNonLoopbackHTTP(t *testing.T) {
	if err := verify.CheckJWKSURL("http://oidc.example.test"); !errors.Is(err, verify.ErrJWKSURL) {
		t.Fatalf("got %v", err)
	}
	if _, err := verify.FetchOIDC("http://oidc.example.test"); !errors.Is(err, verify.ErrJWKSURL) {
		t.Fatalf("got %v", err)
	}
}

func TestFetchOIDCRejectsIssuerMismatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   "https://other.example.test",
			"jwks_uri": "https://other.example.test/jwks.json",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if _, err := verify.FetchOIDC(srv.URL); err == nil {
		t.Fatal("expected issuer mismatch")
	}
}

func TestFetchOIDCRejectsCleartextJWKSURI(t *testing.T) {
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuer,
			"jwks_uri": "http://example.test/jwks.json",
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL
	if _, err := verify.FetchOIDC(issuer); !errors.Is(err, verify.ErrJWKSURL) {
		t.Fatalf("got %v", err)
	}
}

func TestFetchOIDCIgnoresExtraFields(t *testing.T) {
	kf, err := token.GenerateEd25519("wl-1")
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := s.JWKS().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":         issuer,
			"jwks_uri":       issuer + "/jwks.json",
			"token_endpoint": issuer + "/token",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(jwks)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL
	if _, err := verify.FetchOIDC(issuer); err != nil {
		t.Fatal(err)
	}
}

func TestFetchOIDCRejectsTrailingJSON(t *testing.T) {
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"` + issuer + `","jwks_uri":"` + issuer + `/jwks.json"} }`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL
	if _, err := verify.FetchOIDC(issuer); err == nil {
		t.Fatal("trailing closer must fail")
	}
}

func TestLiveOIDCRejectsEmptyJWKS(t *testing.T) {
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuer,
			"jwks_uri": issuer + "/jwks.json",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuer = srv.URL
	if _, err := verify.LiveOIDC(issuer); !errors.Is(err, verify.ErrEmptyJWKS) {
		t.Fatalf("got %v", err)
	}
}
