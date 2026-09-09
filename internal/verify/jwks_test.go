package verify_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

func TestCheckJWKSURL(t *testing.T) {
	if err := verify.CheckJWKSURL("https://sts.example.test/jwks.json"); err != nil {
		t.Fatal(err)
	}
	if err := verify.CheckJWKSURL("http://127.0.0.1:8080/jwks.json"); err != nil {
		t.Fatal(err)
	}
	if err := verify.CheckJWKSURL("http://localhost:8080/jwks.json"); err != nil {
		t.Fatal(err)
	}
	if err := verify.CheckJWKSURL("http://example.test/jwks.json"); !errors.Is(err, verify.ErrJWKSURL) {
		t.Fatalf("got %v", err)
	}
	if err := verify.CheckJWKSURL("file:///tmp/jwks.json"); !errors.Is(err, verify.ErrJWKSURL) {
		t.Fatalf("file: %v", err)
	}
}

func TestFetchJWKSLoopback(t *testing.T) {
	kf, err := token.GenerateEd25519("sts-1")
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.JWKS().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(srv.Close)
	ks, err := verify.FetchJWKS(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks.Keys) != 1 || ks.Keys[0].KID != "sts-1" {
		t.Fatalf("%+v", ks)
	}
}

func TestFetchJWKSRejectsTrailingCloser(t *testing.T) {
	kf, err := token.GenerateEd25519("sts-1")
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.JWKS().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(append(raw, []byte(` }`)...))
	}))
	t.Cleanup(srv.Close)
	if _, err := verify.FetchJWKS(srv.URL); err == nil {
		t.Fatal("trailing closer must fail")
	}
}

func TestLiveJWKSFile(t *testing.T) {
	kf, err := token.GenerateEd25519("sts-1")
	if err != nil {
		t.Fatal(err)
	}
	s, err := token.SignerFromKeyFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(s.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	fn, err := verify.LiveJWKS(path, "")
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

func TestLiveJWKSRejectsBothSources(t *testing.T) {
	if _, err := verify.LiveJWKS("jwks.json", "https://sts.example.test/jwks.json"); err == nil {
		t.Fatal("expected error when both -jwks and -jwks-url are set")
	}
}

func TestFetchJWKSRejectsRedirectToNonLoopbackHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://example.test/jwks.json", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	_, err := verify.FetchJWKS(srv.URL)
	if err == nil || !errors.Is(err, verify.ErrJWKSURL) {
		t.Fatalf("got %v", err)
	}
}
