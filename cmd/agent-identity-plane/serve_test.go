package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestServeSPIFFESourcesExclusive(t *testing.T) {
	dir := t.TempDir()
	base := []string{
		"-registry", filepath.Join(dir, "reg.json"),
		"-signing-key", filepath.Join(dir, "sts.json"),
		"-workload-keys", filepath.Join(dir, "wl.json"),
		"-idp-jwks", filepath.Join(dir, "idp.json"),
		"-audit-log", filepath.Join(dir, "audit.jsonl"),
		"-replay-log", filepath.Join(dir, "replay.jsonl"),
		"-denylist", filepath.Join(dir, "denylist.json"),
	}
	pairs := [][]string{
		{"-spiffe-jwks", filepath.Join(dir, "spiffe.json"), "-spiffe-jwks-url", "https://oidc.example.test/keys"},
		{"-spiffe-jwks", filepath.Join(dir, "spiffe.json"), "-spiffe-oidc-issuer", "https://oidc.example.test"},
		{"-spiffe-jwks-url", "https://oidc.example.test/keys", "-spiffe-oidc-issuer", "https://oidc.example.test"},
	}
	for _, extra := range pairs {
		err := cmdServe(append(append([]string{}, base...), extra...))
		if err == nil || !strings.Contains(err.Error(), "use one of") {
			t.Fatalf("extra %v: got %v", extra, err)
		}
	}
}

func TestServeRejectsCleartextSPIFFEURL(t *testing.T) {
	dir := t.TempDir()
	err := cmdServe([]string{
		"-registry", filepath.Join(dir, "reg.json"),
		"-signing-key", filepath.Join(dir, "sts.json"),
		"-workload-keys", filepath.Join(dir, "wl.json"),
		"-idp-jwks", filepath.Join(dir, "idp.json"),
		"-audit-log", filepath.Join(dir, "audit.jsonl"),
		"-replay-log", filepath.Join(dir, "replay.jsonl"),
		"-denylist", filepath.Join(dir, "denylist.json"),
		"-spiffe-jwks-url", "http://oidc.example.test/jwks.json",
	})
	if err == nil || !strings.Contains(err.Error(), "https or loopback http") {
		t.Fatalf("got %v", err)
	}
	err = cmdServe([]string{
		"-registry", filepath.Join(dir, "reg.json"),
		"-signing-key", filepath.Join(dir, "sts.json"),
		"-workload-keys", filepath.Join(dir, "wl.json"),
		"-idp-jwks", filepath.Join(dir, "idp.json"),
		"-audit-log", filepath.Join(dir, "audit.jsonl"),
		"-replay-log", filepath.Join(dir, "replay.jsonl"),
		"-denylist", filepath.Join(dir, "denylist.json"),
		"-spiffe-oidc-issuer", "http://oidc.example.test",
	})
	if err == nil || !strings.Contains(err.Error(), "https or loopback http") {
		t.Fatalf("oidc: %v", err)
	}
}
