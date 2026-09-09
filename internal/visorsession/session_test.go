package visorsession_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/audit"
	"github.com/themayursinha/agent-identity-plane/internal/gateway"
	"github.com/themayursinha/agent-identity-plane/internal/scenario"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/visoradapter"
	"github.com/themayursinha/agent-identity-plane/internal/visorsession"
)

func testWorld(t *testing.T) *scenario.World {
	t.Helper()
	log, err := audit.NewLogger(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	w, err := scenario.NewWorld(time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC), log)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func identityGateway(t *testing.T, w *scenario.World) *httptest.Server {
	t.Helper()
	cfg := &gateway.Config{
		Bind:         "127.0.0.1:0",
		Audience:     scenario.Gateway,
		Verifier:     w.Verifier,
		Audit:        w.STS.Audit,
		IdentityOnly: true,
		ProofReplay:  sts.NewReplayCache(func() time.Time { return w.Now }),
	}
	return httptest.NewServer(cfg.Handler())
}

func completeMapping() visoradapter.Mapping {
	return visoradapter.Mapping{
		ClientID:    "spiffe://example.test/agent/investigation",
		SessionID:   "txn-abc",
		Principal:   "user1",
		ActingAgent: "spiffe://example.test/agent/investigation",
	}
}

func TestFetchIdentityOnlyMapping(t *testing.T) {
	w := testWorld(t)
	_, tok, err := w.HappyPath()
	if err != nil {
		t.Fatal(err)
	}
	ts := identityGateway(t, w)
	t.Cleanup(ts.Close)
	m, err := visorsession.Fetch(context.Background(), visorsession.Request{
		GatewayURL: ts.URL + "/session",
		Token:      tok,
		ProofKey:   w.WL[scenario.WLInvest],
		Now:        func() time.Time { return w.Now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Complete(); err != nil {
		t.Fatal(err)
	}
	if m.ClientID != scenario.Invest {
		t.Fatalf("client-id %s", m.ClientID)
	}
	if m.SessionID == "" {
		t.Fatal("empty session-id")
	}
	name, args, err := visorsession.Command("mcp-visor", m, []string{"-policy", "policy.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "mcp-visor" {
		t.Fatalf("bin %s", name)
	}
	got := visorsession.FormatArgv(name, args)
	want := "mcp-visor serve -client-id " + m.ClientID + " -session-id " + m.SessionID + " -policy policy.yaml"
	if got != want {
		t.Fatalf("argv %q want %q", got, want)
	}
}

func TestCommandRejectsIdentityFlags(t *testing.T) {
	m := completeMapping()
	cases := [][]string{
		{"-client-id", "spoofed"},
		{"--client-id", "spoofed"},
		{"-client-id=spoofed"},
		{"--client-id=spoofed"},
		{"-session-id", "spoofed"},
		{"--session-id=spoofed"},
		{"-policy", "p.yaml", "-client-id", "spoofed"},
	}
	for _, extra := range cases {
		_, _, err := visorsession.Command("mcp-visor", m, extra)
		if !errors.Is(err, visorsession.ErrIdentityArgs) {
			t.Fatalf("extra %q: %v", extra, err)
		}
	}
}

func TestCommandRejectsIncompleteMapping(t *testing.T) {
	_, _, err := visorsession.Command("mcp-visor", visoradapter.Mapping{ClientID: "x"}, nil)
	if !errors.Is(err, visorsession.ErrMapping) {
		t.Fatalf("got %v", err)
	}
}

func TestFetchRejectsCallerSpoofJSON(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"client_id": "spoofed"})
	}))
	t.Cleanup(ts.Close)
	_, err = visorsession.Fetch(context.Background(), visorsession.Request{
		GatewayURL: ts.URL + "/session",
		Token:      "not-a-jwt",
		ProofKey:   kf,
	})
	if !errors.Is(err, visorsession.ErrMapping) {
		t.Fatalf("got %v", err)
	}
}

func TestFetchRejectsOversizedBody(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("a"), (1<<20)+1))
	}))
	t.Cleanup(ts.Close)
	_, err = visorsession.Fetch(context.Background(), visorsession.Request{
		GatewayURL: ts.URL + "/session",
		Token:      "tok",
		ProofKey:   kf,
	})
	if !errors.Is(err, visorsession.ErrBody) {
		t.Fatalf("got %v", err)
	}
}

func TestFetchRejectsNonLoopbackHTTP(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	_, err = visorsession.Fetch(context.Background(), visorsession.Request{
		GatewayURL: "http://example.test/session",
		Token:      "tok",
		ProofKey:   kf,
	})
	if !errors.Is(err, visorsession.ErrGatewayURL) {
		t.Fatalf("got %v", err)
	}
}

func TestFetchRejectsQueryAndFragment(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"http://127.0.0.1:8090/session?x=1",
		"http://127.0.0.1:8090/session#frag",
	} {
		_, err := visorsession.Fetch(context.Background(), visorsession.Request{
			GatewayURL: u,
			Token:      "tok",
			ProofKey:   kf,
		})
		if !errors.Is(err, visorsession.ErrGatewayURL) {
			t.Fatalf("%s: %v", u, err)
		}
	}
}

func TestFetchRejectsRedirects(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1/session", http.StatusFound)
	}))
	t.Cleanup(ts.Close)
	_, err = visorsession.Fetch(context.Background(), visorsession.Request{
		GatewayURL: ts.URL + "/session",
		Token:      "tok",
		ProofKey:   kf,
	})
	if !errors.Is(err, visorsession.ErrRedirect) {
		t.Fatalf("got %v", err)
	}
}

func TestFetchRequiresTokenAndKey(t *testing.T) {
	kf, err := token.GenerateEd25519("wl")
	if err != nil {
		t.Fatal(err)
	}
	_, err = visorsession.Fetch(context.Background(), visorsession.Request{
		GatewayURL: "http://127.0.0.1:8090/session",
		ProofKey:   kf,
	})
	if !errors.Is(err, visorsession.ErrToken) {
		t.Fatalf("token: %v", err)
	}
	_, err = visorsession.Fetch(context.Background(), visorsession.Request{
		GatewayURL: "http://127.0.0.1:8090/session",
		Token:      "tok",
	})
	if !errors.Is(err, visorsession.ErrProofKey) {
		t.Fatalf("key: %v", err)
	}
}

func TestLoadProofKeyModeAndActive(t *testing.T) {
	kf, err := token.GenerateEd25519("wl-1")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	okPath := filepath.Join(dir, "ok.json")
	b, err := json.Marshal(kf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(okPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := visorsession.LoadProofKey(okPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.KID != "wl-1" {
		t.Fatalf("kid %s", got.KID)
	}
	openPath := filepath.Join(dir, "open.json")
	if err := os.WriteFile(openPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := visorsession.LoadProofKey(openPath); err == nil {
		t.Fatal("expected world-readable key to fail")
	}
}

func TestCommandThenStubVisor(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "argv")
	bin := filepath.Join(dir, "mcp-visor")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + out + "\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	m := completeMapping()
	name, args, err := visorsession.Command(bin, m, []string{"-policy", "policy.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(name, args...)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(got)), "\n")
	want := []string{"serve", "-client-id", m.ClientID, "-session-id", m.SessionID, "-policy", "policy.yaml"}
	if len(lines) != len(want) {
		t.Fatalf("argv %q", got)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("argv[%d]=%q want %q", i, lines[i], want[i])
		}
	}
}

func TestChildEnvDropsAccessToken(t *testing.T) {
	got := visorsession.ChildEnv([]string{
		"PATH=/usr/bin",
		visorsession.AccessTokenEnv + "=stolen",
		"HOME=/tmp",
		visorsession.AccessTokenEnv + "_OTHER=keep",
	})
	want := []string{"PATH=/usr/bin", "HOME=/tmp", visorsession.AccessTokenEnv + "_OTHER=keep"}
	if len(got) != len(want) {
		t.Fatalf("%q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%q vs %q", got, want)
		}
	}
}
