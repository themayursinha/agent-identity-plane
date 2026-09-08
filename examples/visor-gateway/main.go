package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/a2a"
	"github.com/themayursinha/agent-identity-plane/internal/sts"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
	"github.com/themayursinha/agent-identity-plane/internal/visoradapter"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8090", "listen address")
	audience := flag.String("audience", "https://mcp-gateway.example.test", "expected token audience")
	issuer := flag.String("issuer", "https://sts.example.test", "STS issuer")
	jwksPath := flag.String("jwks", "", "STS JWKS file")
	shortName := flag.Bool("client-short-name", true, "derive visor --client-id from the last URI segment")
	identityOnly := flag.Bool("identity-only", false, "verify and return mapping headers without spawning mcp-visor")
	visorBin := flag.String("visor-bin", "", "path to mcp-visor binary")
	visorServer := flag.String("visor-server", "", "mcp-visor -server command")
	visorPolicy := flag.String("visor-policy", "", "mcp-visor -policy path")
	visorAudit := flag.String("visor-audit", "", "mcp-visor -audit-log path")
	flag.Parse()

	if err := sts.ValidateBind(*listen); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if *jwksPath == "" {
		fmt.Fprintln(os.Stderr, "error: -jwks is required")
		os.Exit(1)
	}
	raw, err := os.ReadFile(*jwksPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	ks, err := token.ParseJWKS(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	v := &verify.Verifier{Keys: ks, Issuer: *issuer}
	opt := visoradapter.Options{ShortName: *shortName}

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}))
	mux.Handle("POST /session", a2a.Middleware(v, *audience)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chain, ok := a2a.Chain(r.Context())
		if !ok {
			http.Error(w, "missing chain", http.StatusInternalServerError)
			return
		}
		m := visoradapter.FromChain(chain, opt)
		w.Header().Set("X-Visor-Client-Id", m.ClientID)
		w.Header().Set("X-Visor-Session-Id", m.SessionID)
		w.Header().Set("X-Actor-Chain", strings.Join(m.Hops, " > "))
		if *identityOnly || *visorBin == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(m)
			return
		}
		if *visorServer == "" || *visorPolicy == "" || *visorAudit == "" {
			http.Error(w, "visor spawn requires -visor-server -visor-policy -visor-audit", http.StatusInternalServerError)
			return
		}
		cmd := exec.Command(*visorBin, "serve",
			"-server", *visorServer,
			"-policy", *visorPolicy,
			"-audit-log", *visorAudit,
			"-client-id", m.ClientID,
			"-session-id", m.SessionID,
		)
		cmd.Stdout = io.Discard
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"mapping": m, "visor_pid": cmd.Process.Pid})
	})))

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintf(os.Stderr, "visor-gateway listening on %s audience=%s\n", *listen, *audience)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
