// Package visorsession starts mcp-visor with identity flags taken only
// from a visor-gateway mapping (AI21).
package visorsession

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/dpop"
	"github.com/themayursinha/agent-identity-plane/internal/jsonutil"
	"github.com/themayursinha/agent-identity-plane/internal/token"
	"github.com/themayursinha/agent-identity-plane/internal/verify"
	"github.com/themayursinha/agent-identity-plane/internal/visoradapter"
)

const (
	maxMappingBytes = 1 << 20
	// AccessTokenEnv is the optional STS token source for visor-session.
	// It is stripped from the visor child environment.
	AccessTokenEnv = "AIP_ACCESS_TOKEN"
)

var (
	// ErrGatewayURL is returned when the visor-gateway URL is not https
	// (or loopback http), or includes a query or fragment.
	ErrGatewayURL = errors.New("visorsession: gateway url must be https or loopback http, without query or fragment")
	// ErrIdentityArgs is returned when extra visor arguments try to set
	// -client-id or -session-id.
	ErrIdentityArgs = errors.New("visorsession: visor identity flags are set only from visor-gateway")
	// ErrMapping is returned when the gateway response is not a complete mapping.
	ErrMapping = errors.New("visorsession: gateway mapping is incomplete")
	// ErrBody is returned when the gateway response exceeds 1MiB.
	ErrBody = errors.New("visorsession: gateway response exceeds 1MiB")
	// ErrToken is returned when the access token is missing.
	ErrToken = errors.New("visorsession: access token required")
	// ErrProofKey is returned when the DPoP key is missing.
	ErrProofKey = errors.New("visorsession: dpop key required")
	// ErrRedirect is returned when visor-gateway responds with a redirect.
	// Redirects are not followed: DPoP htm/htu are bound to the configured URL.
	ErrRedirect = errors.New("visorsession: HTTP redirects are not followed")
)

var httpClient = &http.Client{
	Timeout: 2 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		Proxy:               http.ProxyFromEnvironment,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return ErrRedirect
	},
}

// Request is a visor-gateway identity-only fetch.
type Request struct {
	GatewayURL string
	Token      string
	ProofKey   *token.KeyFile
	Now        func() time.Time
}

// CheckGatewayURL allows https anywhere and http only to a loopback host.
// Query strings and fragments are rejected so DPoP htu matches the PEP.
func CheckGatewayURL(rawURL string) error {
	if err := verify.CheckJWKSURL(rawURL); err != nil {
		return fmt.Errorf("%w: %q", ErrGatewayURL, rawURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrGatewayURL, rawURL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: %q", ErrGatewayURL, rawURL)
	}
	return nil
}

// LoadProofKey reads a 0600 Ed25519 key or keyring file for DPoP.
func LoadProofKey(path string) (*token.KeyFile, error) {
	if err := token.CheckSecretFileMode(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	active, keys, err := token.ParseSigningMaterial(raw)
	if err != nil {
		return nil, err
	}
	for _, kf := range keys {
		if kf != nil && kf.KID == active {
			if _, err := token.SignerFromKeyFile(kf); err != nil {
				return nil, err
			}
			return kf, nil
		}
	}
	return nil, fmt.Errorf("%w: active kid %q not in key file", token.ErrInvalidKey, active)
}

// Fetch POSTs to visor-gateway with Authorization DPoP and a DPoP proof
// and returns the verified mapping. It does not exec visor.
func Fetch(ctx context.Context, req Request) (visoradapter.Mapping, error) {
	var zero visoradapter.Mapping
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(req.Token) == "" {
		return zero, ErrToken
	}
	if req.ProofKey == nil {
		return zero, ErrProofKey
	}
	if err := CheckGatewayURL(req.GatewayURL); err != nil {
		return zero, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.GatewayURL, nil)
	if err != nil {
		return zero, err
	}
	htu, err := dpop.OutboundURI(httpReq)
	if err != nil {
		return zero, err
	}
	now := time.Now().UTC()
	if req.Now != nil {
		now = req.Now()
	}
	proof, err := dpop.Prove(req.ProofKey, http.MethodPost, htu, req.Token, now)
	if err != nil {
		return zero, err
	}
	httpReq.Header.Set("Authorization", "DPoP "+req.Token)
	httpReq.Header.Set("DPoP", proof)
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxMappingBytes+1))
	if err != nil {
		return zero, err
	}
	if len(raw) > maxMappingBytes {
		return zero, ErrBody
	}
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("visorsession: gateway status %d", resp.StatusCode)
	}
	var m visoradapter.Mapping
	if err := jsonutil.Unmarshal(raw, &m); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrMapping, err)
	}
	if err := m.Complete(); err != nil {
		return zero, fmt.Errorf("%w: %v", ErrMapping, err)
	}
	return m, nil
}

// RejectIdentityArgs fails closed if extra visor arguments set client-id
// or session-id (including --flag=value forms).
func RejectIdentityArgs(extra []string) error {
	for _, a := range extra {
		name, _, _ := strings.Cut(a, "=")
		switch name {
		case "-client-id", "--client-id", "-session-id", "--session-id":
			return fmt.Errorf("%w: %s", ErrIdentityArgs, a)
		}
	}
	return nil
}

// Command returns visor-bin and argv: serve -client-id <mapping>
// -session-id <mapping> plus extra policy flags. Extra may not set
// identity flags. Mapping must be Complete.
func Command(visorBin string, m visoradapter.Mapping, extra []string) (string, []string, error) {
	if strings.TrimSpace(visorBin) == "" {
		return "", nil, fmt.Errorf("visorsession: visor-bin required")
	}
	if err := m.Complete(); err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrMapping, err)
	}
	if err := RejectIdentityArgs(extra); err != nil {
		return "", nil, err
	}
	args := []string{"serve", "-client-id", m.ClientID, "-session-id", m.SessionID}
	args = append(args, extra...)
	return visorBin, args, nil
}

// FormatArgv joins name and args with spaces for -print.
func FormatArgv(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}

// ChildEnv copies env without AIP_ACCESS_TOKEN so mcp-visor and its
// descendants do not inherit the STS access token.
func ChildEnv(env []string) []string {
	prefix := AccessTokenEnv + "="
	out := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}
