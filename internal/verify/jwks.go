package verify

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/token"
)

const maxJWKSBytes = 1 << 20

// ErrJWKSURL is returned when a JWKS URL is not https (or loopback http).
var ErrJWKSURL = errors.New("verify: jwks url must be https or loopback http")

// LiveJWKS returns a KeysFn that re-reads path or fetches url on each call.
func LiveJWKS(path, rawURL string) (func() (token.JWKS, error), error) {
	if path == "" && rawURL == "" {
		return nil, fmt.Errorf("verify: -jwks or -jwks-url is required")
	}
	if path != "" && rawURL != "" {
		return nil, fmt.Errorf("verify: use -jwks or -jwks-url, not both")
	}
	if rawURL != "" {
		if err := CheckJWKSURL(rawURL); err != nil {
			return nil, err
		}
		return func() (token.JWKS, error) { return FetchJWKS(rawURL) }, nil
	}
	return func() (token.JWKS, error) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return token.JWKS{}, err
		}
		return token.ParseJWKS(raw)
	}, nil
}

// CheckJWKSURL allows https anywhere and http only to a loopback host.
func CheckJWKSURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%w: %q", ErrJWKSURL, rawURL)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if loopbackHost(u.Hostname()) {
			return nil
		}
		return fmt.Errorf("%w: %q", ErrJWKSURL, rawURL)
	default:
		return fmt.Errorf("%w: %q", ErrJWKSURL, rawURL)
	}
}

func loopbackHost(host string) bool {
	h := strings.Trim(host, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// FetchJWKS GETs a JWKS document. TLS 1.2+; body capped at 1MiB.
func FetchJWKS(rawURL string) (token.JWKS, error) {
	if err := CheckJWKSURL(rawURL); err != nil {
		return token.JWKS{}, err
	}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			Proxy:           http.ProxyFromEnvironment,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("verify: too many JWKS redirects")
			}
			return CheckJWKSURL(req.URL.String())
		},
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return token.JWKS{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return token.JWKS{}, fmt.Errorf("verify: jwks url status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return token.JWKS{}, err
	}
	if len(raw) > maxJWKSBytes {
		return token.JWKS{}, fmt.Errorf("verify: jwks document exceeds %d bytes", maxJWKSBytes)
	}
	return token.ParseJWKS(raw)
}
