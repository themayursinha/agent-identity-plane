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

// ErrEmptyJWKS is returned when a JWKS document contains no keys.
var ErrEmptyJWKS = errors.New("verify: empty JWKS")

var jwksClient = &http.Client{
	Timeout: 2 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		Proxy:               http.ProxyFromEnvironment,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        32,
		MaxIdleConnsPerHost: 8,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("verify: too many JWKS redirects")
		}
		return CheckJWKSURL(req.URL.String())
	},
}

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
		ks, err := token.ParseJWKS(raw)
		if err != nil {
			return token.JWKS{}, err
		}
		return requireKeys(ks)
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

func getCapped(rawURL string) ([]byte, error) {
	if err := CheckJWKSURL(rawURL); err != nil {
		return nil, err
	}
	resp, err := jwksClient.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("verify: url status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxJWKSBytes {
		return nil, fmt.Errorf("verify: document exceeds %d bytes", maxJWKSBytes)
	}
	return raw, nil
}

// FetchJWKS GETs a JWKS document. TLS 1.2+; body capped at 1MiB.
func FetchJWKS(rawURL string) (token.JWKS, error) {
	raw, err := getCapped(rawURL)
	if err != nil {
		return token.JWKS{}, err
	}
	ks, err := token.ParseJWKS(raw)
	if err != nil {
		return token.JWKS{}, err
	}
	return requireKeys(ks)
}

func requireKeys(ks token.JWKS) (token.JWKS, error) {
	if len(ks.Keys) == 0 {
		return token.JWKS{}, ErrEmptyJWKS
	}
	return ks, nil
}
