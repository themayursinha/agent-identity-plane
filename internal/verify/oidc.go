package verify

import (
	"fmt"
	"strings"

	"github.com/themayursinha/agent-identity-plane/internal/jsonutil"
	"github.com/themayursinha/agent-identity-plane/internal/token"
)

// OIDCDiscovery is the subset of OpenID Provider Metadata this STS uses.
type OIDCDiscovery struct {
	Issuer  string
	JWKSURI string
}

// FetchOIDC loads {issuer}/.well-known/openid-configuration. The issuer
// URL and the document's jwks_uri must pass CheckJWKSURL. The document
// issuer must match the requested issuer.
func FetchOIDC(issuer string) (OIDCDiscovery, error) {
	iss := strings.TrimRight(issuer, "/")
	if err := CheckJWKSURL(iss); err != nil {
		return OIDCDiscovery{}, err
	}
	raw, err := getCapped(iss + "/.well-known/openid-configuration")
	if err != nil {
		return OIDCDiscovery{}, err
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := jsonutil.Unmarshal(raw, &doc); err != nil {
		return OIDCDiscovery{}, fmt.Errorf("verify: oidc discovery: %w", err)
	}
	docIss := strings.TrimRight(doc.Issuer, "/")
	if docIss == "" || doc.JWKSURI == "" {
		return OIDCDiscovery{}, fmt.Errorf("verify: oidc discovery missing issuer or jwks_uri")
	}
	if docIss != iss {
		return OIDCDiscovery{}, fmt.Errorf("verify: oidc issuer mismatch")
	}
	if err := CheckJWKSURL(doc.JWKSURI); err != nil {
		return OIDCDiscovery{}, err
	}
	return OIDCDiscovery{Issuer: docIss, JWKSURI: doc.JWKSURI}, nil
}

// LiveOIDC returns a KeysFn that re-runs discovery and JWKS fetch on each call.
// Construction fails closed if discovery or JWKS cannot be loaded.
func LiveOIDC(issuer string) (func() (token.JWKS, error), error) {
	fn := func() (token.JWKS, error) {
		d, err := FetchOIDC(issuer)
		if err != nil {
			return token.JWKS{}, err
		}
		return FetchJWKS(d.JWKSURI)
	}
	if _, err := fn(); err != nil {
		return nil, err
	}
	return fn, nil
}
