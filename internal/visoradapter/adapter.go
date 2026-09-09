package visoradapter

import (
	"fmt"
	"strings"

	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

// Mapping is what mcp-visor can consume today (--client-id, --session-id)
// plus the typed lineage fields planned for lineage_require.
type Mapping struct {
	ClientID    string            `json:"client_id"`
	SessionID   string            `json:"session_id"`
	Principal   string            `json:"principal"`
	ActingAgent string            `json:"acting_agent"`
	Hops        []string          `json:"hops"`
	Scope       string            `json:"scope"`
	JTI         string            `json:"jti,omitempty"`
	Lineage     map[string]string `json:"lineage"`
}

const (
	// MappingContentType is the identity-only visor-gateway JSON mapping.
	// Reverse-proxied backend responses must not use this type.
	MappingContentType = "application/vnd.aip.visor-mapping+json"
	HeaderClientID     = "X-Visor-Client-Id"
	HeaderSessionID    = "X-Visor-Session-Id"
)

// Options controls how agent URIs become visor identity names.
type Options struct {
	// ShortName, when true, uses the last path segment of the acting agent
	// URI as ClientID. This is opt-in: last segments are not unique across
	// URI prefixes, so the default mapping is the complete act.sub.
	ShortName bool
}

func FromChain(c verify.ActorChain, opt Options) Mapping {
	client := c.Actor
	if opt.ShortName {
		client = shortName(client)
	}
	lin := map[string]string{
		"principal":    c.Principal,
		"acting_agent": c.Actor,
		"txn":          c.Txn,
		"scope":        c.Scope,
	}
	return Mapping{
		ClientID:    client,
		SessionID:   c.Txn,
		Principal:   c.Principal,
		ActingAgent: c.Actor,
		Hops:        append([]string{}, c.Hops...),
		Scope:       c.Scope,
		JTI:         c.JTI,
		Lineage:     lin,
	}
}

// Complete reports whether the mapping has the visor identity fields a PEP
// may forward: acting agent, client id, session/txn, and principal.
func (m Mapping) Complete() error {
	if strings.TrimSpace(m.ActingAgent) == "" || strings.TrimSpace(m.ClientID) == "" {
		return fmt.Errorf("visoradapter: missing acting agent")
	}
	if strings.TrimSpace(m.SessionID) == "" {
		return fmt.Errorf("visoradapter: missing session id")
	}
	if strings.TrimSpace(m.Principal) == "" {
		return fmt.Errorf("visoradapter: missing principal")
	}
	return nil
}

func shortName(id string) string {
	id = strings.TrimSuffix(id, "/")
	if i := strings.LastIndex(id, "/"); i >= 0 && i+1 < len(id) {
		return id[i+1:]
	}
	return id
}
