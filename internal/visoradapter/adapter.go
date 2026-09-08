package visoradapter

import (
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
	Lineage     map[string]string `json:"lineage"`
}

// Options controls how agent URIs become visor identity names.
type Options struct {
	// ShortName, when true, uses the last path segment of the acting agent
	// URI as ClientID so it can match a compact identities[] name.
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
		Lineage:     lin,
	}
}

func shortName(id string) string {
	id = strings.TrimSuffix(id, "/")
	if i := strings.LastIndex(id, "/"); i >= 0 && i+1 < len(id) {
		return id[i+1:]
	}
	return id
}
