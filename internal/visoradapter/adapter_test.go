package visoradapter

import (
	"testing"

	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

func TestFromChain(t *testing.T) {
	c := verify.ActorChain{
		Principal: "user1",
		Actor:     "spiffe://example.test/agent/investigation",
		Hops:      []string{"user1", "spiffe://example.test/agent/oncall", "spiffe://example.test/agent/investigation"},
		Txn:       "txn-1",
		Scope:     "mcp:github:pr",
		Depth:     2,
	}
	m := FromChain(c, Options{})
	if m.ClientID != c.Actor || m.SessionID != "txn-1" {
		t.Fatalf("%+v", m)
	}
	short := FromChain(c, Options{ShortName: true})
	if short.ClientID != "investigation" {
		t.Fatalf("short %s", short.ClientID)
	}
	if short.Lineage["principal"] != "user1" {
		t.Fatal(short.Lineage)
	}
}
