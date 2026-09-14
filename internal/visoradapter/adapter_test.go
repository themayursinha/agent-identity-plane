package visoradapter

import (
	"strings"
	"testing"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

func TestFromChain(t *testing.T) {
	c := verify.ActorChain{
		Principal: "user1",
		Actor:     "spiffe://example.test/agent/investigation",
		Hops:      []string{"user1", "spiffe://example.test/agent/oncall", "spiffe://example.test/agent/investigation"},
		Txn:       "txn-1",
		JTI:       "jti-1",
		Scope:     "mcp:github:pr",
		Depth:     2,
		Issuer:    "https://sts.example.test",
		Audience:  "https://visor-gateway.example.test",
		Expires:   time.Date(2026, 5, 21, 13, 0, 0, 0, time.UTC),
	}
	m := FromChain(c, Options{})
	if m.ClientID != c.Actor || m.SessionID != "txn-1" || m.JTI != "jti-1" {
		t.Fatalf("%+v", m)
	}
	if err := m.Complete(); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeContext(m.VerifiedActor)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || len(raw) > MaxActorJSONBytes {
		t.Fatalf("encoded size %d", len(raw))
	}
	if err := m.VerifiedActor.ValidateStructure(); err != nil {
		t.Fatal(err)
	}
	if m.VerifiedActor.PrincipalID != "user1" || m.VerifiedActor.ActingAgent != c.Actor {
		t.Fatalf("verified actor %+v", m.VerifiedActor)
	}
	if !m.VerifiedActor.ExpiresAt.Equal(c.Expires) {
		t.Fatalf("expires %v", m.VerifiedActor.ExpiresAt)
	}
	short := FromChain(c, Options{ShortName: true})
	if short.ClientID != "investigation" {
		t.Fatalf("short %s", short.ClientID)
	}
	if short.Lineage["principal"] != "user1" {
		t.Fatal(short.Lineage)
	}
}

func TestFromChainIncomplete(t *testing.T) {
	m := FromChain(verify.ActorChain{Principal: "user1", Txn: "txn-1"}, Options{})
	if err := m.Complete(); err == nil {
		t.Fatal("empty acting agent must be incomplete")
	}
	m = FromChain(verify.ActorChain{Principal: "user1", Actor: "agent"}, Options{})
	if err := m.Complete(); err == nil {
		t.Fatal("empty session must be incomplete")
	}
}

func TestValidateRejectsUnsupportedVerificationMethod(t *testing.T) {
	c := VerifiedActorContext{
		Version:            ActorVersionV1,
		PrincipalID:        "user1",
		ActingAgent:        "coding-agent",
		Transaction:        "txn-1",
		ActorChain:         []ActorRef{{ID: "user1"}, {ID: "coding-agent"}},
		Scopes:             []string{"write"},
		ExpiresAt:          time.Date(2026, 5, 21, 13, 0, 0, 0, time.UTC),
		VerificationMethod: "none",
	}
	if err := c.Seal(); err == nil || !strings.Contains(err.Error(), "unsupported verification_method") {
		t.Fatalf("got %v", err)
	}
}

func TestEncodeContextRejectsOversized(t *testing.T) {
	c := VerifiedActorContext{
		Version:            ActorVersionV1,
		PrincipalID:        "user1",
		ActingAgent:        "coding-agent",
		WorkloadID:         strings.Repeat("a", MaxActorJSONBytes),
		Transaction:        "txn-1",
		ActorChain:         []ActorRef{{ID: "user1"}, {ID: "coding-agent"}},
		Scopes:             []string{"write"},
		ExpiresAt:          time.Date(2026, 5, 21, 13, 0, 0, 0, time.UTC),
		VerificationMethod: ActorVerificationSTSDpop,
	}
	if _, err := EncodeContext(c); err == nil {
		t.Fatal("oversized context must fail closed before pipe write")
	}
}
