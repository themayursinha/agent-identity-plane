package visoradapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/verify"
)

const (
	ActorVersionV1           = "1"
	ActorVerificationSTSDpop = "sts+dpop"
	// MaxActorJSONBytes is below typical Unix pipe capacity (64KiB) so
	// visor-session can fill fd 3 before exec without blocking forever.
	MaxActorJSONBytes = 32 << 10
)

// ActorRef is one hop in the verified actor chain (principal first, acting agent last).
type ActorRef struct {
	ID string `json:"id"`
}

// VerifiedActorContext is the AIP copy of Visor VerifiedActorContext v1.
// It is produced only after STS+DPoP verification. The JSON object is
// written to visor's process-start fd; it is not a tools/call field.
type VerifiedActorContext struct {
	Version              string     `json:"version"`
	PrincipalID          string     `json:"principal_id"`
	ActingAgent          string     `json:"acting_agent"`
	WorkloadID           string     `json:"workload_id,omitempty"`
	Transaction          string     `json:"transaction"`
	ActorChain           []ActorRef `json:"actor_chain"`
	Scopes               []string   `json:"scopes"`
	Issuer               string     `json:"issuer,omitempty"`
	Audience             string     `json:"audience,omitempty"`
	TokenID              string     `json:"token_id,omitempty"`
	ExpiresAt            time.Time  `json:"expires_at"`
	ProofKeyThumbprint   string     `json:"proof_key_thumbprint,omitempty"`
	VerificationMethod   string     `json:"verification_method"`
	IdentitySnapshotHash string     `json:"identity_snapshot_hash"`
}

type snapshotBody struct {
	Version            string     `json:"version"`
	PrincipalID        string     `json:"principal_id"`
	ActingAgent        string     `json:"acting_agent"`
	WorkloadID         string     `json:"workload_id"`
	Transaction        string     `json:"transaction"`
	ActorChain         []ActorRef `json:"actor_chain"`
	Scopes             []string   `json:"scopes"`
	Issuer             string     `json:"issuer"`
	Audience           string     `json:"audience"`
	TokenID            string     `json:"token_id"`
	ExpiresAt          string     `json:"expires_at"`
	ProofKeyThumbprint string     `json:"proof_key_thumbprint"`
	VerificationMethod string     `json:"verification_method"`
}

func SnapshotHash(c VerifiedActorContext) (string, error) {
	scopes := append([]string{}, c.Scopes...)
	chain := append([]ActorRef{}, c.ActorChain...)
	body := snapshotBody{
		Version:            c.Version,
		PrincipalID:        c.PrincipalID,
		ActingAgent:        c.ActingAgent,
		WorkloadID:         c.WorkloadID,
		Transaction:        c.Transaction,
		ActorChain:         chain,
		Scopes:             scopes,
		Issuer:             c.Issuer,
		Audience:           c.Audience,
		TokenID:            c.TokenID,
		ExpiresAt:          c.ExpiresAt.UTC().Format(time.RFC3339Nano),
		ProofKeyThumbprint: c.ProofKeyThumbprint,
		VerificationMethod: c.VerificationMethod,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (c *VerifiedActorContext) Seal() error {
	if c == nil {
		return fmt.Errorf("visoradapter: missing verified actor context")
	}
	h, err := SnapshotHash(*c)
	if err != nil {
		return err
	}
	c.IdentitySnapshotHash = h
	return c.ValidateStructure()
}

func (c VerifiedActorContext) ValidateStructure() error {
	if c.Version != ActorVersionV1 {
		return fmt.Errorf("visoradapter: unsupported verified actor version %q", c.Version)
	}
	if strings.TrimSpace(c.PrincipalID) == "" {
		return fmt.Errorf("visoradapter: missing principal_id")
	}
	if strings.TrimSpace(c.ActingAgent) == "" {
		return fmt.Errorf("visoradapter: missing acting_agent")
	}
	if strings.TrimSpace(c.Transaction) == "" {
		return fmt.Errorf("visoradapter: missing transaction")
	}
	if c.ExpiresAt.IsZero() {
		return fmt.Errorf("visoradapter: missing expires_at")
	}
	if strings.TrimSpace(c.VerificationMethod) == "" {
		return fmt.Errorf("visoradapter: missing verification_method")
	}
	if len(c.ActorChain) == 0 {
		return fmt.Errorf("visoradapter: empty actor_chain")
	}
	if c.ActorChain[0].ID != c.PrincipalID {
		return fmt.Errorf("visoradapter: principal_id must equal actor_chain[0]")
	}
	if c.ActorChain[len(c.ActorChain)-1].ID != c.ActingAgent {
		return fmt.Errorf("visoradapter: acting_agent must equal actor_chain last hop")
	}
	want, err := SnapshotHash(c)
	if err != nil {
		return err
	}
	if c.IdentitySnapshotHash != want {
		return fmt.Errorf("visoradapter: identity_snapshot_hash mismatch")
	}
	return nil
}

func EncodeContext(c VerifiedActorContext) ([]byte, error) {
	if err := c.Seal(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxActorJSONBytes {
		return nil, fmt.Errorf("visoradapter: verified actor context exceeds %d bytes", MaxActorJSONBytes)
	}
	return raw, nil
}

func contextFromChain(c verify.ActorChain) (VerifiedActorContext, error) {
	hops := append([]string{}, c.Hops...)
	if len(hops) == 0 {
		if c.Principal != "" && c.Actor != "" && c.Principal != c.Actor {
			hops = []string{c.Principal, c.Actor}
		} else if c.Principal != "" {
			hops = []string{c.Principal}
		}
	}
	chain := make([]ActorRef, 0, len(hops))
	for _, id := range hops {
		chain = append(chain, ActorRef{ID: id})
	}
	aud := c.Audience
	ctx := VerifiedActorContext{
		Version:            ActorVersionV1,
		PrincipalID:        c.Principal,
		ActingAgent:        c.Actor,
		Transaction:        c.Txn,
		ActorChain:         chain,
		Scopes:             strings.Fields(c.Scope),
		Issuer:             c.Issuer,
		Audience:           aud,
		TokenID:            c.JTI,
		ExpiresAt:          c.Expires,
		ProofKeyThumbprint: c.Claims.ConfirmJKT(),
		VerificationMethod: ActorVerificationSTSDpop,
	}
	if err := ctx.Seal(); err != nil {
		return VerifiedActorContext{}, err
	}
	return ctx, nil
}
