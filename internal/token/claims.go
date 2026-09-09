package token

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrAudience       = errors.New("token: audience mismatch")
	ErrExpired        = errors.New("token: expired")
	ErrNotYetValid    = errors.New("token: not yet valid")
	ErrMissingSubject = errors.New("token: missing sub")
	ErrMissingIssuer  = errors.New("token: missing iss")
	ErrIssuerMismatch = errors.New("token: issuer mismatch")
	ErrMultiAudience  = errors.New("token: minted tokens must have exactly one audience")
	ErrMissingTxn     = errors.New("token: missing txn")
)

// Actor is an RFC 8693 act object. Nested Act is the prior actor.
type Actor struct {
	Iss string `json:"iss,omitempty"`
	Sub string `json:"sub"`
	Act *Actor `json:"act,omitempty"`
}

// Claims is the JWT payload minted by the STS and accepted as a subject token.
type Claims struct {
	Iss      string        `json:"iss"`
	Sub      string        `json:"sub"`
	Aud      Audience      `json:"aud,omitempty"`
	Exp      int64         `json:"exp"`
	Nbf      int64         `json:"nbf,omitempty"`
	Iat      int64         `json:"iat,omitempty"`
	Jti      string        `json:"jti,omitempty"`
	Txn      string        `json:"txn,omitempty"`
	Act      *Actor        `json:"act,omitempty"`
	ActChain []Actor       `json:"actchain,omitempty"`
	Scope    string        `json:"scope,omitempty"`
	Purp     string        `json:"purp,omitempty"`
	Cnf      *Confirmation `json:"cnf,omitempty"`
}

// Confirmation is RFC 7800 cnf. jkt is the RFC 7638 SHA-256 thumbprint
// of the actor-token verification key this hop is bound to.
type Confirmation struct {
	JKT string `json:"jkt"`
}

func (c Claims) ConfirmJKT() string {
	if c.Cnf == nil {
		return ""
	}
	return c.Cnf.JKT
}

// Audience marshals as a JSON string when it holds a single value (the STS
// minting profile) and accepts either a string or array on verify.
type Audience []string

func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	if a == nil {
		return []byte("[]"), nil
	}
	return json.Marshal([]string(a))
}

func (a *Audience) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*a = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			*a = Audience{}
			return nil
		}
		*a = Audience{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err != nil {
		return err
	}
	*a = Audience(ss)
	return nil
}

func (a Audience) Single() (string, bool) {
	if len(a) != 1 || a[0] == "" {
		return "", false
	}
	return a[0], true
}

func (a Audience) Contains(aud string) bool {
	for _, v := range a {
		if v == aud {
			return true
		}
	}
	return false
}

// SingleAudienceClaims is a helper used when minting: rejects multi-aud.
func SingleAudience(aud string) (Audience, error) {
	if aud == "" {
		return nil, ErrMultiAudience
	}
	return Audience{aud}, nil
}

const ClockSkew = 30 * time.Second

// ReplayUntil is the last unix second at which ValidateTime still accepts
// exp (inclusive of ClockSkew). Consumed-token state must be retained
// through this instant, not raw exp.
func ReplayUntil(exp int64) int64 {
	if exp <= 0 {
		return 0
	}
	return exp + int64(ClockSkew/time.Second)
}

// KeyRetirementWait is how long a kid must remain in JWKS after it
// stops minting: mint TTL plus ClockSkew, matching ValidateTime.
func KeyRetirementWait(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = 120 * time.Second
	}
	return ttl + ClockSkew
}

// ValidateTime checks exp/nbf against now with a small clock skew.
func (c Claims) ValidateTime(now time.Time, skew time.Duration) error {
	if skew <= 0 {
		skew = ClockSkew
	}
	unix := now.Unix()
	if c.Exp == 0 || unix > c.Exp+int64(skew.Seconds()) {
		return ErrExpired
	}
	if c.Nbf > 0 && unix+int64(skew.Seconds()) < c.Nbf {
		return ErrNotYetValid
	}
	return nil
}

func (c Claims) ValidateIssuer(want string) error {
	if c.Iss == "" {
		return ErrMissingIssuer
	}
	if want != "" && c.Iss != want {
		return ErrIssuerMismatch
	}
	return nil
}

func (c Claims) ValidateAudience(want string) error {
	if want == "" {
		return ErrAudience
	}
	if !c.Aud.Contains(want) {
		return ErrAudience
	}
	return nil
}

func (c Claims) ValidateSubject() error {
	if strings.TrimSpace(c.Sub) == "" {
		return ErrMissingSubject
	}
	return nil
}

// ActorSubs returns actchain[].sub followed by act.sub (current actor last).
func (c Claims) ActorSubs() []string {
	var out []string
	for _, a := range c.ActChain {
		if a.Sub != "" {
			out = append(out, a.Sub)
		}
	}
	if c.Act != nil && c.Act.Sub != "" {
		out = append(out, c.Act.Sub)
	}
	return out
}

// Depth is the number of agent hops (actchain + current act).
func (c Claims) Depth() int {
	return len(c.ActorSubs())
}

// NestedAct wraps current around the incoming act (RFC 8693 nesting).
func NestedAct(iss, currentSub string, incoming *Actor) *Actor {
	return &Actor{Iss: iss, Sub: currentSub, Act: incoming}
}

// AppendChain copies incoming actchain and appends incoming.act if present.
func AppendChain(incoming Claims) []Actor {
	n := len(incoming.ActChain)
	out := make([]Actor, n, n+1)
	copy(out, incoming.ActChain)
	if incoming.Act != nil && incoming.Act.Sub != "" {
		prior := *incoming.Act
		prior.Act = nil // flatten: actchain entries are not nested
		out = append(out, prior)
	}
	return out
}

// ScopeSet splits an OAuth scope string into a set.
func ScopeSet(scope string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, p := range strings.Fields(scope) {
		out[p] = struct{}{}
	}
	return out
}

func JoinScopes(set map[string]struct{}) string {
	if len(set) == 0 {
		return ""
	}
	parts := make([]string, 0, len(set))
	for s := range set {
		parts = append(parts, s)
	}
	// insertion order of map iteration is randomized; sort for AI9.
	sortStrings(parts)
	return strings.Join(parts, " ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j] < s[j-1] {
			s[j], s[j-1] = s[j-1], s[j]
			j--
		}
	}
}

// Subset reports whether every token in want is present in have.
func Subset(want, have map[string]struct{}) bool {
	for s := range want {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}

func Intersect(a, b map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	for s := range a {
		if _, ok := b[s]; ok {
			out[s] = struct{}{}
		}
	}
	return out
}

func CopySet(in map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	for s := range in {
		out[s] = struct{}{}
	}
	return out
}
