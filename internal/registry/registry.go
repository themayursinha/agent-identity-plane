package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	ErrUnknownField       = errors.New("registry: unknown field")
	ErrInvalid            = errors.New("registry: invalid")
	ErrDuplicateAgent     = errors.New("registry: duplicate agent id")
	ErrEmptyID            = errors.New("registry: empty id")
	ErrMaxDepth           = errors.New("registry: max_depth must be >= 1")
	ErrInvertedWindow     = errors.New("registry: inverted validity window")
	ErrTrailingJSON       = errors.New("registry: trailing json")
	ErrAgentNotFound      = errors.New("registry: agent not found")
	ErrNotAuthorized      = errors.New("registry: agent not authorized on workload")
	ErrAudienceNotAllowed = errors.New("registry: audience not allowed")
	ErrNotYetValid        = errors.New("registry: agent not yet valid")
	ErrExpired            = errors.New("registry: agent expired")
)

// File is the on-disk registry document.
type File struct {
	Version int     `json:"version"`
	Agents  []Agent `json:"agents"`
}

// Agent is a registered AI agent identity.
type Agent struct {
	ID        string   `json:"id"`
	Workloads []string `json:"workloads"`
	Audiences []string `json:"audiences"`
	MaxScopes []string `json:"max_scopes"`
	MaxDepth  int      `json:"max_depth"`
	CreatedAt string   `json:"created_at,omitempty"`
	Expiry    string   `json:"expiry,omitempty"`
}

// Registry is a validated, indexed registry.
type Registry struct {
	Version int
	byID    map[string]Agent
	Agents  []Agent
}

// LoadJSON strictly decodes a registry document.
func LoadJSON(raw []byte) (*Registry, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		if isUnknownField(err) {
			return nil, fmt.Errorf("%w: %v", ErrUnknownField, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if dec.More() {
		return nil, ErrTrailingJSON
	}
	return New(f)
}

func LoadFile(path string) (*Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadJSON(b)
}

func New(f File) (*Registry, error) {
	if f.Version != 1 {
		return nil, fmt.Errorf("%w: version must be 1", ErrInvalid)
	}
	if len(f.Agents) == 0 {
		return nil, fmt.Errorf("%w: agents required", ErrInvalid)
	}
	r := &Registry{Version: f.Version, byID: map[string]Agent{}, Agents: make([]Agent, 0, len(f.Agents))}
	for _, a := range f.Agents {
		if err := validateAgent(a); err != nil {
			return nil, err
		}
		if _, ok := r.byID[a.ID]; ok {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateAgent, a.ID)
		}
		r.byID[a.ID] = a
		r.Agents = append(r.Agents, a)
	}
	return r, nil
}

func validateAgent(a Agent) error {
	if strings.TrimSpace(a.ID) == "" {
		return ErrEmptyID
	}
	if !strings.Contains(a.ID, "://") {
		return fmt.Errorf("%w: agent id must be a URI: %s", ErrInvalid, a.ID)
	}
	if a.MaxDepth < 1 {
		return fmt.Errorf("%w for %s", ErrMaxDepth, a.ID)
	}
	if len(a.Workloads) == 0 {
		return fmt.Errorf("%w: agent %s has no workloads", ErrInvalid, a.ID)
	}
	for _, w := range a.Workloads {
		if strings.TrimSpace(w) == "" {
			return fmt.Errorf("%w: empty workload on %s", ErrInvalid, a.ID)
		}
	}
	if len(a.Audiences) == 0 {
		return fmt.Errorf("%w: agent %s has no audiences", ErrInvalid, a.ID)
	}
	created, err := parseTime(a.CreatedAt)
	if err != nil {
		return fmt.Errorf("%w: created_at: %v", ErrInvalid, err)
	}
	exp, err := parseTime(a.Expiry)
	if err != nil {
		return fmt.Errorf("%w: expiry: %v", ErrInvalid, err)
	}
	if !created.IsZero() && !exp.IsZero() && !exp.After(created) {
		return fmt.Errorf("%w for %s", ErrInvertedWindow, a.ID)
	}
	return nil
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

func isUnknownField(err error) bool {
	return strings.Contains(err.Error(), "unknown field")
}

func (r *Registry) Get(id string) (Agent, bool) {
	a, ok := r.byID[id]
	return a, ok
}

// Authorize checks that agentID may run on workload and call audience at now.
func (r *Registry) Authorize(agentID, workload, audience string, now time.Time) (Agent, error) {
	a, ok := r.byID[agentID]
	if !ok {
		return Agent{}, ErrAgentNotFound
	}
	if err := a.ValidateAt(now); err != nil {
		return Agent{}, err
	}
	if !contains(a.Workloads, workload) {
		return Agent{}, ErrNotAuthorized
	}
	if audience != "" && !contains(a.Audiences, audience) {
		return Agent{}, ErrAudienceNotAllowed
	}
	return a, nil
}

func (a Agent) ValidateAt(now time.Time) error {
	if a.CreatedAt != "" {
		t, err := time.Parse(time.RFC3339, a.CreatedAt)
		if err != nil {
			return ErrInvalid
		}
		if now.Before(t) {
			return ErrNotYetValid
		}
	}
	if a.Expiry != "" {
		t, err := time.Parse(time.RFC3339, a.Expiry)
		if err != nil {
			return ErrInvalid
		}
		if !now.Before(t) {
			return ErrExpired
		}
	}
	return nil
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// Lint returns human-readable issues. Empty means the document is valid.
func Lint(raw []byte) []string {
	_, err := LoadJSON(raw)
	if err == nil {
		return nil
	}
	return []string{err.Error()}
}
