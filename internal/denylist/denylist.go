package denylist

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/themayursinha/agent-identity-plane/internal/jsonutil"
)

const (
	ReasonAgentDenied     = "agent_denied"
	ReasonWorkloadDenied  = "workload_denied"
	ReasonPrincipalDenied = "principal_denied"
	ReasonUnavailable     = "denylist_unavailable"
)

var (
	ErrInvalid   = errors.New("denylist: invalid")
	ErrTrailing  = errors.New("denylist: trailing json")
	ErrUnknown   = errors.New("denylist: unknown field")
	ErrDuplicate = errors.New("denylist: duplicate id")
	ErrEmptyID   = errors.New("denylist: empty id")
)

// File is the on-disk denylist document.
type File struct {
	Version    int      `json:"version"`
	Agents     []string `json:"agents"`
	Workloads  []string `json:"workloads"`
	Principals []string `json:"principals"`
}

// List is a validated, indexed denylist. Nil means nothing is denied.
type List struct {
	agents     map[string]struct{}
	workloads  map[string]struct{}
	principals map[string]struct{}
}

// LoadJSON strictly decodes a denylist document.
func LoadJSON(raw []byte) (*List, error) {
	var f File
	if err := jsonutil.UnmarshalStrict(raw, &f); err != nil {
		if errors.Is(err, jsonutil.ErrTrailing) {
			return nil, ErrTrailing
		}
		if strings.Contains(err.Error(), "unknown field") {
			return nil, fmt.Errorf("%w: %v", ErrUnknown, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return New(f)
}

func LoadFile(path string) (*List, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadJSON(b)
}

func New(f File) (*List, error) {
	if f.Version != 1 {
		return nil, fmt.Errorf("%w: version must be 1", ErrInvalid)
	}
	d := &List{
		agents:     map[string]struct{}{},
		workloads:  map[string]struct{}{},
		principals: map[string]struct{}{},
	}
	if err := indexURI(d.agents, f.Agents, "agent"); err != nil {
		return nil, err
	}
	if err := indexURI(d.workloads, f.Workloads, "workload"); err != nil {
		return nil, err
	}
	if err := indexExact(d.principals, f.Principals, "principal"); err != nil {
		return nil, err
	}
	return d, nil
}

func indexURI(dst map[string]struct{}, ids []string, kind string) error {
	for _, id := range ids {
		if strings.TrimSpace(id) == "" || id != strings.TrimSpace(id) {
			return fmt.Errorf("%w: %s", ErrEmptyID, kind)
		}
		if err := identityURI(id); err != nil {
			return fmt.Errorf("%w: %s id must be a URI: %s", ErrInvalid, kind, id)
		}
		if _, ok := dst[id]; ok {
			return fmt.Errorf("%w: %s %s", ErrDuplicate, kind, id)
		}
		dst[id] = struct{}{}
	}
	return nil
}

func identityURI(id string) error {
	if strings.ContainsAny(id, " \t\r\n") {
		return ErrInvalid
	}
	u, err := url.Parse(id)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ErrInvalid
	}
	return nil
}

func indexExact(dst map[string]struct{}, ids []string, kind string) error {
	for _, id := range ids {
		if strings.TrimSpace(id) == "" || id != strings.TrimSpace(id) {
			return fmt.Errorf("%w: %s", ErrEmptyID, kind)
		}
		if _, ok := dst[id]; ok {
			return fmt.Errorf("%w: %s %s", ErrDuplicate, kind, id)
		}
		dst[id] = struct{}{}
	}
	return nil
}

func has(m map[string]struct{}, id string) bool {
	if m == nil || id == "" {
		return false
	}
	_, ok := m[id]
	return ok
}

func (d *List) HasAgent(id string) bool {
	if d == nil {
		return false
	}
	return has(d.agents, id)
}

func (d *List) HasWorkload(id string) bool {
	if d == nil {
		return false
	}
	return has(d.workloads, id)
}

func (d *List) HasPrincipal(id string) bool {
	if d == nil {
		return false
	}
	return has(d.principals, id)
}

// DenyExchange is the STS check: agent, then workload, then principal.
func (d *List) DenyExchange(agentID, workload, principal string) string {
	if d == nil {
		return ""
	}
	if d.HasAgent(agentID) {
		return ReasonAgentDenied
	}
	if d.HasWorkload(workload) {
		return ReasonWorkloadDenied
	}
	if d.HasPrincipal(principal) {
		return ReasonPrincipalDenied
	}
	return ""
}

// DenyChain is the visor-gateway check: principal, acting agent, and
// every agent-position hop. hops[0] is the principal position; later
// hops are actors even if their URI equals the principal. Last-segment
// short names are not identifiers.
func (d *List) DenyChain(principal, acting string, hops []string) string {
	if d == nil {
		return ""
	}
	if d.HasPrincipal(principal) {
		return ReasonPrincipalDenied
	}
	if d.HasAgent(acting) {
		return ReasonAgentDenied
	}
	for i, h := range hops {
		if h == "" || i == 0 {
			continue
		}
		if d.HasAgent(h) {
			return ReasonAgentDenied
		}
	}
	return ""
}

// Live returns a function that re-reads path on each call. Construction
// fails closed if the file cannot be loaded.
func Live(path string) (func() (*List, error), error) {
	if path == "" {
		return nil, fmt.Errorf("denylist: path required")
	}
	if _, err := LoadFile(path); err != nil {
		return nil, err
	}
	return func() (*List, error) { return LoadFile(path) }, nil
}
