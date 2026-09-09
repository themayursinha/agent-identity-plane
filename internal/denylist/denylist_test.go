package denylist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmptyDenylistAllows(t *testing.T) {
	d, err := LoadJSON([]byte(`{"version":1,"agents":[],"workloads":[],"principals":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if d.DenyExchange("spiffe://example.test/agent/oncall", "spiffe://example.test/workload/oncall", "user1") != "" {
		t.Fatal("empty denylist must allow")
	}
}

func TestExactAgentMatch(t *testing.T) {
	d, err := New(File{Version: 1, Agents: []string{"spiffe://example.test/agent/oncall"}})
	if err != nil {
		t.Fatal(err)
	}
	if d.DenyExchange("spiffe://example.test/agent/oncall", "spiffe://example.test/workload/oncall", "user1") != ReasonAgentDenied {
		t.Fatal("expected agent_denied")
	}
	if d.HasAgent("oncall") || d.HasAgent("spiffe://example.test/agent/oncall/") {
		t.Fatal("short names and trailing-slash ids are distinct")
	}
	if d.DenyExchange("spiffe://example.test/agent/investigation", "spiffe://example.test/workload/oncall", "user1") != "" {
		t.Fatal("other agent must be allowed")
	}
}

func TestWorkloadAndPrincipal(t *testing.T) {
	d, err := New(File{
		Version:    1,
		Workloads:  []string{"spiffe://example.test/workload/oncall"},
		Principals: []string{"user1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.DenyExchange("spiffe://example.test/agent/oncall", "spiffe://example.test/workload/oncall", "user2") != ReasonWorkloadDenied {
		t.Fatal("expected workload_denied")
	}
	if d.DenyExchange("spiffe://example.test/agent/oncall", "spiffe://example.test/workload/other", "user1") != ReasonPrincipalDenied {
		t.Fatal("expected principal_denied")
	}
}

func TestDenyChainInFlightHop(t *testing.T) {
	d, err := New(File{Version: 1, Agents: []string{"spiffe://example.test/agent/oncall"}})
	if err != nil {
		t.Fatal(err)
	}
	hops := []string{"user1", "spiffe://example.test/agent/oncall", "spiffe://example.test/agent/investigation"}
	if d.DenyChain("user1", "spiffe://example.test/agent/investigation", hops) != ReasonAgentDenied {
		t.Fatal("denied hop in a minted chain must fail closed")
	}
	if d.DenyChain("user1", "investigation", hops) != ReasonAgentDenied {
		t.Fatal("short acting name must not bypass hop check")
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []string{
		`{"version":2,"agents":[]}`,
		`{"version":1,"agents":["oncall"]}`,
		`{"version":1,"agents":[""]}`,
		`{"version":1,"agents":["spiffe://a","spiffe://a"]}`,
		`{"version":1,"agents":[],"extra":true}`,
		`{"version":1,"agents":[]} }`,
	}
	for _, raw := range cases {
		if _, err := LoadJSON([]byte(raw)); err == nil {
			t.Fatalf("expected error for %s", raw)
		}
	}
}

func TestLiveReread(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "denylist.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"agents":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	fn, err := Live(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := fn()
	if err != nil {
		t.Fatal(err)
	}
	if d.HasAgent("spiffe://example.test/agent/oncall") {
		t.Fatal("empty")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"agents":["spiffe://example.test/agent/oncall"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err = fn()
	if err != nil {
		t.Fatal(err)
	}
	if !d.HasAgent("spiffe://example.test/agent/oncall") {
		t.Fatal("reread")
	}
}

func TestNilListAllows(t *testing.T) {
	var d *List
	if d.DenyExchange("a", "b", "c") != "" || d.DenyChain("p", "a", nil) != "" {
		t.Fatal("nil denylist must allow")
	}
}
