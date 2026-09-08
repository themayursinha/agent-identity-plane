package registry

import (
	"testing"
	"time"
)

const valid = `{
  "version": 1,
  "agents": [
    {
      "id": "spiffe://example.test/agent/oncall",
      "workloads": ["spiffe://example.test/workload/oncall"],
      "audiences": ["spiffe://example.test/agent/investigation"],
      "max_scopes": ["mcp:github:pr", "mcp:alerts:read"],
      "max_depth": 4,
      "created_at": "2026-01-01T00:00:00Z",
      "expiry": "2027-01-01T00:00:00Z"
    }
  ]
}`

func TestLoadValid(t *testing.T) {
	r, err := LoadJSON([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	a, ok := r.Get("spiffe://example.test/agent/oncall")
	if !ok || a.MaxDepth != 4 {
		t.Fatalf("%v %v", ok, a)
	}
}

func TestUnknownField(t *testing.T) {
	_, err := LoadJSON([]byte(`{"version":1,"agents":[],"extra":true}`))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDuplicateAgent(t *testing.T) {
	raw := `{
	  "version": 1,
	  "agents": [
	    {"id":"spiffe://example.test/agent/a","workloads":["spiffe://example.test/wl"],"audiences":["x"],"max_depth":1},
	    {"id":"spiffe://example.test/agent/a","workloads":["spiffe://example.test/wl"],"audiences":["x"],"max_depth":1}
	  ]
	}`
	_, err := LoadJSON([]byte(raw))
	if err == nil {
		t.Fatal("expected duplicate")
	}
}

func TestMaxDepth(t *testing.T) {
	raw := `{"version":1,"agents":[{"id":"spiffe://example.test/a","workloads":["spiffe://example.test/w"],"audiences":["x"],"max_depth":0}]}`
	_, err := LoadJSON([]byte(raw))
	if err == nil {
		t.Fatal("expected max_depth")
	}
}

func TestInvertedWindow(t *testing.T) {
	raw := `{
	  "version": 1,
	  "agents": [{
	    "id": "spiffe://example.test/a",
	    "workloads": ["spiffe://example.test/w"],
	    "audiences": ["x"],
	    "max_depth": 1,
	    "created_at": "2027-01-01T00:00:00Z",
	    "expiry": "2026-01-01T00:00:00Z"
	  }]
	}`
	_, err := LoadJSON([]byte(raw))
	if err == nil {
		t.Fatal("expected inverted window")
	}
}

func TestAuthorize(t *testing.T) {
	r, err := LoadJSON([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if _, err := r.Authorize("spiffe://example.test/agent/oncall", "spiffe://example.test/workload/oncall", "spiffe://example.test/agent/investigation", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Authorize("missing", "spiffe://example.test/workload/oncall", "spiffe://example.test/agent/investigation", now); err != ErrAgentNotFound {
		t.Fatalf("got %v", err)
	}
	if _, err := r.Authorize("spiffe://example.test/agent/oncall", "spiffe://example.test/workload/other", "spiffe://example.test/agent/investigation", now); err != ErrNotAuthorized {
		t.Fatalf("got %v", err)
	}
	if _, err := r.Authorize("spiffe://example.test/agent/oncall", "spiffe://example.test/workload/oncall", "https://evil.test", now); err != ErrAudienceNotAllowed {
		t.Fatalf("got %v", err)
	}
	if _, err := r.Authorize("spiffe://example.test/agent/oncall", "spiffe://example.test/workload/oncall", "spiffe://example.test/agent/investigation", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)); err != ErrNotYetValid {
		t.Fatalf("got %v", err)
	}
	if _, err := r.Authorize("spiffe://example.test/agent/oncall", "spiffe://example.test/workload/oncall", "spiffe://example.test/agent/investigation", time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)); err != ErrExpired {
		t.Fatalf("got %v", err)
	}
}

func TestTrailingJSON(t *testing.T) {
	_, err := LoadJSON([]byte(valid + `{"x":1}`))
	if err != ErrTrailingJSON {
		t.Fatalf("got %v", err)
	}
}
