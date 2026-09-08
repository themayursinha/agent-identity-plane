package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTraceTxn(t *testing.T) {
	dir := t.TempDir()
	stsPath := filepath.Join(dir, "sts.jsonl")
	visorPath := filepath.Join(dir, "visor.jsonl")
	l, err := NewLogger(stsPath)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-1", AgentID: "oncall", Principal: "user1"}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if err := os.WriteFile(visorPath, []byte(`{"timestamp":"2023-11-14T22:13:21Z","event_type":"tool_call_allowed","session_id":"txn-1","agent_id":"investigation","server":"github","tool":"create_pr","policy_decision":"allow"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := TraceTxn("txn-1", stsPath, visorPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("len %d", len(recs))
	}
	out := FormatTrace(recs)
	if !strings.Contains(out, "token_minted") || !strings.Contains(out, "create_pr") {
		t.Fatal(out)
	}
}
