package audit

import (
	"errors"
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
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-1", AgentID: "oncall", Principal: "user1", JTI: "jti-a"}); err != nil {
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
	if !strings.Contains(out, "token_minted") || !strings.Contains(out, "create_pr") || !strings.Contains(out, "jti=jti-a") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "verified=") || !strings.Contains(out, "unverified=") {
		t.Fatal(out)
	}
	if recs[0].Verified != true || recs[1].Verified != false {
		t.Fatalf("trust %+v %+v", recs[0], recs[1])
	}
}

func TestTraceJTIExpandsTxn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sts.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-1", JTI: "jti-a", AgentID: "oncall"}); err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_001, 0).UTC() })
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-1", JTI: "jti-b", AgentID: "invest"}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	recs, err := Trace(Query{JTI: "jti-a"}, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("len %d", len(recs))
	}
	if recs[0].JTI != "jti-a" || recs[1].JTI != "jti-b" {
		t.Fatalf("%+v", recs)
	}
	none, err := Trace(Query{Txn: "txn-other", JTI: "jti-a"}, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(none) != 0 {
		t.Fatalf("intersect %d", len(none))
	}
}

func TestTraceRejectsBrokenHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sts.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-1", JTI: "jti-a"}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), `"reason_code":"ok"`, `"reason_code":"no"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = TraceTxn("txn-1", path)
	if err == nil || !errors.Is(err, ErrChainBroken) {
		t.Fatalf("got %v want ErrChainBroken", err)
	}
}

func TestTraceAuditPathRejectsGenericPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sts.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-1", JTI: "jti-a", AgentID: "oncall"}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := `{"event_type":"note"}` + "\n" + string(b)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = TraceTxn("txn-1", path)
	if err == nil {
		t.Fatal("generic prefix on -audit must fail closed")
	}
}

func TestTraceVisorJTIDoesNotPivotTxn(t *testing.T) {
	dir := t.TempDir()
	stsPath := filepath.Join(dir, "sts.jsonl")
	visorPath := filepath.Join(dir, "visor.jsonl")
	l, err := NewLogger(stsPath)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-1", JTI: "jti-a", AgentID: "oncall"}); err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_002, 0).UTC() })
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-2", JTI: "jti-b", AgentID: "invest"}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if err := os.WriteFile(visorPath, []byte(`{"timestamp":"2023-11-14T22:13:22Z","event_type":"tool_call_allowed","session_id":"txn-2","jti":"jti-a","tool":"create_pr"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err := Trace(Query{JTI: "jti-a"}, []string{stsPath}, []string{visorPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Txn != "txn-1" {
		t.Fatalf("%+v", recs)
	}
}

func TestTraceOrdersByParsedTimeNotLexical(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sts.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time {
		return time.Date(2023, 11, 14, 22, 13, 20, 123450000, time.UTC)
	})
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "txn-1", JTI: "jti-a"}); err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time {
		return time.Date(2023, 11, 14, 22, 13, 20, 123456000, time.UTC)
	})
	if err := l.Append(Event{EventType: "token_denied", ReasonCode: "replayed_token", Txn: "txn-1", JTI: "jti-a"}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	recs, err := Trace(Query{Txn: "txn-1"}, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("len %d", len(recs))
	}
	if recs[0].EventType != "token_minted" || recs[1].EventType != "token_denied" {
		t.Fatalf("lexical timestamp sort: %+v", recs)
	}
	if recs[0].ChainIndex != 1 || recs[1].ChainIndex != 2 {
		t.Fatalf("chain %+v", recs)
	}
	if recs[0].Timestamp < recs[1].Timestamp {
		t.Fatalf("test setup: timestamps should invert lexically, got %q < %q", recs[0].Timestamp, recs[1].Timestamp)
	}
}
