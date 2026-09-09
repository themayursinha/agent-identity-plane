package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHashChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "t1"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Event{EventType: "token_denied", ReasonCode: "scope_widening", Txn: "t1"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var events []Event
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		events = append(events, e)
	}
	if len(events) != 2 {
		t.Fatalf("len %d", len(events))
	}
	if events[0].PrevHash != GenesisPrevHash {
		t.Fatalf("genesis %s", events[0].PrevHash)
	}
	if events[1].PrevHash != events[0].Hash {
		t.Fatal("chain broken")
	}
	if events[0].ChainIndex != 1 || events[1].ChainIndex != 2 {
		t.Fatalf("index %d %d", events[0].ChainIndex, events[1].ChainIndex)
	}

	l2, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if l2.PrevHash() != events[1].Hash {
		t.Fatal("recover prev hash")
	}
}

func TestAppendInvalidUTF8ReopensAndTraces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err := l.Append(Event{
		EventType:  "token_denied",
		ReasonCode: "invalid_request",
		Txn:        "txn-1",
		JTI:        "jti-1",
		AgentID:    "\xff",
		Audience:   "aud\xfe",
		Scope:      "a\xffb",
		Hops:       []string{"\xfe"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l2, err := NewLogger(path)
	if err != nil {
		t.Fatalf("reopen after invalid UTF-8: %v", err)
	}
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	recs, err := Trace(Query{JTI: "jti-1"}, []string{path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Txn != "txn-1" {
		t.Fatalf("%+v", recs)
	}
}

func TestRecoverRejectsBrokenHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := NewLogger(path)
	if err != nil {
		t.Fatal(err)
	}
	l.SetNow(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	if err := l.Append(Event{EventType: "token_minted", ReasonCode: "ok", Txn: "t1", JTI: "jti-1"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), `"reason_code":"ok"`, `"reason_code":"no"`, 1)
	if tampered == string(b) {
		t.Fatal("replace")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewLogger(path)
	if err == nil || !errors.Is(err, ErrChainBroken) {
		t.Fatalf("got %v want ErrChainBroken", err)
	}
}

func TestRecoverRejectsIncompleteRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, []byte(`{"jti":"x"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLogger(path); err == nil {
		t.Fatal("incomplete audit JSONL must fail closed")
	}
}
