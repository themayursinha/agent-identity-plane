package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
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
