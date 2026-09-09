package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/themayursinha/agent-identity-plane/internal/jsonutil"
)

// GenesisPrevHash is SHA-256 of the empty payload, matching the capability
// receipt convention.
const GenesisPrevHash = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e490166ae4ba7b5b37bcd8deac"

var (
	ErrUnhealthy   = errors.New("audit: sink unhealthy")
	ErrChainBroken = errors.New("audit: hash chain broken")
)

// Event is one STS decision record.
type Event struct {
	Timestamp  string   `json:"timestamp"`
	EventType  string   `json:"event_type"`
	ReasonCode string   `json:"reason_code"`
	Txn        string   `json:"txn,omitempty"`
	JTI        string   `json:"jti,omitempty"`
	AgentID    string   `json:"agent_id,omitempty"`
	Workload   string   `json:"workload,omitempty"`
	Principal  string   `json:"principal,omitempty"`
	Audience   string   `json:"audience,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	Depth      int      `json:"depth,omitempty"`
	Hops       []string `json:"hops,omitempty"`
	Hash       string   `json:"hash"`
	PrevHash   string   `json:"prev_hash"`
	ChainIndex uint64   `json:"chain_index"`
}

type Logger struct {
	mu         sync.Mutex
	file       *os.File
	prevHash   string
	chainIndex uint64
	poisoned   bool
	now        func() time.Time
}

func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Logger{file: f, prevHash: GenesisPrevHash, now: func() time.Time { return time.Now().UTC() }}
	if err := l.recover(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return l, nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

func (l *Logger) SetNow(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

func (l *Logger) recover() error {
	if _, err := l.file.Seek(0, 0); err != nil {
		return err
	}
	sc := bufio.NewScanner(l.file)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	prev := GenesisPrevHash
	var index uint64
	var last Event
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		e, err := decodeAndVerify(line, prev, index+1)
		if err != nil {
			return err
		}
		last = e
		prev = e.Hash
		index = e.ChainIndex
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if index == 0 {
		return nil
	}
	l.prevHash = last.Hash
	l.chainIndex = last.ChainIndex
	return nil
}

func decodeAuditRecord(raw []byte) (Event, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Event{}, fmt.Errorf("audit: corrupt record: %w", err)
	}
	for _, field := range []string{"timestamp", "event_type", "reason_code", "hash", "prev_hash", "chain_index"} {
		if _, ok := probe[field]; !ok {
			return Event{}, fmt.Errorf("audit: record missing %s", field)
		}
	}
	var e Event
	if err := jsonutil.UnmarshalStrict(raw, &e); err != nil {
		return Event{}, fmt.Errorf("audit: corrupt record: %w", err)
	}
	if e.EventType == "" || e.ReasonCode == "" || e.Hash == "" || e.PrevHash == "" || e.ChainIndex == 0 {
		return Event{}, fmt.Errorf("audit: incomplete record")
	}
	return e, nil
}

func decodeAndVerify(raw []byte, prev string, wantIndex uint64) (Event, error) {
	e, err := decodeAuditRecord(raw)
	if err != nil {
		return Event{}, err
	}
	if err := verifyEvent(e, prev, wantIndex); err != nil {
		return Event{}, err
	}
	return e, nil
}

func verifyEvent(e Event, prev string, wantIndex uint64) error {
	if e.PrevHash != prev {
		return fmt.Errorf("%w: prev_hash at index %d", ErrChainBroken, e.ChainIndex)
	}
	if e.ChainIndex != wantIndex {
		return fmt.Errorf("%w: chain_index %d want %d", ErrChainBroken, e.ChainIndex, wantIndex)
	}
	want, err := payloadHash(e)
	if err != nil {
		return err
	}
	if e.Hash != want {
		return fmt.Errorf("%w: hash mismatch at index %d", ErrChainBroken, e.ChainIndex)
	}
	return nil
}

func payloadHash(e Event) (string, error) {
	e.Hash = ""
	payload, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Append writes e, filling hash-chain fields, and Syncs the file.
func (l *Logger) Append(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.poisoned || l.file == nil {
		return ErrUnhealthy
	}
	if e.Timestamp == "" {
		e.Timestamp = l.now().Format(time.RFC3339Nano)
	}
	e.PrevHash = l.prevHash
	e.ChainIndex = l.chainIndex + 1
	h, err := payloadHash(e)
	if err != nil {
		l.poisoned = true
		return err
	}
	e.Hash = h
	line, err := json.Marshal(e)
	if err != nil {
		l.poisoned = true
		return err
	}
	line = append(line, '\n')
	if _, err := l.file.Write(line); err != nil {
		l.poisoned = true
		return err
	}
	if err := l.file.Sync(); err != nil {
		l.poisoned = true
		return err
	}
	l.prevHash = e.Hash
	l.chainIndex = e.ChainIndex
	return nil
}

func (l *Logger) PrevHash() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.prevHash
}
