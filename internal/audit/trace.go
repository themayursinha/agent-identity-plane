package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Record is a reconstructed hop from STS and optional visor JSONL.
type Record struct {
	Source     string   `json:"source"`
	Timestamp  string   `json:"timestamp"`
	EventType  string   `json:"event_type"`
	ReasonCode string   `json:"reason_code,omitempty"`
	AgentID    string   `json:"agent_id,omitempty"`
	Workload   string   `json:"workload,omitempty"`
	Principal  string   `json:"principal,omitempty"`
	Audience   string   `json:"audience,omitempty"`
	Server     string   `json:"server,omitempty"`
	Tool       string   `json:"tool,omitempty"`
	Decision   string   `json:"policy_decision,omitempty"`
	Hops       []string `json:"hops,omitempty"`
	SessionID  string   `json:"session_id,omitempty"`
	Txn        string   `json:"txn,omitempty"`
	JTI        string   `json:"jti,omitempty"`
}

// Query selects records by transaction and/or minted token jti.
type Query struct {
	Txn string
	JTI string
}

// TraceTxn scans JSONL files for records whose txn or session_id matches.
func TraceTxn(txn string, paths ...string) ([]Record, error) {
	return Trace(Query{Txn: txn}, paths...)
}

// Trace reconstructs hops matching txn and/or jti. STS/gateway audit
// files are hash-chain verified (fail closed). A jti-only query returns
// every record for the transaction that minted that jti.
func Trace(q Query, paths ...string) ([]Record, error) {
	q.Txn = strings.TrimSpace(q.Txn)
	q.JTI = strings.TrimSpace(q.JTI)
	if q.Txn == "" && q.JTI == "" {
		return nil, fmt.Errorf("audit: txn or jti required")
	}
	var all []Record
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		recs, err := loadRecords(p)
		if err != nil {
			return nil, err
		}
		all = append(all, recs...)
	}
	txns := map[string]struct{}{}
	if q.JTI != "" {
		for _, r := range all {
			if r.JTI != q.JTI {
				continue
			}
			if r.Txn != "" {
				txns[r.Txn] = struct{}{}
			}
			if r.SessionID != "" {
				txns[r.SessionID] = struct{}{}
			}
		}
		if len(txns) == 0 {
			return nil, nil
		}
		if q.Txn != "" {
			if _, ok := txns[q.Txn]; !ok {
				return nil, nil
			}
			txns = map[string]struct{}{q.Txn: {}}
		}
	} else {
		txns[q.Txn] = struct{}{}
	}
	var out []Record
	for _, r := range all {
		if _, ok := txns[r.Txn]; ok {
			out = append(out, r)
			continue
		}
		if _, ok := txns[r.SessionID]; ok {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Timestamp < out[j].Timestamp
	})
	return out, nil
}

func loadRecords(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lines [][]byte
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		lines = append(lines, cp)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}
	if looksLikeAudit(lines[0]) {
		return loadAuditRecords(path, lines)
	}
	return loadGenericRecords(path, lines)
}

func looksLikeAudit(line []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(line, &probe); err != nil {
		return false
	}
	_, hash := probe["hash"]
	_, prev := probe["prev_hash"]
	_, idx := probe["chain_index"]
	return hash && prev && idx
}

func loadAuditRecords(path string, lines [][]byte) ([]Record, error) {
	prev := GenesisPrevHash
	var index uint64
	var recs []Record
	for _, line := range lines {
		e, err := decodeAndVerify(line, prev, index+1)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		prev = e.Hash
		index = e.ChainIndex
		recs = append(recs, recordFromEvent(path, e))
	}
	return recs, nil
}

func recordFromEvent(path string, e Event) Record {
	return Record{
		Source:     path,
		Timestamp:  e.Timestamp,
		EventType:  e.EventType,
		ReasonCode: e.ReasonCode,
		AgentID:    e.AgentID,
		Workload:   e.Workload,
		Principal:  e.Principal,
		Audience:   e.Audience,
		Hops:       e.Hops,
		Txn:        e.Txn,
		JTI:        e.JTI,
	}
}

func loadGenericRecords(path string, lines [][]byte) ([]Record, error) {
	var recs []Record
	for _, line := range lines {
		var generic map[string]any
		if err := json.Unmarshal(line, &generic); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		r := Record{Source: path}
		r.Txn, _ = generic["txn"].(string)
		r.SessionID, _ = generic["session_id"].(string)
		r.Timestamp, _ = generic["timestamp"].(string)
		r.EventType, _ = generic["event_type"].(string)
		r.ReasonCode, _ = generic["reason_code"].(string)
		r.AgentID, _ = generic["agent_id"].(string)
		r.Workload, _ = generic["workload"].(string)
		r.Principal, _ = generic["principal"].(string)
		r.Audience, _ = generic["audience"].(string)
		r.Server, _ = generic["server"].(string)
		r.Tool, _ = generic["tool"].(string)
		r.Decision, _ = generic["policy_decision"].(string)
		r.JTI, _ = generic["jti"].(string)
		if hops, ok := generic["hops"].([]any); ok {
			for _, h := range hops {
				if s, ok := h.(string); ok {
					r.Hops = append(r.Hops, s)
				}
			}
		}
		recs = append(recs, r)
	}
	return recs, nil
}

func FormatTrace(recs []Record) string {
	var b strings.Builder
	for i, r := range recs {
		fmt.Fprintf(&b, "%d. [%s] %s", i+1, r.EventType, r.Timestamp)
		if r.ReasonCode != "" {
			fmt.Fprintf(&b, " reason=%s", r.ReasonCode)
		}
		if r.JTI != "" {
			fmt.Fprintf(&b, " jti=%s", r.JTI)
		}
		if r.AgentID != "" {
			fmt.Fprintf(&b, " agent=%s", r.AgentID)
		}
		if r.Workload != "" {
			fmt.Fprintf(&b, " workload=%s", r.Workload)
		}
		if r.Principal != "" {
			fmt.Fprintf(&b, " principal=%s", r.Principal)
		}
		if r.Audience != "" {
			fmt.Fprintf(&b, " aud=%s", r.Audience)
		}
		if r.Tool != "" {
			fmt.Fprintf(&b, " tool=%s", r.Tool)
		}
		if r.Decision != "" {
			fmt.Fprintf(&b, " decision=%s", r.Decision)
		}
		if len(r.Hops) > 0 {
			fmt.Fprintf(&b, " hops=%s", strings.Join(r.Hops, " > "))
		}
		b.WriteByte('\n')
	}
	return b.String()
}
