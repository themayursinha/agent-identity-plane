package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Record is a reconstructed hop from STS and optional visor JSONL.
type Record struct {
	Source     string   `json:"source"`
	Verified   bool     `json:"verified,omitempty"`
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
	ChainIndex uint64   `json:"chain_index,omitempty"`
}

// Query selects records by transaction and/or minted token jti.
type Query struct {
	Txn string
	JTI string
}

// TraceTxn reconstructs hops for txn from a chain-verified audit file
// and optional unverified visor JSONL.
func TraceTxn(txn string, auditPath string, visorPaths ...string) ([]Record, error) {
	return Trace(Query{Txn: txn}, []string{auditPath}, visorPaths)
}

// Trace reconstructs hops matching txn and/or jti. Every audit path is
// hash-chain verified (fail closed). visor paths are generic JSONL and
// must not choose the jti→txn mapping. A jti-only query returns every
// record for the transaction that minted that jti on a verified audit
// record, plus visor lines whose session_id equals that txn.
// A verified record that carries the jti but no txn (IdP user-token
// denials) is still returned; visor lines cannot supply that mapping.
func Trace(q Query, auditPaths []string, visorPaths []string) ([]Record, error) {
	q.Txn = strings.TrimSpace(q.Txn)
	q.JTI = strings.TrimSpace(q.JTI)
	if q.Txn == "" && q.JTI == "" {
		return nil, fmt.Errorf("audit: txn or jti required")
	}
	var verified []Record
	for _, p := range auditPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		recs, err := loadAuditFile(p)
		if err != nil {
			return nil, err
		}
		verified = append(verified, recs...)
	}
	var unverified []Record
	for _, p := range visorPaths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		recs, err := loadGenericFile(p)
		if err != nil {
			return nil, err
		}
		unverified = append(unverified, recs...)
	}
	txns := map[string]struct{}{}
	jtiDirect := false
	if q.JTI != "" {
		for _, r := range verified {
			if r.JTI != q.JTI {
				continue
			}
			jtiDirect = true
			if r.Txn != "" {
				txns[r.Txn] = struct{}{}
			}
		}
		if !jtiDirect {
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
	for _, r := range verified {
		if _, ok := txns[r.Txn]; ok && r.Txn != "" {
			out = append(out, r)
			continue
		}
		if q.JTI != "" && r.JTI == q.JTI && r.Txn == "" {
			out = append(out, r)
		}
	}
	for _, r := range unverified {
		if r.Txn != "" {
			if _, ok := txns[r.Txn]; ok {
				out = append(out, r)
				continue
			}
		}
		if r.SessionID != "" {
			if _, ok := txns[r.SessionID]; ok {
				out = append(out, r)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return recordLess(out[i], out[j])
	})
	return out, nil
}

func recordLess(a, b Record) bool {
	ta, tb := parseRecordTime(a.Timestamp), parseRecordTime(b.Timestamp)
	if !ta.Equal(tb) {
		if ta.IsZero() != tb.IsZero() {
			return !ta.IsZero()
		}
		return ta.Before(tb)
	}
	if a.Verified && b.Verified {
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.ChainIndex < b.ChainIndex
	}
	if a.Verified != b.Verified {
		return a.Verified
	}
	return false
}

func parseRecordTime(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

func readLines(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
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
	return lines, nil
}

func loadAuditFile(path string) ([]Record, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	return loadAuditRecords(path, lines)
}

func loadGenericFile(path string) ([]Record, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	return loadGenericRecords(path, lines)
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
		Verified:   true,
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
		ChainIndex: e.ChainIndex,
	}
}

func loadGenericRecords(path string, lines [][]byte) ([]Record, error) {
	var recs []Record
	for _, line := range lines {
		var generic map[string]any
		if err := json.Unmarshal(line, &generic); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		r := Record{Source: path, Verified: false}
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
		trust := "unverified"
		if r.Verified {
			trust = "verified"
		}
		fmt.Fprintf(&b, "%d. [%s] %s %s=%s", i+1, safeTrace(r.EventType), safeTrace(r.Timestamp), trust, safeTrace(r.Source))
		if r.ReasonCode != "" {
			fmt.Fprintf(&b, " reason=%s", safeTrace(r.ReasonCode))
		}
		if r.JTI != "" {
			fmt.Fprintf(&b, " jti=%s", safeTrace(r.JTI))
		}
		if r.AgentID != "" {
			fmt.Fprintf(&b, " agent=%s", safeTrace(r.AgentID))
		}
		if r.Workload != "" {
			fmt.Fprintf(&b, " workload=%s", safeTrace(r.Workload))
		}
		if r.Principal != "" {
			fmt.Fprintf(&b, " principal=%s", safeTrace(r.Principal))
		}
		if r.Audience != "" {
			fmt.Fprintf(&b, " aud=%s", safeTrace(r.Audience))
		}
		if r.Tool != "" {
			fmt.Fprintf(&b, " tool=%s", safeTrace(r.Tool))
		}
		if r.Decision != "" {
			fmt.Fprintf(&b, " decision=%s", safeTrace(r.Decision))
		}
		if len(r.Hops) > 0 {
			hops := make([]string, len(r.Hops))
			for i, h := range r.Hops {
				hops[i] = safeTrace(h)
			}
			fmt.Fprintf(&b, " hops=%s", strings.Join(hops, " > "))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func safeTrace(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}
